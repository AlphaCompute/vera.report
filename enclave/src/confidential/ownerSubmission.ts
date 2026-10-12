import { signOwnerStatement, verifyOwnerStatement } from './authorization.ts';
import type { CaseScope, ManifestEntry, OwnerTrust } from './authorization.ts';
import { caseObjectDigest, openOwnerCaseObject, sealCaseObject } from './caseObject.ts';
import type { ObjectContext, OwnedCaseObject } from './caseObject.ts';
import { createCaseOwner, createOwnerRecovery } from './recovery.ts';
import type { CheckpointPin } from './recovery.ts';
import { readReleaseManifest } from './releaseManifest.ts';
import { encodeBase64, generateCaseStateKey, wrapCaseStateKey } from './caseStateKey.ts';
import type { PrivateKey } from './pgp.ts';
import {
  CHUNKED_FILE_LIMIT, CHUNKED_UPLOAD_LIMIT, EvidenceChangedError, EvidenceTooLargeError, MAX_FILES_PER_UPLOAD,
  bytesEvidenceSource, openOwnerChunkedObject, sealChunkedObject,
} from './caseChunks.ts';
import type { EvidenceSource, SealedChunkedObject } from './caseChunks.ts';

/** Public listings contain the approved summary, opaque reference and optional signed submission facts. */
export const CONFIDENTIAL_FILE_LIMIT = CHUNKED_FILE_LIMIT;
export const CONFIDENTIAL_UPLOAD_LIMIT = CHUNKED_UPLOAD_LIMIT;
export const CONFIDENTIAL_MAX_FILES = MAX_FILES_PER_UPLOAD;
/** Whole-buffer evidence written before the chunked format (read-only compatibility). */
const WHOLE_OBJECT_FILE_LIMIT = 8 * 1024 * 1024 - 4096;
const FILE_FORMAT = 'vera-case-file/v1';
const MAX_FILES = MAX_FILES_PER_UPLOAD;

export type ConfidentialDraft = {
  summary: string;
  narrative: Record<string, string | boolean | null>;
  contact: Record<string, string> | null;
  identity: Record<string, string> | null;
  /** Browser File slices (`blobEvidenceSource`) or in-memory bytes. */
  files: (EvidenceSource | { name: string; type: string; bytes: Uint8Array })[];
};
export type EncryptionProgress = { bytesDone: number; bytesTotal: number };
export type PreparedSubmission = {
  caseId: string;
  /** Body for the case service `publish-case` operation: signatures, owner key
   * envelopes and staged-object digests. Small enough for the attested channel. */
  publishBody: Uint8Array;
  /** Participant-encrypted object ciphertext to upload to staging before publish. */
  stagedObjects: { digest: string; ciphertext: string }[];
  /** Evidence as chunked objects: chunks are re-encrypted on demand for a
   * resumable upload (see `uploadChunkedObjects`) before publish. */
  chunkedObjects: SealedChunkedObject[];
  /** Participant-only; display once, allow copy/download, never transmit or persist. */
  recoveryCode: string;
  /** Opaque AES-GCM package; also offered as an offline download. */
  recoveryPackage: string;
  pin: CheckpointPin;
  owner: { privateKey: PrivateKey; trust: OwnerTrust };
};

function invalid(message = 'Unable to prepare confidential submission'): never { throw new Error(message); }
function randomId(): string {
  return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
}
function json(value: unknown): Uint8Array { return new TextEncoder().encode(JSON.stringify(value)); }
function scalarRecord(value: unknown, max: number): Record<string, string | boolean | null> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length > 32) invalid();
  for (const [key, item] of Object.entries(value)) {
    if (!/^[a-zA-Z][a-zA-Z0-9]{0,63}$/.test(key) ||
        !(item === null || typeof item === 'boolean' || (typeof item === 'string' && item.length <= max))) invalid();
  }
  return { ...value as Record<string, string | boolean | null> };
}

/** Whole-buffer evidence packing (older cases). Packs file name/type inside the
 * encrypted payload; storage sees neither. New evidence uses caseChunks.ts. */
export function packCaseFile(file: { name: string; type: string; bytes: Uint8Array }): Uint8Array {
  if (typeof file.name !== 'string' || !file.name.length || file.name.length > 255 ||
      typeof file.type !== 'string' || file.type.length > 127 || !(file.bytes instanceof Uint8Array)) invalid();
  if (file.bytes.length > WHOLE_OBJECT_FILE_LIMIT) invalid('Evidence file is too large for confidential submission');
  const header = json({ format: FILE_FORMAT, name: file.name, type: file.type });
  const packed = new Uint8Array(4 + header.length + file.bytes.length);
  new DataView(packed.buffer).setUint32(0, header.length);
  packed.set(header, 4); packed.set(file.bytes, 4 + header.length);
  return packed;
}
export function unpackCaseFile(bytes: Uint8Array): { name: string; type: string; bytes: Uint8Array } {
  if (!(bytes instanceof Uint8Array) || bytes.length < 4) invalid();
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  if (size > 1024 || size + 4 > bytes.length) invalid();
  const header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(4, 4 + size)));
  if (!header || Object.keys(header).sort().join(',') !== 'format,name,type' || header.format !== FILE_FORMAT ||
      typeof header.name !== 'string' || typeof header.type !== 'string') invalid();
  return { name: header.name, type: header.type, bytes: bytes.slice(4 + size) };
}

/** Builds a complete, locally verified publish body. `releaseManifest` is the
 * canonical manifest of the backend the participant approves at Submit; the
 * browser must also verify attestation for it before sending anything. */
/** Count, per-file and total limits, checked before anything is read or encrypted. */
export function checkEvidenceSources(files: readonly EvidenceSource[]): void {
  if (files.length > MAX_FILES) throw new EvidenceTooLargeError(`Attach at most ${MAX_FILES} files.`);
  let total = 0;
  for (const file of files) {
    if (!Number.isSafeInteger(file.size) || file.size < 0) invalid();
    if (file.size > CONFIDENTIAL_FILE_LIMIT) throw new EvidenceTooLargeError(`${file.name} is larger than 256 MB.`);
    total += file.size;
  }
  if (total > CONFIDENTIAL_UPLOAD_LIMIT) throw new EvidenceTooLargeError('Files must total 256 MB or less.');
}
function evidenceSources(files: ConfidentialDraft['files']): EvidenceSource[] {
  if (!Array.isArray(files)) invalid();
  return files.map(file => {
    if (!file || typeof file !== 'object') invalid();
    return 'bytes' in file ? bytesEvidenceSource(file) : file;
  });
}

/** Encrypt evidence files as chunked objects, reporting encrypted plaintext bytes. */
export async function sealEvidenceFiles(sources: readonly EvidenceSource[], context: (index: number) => ObjectContext,
  owner: PrivateKey, onProgress?: (progress: EncryptionProgress) => void): Promise<SealedChunkedObject[]> {
  checkEvidenceSources(sources);
  const bytesTotal = sources.reduce((sum, file) => sum + file.size, 0);
  const sealed: SealedChunkedObject[] = [];
  let bytesDone = 0;
  try {
    for (const [index, source] of sources.entries()) {
      sealed.push(await sealChunkedObject(context(index), source, owner));
      bytesDone += source.size;
      try { onProgress?.({ bytesDone, bytesTotal }); } catch { /* progress display must not break encryption */ }
    }
    return sealed;
  } catch (error) {
    for (const item of sealed) item.dispose();
    throw error;
  }
}

/** Builds a complete, locally verified publish body. `releaseManifest` is the
 * canonical manifest of the backend the participant approves at Submit; the
 * browser must also verify attestation for it before sending anything.
 *
 * Metadata (hole 12): every object's size is bucketed inside its encryption
 * (caseObject.ts, caseChunks.ts). The object COUNT is deliberately not padded
 * with dummy objects: every manifest entry is a real, owner-signed, grantable
 * object that the enclave, the owner client, granted firms (which read the signed
 * manifest), recovery and scope-wide grants all treat as content. A dummy would
 * need a new signed manifest field that every verifier and grant path must
 * exclude, and a firm reading the manifest would still see it. Storage therefore
 * sees how many objects a submission has (narrative plus optional contact and
 * identity, plus one per file); the review step says so. */
export async function prepareConfidentialSubmission(draft: ConfidentialDraft, releaseManifest: string,
  now: number, options: { onProgress?: (progress: EncryptionProgress) => void } = {}): Promise<PreparedSubmission> {
  // Snapshot every caller-controlled value before the first await.
  const summary = draft.summary;
  if (typeof summary !== 'string' || !summary.trim() || summary.length > 600) invalid('Add a short summary for legal review');
  const narrative = scalarRecord(draft.narrative, 50_000);
  const contact = draft.contact === null ? null : scalarRecord(draft.contact, 1_000);
  const identity = draft.identity === null ? null : scalarRecord(draft.identity, 1_000);
  if (!Number.isSafeInteger(now) || now <= 0) invalid();
  const sources = evidenceSources(draft.files);
  checkEvidenceSources(sources);
  const packedObjects: { scope: CaseScope; bytes: Uint8Array }[] = [
    { scope: 'narrative', bytes: json(narrative) },
    ...(contact ? [{ scope: 'contact' as const, bytes: json(contact) }] : []),
    ...(identity ? [{ scope: 'identity' as const, bytes: json(identity) }] : []),
  ];
  let ownerSecret: Uint8Array | undefined;
  let evidence: SealedChunkedObject[] = [];
  try {
    const { digest: releaseDigest } = await readReleaseManifest(releaseManifest);
    const { privateKey, trust, recoverySecret } = await createCaseOwner();
    ownerSecret = recoverySecret;
    const caseId = trust.caseId;
    const sealed: (OwnedCaseObject & { objectId: string; context: ObjectContext })[] = [];
    for (const item of packedObjects) {
      const context: ObjectContext = { caseId, objectId: randomId(), scope: item.scope, keyEpoch: 1, objectRevision: 1 };
      sealed.push({ ...await sealCaseObject(context, item.bytes, privateKey), objectId: context.objectId, context });
    }
    evidence = await sealEvidenceFiles(sources, () => ({ caseId, objectId: randomId(), scope: 'evidence',
      keyEpoch: 1, objectRevision: 1 }), privateKey, options.onProgress);
    const signed = async (statement: Parameters<typeof signOwnerStatement>[0]) => {
      const wire = await signOwnerStatement(statement, privateKey);
      return { wire, digest: (await verifyOwnerStatement(wire, trust)).digest };
    };
    const entries: ManifestEntry[] = [
      ...await Promise.all(sealed.map(async item => ({
        objectId: item.objectId, scope: item.context.scope, objectRevision: 1, keyEpoch: 1,
        ciphertextDigest: await caseObjectDigest(item.ciphertext) }))),
      ...evidence.map(item => ({ objectId: item.context.objectId, scope: 'evidence' as const, objectRevision: 1, keyEpoch: 1,
        ciphertextDigest: item.digest })),
    ];
    const listing = await signed({ kind: 'listing', caseId, revision: 1, summary, publishedAt: now, hasAttachments: sources.length > 0 });
    const release = await signed({ kind: 'release', caseId, revision: 1, releaseDigest, issuedAt: now });
    const manifest = await signed({ kind: 'manifest', caseId, revision: 1, objects: entries });
    const checkpoint = await signed({ kind: 'checkpoint', caseId, revision: 1, keyEpoch: 1, previousDigest: null,
      listingDigest: listing.digest, manifestDigest: manifest.digest, grantDigests: [],
      releaseDigests: [release.digest], issuedAt: now });
    // Recovery is exercised (restore round trip) before it is ever reported.
    const recovery = await createOwnerRecovery({ privateKey, trust, recoverySecret }, checkpoint.wire);
    // Prove every object opens with the owner key before claiming the report is recoverable.
    for (const item of sealed) (await openOwnerCaseObject(item, item.context, privateKey)).fill(0);
    for (const item of evidence) {
      (await openOwnerChunkedObject(item.index, item.ownerEnvelope, item.context, item.digest, privateKey)).dispose();
    }
    // Participant-held state key: sealed storage of private case metadata. Only the
    // owner (and later, granted firms) receive wrapped copies; the enclave gets it
    // inside the attested channel and keeps it in memory only.
    const state = generateCaseStateKey(1);
    const ownerStateEnvelope = await wrapCaseStateKey(caseId, state, trust.ownerPublicKey, privateKey);
    const publishBody = json({ caseId, ownerPublicKey: trust.ownerPublicKey.armor(),
      stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch, stateEnvelopes: [ownerStateEnvelope],
      statements: [listing.wire, release.wire, manifest.wire], checkpoint: checkpoint.wire,
      objects: [
        ...sealed.map((item, index) => ({ objectId: item.objectId, stagedDigest: entries[index].ciphertextDigest,
          ownerEnvelope: item.ownerEnvelope })),
        ...evidence.map(item => ({ objectId: item.context.objectId, chunkedIndex: item.index, ownerEnvelope: item.ownerEnvelope })),
      ],
      recoveryPackage: recovery.encryptedPackage });
    state.key.fill(0);
    return { caseId, publishBody, recoveryCode: recovery.recoveryCode, recoveryPackage: recovery.encryptedPackage,
      stagedObjects: sealed.map((item, index) => ({ digest: entries[index].ciphertextDigest, ciphertext: item.ciphertext })),
      chunkedObjects: evidence, pin: recovery.pin, owner: { privateKey, trust } };
  } catch (error) {
    for (const item of evidence) item.dispose();
    if (error instanceof EvidenceChangedError || error instanceof EvidenceTooLargeError) throw error;
    return invalid();
  } finally {
    // The code string is what the participant keeps; no raw secret outlives this call.
    ownerSecret?.fill(0);
    for (const item of packedObjects) item.bytes.fill(0);
  }
}
