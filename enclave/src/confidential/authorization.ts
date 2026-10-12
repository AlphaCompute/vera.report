import { createMessage, readSignature, sign, verify } from './pgp.ts';
import { issuedNotAfter } from './clockSkew.ts';
import { MAX_GRANT_LIFETIME_MS, grantActiveAt, grantCoversObject } from './grantPolicy.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';

/** Shared v1 protocol used by the mounted owner and legal case channels.
 * Private statements MUST be encrypted before storage/transport: signatures
 * provide authenticity, not confidentiality. No platform key is accepted here.
 */
const PROTOCOL = 'vera-owner-authorization/v1';
const MAX_WIRE_LENGTH = 65_536;
const MAX_MANIFEST_OBJECTS = 256;
const SCOPES = ['narrative', 'evidence', 'messages', 'identity', 'contact', 'rewards'] as const;
export type CaseScope = typeof SCOPES[number];
type Base = { caseId: string; revision: number };
export { MAX_GRANT_LIFETIME_MS, grantActiveAt, grantCoversObject };
export type CaseListing = Base & { kind: 'listing'; summary: string; publishedAt?: number; hasAttachments?: boolean };
/** `expiresAt: null` means "until revoked" (owner decision; revocation is the
 * explicit end). `excludedObjectIds`, when present, lists manifest objects this
 * grant does NOT cover even though their scope is granted ("only some files").
 * It is omitted, never empty, so grants signed before it existed keep their
 * canonical digest. New objects are never excluded: whether later files are
 * covered is decided by `objectRevisionLimit` alone. */
export type AccessGrant = Base & {
  kind: 'grant'; grantId: string; organizationId: string; recipientKeyId: string;
  scopes: CaseScope[]; keyEpoch: number; objectRevisionLimit: number | null;
  issuedAt: number; expiresAt: number | null; excludedObjectIds?: string[];
};
export type ReleaseApproval = Base & {
  kind: 'release'; releaseDigest: string; issuedAt: number;
};
/** Owner-signed inventory. Object metadata (scope, revision, epoch, ciphertext
 * digest) comes from here, never from a storage row or request claim, so the
 * host cannot withhold, reorder into another scope, or replay an older object. */
export type ManifestEntry = {
  objectId: string; scope: CaseScope; objectRevision: number; keyEpoch: number; ciphertextDigest: string;
};
export type CaseManifest = Base & { kind: 'manifest'; objects: ManifestEntry[] };
/** Hash-chained current state. `previousDigest` links to the prior checkpoint so
 * two different successors of one checkpoint are verifiable fork evidence. It is
 * the ONLY state-history link: the owner signature over this checkpoint is the
 * owner's consent to exactly this predecessor -> successor step. (A separately
 * signed `transition` statement existed in the draft protocol; it carried no
 * information beyond this field and is no longer accepted. See
 * docs/security/CONFIDENTIAL-CASE-ARCHITECTURE.md, "Protocol simplification".)
 * `listingDigest: null` means unlisted/withdrawn; an older signed listing is not current. */
export type CaseCheckpoint = Base & {
  kind: 'checkpoint'; keyEpoch: number; previousDigest: string | null;
  listingDigest: string | null; manifestDigest: string | null;
  grantDigests: string[]; releaseDigests: string[]; issuedAt: number;
};
export type OwnerStatement = CaseListing | AccessGrant | ReleaseApproval | CaseManifest | CaseCheckpoint;
export type OwnerTrust = {
  caseId: string;
  /** Pin from authenticated recovery/genesis, NEVER from the record being verified. */
  ownerFingerprint: string;
  ownerPublicKey: PublicKey;
};

function invalid(): never { throw new Error('Invalid confidential authorization'); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, fields: string[]): void {
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) invalid();
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) return invalid();
  return value;
}
function fingerprint(value: unknown): string {
  if (typeof value !== 'string' || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value)) return invalid();
  return value;
}
function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) return invalid();
  return value;
}
function unique<T>(value: unknown, max: number, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > max) return invalid();
  const items = value.map(parse);
  if (new Set(items).size !== items.length) invalid();
  return items;
}
function nullableId(value: unknown): string | null {
  return value === null ? null : id(value);
}
function manifestEntry(input: unknown): ManifestEntry {
  const value = record(input);
  exact(value, ['objectId', 'scope', 'objectRevision', 'keyEpoch', 'ciphertextDigest']);
  return { objectId: id(value.objectId), scope: scope(value.scope), objectRevision: positive(value.objectRevision),
    keyEpoch: positive(value.keyEpoch), ciphertextDigest: id(value.ciphertextDigest) };
}
function scope(value: unknown): CaseScope {
  if (!SCOPES.includes(value as CaseScope)) return invalid();
  return value as CaseScope;
}

/** Explicit reconstruction is also the canonical field order. Unknown fields
 * fail rather than disappearing into a signature or a public listing projection.
 */
function parseStatement(input: unknown): OwnerStatement {
  const value = record(input);
  const base = { caseId: id(value.caseId), revision: positive(value.revision) };
  const fields = ['kind', 'caseId', 'revision'];
  switch (value.kind) {
    case 'listing': {
      // Reject extra public fields rather than silently removing signed information.
      const optional = ['publishedAt', 'hasAttachments'].filter(key => Object.prototype.hasOwnProperty.call(value, key));
      exact(value, [...fields, 'summary', ...optional]);
      if (optional.includes('publishedAt') && (typeof value.publishedAt !== 'number' || !Number.isSafeInteger(value.publishedAt) ||
          value.publishedAt < 0 || value.publishedAt > 8_640_000_000_000_000)) invalid();
      if (optional.includes('hasAttachments') && typeof value.hasAttachments !== 'boolean') invalid();
      if (typeof value.summary !== 'string' || !value.summary.trim() ||
          value.summary.length > 600 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value.summary)) invalid();
      return { kind: 'listing', ...base, summary: value.summary as string,
        ...(optional.includes('publishedAt') ? { publishedAt: value.publishedAt as number } : {}),
        ...(optional.includes('hasAttachments') ? { hasAttachments: value.hasAttachments as boolean } : {}) };
    }
    case 'grant': {
      const grantFields = [...fields, 'grantId', 'organizationId', 'recipientKeyId', 'scopes',
        'keyEpoch', 'objectRevisionLimit', 'issuedAt', 'expiresAt'];
      const excludes = Object.prototype.hasOwnProperty.call(value, 'excludedObjectIds');
      exact(value, excludes ? [...grantFields, 'excludedObjectIds'] : grantFields);
      const scopes = unique(value.scopes, SCOPES.length, scope);
      const issuedAt = positive(value.issuedAt);
      const expiresAt = value.expiresAt === null ? null : positive(value.expiresAt);
      if (!scopes.length || (expiresAt !== null && (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_GRANT_LIFETIME_MS))) invalid();
      let excludedObjectIds: string[] | undefined;
      if (excludes) {
        excludedObjectIds = unique(value.excludedObjectIds, MAX_MANIFEST_OBJECTS, id);
        // Canonical: non-empty and sorted, so one decision has exactly one digest.
        if (!excludedObjectIds.length || excludedObjectIds.some((item, index) => index > 0 && item <= excludedObjectIds![index - 1])) invalid();
      }
      return { kind: 'grant', ...base, grantId: id(value.grantId),
        organizationId: id(value.organizationId), recipientKeyId: id(value.recipientKeyId),
        scopes, keyEpoch: positive(value.keyEpoch), objectRevisionLimit: value.objectRevisionLimit === null ? null : positive(value.objectRevisionLimit),
        issuedAt, expiresAt, ...(excludedObjectIds ? { excludedObjectIds } : {}) };
    }
    case 'release':
      exact(value, [...fields, 'releaseDigest', 'issuedAt']);
      return { kind: 'release', ...base, releaseDigest: id(value.releaseDigest), issuedAt: positive(value.issuedAt) };
    case 'manifest': {
      exact(value, [...fields, 'objects']);
      if (!Array.isArray(value.objects) || value.objects.length > MAX_MANIFEST_OBJECTS) invalid();
      const objects = value.objects.map(manifestEntry);
      if (new Set(objects.map(entry => entry.objectId)).size !== objects.length) invalid();
      return { kind: 'manifest', ...base, objects };
    }
    case 'checkpoint': {
      exact(value, [...fields, 'keyEpoch', 'previousDigest', 'listingDigest', 'manifestDigest',
        'grantDigests', 'releaseDigests', 'issuedAt']);
      const keyEpoch = positive(value.keyEpoch);
      const previousDigest = nullableId(value.previousDigest);
      const listingDigest = nullableId(value.listingDigest), manifestDigest = nullableId(value.manifestDigest);
      const grantDigests = unique(value.grantDigests, 64, id), releaseDigests = unique(value.releaseDigests, 32, id);
      return { kind: 'checkpoint', ...base, keyEpoch, previousDigest, listingDigest, manifestDigest,
        grantDigests, releaseDigests, issuedAt: positive(value.issuedAt) };
    }
    // Retired kinds (the draft `transition` statement) and unknown kinds fail closed.
    default: return invalid();
  }
}

function body(ownerFingerprint: string, statement: OwnerStatement): string {
  return JSON.stringify({ protocol: PROTOCOL, ownerFingerprint, statement });
}
async function digest(payload: string): Promise<string> {
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Signing belongs on the owner device. Call only after an affirmative decision.
 * Returns a signed plaintext record; it contains private relationship metadata.
 */
export async function signOwnerStatement(input: OwnerStatement, ownerKey: PrivateKey): Promise<string> {
  // Snapshot before any await so mutable UI state cannot change what was approved.
  const statement = parseStatement(input);
  const ownerFingerprint = fingerprint(ownerKey.getFingerprint());
  if (!ownerKey.isDecrypted()) invalid();
  const signature = await sign({
    message: await createMessage({ binary: new TextEncoder().encode(body(ownerFingerprint, statement)) }),
    signingKeys: ownerKey, detached: true, format: 'armored',
  });
  const wire = JSON.stringify({ protocol: PROTOCOL, ownerFingerprint, statement, signature });
  if (wire.length > MAX_WIRE_LENGTH) invalid();
  return wire;
}

/** Verifies authorship and case binding only, NOT freshness, scope or attestation.
 * The digest identifies the canonical signed payload, not the randomized signature.
 */
export async function verifyOwnerStatement(wire: string, trust: OwnerTrust): Promise<{
  statement: OwnerStatement; digest: string;
}> {
  try {
    const caseId = id(trust.caseId), ownerFingerprint = fingerprint(trust.ownerFingerprint);
    const key = trust.ownerPublicKey;
    if (key.isPrivate() || key.getFingerprint() !== ownerFingerprint ||
        typeof wire !== 'string' || wire.length > MAX_WIRE_LENGTH) invalid();
    const value = record(JSON.parse(wire));
    exact(value, ['protocol', 'ownerFingerprint', 'statement', 'signature']);
    if (value.protocol !== PROTOCOL || value.ownerFingerprint !== ownerFingerprint ||
        typeof value.signature !== 'string' || value.signature.length > 16_384) invalid();
    const statement = parseStatement(value.statement);
    if (statement.caseId !== caseId) invalid();
    const payload = body(ownerFingerprint, statement);
    const signature = await readSignature({ armoredSignature: value.signature as string });
    const result = await verify({
      message: await createMessage({ binary: new TextEncoder().encode(payload) }),
      signature, verificationKeys: key, expectSigned: true, format: 'binary',
    });
    // Consume ALL promises even for malformed multi-signature messages.
    const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
    return { statement, digest: await digest(payload) };
  } catch {
    // Do not echo signed payloads, private metadata, or library diagnostics.
    return invalid();
  }
}

export type CaseReadRequest = {
  organizationId: string; recipientKeyId: string; objectId: string; ciphertextDigest: string;
  scope: CaseScope; releaseDigest: string; keyEpoch: number; objectRevision: number; now: number;
};

export type CaseReadAuthorization = {
  grant: string; release: string; manifest: string; checkpoint: string; checkpointDigest: string;
  trust: OwnerTrust; request: CaseReadRequest;
};

/** Authorization predicate used by the enclave handler and participant clients. The caller MUST:
 * - authenticate the live organization/member and prove recipient key possession;
 * - obtain checkpointDigest from a trusted current-state witness/device checkpoint,
 *   not from the same untrusted server supplying these records;
 * - supply measured releaseDigest, authenticated object revision/epoch and trusted time;
 * - encrypt transport/storage and bind the actual attested channel before key release.
 * A hash supplied by an attacker cannot establish latest state. This function
 * intentionally has no default checkpoint, release, clock, role or bypass.
 */
export async function authorizeCaseRead(input: CaseReadAuthorization): Promise<void> {
  return authorizeCaseReadWith(input, wire => verifyOwnerStatement(wire, { ...input.trust }));
}

/** One authenticated operation only: discard this authorizer at its end. Cache
 * signature verification, NEVER the authorization decision. Each request still
 * validates its current checkpoint, time, recipient, release and object bounds.
 * Wires are verified under one fixed owner trust; no pre-verified caller objects
 * or process-wide cache can cross a case/owner boundary.
 */
export function createCaseReadAuthorizer(ownerTrust: OwnerTrust):
  (input: Omit<CaseReadAuthorization, 'trust'>) => Promise<void> {
  const trust = { ...ownerTrust };
  const verified = new Map<string, ReturnType<typeof verifyOwnerStatement>>();
  return input => authorizeCaseReadWith({ ...input, trust }, wire => {
    let result = verified.get(wire);
    if (!result) {
      result = verifyOwnerStatement(wire, trust);
      verified.set(wire, result);
    }
    return result;
  });
}

async function authorizeCaseReadWith(input: CaseReadAuthorization,
  verifyWire: (wire: string) => ReturnType<typeof verifyOwnerStatement>): Promise<void> {
  const checkpointDigest = id(input.checkpointDigest);
  const request = { ...input.request };
  id(request.organizationId); id(request.recipientKeyId); id(request.releaseDigest);
  id(request.objectId); id(request.ciphertextDigest);
  positive(request.keyEpoch); positive(request.objectRevision); positive(request.now); scope(request.scope);
  const [grantResult, releaseResult, manifestResult, checkpointResult] = await Promise.all([
    verifyWire(input.grant), verifyWire(input.release), verifyWire(input.manifest), verifyWire(input.checkpoint),
  ]);
  const grant = grantResult.statement, release = releaseResult.statement;
  const manifest = manifestResult.statement, checkpoint = checkpointResult.statement;
  if (grant.kind !== 'grant' || release.kind !== 'release' || manifest.kind !== 'manifest' ||
      checkpoint.kind !== 'checkpoint') invalid();
  const entry = manifest.objects.find(item => item.objectId === request.objectId);
  if (!entry || entry.scope !== request.scope || entry.objectRevision !== request.objectRevision ||
      entry.keyEpoch !== request.keyEpoch || entry.ciphertextDigest !== request.ciphertextDigest ||
      checkpoint.manifestDigest !== manifestResult.digest || manifest.revision > checkpoint.revision) invalid();
  if (checkpointResult.digest !== checkpointDigest ||
      !checkpoint.grantDigests.includes(grantResult.digest) ||
      !checkpoint.releaseDigests.includes(releaseResult.digest) ||
      grant.revision > checkpoint.revision || release.revision > checkpoint.revision ||
      // Grants are re-signed at each epoch change; objects sealed under an earlier
      // epoch remain readable by grants that are still current.
      grant.keyEpoch !== checkpoint.keyEpoch || request.keyEpoch > checkpoint.keyEpoch ||
      grant.organizationId !== request.organizationId || grant.recipientKeyId !== request.recipientKeyId ||
      !grantCoversObject(grant, { objectId: request.objectId, scope: request.scope, objectRevision: request.objectRevision }) ||
      release.releaseDigest !== request.releaseDigest ||
      !grantActiveAt(grant, request.now) || !issuedNotAfter(release.issuedAt, request.now) || !issuedNotAfter(checkpoint.issuedAt, request.now)) invalid();
}

/** The only public case-content projection; never accepts a ReportRecord.
 * A listing is current only when the owner-signed checkpoint names its digest;
 * this rejects an older or withdrawn summary republished by the host. */
export async function verifiedListing(wire: string, checkpointWire: string, trust: OwnerTrust): Promise<{
  caseId: string; summary: string; revision: number; publishedAt?: number; hasAttachments?: boolean;
}> {
  const [{ statement, digest }, current] = await Promise.all([
    verifyOwnerStatement(wire, trust), verifyOwnerStatement(checkpointWire, trust)]);
  if (statement.kind !== 'listing' || current.statement.kind !== 'checkpoint' ||
      current.statement.listingDigest !== digest || statement.revision > current.statement.revision) invalid();
  const { publishedAt, hasAttachments } = statement;
  return { caseId: statement.caseId, summary: statement.summary, revision: statement.revision, ...(publishedAt !== undefined ? { publishedAt } : {}), ...(hasAttachments !== undefined ? { hasAttachments } : {}) };
}
