import { createMessage, decrypt, encrypt, enums, readMessage } from './pgp.ts';
import type { PrivateKey, PublicKey, SessionKey } from './pgp.ts';
import { authorizeCaseRead, verifyOwnerStatement } from './authorization.ts';
import type { CaseReadAuthorization, CaseScope } from './authorization.ts';
import { powerOfTwoBucket } from './padding.ts';
import { decodeCanonicalBase64, encodeBase64 } from './base64.ts';

/** Whole-buffer case objects (narrative, contact, identity, older evidence).
 * OpenPGP authenticates/encrypts the payload and each recipient envelope. A new
 * random AES-256 content key is used for each object; only that small key envelope
 * is re-encrypted when sharing. No platform/master-key recovery path exists.
 * Whole-buffer objects are bounded to 8 MiB. Evidence uses the chunked format in
 * caseChunks.ts, whose content keys travel in the same envelope structure under
 * its own format label. Nothing here proves TEE attestation.
 *
 * Size padding (hole 12): new objects frame the payload as `vera-case-object/v1-padded`
 * (header carries the exact length) and zero-fill the framed plaintext to a
 * power-of-two bucket (4 KiB floor, 8 MiB + 4 KiB top bucket) *inside* the signed,
 * integrity-protected OpenPGP message. Readers require the exact bucket and all-zero
 * padding. Objects written before padding (unpadded `vera-case-object/v1` framing)
 * still open. The key-envelope label stays `vera-case-object/v1` for both.
 */
const FORMAT = 'vera-case-object/v1';
/** Inner framing label of padded whole-buffer payloads (never a key-envelope label). */
export const PADDED_PAYLOAD_FORMAT = 'vera-case-object/v1-padded';
/** Envelope label for chunked-object content keys (see caseChunks.ts). A key
 * wrapped for one format is never accepted by the other format's reader. */
export const CHUNKED_ENVELOPE_FORMAT = 'vera-case-object/v2';
type EnvelopeFormat = typeof FORMAT | typeof CHUNKED_ENVELOPE_FORMAT;
const LIMIT = 8 * 1024 * 1024;
const ENVELOPE_LIMIT = 16_384;
/** Largest framed payload (the top padding bucket); also the decryption bound. */
const MAX_FRAMED = LIMIT + 4096;
const MIN_FRAMED = 4096;
// Compression would squeeze the zero padding back out; openpgp's default is
// already uncompressed, pinned here so a library default change cannot undo it.
const CONFIG = { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false,
  maxDecompressedMessageSize: MAX_FRAMED, preferredCompressionAlgorithm: enums.compression.uncompressed };
/** Framed (header + payload) size for `framed` bytes: the padded plaintext size. */
export function caseObjectPaddedBytes(framed: number): number { return powerOfTwoBucket(framed, MIN_FRAMED, MAX_FRAMED); }
export type ObjectContext = {
  caseId: string; objectId: string; scope: CaseScope; keyEpoch: number; objectRevision: number;
};
export type OwnedCaseObject = { ciphertext: string; ownerEnvelope: string };
export type GrantedCaseObject = { ciphertext: string; recipientEnvelope: string };
type KeyEnvelope = {
  format: EnvelopeFormat; context: ObjectContext; ciphertextDigest: string;
  sessionKey: string; grantDigest: string | null; recipientKeyId: string;
};

function invalid(): never { throw new Error('Unable to open confidential case object'); }
function context(input: ObjectContext): ObjectContext {
  if (!input || !/^[a-f0-9]{64}$/.test(input.caseId) || !/^[a-f0-9]{64}$/.test(input.objectId) ||
      !['narrative', 'evidence', 'messages', 'identity', 'contact', 'rewards'].includes(input.scope) ||
      !Number.isSafeInteger(input.keyEpoch) || input.keyEpoch <= 0 ||
      !Number.isSafeInteger(input.objectRevision) || input.objectRevision <= 0) invalid();
  return { caseId: input.caseId, objectId: input.objectId, scope: input.scope,
    keyEpoch: input.keyEpoch, objectRevision: input.objectRevision };
}
function sameContext(actual: ObjectContext, expected: ObjectContext): void {
  if (!actual || Object.keys(actual).length !== 5 ||
      JSON.stringify(context(actual)) !== JSON.stringify(expected)) invalid();
}
async function hash(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes);
  const result = await globalThis.crypto.subtle.digest('SHA-256', copy);
  return Array.from(new Uint8Array(result), byte => byte.toString(16).padStart(2, '0')).join('');
}
function text(value: string): Uint8Array<ArrayBuffer> { return new TextEncoder().encode(value); }
function bounded(value: string, max: number): string {
  if (typeof value !== 'string' || !value.length || value.length > max) invalid();
  return value;
}
const encodeKey = encodeBase64;
function decodeKey(value: string): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) invalid();
  const key = decodeCanonicalBase64(value, 32) ?? invalid();
  if (key.length !== 32) invalid();
  return key;
}

/** Pin this identifier in the owner grant after independent firm key verification.
 * It hashes the exact public-key packet bytes, including subkeys/certifications.
 * Modifying that key bundle therefore requires a new owner grant.
 */
export async function caseRecipientKeyId(key: PublicKey): Promise<string> {
  if (key.isPrivate()) invalid();
  return hash(key.write());
}

/** Digest recorded in the owner-signed manifest for this exact armored ciphertext. */
export async function caseObjectDigest(ciphertext: string): Promise<string> {
  return hash(text(bounded(ciphertext, LIMIT * 2)));
}

async function verifiedDecrypt(ciphertext: string, owner: PublicKey,
  credentials: { decryptionKeys: PrivateKey } | { sessionKeys: SessionKey }, max: number): Promise<Uint8Array> {
  const result = await decrypt({ message: await readMessage({ armoredMessage: ciphertext }),
    ...credentials, verificationKeys: owner, expectSigned: true, format: 'binary',
    config: { ...CONFIG, maxDecompressedMessageSize: max } });
  const verified = await Promise.allSettled(result.signatures.map(signature => signature.verified));
  if (verified.length !== 1 || verified[0].status !== 'fulfilled' || result.data.length > max) {
    result.data.fill(0);
    invalid();
  }
  return result.data;
}

async function wrap(envelope: KeyEnvelope, recipient: PublicKey, owner: PrivateKey): Promise<string> {
  return encrypt({ message: await createMessage({ binary: text(JSON.stringify(envelope)) }),
    encryptionKeys: recipient, signingKeys: owner, wildcard: true, format: 'armored', config: CONFIG });
}

async function unwrapAny(ciphertextDigest: string, envelope: string, expected: ObjectContext,
  recipient: PrivateKey, owner: PublicKey, grantDigest: string | null,
  formats: readonly EnvelopeFormat[]): Promise<{ key: Uint8Array; format: EnvelopeFormat }> {
  const bytes = await verifiedDecrypt(bounded(envelope, ENVELOPE_LIMIT), owner,
    { decryptionKeys: recipient }, 4096);
  try {
    const value: KeyEnvelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const fields = ['format', 'context', 'ciphertextDigest', 'sessionKey', 'grantDigest', 'recipientKeyId'];
    if (!value || Object.keys(value).length !== fields.length ||
        Object.keys(value).some(key => !fields.includes(key)) || !formats.includes(value.format) ||
        value.grantDigest !== grantDigest || value.recipientKeyId !== await caseRecipientKeyId(recipient.toPublic()) ||
        value.ciphertextDigest !== ciphertextDigest) invalid();
    sameContext(value.context, expected);
    return { key: decodeKey(value.sessionKey), format: value.format };
  } finally { bytes.fill(0); }
}
async function unwrap(ciphertextDigest: string, envelope: string, expected: ObjectContext,
  recipient: PrivateKey, owner: PublicKey, grantDigest: string | null): Promise<Uint8Array> {
  return (await unwrapAny(ciphertextDigest, envelope, expected, recipient, owner, grantDigest, [FORMAT])).key;
}

/** Frames and pads a whole-buffer payload (exported for format tests). */
export function packCaseObjectPayload(input: ObjectContext, plaintext: Uint8Array): Uint8Array<ArrayBuffer> {
  const expected = context(input);
  if (!(plaintext instanceof Uint8Array) || plaintext.length > LIMIT) invalid();
  const header = text(JSON.stringify({ format: PADDED_PAYLOAD_FORMAT, context: expected, length: plaintext.length }));
  const result = new Uint8Array(caseObjectPaddedBytes(4 + header.length + plaintext.length));
  new DataView(result.buffer).setUint32(0, header.length);
  result.set(header, 4); result.set(plaintext, header.length + 4);
  return result;
}
/** Inverse of packCaseObjectPayload; also accepts the unpadded legacy framing. */
export function unpackCaseObjectPayload(bytes: Uint8Array, input: ObjectContext): Uint8Array {
  const expected = context(input);
  if (!(bytes instanceof Uint8Array) || bytes.length < 4 || bytes.length > MAX_FRAMED) invalid();
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  if (size > 1024 || size + 4 > bytes.length) invalid();
  const header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(4, size + 4)));
  if (!header || typeof header !== 'object' || Array.isArray(header) || !header.context) invalid();
  if (header.format === FORMAT && Object.keys(header).length === 2) {
    // Legacy (unpadded) framing: the payload is the rest of the message.
    if (bytes.length - size - 4 > LIMIT) invalid();
    sameContext(header.context, expected);
    return bytes.slice(size + 4);
  }
  if (header.format !== PADDED_PAYLOAD_FORMAT || Object.keys(header).join(',') !== 'format,context,length' ||
      !Number.isSafeInteger(header.length) || header.length < 0 || header.length > LIMIT) invalid();
  sameContext(header.context, expected);
  const end = size + 4 + header.length;
  // Exactly the canonical bucket, and nothing but zeros after the payload.
  if (end > bytes.length || bytes.length !== caseObjectPaddedBytes(end) ||
      bytes.subarray(end).some(byte => byte !== 0)) invalid();
  return bytes.slice(size + 4, end);
}

export async function sealCaseObject(input: ObjectContext, plaintext: Uint8Array,
  owner: PrivateKey): Promise<OwnedCaseObject> {
  const expected = context(input);
  if (!(plaintext instanceof Uint8Array) || plaintext.length > LIMIT) invalid();
  const packed = packCaseObjectPayload(expected, plaintext); // Snapshot before the first await.
  const sessionKey: SessionKey = { algorithm: 'aes256', data: globalThis.crypto.getRandomValues(new Uint8Array(32)) };
  try {
    const ciphertext = await encrypt({ message: await createMessage({ binary: packed }), sessionKey,
      signingKeys: owner, format: 'armored', config: CONFIG });
    const ownerEnvelope = await wrap({ format: FORMAT, context: expected,
      ciphertextDigest: await hash(text(ciphertext)), sessionKey: encodeKey(sessionKey.data),
      grantDigest: null, recipientKeyId: await caseRecipientKeyId(owner.toPublic()) }, owner.toPublic(), owner);
    return { ciphertext, ownerEnvelope };
  } finally {
    // Best effort for owned buffers only; JS/library copies cannot be guaranteed erased.
    packed.fill(0); sessionKey.data.fill(0);
  }
}

async function readPayload(ciphertext: string, key: Uint8Array, owner: PublicKey,
  expected: ObjectContext): Promise<Uint8Array> {
  const bytes = await verifiedDecrypt(ciphertext, owner, { sessionKeys: { algorithm: 'aes256', data: key } }, MAX_FRAMED);
  try { return unpackCaseObjectPayload(bytes, expected); } finally { bytes.fill(0); }
}

export async function openOwnerCaseObject(object: OwnedCaseObject, input: ObjectContext,
  owner: PrivateKey): Promise<Uint8Array> {
  let key: Uint8Array | undefined;
  try {
    const expected = context(input), ciphertext = bounded(object.ciphertext, LIMIT * 2);
    key = await unwrap(await hash(text(ciphertext)), object.ownerEnvelope, expected, owner, owner.toPublic(), null);
    return await readPayload(ciphertext, key, owner.toPublic(), expected);
  } catch { return invalid(); } finally { key?.fill(0); }
}

async function snapshotAuthorization(input: CaseReadAuthorization, expected: ObjectContext,
  ciphertext: string): Promise<CaseReadAuthorization> {
  return snapshotDigestAuthorization(input, expected, await hash(text(ciphertext)));
}
function snapshotDigestAuthorization(input: CaseReadAuthorization, expected: ObjectContext,
  ciphertextDigest: string): CaseReadAuthorization {
  const snapshot = { ...input, trust: { ...input.trust }, request: { ...input.request } };
  if (snapshot.trust.caseId !== expected.caseId || snapshot.request.scope !== expected.scope ||
      snapshot.request.objectId !== expected.objectId ||
      snapshot.request.keyEpoch !== expected.keyEpoch || snapshot.request.objectRevision !== expected.objectRevision ||
      snapshot.request.ciphertextDigest !== ciphertextDigest) invalid();
  return snapshot;
}

/** Owner operation: share just the content key; payload ciphertext stays unchanged. */
export async function grantCaseObject(object: OwnedCaseObject, input: ObjectContext,
  owner: PrivateKey, recipient: PublicKey, authorization: CaseReadAuthorization): Promise<GrantedCaseObject> {
  let key: Uint8Array | undefined;
  try {
    const expected = context(input), ciphertext = bounded(object.ciphertext, LIMIT * 2);
    const ownerEnvelope = object.ownerEnvelope, auth = await snapshotAuthorization(authorization, expected, ciphertext);
    if (owner.getFingerprint() !== auth.trust.ownerFingerprint) invalid();
    if (await caseRecipientKeyId(recipient) !== auth.request.recipientKeyId) invalid();
    await authorizeCaseRead(auth);
    key = await unwrap(await hash(text(ciphertext)), ownerEnvelope, expected, owner, owner.toPublic(), null);
    const { digest: grantDigest } = await verifyOwnerStatement(auth.grant, auth.trust);
    const recipientEnvelope = await wrap({ format: FORMAT, context: expected,
      ciphertextDigest: await hash(text(ciphertext)), sessionKey: encodeKey(key), grantDigest,
      recipientKeyId: auth.request.recipientKeyId }, recipient, owner);
    return { ciphertext, recipientEnvelope };
  } catch { return invalid(); } finally { key?.fill(0); }
}

/** Owner operation without downloading the ciphertext: the digest comes from the
 * owner-signed manifest (checked by authorizeCaseRead) and must equal the digest
 * bound inside the owner's own key envelope. Returns only the recipient envelope. */
export async function grantCaseObjectEnvelope(ownerEnvelope: string, input: ObjectContext,
  owner: PrivateKey, recipient: PublicKey, authorization: CaseReadAuthorization): Promise<string> {
  let key: Uint8Array | undefined;
  try {
    const expected = context(input);
    const auth = snapshotDigestAuthorization(authorization, expected, authorization.request.ciphertextDigest);
    if (owner.getFingerprint() !== auth.trust.ownerFingerprint) invalid();
    if (await caseRecipientKeyId(recipient) !== auth.request.recipientKeyId) invalid();
    await authorizeCaseRead(auth);
    const opened = await unwrapAny(auth.request.ciphertextDigest, ownerEnvelope, expected, owner, owner.toPublic(), null,
      [FORMAT, CHUNKED_ENVELOPE_FORMAT]);
    key = opened.key;
    const { digest: grantDigest } = await verifyOwnerStatement(auth.grant, auth.trust);
    // The recipient envelope keeps the owner envelope's format label, so a
    // chunked-object key can only ever open the chunked reader.
    return await wrap({ format: opened.format, context: expected, ciphertextDigest: auth.request.ciphertextDigest,
      sessionKey: encodeKey(key), grantDigest, recipientKeyId: auth.request.recipientKeyId }, recipient, owner);
  } catch { return invalid(); } finally { key?.fill(0); }
}

/** Official-client policy enforcement. A recipient retaining its private key and
 * envelope can retain the disclosed contents; revocation is not remote erasure.
 */
export async function openGrantedCaseObject(object: GrantedCaseObject, input: ObjectContext,
  recipient: PrivateKey, authorization: CaseReadAuthorization): Promise<Uint8Array> {
  let key: Uint8Array | undefined;
  try {
    const expected = context(input), ciphertext = bounded(object.ciphertext, LIMIT * 2);
    const envelope = object.recipientEnvelope, auth = await snapshotAuthorization(authorization, expected, ciphertext);
    if (await caseRecipientKeyId(recipient.toPublic()) !== auth.request.recipientKeyId) invalid();
    await authorizeCaseRead(auth);
    const { digest: grantDigest } = await verifyOwnerStatement(auth.grant, auth.trust);
    key = await unwrap(await hash(text(ciphertext)), envelope, expected, recipient, auth.trust.ownerPublicKey, grantDigest);
    return await readPayload(ciphertext, key, auth.trust.ownerPublicKey, expected);
  } catch { return invalid(); } finally { key?.fill(0); }
}

/** Chunked objects: wrap a content key to the owner, bound to the object context
 * and the digest of its canonical chunk index (the manifest digest). */
export async function sealChunkedContentKey(input: ObjectContext, indexDigest: string, key: Uint8Array,
  owner: PrivateKey): Promise<string> {
  const expected = context(input);
  if (typeof indexDigest !== 'string' || !/^[a-f0-9]{64}$/.test(indexDigest) || !(key instanceof Uint8Array) ||
      key.length !== 32) invalid();
  return wrap({ format: CHUNKED_ENVELOPE_FORMAT, context: expected, ciphertextDigest: indexDigest,
    sessionKey: encodeKey(key), grantDigest: null, recipientKeyId: await caseRecipientKeyId(owner.toPublic()) },
  owner.toPublic(), owner);
}

/** Owner device: the chunked-object content key from the owner's own envelope. */
export async function openOwnerChunkedContentKey(ownerEnvelope: string, input: ObjectContext, indexDigest: string,
  owner: PrivateKey): Promise<Uint8Array> {
  try {
    const expected = context(input);
    if (typeof indexDigest !== 'string' || !/^[a-f0-9]{64}$/.test(indexDigest)) invalid();
    return (await unwrapAny(indexDigest, ownerEnvelope, expected, owner, owner.toPublic(), null,
      [CHUNKED_ENVELOPE_FORMAT])).key;
  } catch { return invalid(); }
}

/** Recipient device: the chunked-object content key, only under a current owner
 * grant, approved release and checkpoint (authorizeCaseRead), exactly as the
 * whole-object reader requires. The index digest is the manifest-signed one. */
export async function openGrantedChunkedContentKey(recipientEnvelope: string, input: ObjectContext,
  recipient: PrivateKey, authorization: CaseReadAuthorization): Promise<Uint8Array> {
  try {
    const expected = context(input);
    const auth = snapshotDigestAuthorization(authorization, expected, authorization.request.ciphertextDigest);
    if (await caseRecipientKeyId(recipient.toPublic()) !== auth.request.recipientKeyId) invalid();
    await authorizeCaseRead(auth);
    const { digest: grantDigest } = await verifyOwnerStatement(auth.grant, auth.trust);
    return (await unwrapAny(auth.request.ciphertextDigest, recipientEnvelope, expected, recipient,
      auth.trust.ownerPublicKey, grantDigest, [CHUNKED_ENVELOPE_FORMAT])).key;
  } catch { return invalid(); }
}
