import { createMessage, decrypt, encrypt, enums, readKey, readMessage, readSignature, sign, verify } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';
import { verifyOrganizationKeyContinuity } from './firmMembers.ts';

/** The organization's shared request list: every member sees the firm's access
 * requests and what came of them, instead of each browser keeping its own list.
 *
 * The list is encrypted to the organization key (only members can read it) and
 * the wire carries a detached signature by the organization key that is
 * registered for the firm, over a header naming the organization, the signing
 * key, the key it is encrypted to, a version and the ciphertext digest. The
 * enclave verifies that signature and stores a write only as exactly the next
 * version (compare-and-set), so neither the host nor another organization can
 * forge or reorder a list. The host can still replay an older stored version;
 * each member device refuses any version below the newest it has seen.
 *
 * During an organization key rotation the steward still authenticates with the
 * old (registered) key but encrypts the list to the new key only, and attaches
 * the old public key plus the continuity statement signed by both keys. A device
 * holding the new key accepts the old signer only through that continuity.
 *
 * At rest the host keeps only the organization ID, the version and the sealed
 * wire. The header carries no write time (v1 carried `issuedAt`, a client clock
 * reading that a database snapshot could match against the creation time of the
 * request row the write announced) and the wire is padded with trailing JSON
 * whitespace to a multiple of FIRM_SHARED_LIST_BUCKET, so one added request does
 * not show as a size change. Rollback protection relies on `version` alone.
 */
const FORMAT = 'vera-firm-shared-list/v2';
/** Read-only: lists written before v2 still open, but the enclave refuses v1 writes. */
const LEGACY_FORMAT = 'vera-firm-shared-list/v1';
const PAYLOAD = 'vera-firm-shared-list-payload/v1';
/** Bounded so a write fits in one encrypted channel request and read reply. */
export const FIRM_SHARED_LIST_MAX = 120 * 1024;
/** Stored wires are padded to a multiple of this size (FIRM_SHARED_LIST_MAX is one). */
export const FIRM_SHARED_LIST_BUCKET = 8 * 1024;
export const FIRM_SHARED_REQUEST_LIMIT = 150;
const CONFIG = { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false, maxDecompressedMessageSize: 1024 * 1024 };

export type SharedRequestState = 'requested' | 'withdrawn' | 'granted';
export type SharedRequest = {
  caseId: string; requestId: string; ownerPublicKey: string; summary: string;
  requestedAt: number; expiresAt: number;
  /** Organization key the request was made with. A different current key means the reporter must renew access. */
  recipientKeyId: string;
  state: SharedRequestState; updatedAt: number;
  /** Earliest expiry of the grants seen when a member last opened the case (null: until revoked, or not yet granted). */
  grantExpiresAt: number | null;
};
export type FirmSharedList = { keyEpoch: number; requests: SharedRequest[] };
export type FirmSharedListHeader = {
  format: typeof FORMAT | typeof LEGACY_FORMAT; organizationId: string; recipientKeyId: string; encryptedToKeyId: string;
  version: number; ciphertextDigest: string; predecessorDigest: string | null;
  /** v1 only (legacy reads). */
  issuedAt?: number;
};
export class FirmSharedListKeyChanged extends Error {
  constructor() { super('The organization key changed. Update this device to the new key.'); }
}

function invalid(): never { throw new Error('Invalid organization request list'); }
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
function exact(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const keys = Object.keys(value as object);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) invalid();
  return value as Record<string, unknown>;
}
async function sha256(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

export function validSharedRequest(value: unknown): value is SharedRequest {
  try {
    const item = exact(value, ['caseId', 'requestId', 'ownerPublicKey', 'summary', 'requestedAt', 'expiresAt',
      'recipientKeyId', 'state', 'updatedAt', 'grantExpiresAt']);
    return hex(item.caseId) && hex(item.requestId) && hex(item.recipientKeyId) &&
      typeof item.ownerPublicKey === 'string' && item.ownerPublicKey.length > 0 && item.ownerPublicKey.length <= 8192 &&
      typeof item.summary === 'string' && item.summary.length <= 600 &&
      positive(item.requestedAt) && positive(item.expiresAt) && positive(item.updatedAt) &&
      (item.state === 'requested' || item.state === 'withdrawn' || item.state === 'granted') &&
      (item.grantExpiresAt === null || positive(item.grantExpiresAt));
  } catch { return false; }
}
export function validFirmSharedList(value: unknown): value is FirmSharedList {
  try {
    const list = exact(value, ['keyEpoch', 'requests']);
    return positive(list.keyEpoch) && Array.isArray(list.requests) && list.requests.length <= FIRM_SHARED_REQUEST_LIMIT &&
      list.requests.every(validSharedRequest) &&
      new Set((list.requests as SharedRequest[]).map(item => item.caseId)).size === list.requests.length;
  } catch { return false; }
}
function header(value: unknown): FirmSharedListHeader {
  const legacy = !!value && typeof value === 'object' && (value as Record<string, unknown>).format === LEGACY_FORMAT;
  const item = exact(value, ['format', 'organizationId', 'recipientKeyId', 'encryptedToKeyId', 'version',
    ...(legacy ? ['issuedAt'] : []), 'ciphertextDigest', 'predecessorDigest']);
  if ((item.format !== FORMAT && !legacy) || (legacy && !positive(item.issuedAt)) ||
      !hex(item.organizationId) || !hex(item.recipientKeyId) || !hex(item.encryptedToKeyId) ||
      !positive(item.version) || !hex(item.ciphertextDigest) ||
      (item.predecessorDigest !== null && !hex(item.predecessorDigest))) invalid();
  return item as FirmSharedListHeader;
}
type Wire = { header: FirmSharedListHeader; ciphertext: string; signature: string;
  predecessor: { publicKey: string; continuity: string } | null };
async function parse(wire: unknown): Promise<Wire> {
  if (typeof wire !== 'string' || wire.length > FIRM_SHARED_LIST_MAX) invalid();
  const value = exact(JSON.parse(wire as string), ['header', 'ciphertext', 'signature', 'predecessor']);
  const parsed = header(value.header);
  if (typeof value.ciphertext !== 'string' || !value.ciphertext.startsWith('-----BEGIN PGP MESSAGE-----') ||
      typeof value.signature !== 'string' || value.signature.length > 16_384 ||
      await sha256(value.ciphertext) !== parsed.ciphertextDigest) invalid();
  let predecessor: Wire['predecessor'] = null;
  if (value.predecessor !== null) {
    const item = exact(value.predecessor, ['publicKey', 'continuity']);
    if (typeof item.publicKey !== 'string' || item.publicKey.length > 16_384 ||
        typeof item.continuity !== 'string' || item.continuity.length > 64 * 1024) invalid();
    predecessor = { publicKey: item.publicKey as string, continuity: item.continuity as string };
  }
  if (parsed.predecessorDigest !== (predecessor ? await sha256(JSON.stringify(predecessor)) : null)) invalid();
  return { header: parsed, ciphertext: value.ciphertext as string, signature: value.signature as string, predecessor };
}
async function verifySigned(value: Wire, key: PublicKey): Promise<void> {
  const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value.header)) }),
    signature: await readSignature({ armoredSignature: value.signature }), verificationKeys: key, expectSigned: true, format: 'binary' });
  const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
  if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
}

/** Member device: encrypt and sign the next version of the list. `signer` is the
 * organization key registered with VERA; `recipient` is the key members hold
 * (the same key, or the new key during a rotation, with `predecessor`). */
export async function sealFirmSharedList(list: FirmSharedList, input: { organizationId: string; version: number },
  signer: PrivateKey, recipient: PublicKey = signer.toPublic(),
  predecessor: { publicKey: string; continuity: string } | null = null): Promise<string> {
  let payload: Uint8Array | undefined;
  try {
    if (!validFirmSharedList(list) || !hex(input.organizationId) || !positive(input.version) ||
        !signer.isDecrypted() || recipient.isPrivate()) invalid();
    const recipientKeyId = await caseRecipientKeyId(signer.toPublic()), encryptedToKeyId = await caseRecipientKeyId(recipient);
    if ((recipientKeyId === encryptedToKeyId) !== (predecessor === null)) invalid();
    payload = new TextEncoder().encode(JSON.stringify({ format: PAYLOAD, organizationId: input.organizationId,
      keyEpoch: list.keyEpoch, requests: list.requests }));
    const ciphertext = await encrypt({ message: await createMessage({ binary: payload }), encryptionKeys: recipient,
      format: 'armored', config: { preferredCompressionAlgorithm: enums.compression.zlib } }) as string;
    const signed: FirmSharedListHeader = { format: FORMAT, organizationId: input.organizationId, recipientKeyId, encryptedToKeyId,
      version: input.version, ciphertextDigest: await sha256(ciphertext),
      predecessorDigest: predecessor ? await sha256(JSON.stringify({ publicKey: predecessor.publicKey, continuity: predecessor.continuity })) : null };
    const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(signed)) }),
      signingKeys: signer, detached: true, format: 'armored' }) as string;
    const wire = JSON.stringify({ header: signed, ciphertext, signature,
      predecessor: predecessor ? { publicKey: predecessor.publicKey, continuity: predecessor.continuity } : null });
    if (wire.length > FIRM_SHARED_LIST_MAX) throw new RangeError('The organization request list is full');
    // Trailing whitespace is valid JSON; every character above is ASCII, so length is bytes.
    return wire.padEnd(Math.ceil(wire.length / FIRM_SHARED_LIST_BUCKET) * FIRM_SHARED_LIST_BUCKET, ' ');
  } catch (error) { if (error instanceof RangeError) throw error; return invalid(); } finally { payload?.fill(0); }
}

/** Enclave write check: signed by exactly the organization's registered key, for
 * that organization. Returns the header so the store can compare-and-set the version. */
export async function verifyFirmSharedListWrite(wire: unknown, expected: {
  organizationId: string; recipientKeyId: string; publicKey: string;
}): Promise<FirmSharedListHeader> {
  try {
    // New writes are v2 (no write time in the header) and padded to a bucket.
    if (typeof wire !== 'string' || wire.length % FIRM_SHARED_LIST_BUCKET !== 0) invalid();
    const value = await parse(wire);
    if (value.header.format !== FORMAT || value.header.organizationId !== expected.organizationId ||
        value.header.recipientKeyId !== expected.recipientKeyId) invalid();
    const key = await readKey({ armoredKey: expected.publicKey });
    if (key.isPrivate() || await caseRecipientKeyId(key) !== expected.recipientKeyId) invalid();
    await verifySigned(value, key);
    if ((value.header.encryptedToKeyId === value.header.recipientKeyId) !== (value.predecessor === null)) invalid();
    return value.header;
  } catch { return invalid(); }
}

/** Member device read. Accepts a list signed by this device's organization key,
 * or by its direct predecessor through a continuity statement both keys signed.
 * `minimumVersion` is this device's pin; an older list is refused. */
export async function openFirmSharedList(wire: unknown, expected: { organizationId: string; minimumVersion: number },
  organizationKey: PrivateKey): Promise<{ list: FirmSharedList; version: number; header: FirmSharedListHeader }> {
  let data: Uint8Array | undefined;
  let changed = false;
  try {
    const value = await parse(wire);
    const own = organizationKey.toPublic(), ownKeyId = await caseRecipientKeyId(own);
    if (value.header.organizationId !== expected.organizationId || !Number.isSafeInteger(expected.minimumVersion) ||
        value.header.version < expected.minimumVersion) invalid();
    if (value.header.recipientKeyId === ownKeyId) {
      await verifySigned(value, own);
      if (value.header.encryptedToKeyId !== ownKeyId) { changed = true; invalid(); }
      if (value.predecessor !== null) invalid();
    } else {
      if (!value.predecessor || value.header.encryptedToKeyId !== ownKeyId) invalid();
      const previous = await readKey({ armoredKey: value.predecessor.publicKey });
      if (previous.isPrivate() || await caseRecipientKeyId(previous) !== value.header.recipientKeyId) invalid();
      const { statement, nextPublicKey } = await verifyOrganizationKeyContinuity(value.predecessor.continuity,
        { organizationId: expected.organizationId, previousPublicKey: previous });
      if (statement.nextRecipientKeyId !== ownKeyId || nextPublicKey.getFingerprint() !== own.getFingerprint()) invalid();
      await verifySigned(value, previous);
    }
    const result = await decrypt({ message: await readMessage({ armoredMessage: value.ciphertext }), decryptionKeys: organizationKey,
      format: 'binary', config: CONFIG });
    data = result.data as Uint8Array;
    const payload = exact(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)), ['format', 'organizationId', 'keyEpoch', 'requests']);
    const list = { keyEpoch: payload.keyEpoch, requests: payload.requests };
    if (payload.format !== PAYLOAD || payload.organizationId !== expected.organizationId || !validFirmSharedList(list)) invalid();
    return { list: list as FirmSharedList, version: value.header.version, header: value.header };
  } catch {
    if (changed) throw new FirmSharedListKeyChanged();
    return invalid();
  } finally { data?.fill(0); }
}
