import { createMessage, decrypt, encrypt, generateKey, readMessage } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { decodeCanonicalBase64, encodeBase64 } from './base64.ts';

/** Participant-held case state key (owner decision 2026-09-27).
 * Private case metadata (grants, manifests, releases, checkpoints, recipient
 * routing) is stored as AES-256-GCM deltas under a random per-case key. The key
 * is wrapped only to the owner and currently granted firms; the enclave holds it
 * in memory after one of them unlocks the case. No platform or KMS-only copy
 * exists. Rotation (on revocation) carries the previous key inside the first
 * delta of the new epoch, so the newest key opens the whole history while a
 * revoked holder of an old key cannot read later deltas.
 */
const KEY_FORMAT = 'vera-case-state-key/v1';
const DELTA_FORMAT = 'vera-sealed-case-delta/v1';
const CONFIG = { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false, maxDecompressedMessageSize: 4096 };
const MAX_DELTA = 4 * 1024 * 1024;

export type CaseStateKey = { stateEpoch: number; key: Uint8Array };

function invalid(): never { throw new Error('Invalid confidential case state'); }
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) invalid();
  return value as string;
}
function epoch(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) invalid();
  return value as number;
}
function keyBytes(value: unknown): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.length !== 32) invalid();
  return new Uint8Array(value as Uint8Array);
}
export { encodeBase64 };
export function decodeBase64(value: unknown, max: number): Uint8Array<ArrayBuffer> {
  return decodeCanonicalBase64(value, max) ?? invalid();
}
function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }

export function generateCaseStateKey(stateEpoch = 1): CaseStateKey {
  return { stateEpoch: epoch(stateEpoch), key: globalThis.crypto.getRandomValues(new Uint8Array(32)) };
}

/** Owner operation: wrap the state key to one participant (owner or granted firm),
 * signed by the owner. Recipient key IDs are hidden (wildcard). */
export async function wrapCaseStateKey(caseId: string, state: CaseStateKey, recipient: PublicKey,
  owner: PrivateKey): Promise<string> {
  const payload = new TextEncoder().encode(JSON.stringify({ format: KEY_FORMAT, caseId: identifier(caseId),
    stateEpoch: epoch(state.stateEpoch), key: encodeBase64(keyBytes(state.key)) }));
  try {
    if (recipient.isPrivate() || !owner.isDecrypted()) invalid();
    return await encrypt({ message: await createMessage({ binary: payload }), encryptionKeys: recipient,
      signingKeys: owner, wildcard: true, format: 'armored', config: CONFIG });
  } catch { return invalid(); } finally { payload.fill(0); }
}

/** Participant operation: open this participant's envelope; verifies the owner signature. */
export async function unwrapCaseStateKey(envelope: string, caseId: string, reader: PrivateKey,
  owner: PublicKey): Promise<CaseStateKey> {
  let data: Uint8Array | undefined;
  try {
    if (typeof envelope !== 'string' || envelope.length > 16_384) invalid();
    const result = await decrypt({ message: await readMessage({ armoredMessage: envelope }), decryptionKeys: reader,
      verificationKeys: owner, expectSigned: true, format: 'binary', config: CONFIG });
    data = result.data as Uint8Array;
    const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
    if (!value || Object.keys(value).sort().join(',') !== 'caseId,format,key,stateEpoch' || value.format !== KEY_FORMAT ||
        value.caseId !== identifier(caseId)) invalid();
    return { stateEpoch: epoch(value.stateEpoch), key: keyBytes(decodeBase64(value.key, 32)) };
  } catch { return invalid(); } finally { data?.fill(0); }
}

/** Among unlabeled envelopes, find the one this participant can open. */
export async function findCaseStateKey(envelopes: readonly string[], caseId: string, reader: PrivateKey,
  owner: PublicKey): Promise<CaseStateKey> {
  if (!Array.isArray(envelopes) || envelopes.length > 128) invalid();
  let best: CaseStateKey | null = null;
  for (const envelope of envelopes) {
    try {
      const found = await unwrapCaseStateKey(envelope, caseId, reader, owner);
      if (!best || found.stateEpoch > best.stateEpoch) best = found;
    } catch { /* Not addressed to this reader. */ }
  }
  if (!best) invalid();
  return best!;
}

/** Stored state-key envelope lists are padded to one of these sizes. The list
 * length would otherwise be the owner plus each current grantee. */
export const STATE_ENVELOPE_PAD_SIZES = [16, 32, 64, 128] as const;
export function paddedStateEnvelopeCount(count: number): number {
  const size = STATE_ENVELOPE_PAD_SIZES.find(item => item >= count);
  if (!Number.isSafeInteger(count) || count < 0 || size === undefined) invalid();
  return size!;
}
function randomBelow(limit: number): number {
  // Rejection sampling: an unbiased index in [0, limit).
  const bound = Math.floor(0x1_0000_0000 / limit) * limit;
  const word = new Uint32Array(1);
  do globalThis.crypto.getRandomValues(word); while (word[0] >= bound);
  return word[0] % limit;
}

/** Enclave operation: pads participant envelopes with decoys and shuffles them.
 * A decoy is a real `wrapCaseStateKey` output (same format, case ID and epoch,
 * same key algorithms as every participant key) of a random, discarded state key
 * to a throwaway key, so size, packet structure and hidden recipient match a real
 * envelope. No participant can open a decoy; `findCaseStateKey` skips it. */
export async function padStateEnvelopes(envelopes: readonly string[], caseId: string, stateEpoch: number): Promise<string[]> {
  const id = identifier(caseId), at = epoch(stateEpoch);
  if (!Array.isArray(envelopes) || envelopes.some(item => typeof item !== 'string')) invalid();
  const target = paddedStateEnvelopeCount(envelopes.length);
  const list = [...envelopes];
  if (list.length < target) {
    const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Vera state key decoy' }], format: 'object' });
    const publicKey = privateKey.toPublic();
    while (list.length < target) {
      const decoy = generateCaseStateKey(at);
      try { list.push(await wrapCaseStateKey(id, decoy, publicKey, privateKey)); } finally { decoy.key.fill(0); }
    }
  }
  for (let index = list.length - 1; index > 0; index--) {
    const other = randomBelow(index + 1);
    [list[index], list[other]] = [list[other], list[index]];
  }
  return list;
}

function additionalData(caseId: string, stateEpoch: number, sequence: number): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify({ format: DELTA_FORMAT, caseId, stateEpoch, sequence }));
}

/** Seal one state delta at a fixed position in the case history. */
export async function sealCaseDelta(caseId: string, state: CaseStateKey, sequence: number,
  plaintext: Uint8Array): Promise<string> {
  const id = identifier(caseId), stateEpoch = epoch(state.stateEpoch);
  if (!Number.isSafeInteger(sequence) || sequence < 0 || !(plaintext instanceof Uint8Array) || plaintext.length > MAX_DELTA) invalid();
  const key = await globalThis.crypto.subtle.importKey('raw', keyBytes(state.key), 'AES-GCM', false, ['encrypt']);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
    additionalData: additionalData(id, stateEpoch, sequence), tagLength: 128 }, key, new Uint8Array(plaintext)));
  return JSON.stringify({ format: DELTA_FORMAT, stateEpoch, sequence, nonce: encodeBase64(nonce), ciphertext: encodeBase64(ciphertext) });
}

/** Public header of a sealed delta (epoch and position only). */
export function sealedDeltaHeader(wire: string): { stateEpoch: number; sequence: number } {
  try {
    const value = JSON.parse(wire);
    if (!value || Object.keys(value).sort().join(',') !== 'ciphertext,format,nonce,sequence,stateEpoch' ||
        value.format !== DELTA_FORMAT || !Number.isSafeInteger(value.sequence) || value.sequence < 0) invalid();
    return { stateEpoch: epoch(value.stateEpoch), sequence: value.sequence };
  } catch { return invalid(); }
}

export async function openCaseDelta(caseId: string, state: CaseStateKey, expectedSequence: number,
  wire: string): Promise<Uint8Array> {
  try {
    if (typeof wire !== 'string' || wire.length > MAX_DELTA * 2) invalid();
    const header = sealedDeltaHeader(wire), value = JSON.parse(wire);
    if (header.sequence !== expectedSequence || header.stateEpoch !== state.stateEpoch) invalid();
    const key = await globalThis.crypto.subtle.importKey('raw', keyBytes(state.key), 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: decodeBase64(value.nonce, 12),
      additionalData: additionalData(identifier(caseId), header.stateEpoch, expectedSequence), tagLength: 128 },
      key, decodeBase64(value.ciphertext, MAX_DELTA + 16)));
  } catch { return invalid(); }
}

/** Opaque recipient routing tag: storage sees this instead of a firm key ID. */
export async function caseMailboxTag(mailboxKey: Uint8Array, caseId: string, recipientKeyId: string): Promise<string> {
  const key = await globalThis.crypto.subtle.importKey('raw', keyBytes(mailboxKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key,
    new TextEncoder().encode(`vera-case-mailbox/v1:${identifier(caseId)}:${identifier(recipientKeyId)}`))));
}
