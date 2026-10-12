import { createMessage, decrypt, encrypt, enums, generateKey, readKey, readMessage } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';
import { verifyApprovedCaseChannel } from './attestation.ts';
import type { ApprovedReleaseInput } from './releaseManifest.ts';
import { padJsonBytes, powerOfTwoBucket } from './padding.ts';
import { CLOCK_SKEW_MS } from './clockSkew.ts';
import { pgpSigningDate, pgpVerificationDate } from './pgpClock.ts';
import { decodeCanonicalBase64, encodeBase64 } from './base64.ts';

/** A channel key lies beyond the supported peer-clock tolerance. Keep this
 * distinct from failed signatures without exposing OpenPGP diagnostics. */
export class ChannelClockError extends Error {
  constructor() { super('Confidential channel clock is outside the supported range'); this.name = 'ChannelClockError'; }
}

/** OpenPGP uses one date for key validation and the message signature. Advance
 * only as far as these ephemeral keys require, never by the whole skew budget.
 * This works for either peer and retains the browser's attested signing clock. */
function signingDate(recipient: PublicKey, signer: PrivateKey): Date {
  const now = pgpSigningDate().getTime();
  const date = Math.max(now, recipient.getCreationTime().getTime(), signer.getCreationTime().getTime());
  if (date > now + CLOCK_SKEW_MS) throw new ChannelClockError();
  return new Date(date);
}

/** Requests (browser -> enclave) keep the original bounds. Responses may carry
 * one 512 KiB evidence chunk (base64 in JSON), so they are allowed to be larger;
 * the enclave's inbound limits are unchanged. */
const MAX_BODY = 256 * 1024, MAX_PLAINTEXT = 384 * 1024, MAX_WIRE = 768 * 1024;
const MAX_RESPONSE_BODY = 768 * 1024, MAX_RESPONSE_PLAINTEXT = 4 * (MAX_RESPONSE_BODY / 3) + 16 * 1024,
  MAX_RESPONSE_WIRE = 1536 * 1024;
/** Size padding (hole 12): the signed JSON plaintext of every request and response
 * is padded with trailing spaces to a power of two of at least 16 KiB (capped at
 * the direction's plaintext bound, itself the top bucket) before signing and
 * encryption, so the relay sees a handful of wire sizes instead of the exact size
 * of each operation. Trailing whitespace is valid JSON: peers without padding
 * still parse padded messages, and padded peers still parse unpadded ones. */
export const CHANNEL_MIN_PADDED_BYTES = 16 * 1024;
type Bounds = { body: number; plaintext: number; wire: number };
const REQUEST: Bounds = { body: MAX_BODY, plaintext: MAX_PLAINTEXT, wire: MAX_WIRE };
const RESPONSE: Bounds = { body: MAX_RESPONSE_BODY, plaintext: MAX_RESPONSE_PLAINTEXT, wire: MAX_RESPONSE_WIRE };
function config(bounds: Bounds) {
  return { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false,
    maxDecompressedMessageSize: bounds.plaintext, preferredCompressionAlgorithm: enums.compression.uncompressed };
}
type Binding = { nonce: string; requestId: string; serverKeyId: string; requestDigest: string };
export type OpenChannelRequest = { body: Uint8Array; replyKey: PublicKey; binding: Binding };
function invalid(): never { throw new Error('Invalid confidential channel message'); }
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) invalid();
  return value;
}
function hex(value: Uint8Array): string { return Array.from(value, v => v.toString(16).padStart(2, '0')).join(''); }
const encode = encodeBase64;
function decode(value: unknown, max: number): Uint8Array<ArrayBuffer> { return decodeCanonicalBase64(value, max) ?? invalid(); }
function bodyBytes(value: Uint8Array, bounds: Bounds = REQUEST): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.length > bounds.body) invalid();
  return new Uint8Array(value);
}
function parse(bytes: Uint8Array, fields: string[], bounds: Bounds = REQUEST): Record<string, unknown> {
  if (bytes.length > bounds.plaintext) invalid();
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== fields.length ||
      Object.keys(value).some(key => !fields.includes(key))) invalid();
  return value;
}
async function digest(wire: string): Promise<string> {
  return hex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(wire))));
}
function wire(value: string, bounds: Bounds = REQUEST): string {
  if (typeof value !== 'string' || !value.length || value.length > bounds.wire) invalid();
  return value;
}
/** Padded plaintext size of a channel message of `size` JSON bytes. */
export function channelPaddedBytes(size: number, direction: 'request' | 'response'): number {
  return powerOfTwoBucket(size, CHANNEL_MIN_PADDED_BYTES, (direction === 'request' ? REQUEST : RESPONSE).plaintext);
}
async function sealed(value: unknown, recipient: PublicKey, signer: PrivateKey, bounds: Bounds = REQUEST): Promise<string> {
  const json = new TextEncoder().encode(JSON.stringify(value));
  let bytes: Uint8Array | undefined;
  try {
    if (json.length > bounds.plaintext) invalid();
    bytes = padJsonBytes(json, powerOfTwoBucket(json.length, CHANNEL_MIN_PADDED_BYTES, bounds.plaintext));
    return wire(await encrypt({ message: await createMessage({ binary: new Uint8Array(bytes) }),
      encryptionKeys: recipient, signingKeys: signer, date: signingDate(recipient, signer),
      wildcard: true, format: 'armored', config: config(bounds) }), bounds);
  } finally { json.fill(0); bytes?.fill(0); }
}
async function opened(ciphertext: string, recipient: PrivateKey, signer?: PublicKey, bounds: Bounds = REQUEST): Promise<Uint8Array> {
  const result = await decrypt({ message: await readMessage({ armoredMessage: wire(ciphertext, bounds) }),
    // Verification may look ahead within the existing peer-clock budget. Do
    // not use this date for signing: it would create future-dated requests.
    decryptionKeys: recipient, verificationKeys: signer, expectSigned: !!signer,
    date: new Date(pgpVerificationDate().getTime() + CLOCK_SKEW_MS), format: 'binary', config: config(bounds) });
  const signatures = await Promise.allSettled(result.signatures.map(value => value.verified));
  if (result.data.length > bounds.plaintext || signatures.length !== 1 || (signer && signatures[0].status !== 'fulfilled')) {
    result.data.fill(0); invalid();
  }
  return result.data;
}

/** Browser-local pending operation. JSON exposes ciphertext only, never keys.
 * Opening a reply consumes the operation even if verification fails. */
export class PendingChannelRequest {
  #replyKey: PrivateKey | undefined;
  #serverKey: PublicKey;
  #binding: Binding;
  constructor(readonly ciphertext: string, replyKey: PrivateKey, serverKey: PublicKey, binding: Binding) {
    this.#replyKey = replyKey; this.#serverKey = serverKey; this.#binding = { ...binding };
  }
  async openResponse(ciphertext: string): Promise<Uint8Array> {
    const key = this.#replyKey;
    this.#replyKey = undefined;
    let plaintext: Uint8Array | undefined;
    try {
      if (!key) invalid();
      plaintext = await opened(ciphertext, key, this.#serverKey, RESPONSE);
      const value = parse(plaintext, ['format', 'nonce', 'requestId', 'serverKeyId', 'requestDigest', 'body'], RESPONSE);
      if (value.format !== 'vera-channel-response/v1' || Object.entries(this.#binding).some(([k, v]) => value[k] !== v)) invalid();
      return decode(value.body, MAX_RESPONSE_BODY);
    } catch { return invalid(); } finally { plaintext?.fill(0); }
  }
  close(): void { this.#replyKey = undefined; }
}

/** Internal wire primitive. The supplied server key MUST already have passed
 * complete attestation. Product clients use createApprovedChannelRequest below. */
export async function sealChannelRequest(serverKey: PublicKey, nonce: string, body: Uint8Array): Promise<PendingChannelRequest> {
  let input: Uint8Array | undefined;
  try {
    const challenge = id(nonce); input = bodyBytes(body);
    if (serverKey.isPrivate()) invalid();
    const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Vera ephemeral reply' }], format: 'object' });
    const binding = { nonce: challenge, requestId: hex(globalThis.crypto.getRandomValues(new Uint8Array(32))),
      serverKeyId: await caseRecipientKeyId(serverKey), requestDigest: '' };
    const ciphertext = await sealed({ format: 'vera-channel-request/v1', nonce: binding.nonce,
      requestId: binding.requestId, serverKeyId: binding.serverKeyId,
      replyPublicKey: encode(publicKey.write()), body: encode(input) }, serverKey, privateKey);
    binding.requestDigest = await digest(ciphertext);
    return new PendingChannelRequest(ciphertext, privateKey, serverKey, binding);
  } catch (error) {
    if (error instanceof ChannelClockError) throw error;
    return invalid();
  } finally { input?.fill(0); }
}

/** Enclave only. This proves the ephemeral sender key, NOT firm membership or
 * case authorization. Never dispatch the returned body without those checks. */
export async function openChannelRequest(ciphertext: string, nonce: string, serverKey: PrivateKey): Promise<OpenChannelRequest> {
  let inspection: Uint8Array | undefined, plaintext: Uint8Array | undefined;
  try {
    const challenge = id(nonce), encrypted = wire(ciphertext);
    inspection = await opened(encrypted, serverKey);
    const fields = ['format', 'nonce', 'requestId', 'serverKeyId', 'replyPublicKey', 'body'];
    const untrusted = parse(inspection, fields);
    const replyKey = await readKey({ binaryKey: decode(untrusted.replyPublicKey, 1024) });
    if (replyKey.isPrivate()) invalid();
    plaintext = await opened(encrypted, serverKey, replyKey);
    const value = parse(plaintext, fields);
    if (value.format !== 'vera-channel-request/v1' || value.nonce !== challenge ||
        value.serverKeyId !== await caseRecipientKeyId(serverKey.toPublic())) invalid();
    return { body: decode(value.body, MAX_BODY), replyKey, binding: {
      nonce: challenge, requestId: id(value.requestId), serverKeyId: id(value.serverKeyId), requestDigest: await digest(encrypted),
    } };
  } catch { return invalid(); } finally { inspection?.fill(0); plaintext?.fill(0); }
}

/** Enclave only. Reply routing comes from the authenticated encrypted request,
 * never from host headers, URLs or a separate reply-key parameter. */
export async function sealChannelResponse(request: OpenChannelRequest, body: Uint8Array, serverKey: PrivateKey): Promise<string> {
  let input: Uint8Array | undefined;
  try {
    input = bodyBytes(body, RESPONSE);
    const binding = { ...request.binding }, replyKey = request.replyKey;
    for (const value of Object.values(binding)) id(value);
    if (replyKey.isPrivate() || binding.serverKeyId !== await caseRecipientKeyId(serverKey.toPublic())) invalid();
    return await sealed({ format: 'vera-channel-response/v1', ...binding, body: encode(input) }, replyKey, serverKey, RESPONSE);
  } catch { return invalid(); } finally { input?.fill(0); }
}

export async function createApprovedChannelRequest(document: Uint8Array, publicKey: Uint8Array,
  approval: ApprovedReleaseInput, body: Uint8Array): Promise<PendingChannelRequest> {
  let input: Uint8Array | undefined;
  try {
    input = bodyBytes(body);
    if (!(approval.nonce instanceof Uint8Array) || approval.nonce.length !== 32) invalid();
    const nonce = new Uint8Array(approval.nonce);
    const verified = await verifyApprovedCaseChannel(document, publicKey, { ...approval, nonce });
    return await sealChannelRequest(await readKey({ binaryKey: verified.publicKey }), hex(nonce), input);
  } catch (error) {
    if (error instanceof ChannelClockError) throw error;
    return invalid();
  } finally { input?.fill(0); }
}
