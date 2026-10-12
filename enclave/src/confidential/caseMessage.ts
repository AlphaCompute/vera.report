import { createMessage, decrypt, encrypt, enums, readMessage } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';
import type { OwnerTrust } from './authorization.ts';
import { padJsonBytes, powerOfTwoBucket } from './padding.ts';

/** End-to-end encrypted owner <-> organization conversation messages.
 * Each message is signed by its sender and encrypted to both participants so the
 * sender can reread its own history. Case, organization, direction and a
 * per-sender sequence number are inside the signed ciphertext; the relay stores
 * opaque bytes only. Whether an organization may message at all (a current grant
 * with the `messages` scope) is enforced by the service and the receiving client.
 *
 * Size padding (hole 12): the signed JSON is padded with trailing spaces to a
 * power of two between 4 KiB and 32 KiB before encryption, so stored and relayed
 * messages show a size bucket, not the message length. Trailing whitespace is
 * valid JSON, so older messages and older readers are unaffected.
 */
const FORMAT = 'vera-case-message/v1';
const MAX_BODY = 10_000;
const MAX_ARMORED = 48 * 1024;
const MAX_PLAINTEXT = 32 * 1024;
export const MESSAGE_MIN_PADDED_BYTES = 4096;
const CONFIG = { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false,
  maxDecompressedMessageSize: MAX_PLAINTEXT, preferredCompressionAlgorithm: enums.compression.uncompressed };

export type MessageSender = 'owner' | 'organization';
export type CaseMessage = {
  format: typeof FORMAT; caseId: string; organizationId: string; recipientKeyId: string;
  sender: MessageSender; sequence: number; sentAt: number; body: string;
};
export type MessageParticipants = {
  owner: OwnerTrust;
  /** Independently pinned organization key, never a key supplied by the relay. */
  organization: { organizationId: string; publicKey: PublicKey };
};

function invalid(): never { throw new Error('Invalid confidential case message'); }
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) invalid();
  return value as string;
}
function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) invalid();
  return value as number;
}
function parse(input: unknown): CaseMessage {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  const fields = ['format', 'caseId', 'organizationId', 'recipientKeyId', 'sender', 'sequence', 'sentAt', 'body'];
  if (Object.keys(value).length !== fields.length || Object.keys(value).some(key => !fields.includes(key)) ||
      value.format !== FORMAT || (value.sender !== 'owner' && value.sender !== 'organization') ||
      typeof value.body !== 'string' || !value.body.trim() || value.body.length > MAX_BODY ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value.body)) invalid();
  return { format: FORMAT, caseId: identifier(value.caseId), organizationId: identifier(value.organizationId),
    recipientKeyId: identifier(value.recipientKeyId), sender: value.sender as MessageSender,
    sequence: positive(value.sequence), sentAt: positive(value.sentAt), body: value.body as string };
}
async function pinned(participants: MessageParticipants): Promise<{
  owner: PublicKey; organization: PublicKey; caseId: string; organizationId: string; recipientKeyId: string;
}> {
  const owner = participants.owner.ownerPublicKey, organization = participants.organization.publicKey;
  if (owner.isPrivate() || organization.isPrivate() ||
      owner.getFingerprint() !== participants.owner.ownerFingerprint) invalid();
  return { owner, organization, caseId: identifier(participants.owner.caseId),
    organizationId: identifier(participants.organization.organizationId),
    recipientKeyId: await caseRecipientKeyId(organization) };
}

/** Sender-device operation. `sender` must hold the matching private key. */
export async function sealCaseMessage(input: { sender: MessageSender; sequence: number; sentAt: number; body: string },
  participants: MessageParticipants, senderKey: PrivateKey): Promise<string> {
  let plaintext: Uint8Array | undefined;
  try {
    // Snapshot before any await.
    const draft = { sender: input.sender, sequence: input.sequence, sentAt: input.sentAt, body: input.body };
    const keys = await pinned(participants);
    const expectedSender = draft.sender === 'owner' ? keys.owner : keys.organization;
    if (!senderKey.isDecrypted() || senderKey.getFingerprint() !== expectedSender.getFingerprint()) invalid();
    const message = parse({ format: FORMAT, caseId: keys.caseId, organizationId: keys.organizationId,
      recipientKeyId: keys.recipientKeyId, ...draft });
    const json = new TextEncoder().encode(JSON.stringify(message));
    plaintext = padJsonBytes(json, powerOfTwoBucket(json.length, MESSAGE_MIN_PADDED_BYTES, MAX_PLAINTEXT));
    json.fill(0);
    const armored = await encrypt({ message: await createMessage({ binary: new Uint8Array(plaintext) }),
      encryptionKeys: [keys.owner, keys.organization], signingKeys: senderKey, wildcard: true,
      format: 'armored', config: CONFIG });
    if (armored.length > MAX_ARMORED) invalid();
    return armored;
  } catch { return invalid(); } finally { plaintext?.fill(0); }
}

/** Participant-device operation. Verifies the sender signature against the pinned
 * key for the claimed direction and the exact case/organization binding. Pass the
 * highest sequence already accepted from that sender to reject replay/reordering.
 */
export async function openCaseMessage(armored: string, participants: MessageParticipants, readerKey: PrivateKey,
  lastSequence: { owner: number; organization: number }): Promise<CaseMessage> {
  let inspected: Uint8Array | undefined, verifiedBytes: Uint8Array | undefined;
  try {
    if (typeof armored !== 'string' || armored.length > MAX_ARMORED) invalid();
    const keys = await pinned(participants);
    const floor = { owner: lastSequence.owner, organization: lastSequence.organization };
    if (!Number.isSafeInteger(floor.owner) || floor.owner < 0 ||
        !Number.isSafeInteger(floor.organization) || floor.organization < 0) invalid();
    const reader = readerKey.getFingerprint();
    if (reader !== keys.owner.getFingerprint() && reader !== keys.organization.getFingerprint()) invalid();
    // First pass selects the claimed sender; its output is untrusted.
    const inspection = await decrypt({ message: await readMessage({ armoredMessage: armored }),
      decryptionKeys: readerKey, format: 'binary', config: CONFIG });
    inspected = inspection.data as Uint8Array;
    await Promise.allSettled(inspection.signatures.map(signature => signature.verified));
    if (inspection.signatures.length !== 1) invalid();
    const claimed = parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(inspected)));
    const senderKey = claimed.sender === 'owner' ? keys.owner : keys.organization;
    const verified = await decrypt({ message: await readMessage({ armoredMessage: armored }),
      decryptionKeys: readerKey, verificationKeys: senderKey, expectSigned: true, format: 'binary', config: CONFIG });
    verifiedBytes = verified.data as Uint8Array;
    const signatures = await Promise.allSettled(verified.signatures.map(signature => signature.verified));
    if (signatures.length !== 1 || signatures[0].status !== 'fulfilled') invalid();
    const message = parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(verifiedBytes)));
    if (message.caseId !== keys.caseId || message.organizationId !== keys.organizationId ||
        message.recipientKeyId !== keys.recipientKeyId || message.sender !== claimed.sender ||
        message.sequence <= floor[message.sender]) invalid();
    return message;
  } catch { return invalid(); } finally { inspected?.fill(0); verifiedBytes?.fill(0); }
}
