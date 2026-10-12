import { createMessage, decrypt, encrypt, enums, readKey, readMessage } from './pgp.ts';
import type { PrivateKey } from './pgp.ts';
import type { MessageParticipants } from './caseMessage.ts';
import { caseRecipientKeyId } from './caseObject.ts';
import { padJsonBytes } from './padding.ts';

/** A fixed-purpose acknowledgement, not a conversation message. Signed by the
 * organization after its browser decrypts a report, encrypted to the reporter.
 * It confirms an open, not that a person read or reviewed the report. */
const FORMAT = 'vera-report-open/v1';
const CONFIG = { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false,
  maxDecompressedMessageSize: 8192, preferredCompressionAlgorithm: enums.compression.uncompressed };
export type ReportOpenReceipt = { format: typeof FORMAT; caseId: string; organizationId: string;
  recipientKeyId: string; publicKey: string; checkpointDigest: string; openedAt: number };
function invalid(): never { throw new Error('Invalid report-open receipt'); }
function parse(value: unknown): ReportOpenReceipt {
  const row = value as ReportOpenReceipt;
  if (!row || typeof row !== 'object' || Array.isArray(row) ||
      Object.keys(row).sort().join(',') !== 'caseId,checkpointDigest,format,openedAt,organizationId,publicKey,recipientKeyId' ||
      typeof row.publicKey !== 'string' || row.publicKey.length > 4096 ||
      row.format !== FORMAT || ![row.caseId, row.organizationId, row.recipientKeyId, row.checkpointDigest]
        .every(id => typeof id === 'string' && /^[a-f0-9]{64}$/.test(id)) ||
      !Number.isSafeInteger(row.openedAt) || row.openedAt <= 0) invalid();
  return row;
}
async function binding(participants: MessageParticipants) {
  if (participants.owner.ownerPublicKey.isPrivate() || participants.organization.publicKey.isPrivate() ||
      participants.owner.ownerPublicKey.getFingerprint() !== participants.owner.ownerFingerprint) invalid();
  return { caseId: participants.owner.caseId, organizationId: participants.organization.organizationId,
    recipientKeyId: await caseRecipientKeyId(participants.organization.publicKey) };
}
export async function sealReportOpenReceipt(input: { checkpointDigest: string; openedAt: number },
  participants: MessageParticipants, firmKey: PrivateKey): Promise<string> {
  if (!firmKey.isDecrypted() || firmKey.getFingerprint() !== participants.organization.publicKey.getFingerprint()) invalid();
  const row = parse({ format: FORMAT, ...await binding(participants), publicKey: firmKey.toPublic().armor(), ...input });
  const json = new TextEncoder().encode(JSON.stringify(row));
  const bytes = padJsonBytes(json, 8192);
  json.fill(0);
  try {
    return await encrypt({ message: await createMessage({ binary: bytes.slice() }),
      encryptionKeys: participants.owner.ownerPublicKey, signingKeys: firmKey, wildcard: true,
      format: 'armored', config: CONFIG });
  } finally { bytes.fill(0); }
}
export async function openReportOpenReceipt(armored: string, participants: MessageParticipants,
  ownerKey: PrivateKey, historicalRecipientKeyIds: readonly string[] = []): Promise<ReportOpenReceipt> {
  let inspected: Uint8Array | undefined, bytes: Uint8Array | undefined;
  try {
    if (typeof armored !== 'string' || armored.length > 16 * 1024 ||
        ownerKey.getFingerprint() !== participants.owner.ownerFingerprint) invalid();
    const expected = await binding(participants);
    // The encrypted public key preserves historical verification after a firm
    // rotates its key. Trust comes from the caller's owner-signed grant history,
    // never from this embedded key alone. No unverified data reaches the UI.
    const inspection = await decrypt({ message: await readMessage({ armoredMessage: armored }),
      decryptionKeys: ownerKey, format: 'binary', config: CONFIG });
    inspected = inspection.data as Uint8Array;
    await Promise.allSettled(inspection.signatures.map(item => item.verified));
    if (inspection.signatures.length !== 1 || inspected.length > 8192) invalid();
    const untrusted = parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(inspected)));
    const publicKey = await readKey({ armoredKey: untrusted.publicKey });
    if (publicKey.isPrivate() || await caseRecipientKeyId(publicKey) !== untrusted.recipientKeyId ||
        ![expected.recipientKeyId, ...historicalRecipientKeyIds].includes(untrusted.recipientKeyId)) invalid();
    const opened = await decrypt({ message: await readMessage({ armoredMessage: armored }),
      decryptionKeys: ownerKey, verificationKeys: publicKey, expectSigned: true,
      format: 'binary', config: CONFIG });
    bytes = opened.data as Uint8Array;
    const signatures = await Promise.allSettled(opened.signatures.map(item => item.verified));
    if (bytes.length > 8192 || signatures.length !== 1 || signatures[0].status !== 'fulfilled') invalid();
    const row = parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
    if (row.caseId !== expected.caseId || row.organizationId !== expected.organizationId ||
        row.recipientKeyId !== untrusted.recipientKeyId) invalid();
    return row;
  } catch { return invalid(); } finally { inspected?.fill(0); bytes?.fill(0); }
}
