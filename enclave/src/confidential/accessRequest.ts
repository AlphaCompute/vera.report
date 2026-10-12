import { requestRoutingTag, requestTimeBucket } from './requestRouting.ts';
import { FEE_BASES, RESPONSE_TIMES } from './requestDetails.ts';
import { issuedNotAfter } from './clockSkew.ts';
import { createMessage, decrypt, encrypt, readMessage } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';
import type { CaseScope, OwnerTrust } from './authorization.ts';

const FORMAT = 'vera-legal-access-request/v1';
/** v2 adds structured, firm-signed details. Both stay accepted: a v1 request
 * simply has `details: null`. */
const FORMAT_V2 = 'vera-legal-access-request/v2';
const MAX_LIFETIME = 30 * 24 * 60 * 60 * 1000;
const CONFIG = { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false,
  maxDecompressedMessageSize: 8192 };
export { FEE_BASES, RESPONSE_TIMES };
/** Structured request fields, encrypted to the owner and signed by the firm key
 * with the rest of the request. The profile fields (practice areas,
 * jurisdiction, website) are the organization's own claims; the owner's browser
 * shows a website only when it is on the domain that confirmed the firm key. */
export type AccessRequestDetails = {
  kind: 'new' | 'renewal';
  conflictsChecked: boolean;
  feeBasis: typeof FEE_BASES[number];
  responseTime: typeof RESPONSE_TIMES[number];
  practiceAreas: string[];
  jurisdiction: string;
  website: string | null;
};
export type AccessRequestInput = {
  requestId: string; scopes: CaseScope[]; objectRevisionLimit: number | null;
  purpose: string; issuedAt: number; expiresAt: number;
  /** Omit only for a legacy v1 request. */
  details?: AccessRequestDetails;
};
export type LegalAccessRequest = Omit<AccessRequestInput, 'details'> & {
  format: typeof FORMAT | typeof FORMAT_V2; caseId: string; ownerFingerprint: string;
  organizationId: string; recipientKeyId: string; details: AccessRequestDetails | null;
};
export type TrustedLegalOrganization = {
  organizationId: string;
  /** Independently authenticated/pinned firm key, not a key supplied by this request. */
  publicKey: PublicKey;
  approved: boolean;
};
export type DeliveredLegalAccessRequest = {
  caseId: string; requestId: string; organizationId: string; recipientKeyId: string;
  expiresAt: number; status: 'pending'; ciphertext: string; routing?: 'blinded-v1';
};

function invalid(): never { throw new Error('Invalid confidential access request'); }
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) invalid();
  return value as string;
}
function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) invalid();
  return value as number;
}
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
function line(value: unknown, max: number, allowEmpty: boolean): string {
  if (typeof value !== 'string' || value.length > max || value !== value.trim() || /[\r\n]/.test(value) ||
      CONTROL.test(value) || (!allowEmpty && !value.length)) invalid();
  return value as string;
}
/** A public https page, nothing else: no credentials, ports or non-https schemes. */
export function requestWebsite(value: unknown): string | null {
  if (value === null) return null;
  const text = line(value, 200, false);
  let url: URL;
  try { url = new URL(text); } catch { return invalid(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.href !== text ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(url.hostname)) invalid();
  return text;
}
export function parseRequestDetails(input: unknown): AccessRequestDetails {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  if (Object.keys(value).sort().join(',') !== 'conflictsChecked,feeBasis,jurisdiction,kind,practiceAreas,responseTime,website' ||
      (value.kind !== 'new' && value.kind !== 'renewal') || typeof value.conflictsChecked !== 'boolean' ||
      !FEE_BASES.includes(value.feeBasis as AccessRequestDetails['feeBasis']) ||
      !RESPONSE_TIMES.includes(value.responseTime as AccessRequestDetails['responseTime']) ||
      !Array.isArray(value.practiceAreas) || value.practiceAreas.length > 6) invalid();
  const practiceAreas = (value.practiceAreas as unknown[]).map(item => line(item, 60, false));
  if (new Set(practiceAreas).size !== practiceAreas.length) invalid();
  return { kind: value.kind as AccessRequestDetails['kind'], conflictsChecked: value.conflictsChecked as boolean,
    feeBasis: value.feeBasis as AccessRequestDetails['feeBasis'], responseTime: value.responseTime as AccessRequestDetails['responseTime'],
    practiceAreas, jurisdiction: line(value.jurisdiction, 120, true), website: requestWebsite(value.website) };
}
function parse(input: unknown): LegalAccessRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  const v2 = value.format === FORMAT_V2;
  const fields = ['format', 'caseId', 'ownerFingerprint', 'organizationId', 'recipientKeyId',
    'requestId', 'scopes', 'objectRevisionLimit', 'purpose', 'issuedAt', 'expiresAt', ...(v2 ? ['details'] : [])];
  if (Object.keys(value).length !== fields.length || Object.keys(value).some(key => !fields.includes(key)) ||
      (value.format !== FORMAT && !v2) || typeof value.ownerFingerprint !== 'string' ||
      !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value.ownerFingerprint)) invalid();
  const allowed = ['narrative', 'evidence', 'messages', 'identity', 'contact', 'rewards'];
  if (!Array.isArray(value.scopes) || !value.scopes.length || value.scopes.length > allowed.length ||
      value.scopes.some(scope => typeof scope !== 'string' || !allowed.includes(scope)) ||
      new Set(value.scopes).size !== value.scopes.length) invalid();
  if (typeof value.purpose !== 'string' || !value.purpose.trim() || value.purpose.length > 1000 ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value.purpose)) invalid();
  const issuedAt = positive(value.issuedAt), expiresAt = positive(value.expiresAt);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_LIFETIME) invalid();
  return { format: v2 ? FORMAT_V2 : FORMAT, caseId: identifier(value.caseId), ownerFingerprint: value.ownerFingerprint as string,
    organizationId: identifier(value.organizationId), recipientKeyId: identifier(value.recipientKeyId),
    requestId: identifier(value.requestId), scopes: [...value.scopes as CaseScope[]],
    objectRevisionLimit: value.objectRevisionLimit === null ? null : positive(value.objectRevisionLimit),
    purpose: value.purpose as string, issuedAt, expiresAt, details: v2 ? parseRequestDetails(value.details) : null };
}
function parseBytes(bytes: Uint8Array): LegalAccessRequest {
  return parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
}

/** Firm-device operation. The owner key must already be authenticated by the
 * listing/genesis trust path. Only the returned ciphertext may be stored/relayed.
 */
export async function createLegalAccessRequest(input: AccessRequestInput,
  organizationId: string, organizationKey: PrivateKey, owner: OwnerTrust): Promise<string> {
  let plaintext: Uint8Array | undefined;
  try {
    const structured = !!input && Object.prototype.hasOwnProperty.call(input, 'details');
    const inputFields = ['requestId', 'scopes', 'objectRevisionLimit', 'purpose', 'issuedAt', 'expiresAt',
      ...(structured ? ['details'] : [])];
    if (!input || Object.keys(input).length !== inputFields.length || Object.keys(input).some(key => !inputFields.includes(key))) invalid();
    // Snapshot the decision before awaiting cryptography.
    const { details, ...base } = input;
    const request = parse({ ...base, format: structured ? FORMAT_V2 : FORMAT, caseId: owner.caseId,
      ownerFingerprint: owner.ownerFingerprint, organizationId, recipientKeyId: '0'.repeat(64),
      ...(structured ? { details: details && { ...details, practiceAreas: Array.isArray(details.practiceAreas) ? [...details.practiceAreas] : details.practiceAreas } } : {}) });
    const ownerKey = owner.ownerPublicKey;
    if (ownerKey.isPrivate() || ownerKey.getFingerprint() !== request.ownerFingerprint || !organizationKey.isDecrypted()) invalid();
    request.recipientKeyId = await caseRecipientKeyId(organizationKey.toPublic());
    const { details: parsedDetails, ...wire } = request;
    plaintext = new TextEncoder().encode(JSON.stringify(parsedDetails ? { ...wire, details: parsedDetails } : wire));
    if (plaintext.length > 8192) invalid();
    return await encrypt({ message: await createMessage({ binary: new Uint8Array(plaintext) }),
      encryptionKeys: ownerKey, signingKeys: organizationKey, wildcard: true, format: 'armored', config: CONFIG });
  } catch { return invalid(); } finally { plaintext?.fill(0); }
}

/** Owner-device operation. Directory entries MUST be independently pinned and
 * currently whitelisted, not populated from the encrypted request or an operator
 * assertion alone. No network lookup is performed on unverified request data.
 * This authenticates a request, never grants access or signs owner consent.
 * The enclave service still needs authenticated membership, quotas, encrypted
 * persistence, expiry/withdrawal state and idempotency/deduplication.
 */
export async function openLegalAccessRequest(ciphertext: string, caseId: string, owner: PrivateKey,
  directory: readonly TrustedLegalOrganization[], now: number): Promise<LegalAccessRequest> {
  let inspected: Uint8Array | undefined, verifiedBytes: Uint8Array | undefined;
  try {
    const expectedCase = identifier(caseId), currentTime = positive(now);
    if (typeof ciphertext !== 'string' || ciphertext.length > 16_384 || directory.length > 256) invalid();
    const pinned = directory.map(entry => ({ ...entry }));
    if (new Set(pinned.map(entry => entry.organizationId)).size !== pinned.length) invalid();
    // Inspect only enough decrypted data to select a key from the caller's pinned
    // roster. It is still untrusted and must not reach UI, logs, or a lookup URL.
    const inspection = await decrypt({ message: await readMessage({ armoredMessage: ciphertext }),
      decryptionKeys: owner, format: 'binary', config: CONFIG });
    const inspectedBytes: Uint8Array = inspection.data;
    inspected = inspectedBytes;
    await Promise.allSettled(inspection.signatures.map(signature => signature.verified));
    if (inspection.signatures.length !== 1 || inspectedBytes.length > 8192) invalid();
    const untrusted = parseBytes(inspectedBytes);
    const organization = pinned.find(entry => entry.organizationId === untrusted.organizationId);
    if (!organization || organization.approved !== true || organization.publicKey.isPrivate() ||
        await caseRecipientKeyId(organization.publicKey) !== untrusted.recipientKeyId) invalid();
    // Decrypt again with the selected trusted key so the library verifies the full
    // original OpenPGP signed message, including its literal packet metadata.
    const verified = await decrypt({ message: await readMessage({ armoredMessage: ciphertext }),
      decryptionKeys: owner, verificationKeys: organization.publicKey, expectSigned: true,
      format: 'binary', config: CONFIG });
    const messageBytes: Uint8Array = verified.data;
    verifiedBytes = messageBytes;
    const signatures = await Promise.allSettled(verified.signatures.map(signature => signature.verified));
    if (signatures.length !== 1 || signatures[0].status !== 'fulfilled' || messageBytes.length > 8192) invalid();
    const request = parseBytes(messageBytes);
    if (request.caseId !== expectedCase || request.ownerFingerprint !== owner.getFingerprint() ||
        !issuedNotAfter(request.issuedAt, currentTime) || request.expiresAt <= currentTime) invalid();
    return request;
  } catch { return invalid(); } finally { inspected?.fill(0); verifiedBytes?.fill(0); }
}

/** Owner inbox boundary. Delivery metadata and pending status MUST come from
 * authenticated current state, not an arbitrary host row. The caller's case ID
 * is independently pinned by its owner recovery state. Only return a request
 * when the verified encrypted payload agrees with every delivery binding.
 * This does not establish current-state freshness or authorize any case access. */
export async function openDeliveredLegalAccessRequest(delivery: DeliveredLegalAccessRequest,
  caseId: string, owner: PrivateKey, directory: readonly TrustedLegalOrganization[],
  now: number): Promise<LegalAccessRequest> {
  try {
    if (!delivery || typeof delivery !== 'object' || Array.isArray(delivery) ||
        Object.keys(delivery).sort().join(',') !== (delivery.routing === 'blinded-v1'
          ? 'caseId,ciphertext,expiresAt,organizationId,recipientKeyId,requestId,routing,status'
          : 'caseId,ciphertext,expiresAt,organizationId,recipientKeyId,requestId,status')) invalid();
    const row = { ...delivery }, expectedCase = identifier(caseId), currentTime = positive(now);
    for (const value of [row.caseId, row.requestId, row.organizationId, row.recipientKeyId]) identifier(value);
    if (row.caseId !== expectedCase || row.status !== 'pending' || positive(row.expiresAt) <= currentTime) invalid();
    const request = await openLegalAccessRequest(row.ciphertext, expectedCase, owner, directory, currentTime);
    const expected = row.routing === 'blinded-v1' ? {
      requestId: await requestRoutingTag('request', request.requestId),
      organizationId: await requestRoutingTag('organization', request.requestId, request.organizationId),
      recipientKeyId: await requestRoutingTag('recipient', request.requestId, request.recipientKeyId),
    } : request;
    // Blinded rows carry the signed expiry rounded down to the UTC day, and the
    // owner client keeps that value when it resolves the routing (older rows
    // carry it exactly). Either way the host can only shorten a request.
    const expiry = row.expiresAt === request.expiresAt || row.expiresAt === requestTimeBucket(request.expiresAt);
    if (expected.requestId !== row.requestId || expected.organizationId !== row.organizationId ||
        expected.recipientKeyId !== row.recipientKeyId || !expiry) invalid();
    return request;
  } catch { return invalid(); }
}
