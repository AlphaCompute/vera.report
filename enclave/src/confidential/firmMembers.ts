import { createMessage, decrypt, encrypt, generateKey, readKey, readMessage, readPrivateKey, readSignature, sign, verify } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';

/** Firm member key distribution (architecture: "Organization membership and recovery").
 *
 * The organization key is the firm's case-access key: owner grants name its
 * recipient key ID. Members never share a login or pass the private key around
 * by hand. Instead the firm STEWARD (a firm person, never Alpha Compute) wraps the
 * organization private key to each member's own device key, signed by the
 * steward and bound to (organizationId, memberId, member device key, keyEpoch).
 * The member's device verifies the steward signature and that the unwrapped key
 * is exactly the organization key it already trusts (e.g. from the approved
 * registration), so neither the relay nor Vera's database can substitute a key.
 *
 * Member removal = organization key rotation: a NEW organization key and a
 * continuity statement signed by BOTH the old and the new key, naming the removed
 * members. The steward rewraps only the new key, only to remaining members.
 *
 * A rotated organization key is a different case recipient. Continuity does NOT
 * carry case access: every owner must approve a NEW grant (and state-key
 * envelope) to the new recipient key ID in the owner flow. Nothing here, and no
 * service, may silently rewrap case keys to the new organization key. Rotation
 * also cannot revoke plaintext or keys a removed member already decrypted; owners
 * revoke/rotate their case state to cut the old key off from later history.
 */
const WRAP = 'vera-firm-member-key/v1';
const CONTINUITY = 'vera-firm-key-continuity/v1';
const CONFIG = { allowUnauthenticatedMessages: false, allowUnauthenticatedStream: false, maxDecompressedMessageSize: 64 * 1024 };
const MAX_ENVELOPE = 96 * 1024;

export type MemberKeyBinding = { organizationId: string; memberId: string; keyEpoch: number; issuedAt: number };
export type OrganizationKeyContinuity = {
  format: typeof CONTINUITY; organizationId: string; previousKeyEpoch: number; keyEpoch: number;
  previousFingerprint: string; previousRecipientKeyId: string; nextFingerprint: string; nextRecipientKeyId: string;
  removedMemberIds: string[]; issuedAt: number;
  /** Always 'required': a rotated key receives no case access without new owner grants. */
  ownerApproval: 'required';
};

function invalid(): never { throw new Error('Invalid firm member key material'); }
function hex64(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) invalid();
  return value as string;
}
function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) invalid();
  return value as number;
}
function exact(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const keys = Object.keys(value as object);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) invalid();
  return value as Record<string, unknown>;
}
async function singleVerified(signatures: { verified: Promise<unknown> }[]): Promise<void> {
  const verified = await Promise.allSettled(signatures.map(item => item.verified));
  if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
}

/** Steward operation: wrap the organization private key to one member device key. */
export async function wrapOrganizationKeyForMember(binding: MemberKeyBinding, organizationKey: PrivateKey,
  memberDeviceKey: PublicKey, steward: PrivateKey): Promise<string> {
  let payload: Uint8Array | undefined;
  try {
    if (!organizationKey.isDecrypted() || memberDeviceKey.isPrivate() || !steward.isDecrypted() ||
        memberDeviceKey.getFingerprint() === organizationKey.getFingerprint()) invalid();
    payload = new TextEncoder().encode(JSON.stringify({ format: WRAP, organizationId: hex64(binding.organizationId),
      memberId: hex64(binding.memberId), keyEpoch: positive(binding.keyEpoch), issuedAt: positive(binding.issuedAt),
      memberKeyFingerprint: memberDeviceKey.getFingerprint(), organizationFingerprint: organizationKey.getFingerprint(),
      organizationPrivateKey: organizationKey.armor() }));
    return await encrypt({ message: await createMessage({ binary: payload }), encryptionKeys: memberDeviceKey,
      signingKeys: steward, format: 'armored', config: CONFIG });
  } catch { return invalid(); } finally { payload?.fill(0); }
}

/** Member-device operation. `organizationPublicKey` is the organization key this
 * device already trusts (approved registration / continuity chain) and `steward`
 * the steward key pinned inside the firm. The returned key is exactly that
 * organization key at exactly `keyEpoch`. */
export async function unwrapOrganizationKey(envelope: string, expected: {
  organizationId: string; memberId: string; keyEpoch: number; organizationPublicKey: PublicKey; steward: PublicKey;
}, memberDevice: PrivateKey): Promise<{ organizationKey: PrivateKey; binding: MemberKeyBinding }> {
  let data: Uint8Array | undefined;
  try {
    if (typeof envelope !== 'string' || envelope.length > MAX_ENVELOPE || expected.steward.isPrivate()) invalid();
    const result = await decrypt({ message: await readMessage({ armoredMessage: envelope }), decryptionKeys: memberDevice,
      verificationKeys: expected.steward, expectSigned: true, format: 'binary', config: CONFIG });
    await singleVerified(result.signatures);
    data = result.data as Uint8Array;
    const value = exact(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)), ['format', 'organizationId',
      'memberId', 'keyEpoch', 'issuedAt', 'memberKeyFingerprint', 'organizationFingerprint', 'organizationPrivateKey']);
    if (value.format !== WRAP || value.organizationId !== hex64(expected.organizationId) ||
        value.memberId !== hex64(expected.memberId) || value.keyEpoch !== positive(expected.keyEpoch) ||
        value.memberKeyFingerprint !== memberDevice.getFingerprint() ||
        value.organizationFingerprint !== expected.organizationPublicKey.getFingerprint() ||
        typeof value.organizationPrivateKey !== 'string') invalid();
    const organizationKey = await readPrivateKey({ armoredKey: value.organizationPrivateKey as string });
    if (!organizationKey.isDecrypted() || organizationKey.getFingerprint() !== expected.organizationPublicKey.getFingerprint() ||
        organizationKey.toPublic().armor() !== expected.organizationPublicKey.armor()) invalid();
    return { organizationKey, binding: { organizationId: value.organizationId as string, memberId: value.memberId as string,
      keyEpoch: value.keyEpoch as number, issuedAt: positive(value.issuedAt) } };
  } catch { return invalid(); } finally { data?.fill(0); }
}

async function signText(text: string, key: PrivateKey): Promise<string> {
  return sign({ message: await createMessage({ binary: new TextEncoder().encode(text) }), signingKeys: key,
    detached: true, format: 'armored' }) as Promise<string>;
}
async function verifyText(text: string, armored: unknown, key: PublicKey): Promise<void> {
  if (typeof armored !== 'string' || armored.length > 16_384) invalid();
  const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(text) }),
    signature: await readSignature({ armoredSignature: armored as string }), verificationKeys: key,
    expectSigned: true, format: 'binary' });
  await singleVerified(result.signatures);
}
function continuityStatement(value: unknown): OrganizationKeyContinuity {
  const statement = exact(value, ['format', 'organizationId', 'previousKeyEpoch', 'keyEpoch', 'previousFingerprint',
    'previousRecipientKeyId', 'nextFingerprint', 'nextRecipientKeyId', 'removedMemberIds', 'issuedAt', 'ownerApproval']);
  if (statement.format !== CONTINUITY || statement.ownerApproval !== 'required' ||
      !Array.isArray(statement.removedMemberIds) || statement.removedMemberIds.length > 256 ||
      typeof statement.previousFingerprint !== 'string' || typeof statement.nextFingerprint !== 'string' ||
      statement.previousFingerprint === statement.nextFingerprint) invalid();
  const removed = (statement.removedMemberIds as unknown[]).map(hex64);
  if (new Set(removed).size !== removed.length) invalid();
  const previousKeyEpoch = positive(statement.previousKeyEpoch);
  if (statement.keyEpoch !== previousKeyEpoch + 1) invalid();
  return { format: CONTINUITY, organizationId: hex64(statement.organizationId), previousKeyEpoch,
    keyEpoch: previousKeyEpoch + 1, previousFingerprint: statement.previousFingerprint as string,
    previousRecipientKeyId: hex64(statement.previousRecipientKeyId), nextFingerprint: statement.nextFingerprint as string,
    nextRecipientKeyId: hex64(statement.nextRecipientKeyId), removedMemberIds: removed, issuedAt: positive(statement.issuedAt),
    ownerApproval: 'required' };
}

/** Steward operation for member removal (or any compromise suspicion): create a
 * new organization key and a continuity statement signed by the old AND the new
 * key. Afterwards: rewrap the new key to remaining members only, submit the new
 * public key for approval, and ask each case owner for a new grant. */
export async function rotateOrganizationKey(input: {
  organizationId: string; previousKeyEpoch: number; removedMemberIds: string[]; issuedAt: number;
}, previousKey: PrivateKey): Promise<{ organizationKey: PrivateKey; continuity: string; statement: OrganizationKeyContinuity }> {
  try {
    if (!previousKey.isDecrypted()) invalid();
    const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Vera legal organization' }], format: 'object' });
    const statement = continuityStatement({ format: CONTINUITY, organizationId: input.organizationId,
      previousKeyEpoch: input.previousKeyEpoch, keyEpoch: input.previousKeyEpoch + 1,
      previousFingerprint: previousKey.getFingerprint(), previousRecipientKeyId: await caseRecipientKeyId(previousKey.toPublic()),
      nextFingerprint: privateKey.getFingerprint(), nextRecipientKeyId: await caseRecipientKeyId(privateKey.toPublic()),
      removedMemberIds: input.removedMemberIds, issuedAt: input.issuedAt, ownerApproval: 'required' });
    const text = JSON.stringify(statement);
    const continuity = JSON.stringify({ statement, nextPublicKey: privateKey.toPublic().armor(),
      previousSignature: await signText(text, previousKey), nextSignature: await signText(text, privateKey) });
    return { organizationKey: privateKey, continuity, statement };
  } catch { return invalid(); }
}

/** Anyone holding the previous organization public key (members, owners' devices,
 * onboarding) can verify the rotation. The result is evidence of continuity for
 * display and auditing only: it authorizes no case access by itself. */
export async function verifyOrganizationKeyContinuity(document: string, expected: {
  organizationId: string; previousPublicKey: PublicKey;
}): Promise<{ statement: OrganizationKeyContinuity; nextPublicKey: PublicKey }> {
  try {
    if (typeof document !== 'string' || document.length > 64 * 1024) invalid();
    const value = exact(JSON.parse(document), ['statement', 'nextPublicKey', 'previousSignature', 'nextSignature']);
    const statement = continuityStatement(value.statement);
    if (typeof value.nextPublicKey !== 'string' || value.nextPublicKey.length > 16_384) invalid();
    const nextPublicKey = await readKey({ armoredKey: value.nextPublicKey as string });
    const previous = expected.previousPublicKey;
    if (nextPublicKey.isPrivate() || previous.isPrivate() || statement.organizationId !== hex64(expected.organizationId) ||
        statement.previousFingerprint !== previous.getFingerprint() ||
        statement.previousRecipientKeyId !== await caseRecipientKeyId(previous) ||
        statement.nextFingerprint !== nextPublicKey.getFingerprint() ||
        statement.nextRecipientKeyId !== await caseRecipientKeyId(nextPublicKey)) invalid();
    await nextPublicKey.getEncryptionKey(); await nextPublicKey.getSigningKey();
    const text = JSON.stringify(statement);
    await verifyText(text, value.previousSignature, previous);
    await verifyText(text, value.nextSignature, nextPublicKey);
    return { statement, nextPublicKey };
  } catch { return invalid(); }
}

const MEMBER_ID = 'vera-firm-member/v1';
const PROFILE = 'vera-firm-member-profile/v1';
export const MEMBER_NAME_MAX = 80;
export const MEMBER_CONTACT_MAX = 120;
export type MemberProfile = { name: string; contact: string };

/** Stable member ID for a verified identity-provider subject in one provider
 * organization. The enclave derives it from the verified login token, never
 * from a request field, so the host cannot choose which member an envelope names. */
export async function firmMemberId(providerOrganizationId: string, subject: string): Promise<string> {
  if (typeof providerOrganizationId !== 'string' || !providerOrganizationId || providerOrganizationId.length > 256 ||
      typeof subject !== 'string' || !subject || subject.length > 256) invalid();
  const bytes = new TextEncoder().encode(JSON.stringify([MEMBER_ID, providerOrganizationId, subject]));
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Groups a device key fingerprint for reading aloud: `ABCD EF01 …`. */
export function formatDeviceCode(fingerprint: string): string {
  if (typeof fingerprint !== 'string' || !/^[a-f0-9]{40,64}$/.test(fingerprint)) invalid();
  return fingerprint.toUpperCase().match(/.{4}/g)!.join(' ');
}

function profileText(value: unknown, max: number): string {
  if (typeof value !== 'string') invalid();
  const text = (value as string).normalize('NFC').replace(/\s+/g, ' ').trim();
  if (text.length > max || /[\u0000-\u001f\u007f]/.test(text)) invalid();
  return text;
}

/** New-member device: the name and contact the steward sees, encrypted to the
 * organization key (so the host sees neither) and signed by this device key.
 * The signature does not authenticate the person: anyone can encrypt to the
 * organization's public key. Stewards confirm the device code out of band. */
export async function sealMemberProfile(input: { organizationId: string; profile: MemberProfile },
  organizationPublicKey: PublicKey, device: PrivateKey): Promise<string> {
  let payload: Uint8Array | undefined;
  try {
    if (organizationPublicKey.isPrivate() || !device.isDecrypted()) invalid();
    const name = profileText(input.profile.name, MEMBER_NAME_MAX), contact = profileText(input.profile.contact, MEMBER_CONTACT_MAX);
    if (!name) invalid();
    payload = new TextEncoder().encode(JSON.stringify({ format: PROFILE, organizationId: hex64(input.organizationId),
      deviceFingerprint: device.getFingerprint(), name, contact }));
    return await encrypt({ message: await createMessage({ binary: payload }), encryptionKeys: organizationPublicKey,
      signingKeys: device, format: 'armored', config: CONFIG });
  } catch { return invalid(); } finally { payload?.fill(0); }
}

/** Steward device: opens a profile only if the registered device key signed it
 * for this organization. */
export async function openMemberProfile(sealed: string, expected: { organizationId: string; devicePublicKey: PublicKey },
  organizationKey: PrivateKey): Promise<MemberProfile> {
  let data: Uint8Array | undefined;
  try {
    if (typeof sealed !== 'string' || sealed.length > 8192 || expected.devicePublicKey.isPrivate()) invalid();
    const result = await decrypt({ message: await readMessage({ armoredMessage: sealed }), decryptionKeys: organizationKey,
      verificationKeys: expected.devicePublicKey, expectSigned: true, format: 'binary', config: CONFIG });
    await singleVerified(result.signatures);
    data = result.data as Uint8Array;
    const value = exact(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)),
      ['format', 'organizationId', 'deviceFingerprint', 'name', 'contact']);
    if (value.format !== PROFILE || value.organizationId !== hex64(expected.organizationId) ||
        value.deviceFingerprint !== expected.devicePublicKey.getFingerprint()) invalid();
    const name = profileText(value.name, MEMBER_NAME_MAX), contact = profileText(value.contact, MEMBER_CONTACT_MAX);
    if (!name) invalid();
    return { name, contact };
  } catch { return invalid(); } finally { data?.fill(0); }
}
