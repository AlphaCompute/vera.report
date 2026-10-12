import { generateKey, readKey, readPrivateKey } from '../../enclave/src/confidential/pgp';
import type { PrivateKey, PublicKey } from '../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../enclave/src/confidential/caseObject';
import { verifyFirmKeyBinding } from '../../enclave/src/confidential/firmKeyBinding';
import type { FirmProfile } from '../../enclave/src/confidential/firmKeyBinding';
import {
  formatDeviceCode, openMemberProfile, rotateOrganizationKey, sealMemberProfile, unwrapOrganizationKey,
  verifyOrganizationKeyContinuity, wrapOrganizationKeyForMember,
} from '../../enclave/src/confidential/firmMembers';
import type { MemberProfile, OrganizationKeyContinuity } from '../../enclave/src/confidential/firmMembers';
import { signParticipantRequest } from '../../enclave/src/confidential/participantRequest';
import { CONFIDENTIAL_AUDIENCE, ChannelSessions, ConfidentialUnavailableError, authenticatedOperation, base64, exchange, trustedClock, verifiedSession } from './client';
import type { ChannelRelay } from './client';
import type { FirmSession } from './firmCase';
import type { FirmIdentity } from './firmKey';
import { validFirmDomain, validOrganizationId } from './firmKey';

/** Member device keys in the browser (architecture: "Organization membership
 * and recovery"). A new lawyer creates a device key on their own device and
 * registers its public half; a member holding the organization key (the steward)
 * compares the device code with the lawyer, wraps the organization key to that
 * device here and uploads the envelope. The envelope is signed by the
 * organization key itself, so a member device accepts it only if it opens to
 * exactly the approved organization key returned by the enclave, on first
 * join and after every rotation. The continuity statement both keys sign is
 * shown as evidence but never installs a key by itself. VERA and its host never
 * see the organization private key.
 *
 * Removal rotates the organization key. The new key is a different case
 * recipient: every reporter must allow the organization again, and nothing here
 * moves case access to the new key.
 */
export type DeviceState = 'none' | 'pending' | 'approved' | 'removed';
export type DeviceStatus = {
  memberId: string; state: DeviceState; deviceFingerprint: string | null;
  envelope: string | null; keyEpoch: number | null; continuity: string | null;
};
export type MemberDevice = {
  memberId: string; state: Exclude<DeviceState, 'none'>; devicePublicKey: PublicKey; deviceFingerprint: string;
  deviceCode: string; profile: MemberProfile | null; keyEpoch: number | null; revision: number;
  registeredAt: number; updatedAt: number; enrolled: boolean;
};
export type JoinTarget = { organizationId: string; domain: string };
export class FirmMemberError extends Error {
  constructor(readonly code: 'conflict' | 'limit' | 'not-approved' | 'key-mismatch' | 'domain-unverified' | 'not-confirmed'
    | 'other-account' | 'not-registered') {
    super({
      conflict: 'Someone else changed this list at the same time. Reload it and try again.',
      limit: 'Your organization has reached the limit of 64 devices. Remove a device you no longer use first.',
      'not-approved': 'This device has not been approved yet.',
      'key-mismatch': 'The organization key sent to this device does not match your approved organization key. Nothing was saved. Tell your steward.',
      'domain-unverified': 'Your approved organization key could not be confirmed. Check your sign-in and ask your steward to check the organization approval.',
      'not-confirmed': 'Your organization replaced its key, but the new key has not been approved yet. This device keeps its current key until it does. If this lasts, tell your steward.',
      'other-account': 'You are signed in with a different account than the one that registered this device. Sign in with the account you used to join your organization.',
      'not-registered': 'This device is no longer registered with your organization. Open the join link from your steward to register it again.',
    }[code]);
    this.name = 'FirmMemberError';
  }
}
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ConfidentialUnavailableError();
  return value as Record<string, unknown>;
}

/** Parses `#organization=<id>&domain=<domain>` (a join link carries no secret). */
export function readJoinTarget(fragment: string): JoinTarget | null {
  const values = new URLSearchParams(fragment.replace(/^#/, ''));
  const organizationId = (values.get('organization') ?? '').trim().toLowerCase(), domain = (values.get('domain') ?? '').trim().toLowerCase();
  return validOrganizationId(organizationId) && validFirmDomain(domain) ? { organizationId, domain } : null;
}
export function joinLink(origin: string, target: JoinTarget): string {
  return `${origin}/legal/join#organization=${target.organizationId}&domain=${encodeURIComponent(target.domain)}`;
}

/** Explicit attested onboarding state, distinct from connectivity/auth failures. */
export class OrganizationKeyPendingError extends Error {
  constructor() { super('Your organization key is awaiting registration.'); this.name = 'OrganizationKeyPendingError'; }
}

/** Read the approved organization key inside a verified enclave channel.
 * Membership is checked by the enclave; the host cannot substitute a key. */
export async function approvedOrganizationProfile(target: JoinTarget, input: {
  relay: ChannelRelay; releaseManifest: string; accessToken: string; now: number;
}): Promise<{ publicKey: PublicKey; profile: FirmProfile | null }> {
  try {
    const reply = await call(input.relay, input.releaseManifest, input.now, {
      operation: 'legal.organization-key', accessToken: input.accessToken, organizationId: target.organizationId, domain: target.domain,
    });
    if (reply.organizationId === target.organizationId && reply.domain === target.domain && reply.state === 'awaiting-key') {
      throw new OrganizationKeyPendingError();
    }
    if (reply.organizationId !== target.organizationId || reply.domain !== target.domain || typeof reply.publicKey !== 'string') throw new Error();
    const key = await readKey({ armoredKey: reply.publicKey });
    if (key.isPrivate()) throw new Error();
    let profile: FirmProfile | null = null;
    if (typeof reply.bindingDocument === 'string') {
      const binding = await verifyFirmKeyBinding(reply.bindingDocument, target);
      if (binding.binding.recipientKeyId !== await caseRecipientKeyId(key)) throw new Error();
      profile = binding.profile;
    }
    return { publicKey: key, profile };
  } catch (error) {
    if (error instanceof OrganizationKeyPendingError) throw error;
    throw new FirmMemberError('domain-unverified');
  }
}

export async function publishedOrganizationKey(target: JoinTarget,
  input: Parameters<typeof approvedOrganizationProfile>[1]): Promise<PublicKey> {
  return (await approvedOrganizationProfile(target, input)).publicKey;
}

export async function createMemberDeviceKey(): Promise<PrivateKey> {
  const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'VERA legal member device' }], format: 'object' });
  return privateKey;
}
export function deviceCode(key: PrivateKey | PublicKey): string { return formatDeviceCode(key.getFingerprint()); }

async function call(relay: ChannelRelay, releaseManifest: string, now: number, request: unknown): Promise<Record<string, unknown>> {
  try {
    const session = await verifiedSession(relay, releaseManifest, now);
    return record(await exchange(relay, session, request));
  } catch { throw new ConfidentialUnavailableError(); }
}
function deviceStatus(reply: Record<string, unknown>): DeviceStatus {
  if (!hex(reply.memberId) || !['none', 'pending', 'approved', 'removed'].includes(reply.state as string)) throw new ConfidentialUnavailableError();
  if (reply.state === 'none') return { memberId: reply.memberId, state: 'none', deviceFingerprint: null, envelope: null, keyEpoch: null, continuity: null };
  if (typeof reply.deviceFingerprint !== 'string' || (reply.envelope !== null && typeof reply.envelope !== 'string') ||
      (reply.keyEpoch !== null && !Number.isSafeInteger(reply.keyEpoch)) ||
      (reply.continuity !== null && typeof reply.continuity !== 'string')) throw new ConfidentialUnavailableError();
  return { memberId: reply.memberId, state: reply.state as DeviceState, deviceFingerprint: reply.deviceFingerprint,
    envelope: reply.envelope as string | null, keyEpoch: reply.keyEpoch as number | null, continuity: reply.continuity as string | null };
}

/** New member: register this device's public key with a profile encrypted to the organization key. */
export async function registerMemberDevice(input: { relay: ChannelRelay; releaseManifest: string; accessToken: string; now: number;
  organizationId: string; organizationPublicKey: PublicKey; device: PrivateKey; profile: MemberProfile }): Promise<DeviceStatus> {
  const profile = await sealMemberProfile({ organizationId: input.organizationId, profile: input.profile },
    input.organizationPublicKey, input.device);
  const reply = await call(input.relay, input.releaseManifest, input.now, { operation: 'legal.device-register',
    accessToken: input.accessToken, body: base64(encode({ organizationId: input.organizationId,
      devicePublicKey: input.device.toPublic().armor(), profile })) });
  if (reply.error === 'limit') throw new FirmMemberError('limit');
  if (reply.error !== undefined) throw new FirmMemberError('conflict');
  const status = deviceStatus(reply);
  if (status.deviceFingerprint !== input.device.getFingerprint()) throw new ConfidentialUnavailableError();
  return status;
}

export async function readMemberDeviceStatus(input: { relay: ChannelRelay; releaseManifest: string; accessToken: string;
  now: number; organizationId: string }): Promise<DeviceStatus> {
  return deviceStatus(await call(input.relay, input.releaseManifest, input.now, { operation: 'legal.device-status',
    accessToken: input.accessToken, body: base64(encode({ organizationId: input.organizationId })) }));
}

/** Member device: opens its envelope only to the organization key the firm
 * has registered in the approved roster (`published`), on first join and after every
 * rotation alike. Host rows are untrusted, and after a removal the removed
 * member still holds the old organization key, so a continuity statement signed
 * by that old key cannot be what installs a new key here: it is display and
 * audit evidence only, attached when it verifies from `held` (the organization
 * public key this device already holds) and names exactly the published key.
 * While the approved roster still names `held` (or cannot be read), the rotated key
 * is not confirmed yet and nothing is installed. A key epoch at or below
 * `minimumKeyEpoch` is refused, so an old envelope cannot be replayed. */
export async function openApprovedDevice(status: DeviceStatus, input: {
  organizationId: string; device: PrivateKey; minimumKeyEpoch: number;
  held?: PublicKey | null; published: () => Promise<PublicKey>;
}): Promise<{ organizationKey: PrivateKey; keyEpoch: number; continuity: OrganizationKeyContinuity | null }> {
  if (status.state !== 'approved' || !status.envelope || !status.keyEpoch) throw new FirmMemberError('not-approved');
  if (status.deviceFingerprint !== input.device.getFingerprint() || status.keyEpoch <= input.minimumKeyEpoch) {
    throw new FirmMemberError('key-mismatch');
  }
  const held = input.held ?? null;
  let anchor: PublicKey;
  try { anchor = await input.published(); } catch { throw new FirmMemberError(held ? 'not-confirmed' : 'domain-unverified'); }
  // The approved roster still names the key this device holds: the rotation is not confirmed yet.
  if (held && anchor.getFingerprint() === held.getFingerprint()) throw new FirmMemberError('not-confirmed');
  let organizationKey: PrivateKey;
  try {
    ({ organizationKey } = await unwrapOrganizationKey(status.envelope, { organizationId: input.organizationId,
      memberId: status.memberId, keyEpoch: status.keyEpoch, organizationPublicKey: anchor, steward: anchor }, input.device));
  } catch { throw new FirmMemberError('key-mismatch'); }
  let continuity: OrganizationKeyContinuity | null = null;
  if (status.continuity && held) {
    try {
      const verified = await verifyOrganizationKeyContinuity(status.continuity, { organizationId: input.organizationId, previousPublicKey: held });
      if (verified.statement.keyEpoch === status.keyEpoch && verified.nextPublicKey.getFingerprint() === anchor.getFingerprint()) {
        continuity = verified.statement;
      }
    } catch { /* evidence only: a device that missed a rotation cannot verify it from its older key */ }
  }
  return { organizationKey, keyEpoch: status.keyEpoch, continuity };
}

export async function firmIdentityFromKey(organizationKey: PrivateKey, target: JoinTarget): Promise<FirmIdentity> {
  return { organizationId: target.organizationId, domain: target.domain, privateKey: organizationKey,
    recipientKeyId: await caseRecipientKeyId(organizationKey.toPublic()) };
}

/** Organization-key operation for member management. The single-use challenge
 * is issued inside the same attested session that carries the proof (the
 * enclave keeps it in that session's memory), and the proof is bound to that
 * session's nonce and key. A change is never re-sent automatically. */
async function stewardOperation(session: FirmSession, operation: string, body: unknown, now: number): Promise<Record<string, unknown>> {
  const accessToken = await session.accessToken();
  const bytes = encode(body);
  try {
    // Transient: one flow, closed by its last request (the organization key may change mid-rotation).
    const sessions = new ChannelSessions(session.relay, session.releaseManifest, undefined, true);
    return record(await authenticatedOperation(sessions, { challengeOperation: 'legal.challenge', clock: trustedClock(now),
      sign: (challenge, channel, issuedAt) => signParticipantRequest({ audience: CONFIDENTIAL_AUDIENCE, role: 'organization',
        caseId: session.firm.organizationId, organizationId: session.firm.organizationId, operation: 'manage-members',
        body: bytes, challenge, issuedAt, nonce: channel.nonce, serverKeyId: channel.serverKeyId }, session.firm.privateKey),
      request: proof => ({ operation, accessToken, proof, body: base64(bytes) }) }));
  } catch { throw new ConfidentialUnavailableError(); } finally { bytes.fill(0); }
}
async function memberOperation(session: FirmSession, operation: string, body: unknown, now: number): Promise<Record<string, unknown>> {
  const accessToken = await session.accessToken();
  return call(session.relay, session.releaseManifest, now, { operation, accessToken, body: base64(encode(body)) });
}

/** Renew this approved device's membership with proofs from both locally held keys.
 * Decoded token fields are hints only; the enclave independently verifies the JWT. */
export async function enrollApprovedMemberDevice(input: {
  relay: ChannelRelay; releaseManifest: string; accessToken: string; now: number;
  firm: FirmIdentity; device: PrivateKey; memberId: string;
}): Promise<void> {
  const { signEnrollmentChallenge } = await import('../../enclave/src/confidential/enrollmentProof');
  const { signMembershipAuthorization } = await import('../../enclave/src/confidential/membershipAuthorization');
  const { trustedTime } = await import('./client');
  const payload = input.accessToken.split('.')[1];
  if (!payload) throw new ConfidentialUnavailableError();
  const claims = record(JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))));
  if (typeof claims.sub !== 'string' || typeof claims.org_id !== 'string') throw new ConfidentialUnavailableError();
  const random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join('');
  const issuedAt = trustedTime(input.now), expiresAt = issuedAt + 7 * 86400000;
  const challenge = { format: 'vera-legal-enrollment/v1' as const, invitationId: random(),
    organizationId: input.firm.organizationId, providerOrganizationId: claims.org_id, subject: claims.sub,
    recipientKeyId: input.firm.recipientKeyId, nonce: random(), expiresAt };
  const authorization = await signMembershipAuthorization({ format: 'vera-membership-authorization/v1',
    organizationId: challenge.organizationId, providerOrganizationId: challenge.providerOrganizationId,
    subject: challenge.subject, recipientKeyId: challenge.recipientKeyId, issuedAt, expiresAt }, input.firm.privateKey);
  const proof = await signEnrollmentChallenge(challenge, input.firm.privateKey);
  const deviceProof = await signEnrollmentChallenge({ ...challenge, recipientKeyId: await caseRecipientKeyId(input.device.toPublic()) }, input.device);
  const reply = await call(input.relay, input.releaseManifest, input.now, { operation: 'legal.device-enroll',
    accessToken: input.accessToken, body: base64(encode({ organizationId: input.firm.organizationId,
      enrollment: { challenge, proof, authorization, delegation: {
        memberId: input.memberId, deviceFingerprint: input.device.getFingerprint(), deviceProof,
      } } })) });
  if (reply.enrolled !== true || reply.expiresAt !== expiresAt) throw new ConfidentialUnavailableError();
}

/** Submit a replacement with current membership, a fresh proof from the old key and the
 * continuity statement signed by the registered key and the new one. */
export async function submitReplacementOrganizationKey(session: FirmSession, next: FirmIdentity, bindingDocument: string,
  continuity: string, now: number): Promise<void> {
  if (next.organizationId !== session.firm.organizationId || next.domain !== session.firm.domain ||
      next.recipientKeyId === session.firm.recipientKeyId) throw new ConfidentialUnavailableError();
  const reply = await stewardOperation(session, 'legal.replace-organization-key', {
    organizationId: session.firm.organizationId, bindingDocument, continuity,
  }, now);
  if (reply.submitted !== true || reply.recipientKeyId !== next.recipientKeyId) throw new ConfidentialUnavailableError();
}

/** Invite a colleague at the approved email domain, using the steward's signed authority. */
export async function inviteOrganizationMember(session: FirmSession, email: string, now: number): Promise<void> {
  const reply = await stewardOperation(session, 'legal.firm-invite-member', {
    organizationId: session.firm.organizationId, email: email.trim().toLowerCase(),
  }, now);
  if (reply.invited !== true) throw new ConfidentialUnavailableError();
}

/** Every device registered for this organization, with profiles opened here. A
 * profile that does not open is shown as unknown; it is never trusted. */
export async function listMemberDevices(session: FirmSession, now: number): Promise<MemberDevice[]> {
  const devices: unknown[] = [], seen = new Set<string>();
  let cursor: string | undefined;
  let restarted = false;
  do {
    const reply = await memberOperation(session, 'legal.members', { organizationId: session.firm.organizationId,
      ...(cursor ? { cursor } : {}) }, now);
    if (reply.error === 'roster-changed') {
      if (!cursor || restarted) throw new ConfidentialUnavailableError();
      devices.length = 0; seen.clear(); cursor = undefined; restarted = true;
      continue;
    }
    if (!Array.isArray(reply.devices) || devices.length + reply.devices.length > 128) throw new ConfidentialUnavailableError();
    devices.push(...reply.devices);
    // Missing `next` supports older measured releases with a single-page reply.
    if (reply.next == null) break;
    if (!reply.devices.length || typeof reply.next !== 'string' || !/^[a-f0-9]{64}:[1-9][0-9]{0,2}$/.test(reply.next) ||
        seen.has(reply.next)) throw new ConfidentialUnavailableError();
    cursor = reply.next; seen.add(cursor);
  } while (true);
  const result: MemberDevice[] = [];
  const memberIds = new Set<string>();
  for (const item of devices) {
    const row = record(item);
    if (!hex(row.memberId) || !['pending', 'approved', 'removed'].includes(row.state as string) ||
        typeof row.devicePublicKey !== 'string' || typeof row.profile !== 'string' || !Number.isSafeInteger(row.revision) ||
        !Number.isSafeInteger(row.registeredAt) || !Number.isSafeInteger(row.updatedAt) || typeof row.enrolled !== 'boolean' ||
        (row.keyEpoch !== null && !Number.isSafeInteger(row.keyEpoch))) throw new ConfidentialUnavailableError();
    if (memberIds.has(row.memberId)) throw new ConfidentialUnavailableError();
    memberIds.add(row.memberId);
    let key: PublicKey;
    try { key = await readKey({ armoredKey: row.devicePublicKey }); } catch { throw new ConfidentialUnavailableError(); }
    if (key.isPrivate() || key.getFingerprint() !== row.deviceFingerprint) throw new ConfidentialUnavailableError();
    let profile: MemberProfile | null = null;
    try { profile = await openMemberProfile(row.profile, { organizationId: session.firm.organizationId, devicePublicKey: key }, session.firm.privateKey); }
    catch { profile = null; }
    result.push({ memberId: row.memberId, state: row.state as MemberDevice['state'], devicePublicKey: key,
      deviceFingerprint: key.getFingerprint(), deviceCode: formatDeviceCode(key.getFingerprint()), profile,
      keyEpoch: row.keyEpoch as number | null, revision: row.revision as number, registeredAt: row.registeredAt as number,
      updatedAt: row.updatedAt as number, enrolled: row.enrolled });
  }
  return result;
}

/** Steward: after comparing the device code with the lawyer, wrap the organization
 * key to exactly that device key and bind it to the member and key epoch. */
export async function approveMemberDevice(session: FirmSession, device: MemberDevice, keyEpoch: number, now: number): Promise<void> {
  if (device.state !== 'pending' || !Number.isSafeInteger(keyEpoch) || keyEpoch < 1) throw new FirmMemberError('conflict');
  const envelope = await wrapOrganizationKeyForMember({ organizationId: session.firm.organizationId, memberId: device.memberId,
    keyEpoch, issuedAt: now }, session.firm.privateKey, device.devicePublicKey, session.firm.privateKey);
  const reply = await stewardOperation(session, 'legal.member-approve', { organizationId: session.firm.organizationId,
    memberId: device.memberId, expectedRevision: device.revision, deviceFingerprint: device.deviceFingerprint, envelope, keyEpoch }, now);
  if (reply.state !== 'approved') throw new FirmMemberError('conflict');
}

/** Steward: remove a device (or decline a pending one). Its enrolled membership
 * stops working at once; the organization key must still be rotated. */
export async function removeMemberDevice(session: FirmSession, device: MemberDevice, now: number): Promise<void> {
  const reply = await stewardOperation(session, 'legal.member-remove', { organizationId: session.firm.organizationId,
    memberId: device.memberId, expectedRevision: device.revision }, now);
  if (reply.state !== 'removed') throw new FirmMemberError('conflict');
}

export type RotationResult = {
  next: FirmIdentity; continuity: string; statement: OrganizationKeyContinuity;
  /** Remaining approved devices that did not receive the new key; retry with `distributeRotatedKey`. */
  missed: string[];
};

/** Steward, after removing members: create the next organization key (continuity
 * signed by the old and new keys, naming the removed members) and wrap it to
 * every remaining approved device. Authenticates with the still-registered old key. */
export async function rotateOrganizationAfterRemoval(session: FirmSession, input: {
  keyEpoch: number; removedMemberIds: string[]; devices: MemberDevice[];
}, now: number): Promise<RotationResult> {
  const prepared = await prepareOrganizationRotation(session, input, now);
  const missed = await distributeRotatedKey(session, prepared, input.devices, now);
  return { ...prepared, missed };
}

/** Creates the next organization key and its continuity statement locally,
 * without sending anything. The page saves the new key file before the new key
 * reaches any device, so a failure part-way can never leave devices holding a
 * key the steward has no copy of. */
export async function prepareOrganizationRotation(session: FirmSession, input: { keyEpoch: number; removedMemberIds: string[] },
  now: number): Promise<Omit<RotationResult, 'missed'>> {
  if (!Number.isSafeInteger(input.keyEpoch) || input.keyEpoch < 1 || !input.removedMemberIds.every(hex)) throw new FirmMemberError('conflict');
  const rotated = await rotateOrganizationKey({ organizationId: session.firm.organizationId, previousKeyEpoch: input.keyEpoch,
    removedMemberIds: [...new Set(input.removedMemberIds)], issuedAt: now }, session.firm.privateKey);
  const next = { ...session.firm, privateKey: rotated.organizationKey, recipientKeyId: rotated.statement.nextRecipientKeyId };
  return { next, continuity: rotated.continuity, statement: rotated.statement };
}

/** The organization key epoch this steward's device knows: the newest of the
 * shared list's epoch and this device's own envelope epoch. */
export function knownKeyEpoch(...epochs: (number | null | undefined)[]): number {
  return Math.max(1, ...epochs.filter((value): value is number => Number.isSafeInteger(value) && (value as number) > 0));
}

/** Removed devices that held the current organization key: the removal is not
 * finished until the key is replaced. Declined requests never held a key. A
 * display aid only; the host could hide a row, so the wizard itself rotates. */
export function unfinishedRemovals(devices: MemberDevice[], keyEpoch: number): MemberDevice[] {
  return devices.filter(item => item.state === 'removed' && item.keyEpoch !== null && item.keyEpoch >= keyEpoch);
}

/** Wraps the new key to approved devices that do not have it yet, in bounded
 * batches. Returns member IDs still missing it (for a retry). */
export async function distributeRotatedKey(session: FirmSession, rotation: { next: FirmIdentity; continuity: string;
  statement: OrganizationKeyContinuity }, devices: MemberDevice[], now: number): Promise<string[]> {
  const removed = new Set(rotation.statement.removedMemberIds);
  const targets = devices.filter(item => item.state === 'approved' && !removed.has(item.memberId) &&
    (item.keyEpoch ?? 0) < rotation.statement.keyEpoch);
  const missed: string[] = [];
  for (let offset = 0; offset < targets.length; offset += 16) {
    const batch = targets.slice(offset, offset + 16);
    const envelopes = [];
    for (const item of batch) {
      envelopes.push({ memberId: item.memberId, expectedRevision: item.revision, envelope: await wrapOrganizationKeyForMember({
        organizationId: session.firm.organizationId, memberId: item.memberId, keyEpoch: rotation.statement.keyEpoch, issuedAt: now },
      rotation.next.privateKey, item.devicePublicKey, rotation.next.privateKey) });
    }
    let updated: string[] = [];
    try {
      const reply = await stewardOperation(session, 'legal.members-rotate', { organizationId: session.firm.organizationId,
        continuity: rotation.continuity, envelopes }, now);
      if (Array.isArray(reply.updated)) updated = reply.updated.filter(hex);
    } catch { /* counted as missed below */ }
    missed.push(...batch.map(item => item.memberId).filter(memberId => !updated.includes(memberId)));
  }
  return missed;
}

/** Reads a private key file line into a key object (vault payloads). */
export async function readDeviceKey(armored: string): Promise<PrivateKey> {
  const key = await readPrivateKey({ armoredKey: armored });
  if (!key.isDecrypted()) throw new Error('Invalid device key');
  return key;
}
