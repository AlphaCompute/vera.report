import { verifyDeviceMembership } from '../legal/enrollment.js';
import type { MemberEnrollment } from '../legal/enrollment.js';
import type { EnrollmentStore } from '../legal/enrollment.js';
import { verifyFirmKeyBinding } from '../confidential/firmKeyBinding.js';
import { readKey } from '../confidential/pgp.js';
import { createHash } from 'node:crypto';
import { caseRecipientKeyId } from '../confidential/caseObject.js';
import { firmMemberId, verifyOrganizationKeyContinuity } from '../confidential/firmMembers.js';
import { FIRM_SHARED_LIST_MAX, verifyFirmSharedListWrite } from '../confidential/firmSharedList.js';
import { verifyParticipantRequest } from '../confidential/participantRequest.js';
import type { LegalIdentity } from '../legal/identity.js';
import type { OrganizationContext } from './service.js';
import type { SessionChallenges } from '../session-challenges.js';

/** Firm member devices and the organization's shared request list.
 *
 * Member device keys (architecture: "Organization membership and recovery"):
 * a new lawyer signs in with the firm's identity-provider organization and
 * registers a device public key with a profile (name, contact) encrypted to the
 * organization key. A member holding the organization key (the steward) compares
 * the device code with the lawyer out of band, wraps the organization key to that
 * device in their own browser and uploads the envelope. VERA never holds the
 * organization private key or the profile plaintext. Removing a member marks the
 * device removed and deactivates its enrolled membership immediately; the steward
 * then rotates the organization key and re-wraps it to remaining devices only.
 *
 * Host rows are untrusted. The member ID is derived here from the verified login,
 * never from a request; stewards authenticate approvals with the registered
 * organization key over a single-use, channel-bound challenge; revision
 * compare-and-set stops replay of an old approval after a removal. A hostile host
 * could still substitute a device key in a pending row: that is why the steward
 * must compare the device code with the lawyer before approving, and why the
 * member device verifies every envelope against the organization key it already
 * trusts (approved organization registration, or the continuity chain after a rotation).
 */
export type FirmDeviceState = 'pending' | 'approved' | 'removed';
export type FirmDevice = {
  organizationId: string; memberId: string; providerOrganizationId: string; subject: string;
  devicePublicKey: string; deviceFingerprint: string; profile: string; state: FirmDeviceState;
  envelope: string | null; keyEpoch: number | null; continuity: string | null;
  revision: number; registeredAt: number; updatedAt: number;
};
export interface LegalFirmStore {
  submitLegalOrganizationKeyCandidate?: EnrollmentStore['submitLegalOrganizationKeyCandidate'];
  putFirmDeviceMembership?(value: { organizationId: string; providerOrganizationId: string; subject: string;
    recipientKeyId: string; enrollment: MemberEnrollment }, now: number): Promise<boolean>;
  inviteLegalOrganizationMember?(value: { organizationId: string; providerOrganizationId: string; domain: string; email: string }, now: number): Promise<{ invited: true }>;
  listFirmDevices(organizationId: string): Promise<FirmDevice[]>;
  getFirmDevice(organizationId: string, memberId: string): Promise<FirmDevice | null>;
  /** Insert when `expectedRevision` is 0; otherwise replace only the row at that revision. */
  putFirmDevice(device: FirmDevice, expectedRevision: number): Promise<boolean>;
  /** Atomically retire this device and its membership/invitations before key rotation. */
  removeFirmDevice(device: FirmDevice, expectedRevision: number): Promise<boolean>;
  getFirmSharedList(organizationId: string): Promise<{ version: number; record: string } | null>;
  /** Compare-and-set on version; `expectedVersion` 0 inserts the first version. */
  putFirmSharedList(organizationId: string, expectedVersion: number, next: { version: number; record: string }): Promise<boolean>;
  /** Organization-key-signed setup statements (`firmSetup.ts`) kept with the
   * organization row; `legalSetup.ts` verifies them on every read. */
  getOrganizationSetup(organizationId: string): Promise<{ custody: string | null; terms: string | null } | null>;
  /** Replaces one statement on a live (approved, not revoked) organization row. */
  putOrganizationSetup(organizationId: string, kind: 'custody' | 'terms', statement: string): Promise<boolean>;
}
type Principal = { context: OrganizationContext; identity: LegalIdentity; recheck(): Promise<void> };
type Dependencies = {
  store: LegalFirmStore;
  now(): number;
  audience: string;
  verify(accessToken: string, scope: 'legal:enroll'): Promise<LegalIdentity>;
  /** Approved, onboarding-signed organization bound to this identity-provider organization. */
  organization(organizationId: string, providerOrganizationId: string): Promise<OrganizationContext>;
  approvedDomain?(organizationId: string, providerOrganizationId: string): Promise<string>;
  principal(accessToken: unknown, scope: 'legal:case'): Promise<Principal>;
  /** Current enrollment of a member (display hint only; authorization never relies on it). */
  enrolled(subject: string, providerOrganizationId: string, recipientKeyId: string): Promise<boolean>;
};
/** The attested channel session a firm operation arrives on. `challenges` is that
 * session's enclave-memory ledger (see session-challenges.ts): a steward proof is
 * accepted only over a challenge issued in this same session and not yet used. */
export type LegalFirmChannel = { nonce: string; serverKeyId: string; challenges: SessionChallenges };
export const FIRM_DEVICE_LIMIT = 64;
const ROTATION_BATCH = 16;
const ID = /^[a-f0-9]{64}$/, FINGERPRINT = /^[a-f0-9]{40,64}$/;
const OPERATIONS = ['legal.device-enroll', 'legal.device-register', 'legal.device-status', 'legal.members', 'legal.member-approve',
  'legal.member-remove', 'legal.members-rotate', 'legal.firm-invite-member', 'legal.replace-organization-key', 'legal.firm-list-read', 'legal.firm-list-write'] as const;
function denied(): never { throw new Error('Legal organization operation unavailable'); }
function object(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) denied();
  const keys = Object.keys(value as object);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) denied();
  return value as Record<string, unknown>;
}
function id(value: unknown): string { if (typeof value !== 'string' || !ID.test(value)) denied(); return value as string; }
function revision(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) denied();
  return value as number;
}
function armoredMessage(value: unknown, max: number): string {
  if (typeof value !== 'string' || value.length > max || !value.startsWith('-----BEGIN PGP MESSAGE-----')) denied();
  return value as string;
}
function decodeBody(body: unknown, max: number): Record<string, unknown> {
  if (typeof body !== 'string' || body.length > Math.ceil(max / 3) * 4) denied();
  const bytes = Buffer.from(body as string, 'base64');
  if (bytes.length > max || bytes.toString('base64') !== body) denied();
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!value || typeof value !== 'object' || Array.isArray(value)) denied();
  return value as Record<string, unknown>;
}

/** Re-validates an untrusted host row against the organization and the member ID
 * the enclave derives from the stored subject. */
async function trustedDevice(row: unknown, organizationId: string, providerOrganizationId: string, fingerprints: Map<string, string>): Promise<FirmDevice> {
  const value = object(row, ['organizationId', 'memberId', 'providerOrganizationId', 'subject', 'devicePublicKey',
    'deviceFingerprint', 'profile', 'state', 'envelope', 'keyEpoch', 'continuity', 'revision', 'registeredAt', 'updatedAt']);
  if (value.organizationId !== organizationId || value.providerOrganizationId !== providerOrganizationId ||
      typeof value.subject !== 'string' || id(value.memberId) !== await firmMemberId(providerOrganizationId, value.subject) ||
      typeof value.devicePublicKey !== 'string' || value.devicePublicKey.length > 16_384 ||
      typeof value.deviceFingerprint !== 'string' || !FINGERPRINT.test(value.deviceFingerprint) ||
      !['pending', 'approved', 'removed'].includes(value.state as string) ||
      !Number.isSafeInteger(value.registeredAt) || !Number.isSafeInteger(value.updatedAt)) denied();
  revision(value.revision);
  armoredMessage(value.profile, 8192);
  const armored = value.devicePublicKey as string;
  let fingerprint = fingerprints.get(armored);
  if (fingerprint === undefined) {
    const key = await readKey({ armoredKey: armored });
    if (key.isPrivate()) denied();
    fingerprint = key.getFingerprint();
    if (fingerprints.size >= FIRM_DEVICE_LIMIT * 2) fingerprints.delete(fingerprints.keys().next().value!);
    fingerprints.set(armored, fingerprint);
  }
  if (fingerprint !== value.deviceFingerprint) denied();
  if (value.state === 'approved') {
    armoredMessage(value.envelope, 96 * 1024); revision(value.keyEpoch);
    if (value.continuity !== null && (typeof value.continuity !== 'string' || value.continuity.length > 64 * 1024)) denied();
  } else if (value.envelope !== null || value.continuity !== null) denied();
  // A removed device keeps the key epoch it last held (null if it never held
  // one, e.g. a declined request) so stewards can see a removal still needs a
  // rotation. It is a display hint: nothing authorizes on it.
  else if (value.state === 'pending' && value.keyEpoch !== null) denied();
  else if (value.keyEpoch !== null) revision(value.keyEpoch);
  return { ...value } as FirmDevice;
}

export function isLegalFirmOperation(operation: unknown): boolean {
  return typeof operation === 'string' && (OPERATIONS as readonly string[]).includes(operation);
}

export function createLegalFirmOperations(deps: Dependencies) {
  const { store } = deps;
  // Public key parsing is deterministic for these exact bytes. Bound the cache
  // so paginated rosters do not parse every unchanged key on every page. No
  // membership, approval, revision, or private material is cached.
  const fingerprints = new Map<string, string>();
  async function devices(context: OrganizationContext, providerOrganizationId: string): Promise<FirmDevice[]> {
    const rows = await store.listFirmDevices(context.organizationId);
    if (!Array.isArray(rows) || rows.length > FIRM_DEVICE_LIMIT * 2) denied();
    const seen = new Set<string>(), result: FirmDevice[] = [];
    for (const row of rows) {
      const device = await trustedDevice(row, context.organizationId, providerOrganizationId, fingerprints);
      if (seen.has(device.memberId)) denied();
      seen.add(device.memberId); result.push(device);
    }
    return result;
  }
  async function device(context: OrganizationContext, providerOrganizationId: string, memberId: string): Promise<FirmDevice | null> {
    const row = await store.getFirmDevice(context.organizationId, memberId);
    if (!row) return null;
    const found = await trustedDevice(row, context.organizationId, providerOrganizationId, fingerprints);
    if (found.memberId !== memberId) denied();
    return found;
  }
  /** Key possession by the registered organization key, bound to this channel
   * session and a single-use challenge; the organization ID takes the case slot. */
  async function stewardProof(raw: Uint8Array, proof: unknown, context: OrganizationContext, channel: LegalFirmChannel) {
    if (typeof proof !== 'string' || proof.length > 20_000) denied();
    let challenge: string;
    try {
      challenge = id(JSON.parse(proof as string)?.request?.challenge);
      await verifyParticipantRequest(proof as string, { audience: deps.audience, role: 'organization', caseId: context.organizationId,
        organizationId: context.organizationId, operation: 'manage-members', body: raw, challenge, now: deps.now(),
        nonce: channel.nonce, serverKeyId: channel.serverKeyId },
      await readKey({ armoredKey: context.publicKey }));
    } catch { return denied(); }
    // Consume only after the signature verifies, so an attacker cannot burn challenges.
    // Single use is enforced in enclave memory; the host store never holds challenges.
    if (!channel.challenges || typeof channel.challenges.consume !== 'function' ||
        !channel.challenges.consume(challenge, deps.now())) denied();
  }
  function status(found: FirmDevice | null, memberId: string) {
    if (!found) return { memberId, state: 'none' as const };
    return { memberId, state: found.state, deviceFingerprint: found.deviceFingerprint, envelope: found.envelope,
      keyEpoch: found.keyEpoch, continuity: found.continuity };
  }
  async function providerFor(accessToken: unknown): Promise<LegalIdentity> {
    if (typeof accessToken !== 'string') denied();
    return deps.verify(accessToken as string, 'legal:enroll');
  }

  return async function run(request: Record<string, unknown>, channel: LegalFirmChannel): Promise<{
    result: unknown; replyLimit: number;
  }> {
    const operation = request.operation as typeof OPERATIONS[number];
    const withProof = operation === 'legal.replace-organization-key' || operation === 'legal.firm-invite-member' || operation === 'legal.member-approve' || operation === 'legal.member-remove' || operation === 'legal.members-rotate';
    object(request, withProof ? ['operation', 'accessToken', 'body', 'proof'] : ['operation', 'accessToken', 'body']);
    const limit = operation === 'legal.firm-list-write' ? FIRM_SHARED_LIST_MAX + 1024
      : operation === 'legal.members-rotate' || operation === 'legal.replace-organization-key' ? 96 * 1024 : 32 * 1024;
    const body = decodeBody(request.body, limit);
    const raw = new Uint8Array(Buffer.from(request.body as string, 'base64'));

    if (operation === 'legal.device-enroll') {
      const actor = await providerFor(request.accessToken);
      const input = object(body, ['organizationId', 'enrollment']);
      const context = await deps.organization(id(input.organizationId), actor.providerOrganizationId);
      const memberId = await firmMemberId(actor.providerOrganizationId, actor.subject);
      const found = await device(context, actor.providerOrganizationId, memberId);
      if (!found || found.subject !== actor.subject || !store.putFirmDeviceMembership) denied();
      const enrollment = input.enrollment as MemberEnrollment;
      await verifyDeviceMembership(enrollment, await readKey({ armoredKey: context.publicKey }), found!, deps.now());
      if (actor.expiresAt <= deps.now()) denied();
      if (!await store.putFirmDeviceMembership!({ organizationId: context.organizationId, providerOrganizationId: actor.providerOrganizationId,
        subject: actor.subject, recipientKeyId: context.recipientKeyId, enrollment }, deps.now())) denied();
      return { result: { enrolled: true, expiresAt: enrollment.challenge.expiresAt }, replyLimit: 4096 };
    }

    if (operation === 'legal.device-register' || operation === 'legal.device-status') {
      // Not yet enrolled: the verified login and its identity-provider organization
      // must match an approved, onboarding-signed organization.
      const actor = await providerFor(request.accessToken);
      const input = object(body, operation === 'legal.device-register' ? ['organizationId', 'devicePublicKey', 'profile'] : ['organizationId']);
      const context = await deps.organization(id(input.organizationId), actor.providerOrganizationId);
      const memberId = await firmMemberId(actor.providerOrganizationId, actor.subject);
      const existing = await device(context, actor.providerOrganizationId, memberId);
      if (existing && existing.subject !== actor.subject) denied();
      if (operation === 'legal.device-status') {
        if (actor.expiresAt <= deps.now()) denied();
        return { result: status(existing, memberId), replyLimit: 128 * 1024 };
      }
      if (typeof input.devicePublicKey !== 'string' || input.devicePublicKey.length > 16_384) denied();
      const key = await readKey({ armoredKey: input.devicePublicKey as string });
      if (key.isPrivate() || await caseRecipientKeyId(key) === context.recipientKeyId) denied();
      await key.getEncryptionKey(); await key.getSigningKey();
      const fingerprint = key.getFingerprint(), profile = armoredMessage(input.profile, 8192);
      if (existing && existing.state !== 'removed' && existing.deviceFingerprint === fingerprint) {
        return { result: status(existing, memberId), replyLimit: 128 * 1024 };
      }
      const all = await devices(context, actor.providerOrganizationId);
      if (all.filter(item => item.state !== 'removed' && item.memberId !== memberId).length >= FIRM_DEVICE_LIMIT) {
        return { result: { error: 'limit' }, replyLimit: 4096 };
      }
      const time = deps.now();
      const next: FirmDevice = { organizationId: context.organizationId, memberId, providerOrganizationId: actor.providerOrganizationId,
        subject: actor.subject, devicePublicKey: key.armor(), deviceFingerprint: fingerprint, profile, state: 'pending',
        envelope: null, keyEpoch: null, continuity: null, revision: (existing?.revision ?? 0) + 1,
        registeredAt: time, updatedAt: time };
      if (!await store.putFirmDevice(next, existing?.revision ?? 0)) return { result: { error: 'conflict' }, replyLimit: 4096 };
      if (actor.expiresAt <= deps.now()) denied();
      return { result: status(next, memberId), replyLimit: 4096 };
    }

    // Enrolled members holding the registered organization key.
    const actor = await deps.principal(request.accessToken, 'legal:case');
    const context = actor.context;
    const provider = actor.identity.providerOrganizationId;
    let result: unknown, replyLimit = 4096;
    if (operation === 'legal.replace-organization-key') {
      const input = object(body, ['organizationId', 'bindingDocument', 'continuity']);
      if (id(input.organizationId) !== context.organizationId || typeof input.bindingDocument !== 'string' ||
          input.bindingDocument.length > 65_536 || typeof input.continuity !== 'string' ||
          !deps.approvedDomain || !store.submitLegalOrganizationKeyCandidate) denied();
      const domain = await deps.approvedDomain!(context.organizationId, provider);
      const candidate = await verifyFirmKeyBinding(input.bindingDocument as string, { organizationId: context.organizationId, domain });
      if (candidate.binding.recipientKeyId === context.recipientKeyId) denied();
      // The continuity statement is a durable signature by the registered key over
      // the new one. The enclave verifies it again before registering the key, so a
      // candidate row planted in the host database cannot become a registration.
      const continuity = await verifyOrganizationKeyContinuity(input.continuity as string, { organizationId: context.organizationId,
        previousPublicKey: await readKey({ armoredKey: context.publicKey }) });
      if (continuity.statement.nextRecipientKeyId !== candidate.binding.recipientKeyId ||
          continuity.nextPublicKey.getFingerprint() !== candidate.publicKey.getFingerprint()) denied();
      await stewardProof(raw, request.proof, context, channel);
      await actor.recheck();
      await store.submitLegalOrganizationKeyCandidate!({ organizationId: context.organizationId, providerOrganizationId: provider,
        domain, bindingDocument: input.bindingDocument as string, subject: actor.identity.subject,
        recipientKeyId: candidate.binding.recipientKeyId, previousRecipientKeyId: context.recipientKeyId,
        continuity: input.continuity as string }, deps.now());
      result = { submitted: true, recipientKeyId: candidate.binding.recipientKeyId };
    } else if (operation === 'legal.firm-invite-member') {
      const input = object(body, ['organizationId', 'email']);
      if (id(input.organizationId) !== context.organizationId || typeof input.email !== 'string' || input.email.length > 254 ||
          !/^[^@\s]+@[^@\s]+$/.test(input.email) || !deps.approvedDomain || !store.inviteLegalOrganizationMember) denied();
      const email = (input.email as string).toLowerCase();
      const domain = await deps.approvedDomain!(context.organizationId, provider);
      if (email.slice(email.lastIndexOf('@') + 1) !== domain) denied();
      await stewardProof(raw, request.proof, context, channel);
      await actor.recheck();
      result = await store.inviteLegalOrganizationMember!({ organizationId: context.organizationId,
        providerOrganizationId: provider, domain, email }, deps.now());
    } else if (operation === 'legal.firm-list-read' || operation === 'legal.firm-list-write') {
      const input = object(body, operation === 'legal.firm-list-read' ? ['organizationId'] : ['organizationId', 'record']);
      if (id(input.organizationId) !== context.organizationId) denied();
      if (operation === 'legal.firm-list-read') {
        const stored = await store.getFirmSharedList(context.organizationId);
        if (stored && (!Number.isSafeInteger(stored.version) || stored.version < 1 || typeof stored.record !== 'string' ||
            stored.record.length > FIRM_SHARED_LIST_MAX)) denied();
        result = { record: stored?.record ?? null, version: stored?.version ?? 0 };
        replyLimit = FIRM_SHARED_LIST_MAX + 1024;
      } else {
        const header = await verifyFirmSharedListWrite(input.record, context);
        const stored = await store.getFirmSharedList(context.organizationId);
        const current = stored?.version ?? 0;
        if (!Number.isSafeInteger(current) || current < 0) denied();
        result = header.version === current + 1 &&
          await store.putFirmSharedList(context.organizationId, current, { version: header.version, record: input.record as string })
          ? { version: header.version } : { error: 'conflict', version: current };
      }
    } else {
      const all = await devices(context, provider);
      if (operation === 'legal.members') {
        const input = object(body, 'cursor' in body ? ['organizationId', 'cursor'] : ['organizationId']);
        if (id(input.organizationId) !== context.organizationId) denied();
        all.sort((a, b) => a.registeredAt - b.registeredAt || a.memberId.localeCompare(b.memberId));
        // Every device mutation increments its revision. Hash compact version
        // metadata, not up to 24 MiB of profiles, envelopes and continuity data.
        // This detects concurrent roster changes; it is not an authenticity proof.
        const snapshot = createHash('sha256').update(JSON.stringify(all.map(item =>
          [item.memberId, item.revision, item.registeredAt, item.updatedAt, item.state, item.keyEpoch]))).digest('hex');
        let offset = 0;
        if ('cursor' in input) {
          if (typeof input.cursor !== 'string' || !/^[a-f0-9]{64}:[1-9][0-9]{0,2}$/.test(input.cursor)) denied();
          const [digest, index] = (input.cursor as string).split(':');
          offset = Number(index);
          // The browser discards partial rows and retries this read once.
          if (digest !== snapshot) return { result: { error: 'roster-changed' }, replyLimit: 4096 };
          if (offset >= all.length) denied();
        }
        const rows = [];
        let bytes = 0;
        for (const item of all.slice(offset)) {
          const row = { memberId: item.memberId, devicePublicKey: item.devicePublicKey, deviceFingerprint: item.deviceFingerprint,
            profile: item.profile, state: item.state, keyEpoch: item.keyEpoch, revision: item.revision,
            registeredAt: item.registeredAt, updatedAt: item.updatedAt,
            enrolled: item.state === 'removed' ? false : await deps.enrolled(item.subject, provider, context.recipientKeyId) };
          const size = Buffer.byteLength(JSON.stringify(row), 'utf8') + 1;
          // Leave room for the wrapper/cursor within the existing reply limit.
          // Measure encoded bytes: untrusted profile text can require escaping.
          if (bytes + size > 180 * 1024) break;
          rows.push(row); bytes += size;
        }
        if (!rows.length && offset < all.length) denied();
        const next = offset + rows.length;
        result = { devices: rows, next: next < all.length ? `${snapshot}:${next}` : null };
        replyLimit = 200 * 1024;
      } else if (operation === 'legal.member-approve') {
        const input = object(body, ['organizationId', 'memberId', 'expectedRevision', 'deviceFingerprint', 'envelope', 'keyEpoch']);
        if (id(input.organizationId) !== context.organizationId) denied();
        await stewardProof(raw, request.proof, context, channel);
        const found = all.find(item => item.memberId === id(input.memberId));
        if (!found || found.state !== 'pending' || found.revision !== revision(input.expectedRevision) ||
            found.deviceFingerprint !== input.deviceFingerprint) return { result: { error: 'conflict' }, replyLimit };
        const next = { ...found, state: 'approved' as const, envelope: armoredMessage(input.envelope, 96 * 1024),
          keyEpoch: revision(input.keyEpoch), continuity: null, revision: found.revision + 1, updatedAt: deps.now() };
        result = await store.putFirmDevice(next, found.revision) ? { state: 'approved', revision: next.revision } : { error: 'conflict' };
      } else if (operation === 'legal.member-remove') {
        const input = object(body, ['organizationId', 'memberId', 'expectedRevision']);
        if (id(input.organizationId) !== context.organizationId) denied();
        await stewardProof(raw, request.proof, context, channel);
        const found = all.find(item => item.memberId === id(input.memberId));
        if (!found || found.state === 'removed' || found.revision !== revision(input.expectedRevision)) {
          return { result: { error: 'conflict' }, replyLimit };
        }
        const next = { ...found, state: 'removed' as const, envelope: null, keyEpoch: found.state === 'approved' ? found.keyEpoch : null, continuity: null,
          revision: found.revision + 1, updatedAt: deps.now() };
        if (!await store.removeFirmDevice(next, found.revision)) return { result: { error: 'conflict' }, replyLimit };
        result = { state: 'removed', revision: next.revision };
      } else {
        // legal.members-rotate: distribute the NEW organization key to remaining devices.
        const input = object(body, ['organizationId', 'continuity', 'envelopes']);
        if (id(input.organizationId) !== context.organizationId || typeof input.continuity !== 'string' ||
            !Array.isArray(input.envelopes) || !input.envelopes.length || input.envelopes.length > ROTATION_BATCH) denied();
        await stewardProof(raw, request.proof, context, channel);
        // Continuity must start at the key registered for this organization now.
        const { statement } = await verifyOrganizationKeyContinuity(input.continuity as string,
          { organizationId: context.organizationId, previousPublicKey: await readKey({ armoredKey: context.publicKey }) });
        if (statement.previousRecipientKeyId !== context.recipientKeyId) denied();
        const removed = new Set(statement.removedMemberIds), updated: string[] = [];
        if (all.some(item => removed.has(item.memberId) && item.state !== 'removed')) denied();
        const seen = new Set<string>();
        for (const entry of input.envelopes as unknown[]) {
          const item = object(entry, ['memberId', 'expectedRevision', 'envelope']);
          const memberId = id(item.memberId);
          if (seen.has(memberId) || removed.has(memberId)) denied();
          seen.add(memberId);
          const found = all.find(value => value.memberId === memberId);
          if (!found || found.state !== 'approved' || found.revision !== revision(item.expectedRevision) ||
              (found.keyEpoch ?? 0) >= statement.keyEpoch) continue;
          const next = { ...found, envelope: armoredMessage(item.envelope, 96 * 1024), keyEpoch: statement.keyEpoch,
            continuity: input.continuity as string, revision: found.revision + 1, updatedAt: deps.now() };
          if (await store.putFirmDevice(next, found.revision)) updated.push(memberId);
        }
        result = { updated };
        replyLimit = 8192;
      }
    }
    await actor.recheck();
    return { result, replyLimit };
  };
}
