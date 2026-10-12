import { readKey, readPrivateKey } from '../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../enclave/src/confidential/caseObject';
import type { CheckpointPin } from '../../enclave/src/confidential/recovery';
import type { OwnerTrust } from '../../enclave/src/confidential/authorization';
import type { FirmSession, PinnedReleases } from './firmCase';
import type { FirmIdentity } from './firmKey';
import { validFirmDomain, validOrganizationId } from './firmKey';
import { parseRequestDetails } from '../../enclave/src/confidential/accessRequest';

/** The organization's own profile, sent (signed and encrypted to the reporter)
 * with each access request. Kept in the encrypted workspace only. */
export type FirmProfile = { practiceAreas: string[]; jurisdiction: string; website: string | null };
export const EMPTY_FIRM_PROFILE: FirmProfile = { practiceAreas: [], jurisdiction: '', website: null };
/** Throws unless the profile is exactly what a request may carry. */
export function validFirmProfile(value: unknown): FirmProfile {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'jurisdiction,practiceAreas,website') invalid();
  const input = value as FirmProfile;
  const parsed = parseRequestDetails({ kind: 'new', conflictsChecked: false, feeBasis: 'to-discuss', responseTime: 'one-week',
    practiceAreas: input.practiceAreas, jurisdiction: input.jurisdiction, website: input.website });
  return { practiceAreas: parsed.practiceAreas, jurisdiction: parsed.jurisdiction, website: parsed.website };
}

export type RememberedRequest = { caseId: string; requestId: string; ownerPublicKey: string; summary: string; requestedAt: number };
/** This device's member key (absent when the organization key file is used directly). */
export type FirmWorkspaceDevice = { memberId: string; privateKey: string; keyEpoch: number };
export type FirmWorkspace = {
  format: 'vera-legal-workspace/v1'; organizationId: string; domain: string; recipientKeyId: string; privateKey: string;
  requests: RememberedRequest[]; owners: { caseId: string; ownerPublicKey: string }[];
  /** `releaseDigests`: the release approvals listed in that pinned checkpoint
   * (absent in workspaces saved before they were kept). */
  pins: (CheckpointPin & { releaseDigests?: string[] })[]; sequences: { caseId: string; owner: number; organization: number }[];
  /** Absent in workspaces saved before organization profiles existed. */
  profile?: FirmProfile;
  /** Added with member devices; older backups omit both. */
  device?: FirmWorkspaceDevice | null;
  /** Newest shared request list version this device has seen (rollback pin). */
  sharedListVersion?: number;
};
/** A device waiting for a steward's approval: it holds only its own key. */
export type PendingDeviceWorkspace = {
  format: 'vera-legal-device/v1'; organizationId: string; domain: string; memberId: string; privateKey: string; registeredAt: number;
};
export function isPendingDeviceWorkspace(value: unknown): value is PendingDeviceWorkspace {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as PendingDeviceWorkspace;
  return Object.keys(item).sort().join(',') === 'domain,format,memberId,organizationId,privateKey,registeredAt' &&
    item.format === 'vera-legal-device/v1' && validOrganizationId(item.organizationId) && validFirmDomain(item.domain) &&
    hex(item.memberId) && typeof item.privateKey === 'string' && item.privateKey.length <= 65536 && positive(item.registeredAt);
}
const hex = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const positive = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
function invalid(): never { throw new Error('This organization workspace backup is invalid'); }
export function validRequest(value: unknown): value is RememberedRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as RememberedRequest;
  return Object.keys(item).sort().join(',') === 'caseId,ownerPublicKey,requestId,requestedAt,summary' &&
    hex(item.caseId) && hex(item.requestId) && typeof item.ownerPublicKey === 'string' && item.ownerPublicKey.length <= 65536 &&
    typeof item.summary === 'string' && item.summary.length <= 10000 && positive(item.requestedAt);
}
export const FIRM_WORKSPACE_CASE_LIMIT = 200;
/** Retain all authenticated anchors. Withdrawing a request does not free its
 * freshness pin, so capacity counts historical case anchors too. */
export function assertFirmWorkspaceCapacity(session: Pick<FirmSession, 'owners' | 'pins' | 'sequences'>,
  requests: readonly RememberedRequest[] = [], newCaseId?: string): void {
  const cases = new Set([...session.owners.keys(), ...session.pins.keys(), ...session.sequences.keys(),
    ...requests.map(request => request.caseId), ...(newCaseId ? [newCaseId] : [])]);
  if (cases.size > FIRM_WORKSPACE_CASE_LIMIT || requests.length > FIRM_WORKSPACE_CASE_LIMIT) {
    throw new Error('This workspace has reached its saved-case limit. Keep its backup and use a separate workspace for new cases.');
  }
}
export function firmWorkspace(session: FirmSession, requests: RememberedRequest[],
  extras: { device?: FirmWorkspaceDevice | null; sharedListVersion?: number; profile?: FirmProfile | null } = {}): FirmWorkspace {
  const profile = extras.profile;
  assertFirmWorkspaceCapacity(session, requests);
  return { format: 'vera-legal-workspace/v1', organizationId: session.firm.organizationId, domain: session.firm.domain,
    device: extras.device ? { ...extras.device } : null, sharedListVersion: extras.sharedListVersion ?? 0,
    recipientKeyId: session.firm.recipientKeyId, privateKey: session.firm.privateKey.armor(),
    requests: requests.map(item => ({ ...item })),
    owners: [...session.owners.values()].map(owner => ({ caseId: owner.caseId, ownerPublicKey: owner.ownerPublicKey.armor() })),
    pins: [...session.pins.values()].map(pin => {
      const releases = session.pinReleases?.get(pin.caseId);
      return releases && releases.digest === pin.digest ? { ...pin, releaseDigests: [...releases.releaseDigests] } : { ...pin };
    }),
    sequences: [...session.sequences].map(([caseId, floors]) => ({ caseId, ...floors })),
    ...(profile ? { profile: validFirmProfile(profile) } : {}) };
}
/** Validate the encrypted payload again before restoring any private authority.
 * Saved pins establish a device's prior observation, never global freshness. */
export async function readFirmWorkspace(value: unknown): Promise<{
  firm: FirmIdentity; requests: RememberedRequest[]; owners: Map<string, OwnerTrust>;
  pins: Map<string, CheckpointPin>; pinReleases: Map<string, PinnedReleases>;
  sequences: Map<string, { owner: number; organization: number }>;
  profile: FirmProfile | null;
  device: { memberId: string; privateKey: PrivateKey; keyEpoch: number } | null; sharedListVersion: number;
}> {
  const fields = value && typeof value === 'object' && !Array.isArray(value) ? Object.keys(value).sort().join(',') : '';
  // Older backups omit the organization profile and/or the member device fields.
  const base = 'domain,format,organizationId,owners,pins,privateKey,recipientKeyId,requests,sequences';
  const withDevice = 'device,domain,format,organizationId,owners,pins,privateKey,recipientKeyId,requests,sequences,sharedListVersion';
  const withProfile = 'domain,format,organizationId,owners,pins,privateKey,profile,recipientKeyId,requests,sequences';
  const withBoth = 'device,domain,format,organizationId,owners,pins,privateKey,profile,recipientKeyId,requests,sequences,sharedListVersion';
  if (fields !== base && fields !== withDevice && fields !== withProfile && fields !== withBoth) invalid();
  const item = value as FirmWorkspace;
  let device: { memberId: string; privateKey: PrivateKey; keyEpoch: number } | null = null;
  const sharedListVersion = item.sharedListVersion ?? 0;
  if (!Number.isSafeInteger(sharedListVersion) || sharedListVersion < 0) invalid();
  if (item.device !== undefined && item.device !== null) {
    const entry = item.device;
    if (typeof entry !== 'object' || Object.keys(entry).sort().join(',') !== 'keyEpoch,memberId,privateKey' ||
        !hex(entry.memberId) || !positive(entry.keyEpoch) || typeof entry.privateKey !== 'string' || entry.privateKey.length > 65536) invalid();
    const key = await readPrivateKey({ armoredKey: entry.privateKey });
    if (!key.isDecrypted()) invalid();
    device = { memberId: entry.memberId, privateKey: key, keyEpoch: entry.keyEpoch };
  }
  if (item.format !== 'vera-legal-workspace/v1' || !validOrganizationId(item.organizationId) || !validFirmDomain(item.domain) ||
      !hex(item.recipientKeyId) || typeof item.privateKey !== 'string' || item.privateKey.length > 65536) invalid();
  for (const list of [item.requests, item.owners, item.pins, item.sequences]) if (!Array.isArray(list) || list.length > FIRM_WORKSPACE_CASE_LIMIT) invalid();
  if (!item.requests.every(validRequest) || new Set(item.requests.map(request => request.caseId)).size !== item.requests.length) invalid();
  const privateKey = await readPrivateKey({ armoredKey: item.privateKey });
  if (!privateKey.isDecrypted() || await caseRecipientKeyId(privateKey.toPublic()) !== item.recipientKeyId) invalid();
  const owners = new Map<string, OwnerTrust>();
  for (const entry of item.owners) {
    if (!entry || Object.keys(entry).sort().join(',') !== 'caseId,ownerPublicKey' || !hex(entry.caseId) ||
        typeof entry.ownerPublicKey !== 'string' || entry.ownerPublicKey.length > 65536 || owners.has(entry.caseId)) invalid();
    const key = await readKey({ armoredKey: entry.ownerPublicKey });
    if (key.isPrivate()) invalid();
    owners.set(entry.caseId, { caseId: entry.caseId, ownerFingerprint: key.getFingerprint(), ownerPublicKey: key });
  }
  for (const request of item.requests) {
    const key = await readKey({ armoredKey: request.ownerPublicKey });
    const prior = owners.get(request.caseId);
    if (key.isPrivate() || (prior && prior.ownerFingerprint !== key.getFingerprint())) invalid();
    owners.set(request.caseId, { caseId: request.caseId, ownerFingerprint: key.getFingerprint(), ownerPublicKey: key });
  }
  const pins = new Map<string, CheckpointPin>(), pinReleases = new Map<string, PinnedReleases>();
  for (const pin of item.pins) {
    const keys = pin && typeof pin === 'object' ? Object.keys(pin).sort().join(',') : '';
    if (!pin || (keys !== 'caseId,digest,keyEpoch,ownerFingerprint,revision' &&
        keys !== 'caseId,digest,keyEpoch,ownerFingerprint,releaseDigests,revision') ||
        !hex(pin.caseId) || !hex(pin.digest) || !positive(pin.revision) || !positive(pin.keyEpoch) ||
        !owners.has(pin.caseId) || owners.get(pin.caseId)!.ownerFingerprint !== pin.ownerFingerprint || pins.has(pin.caseId)) invalid();
    const { releaseDigests, ...checkpoint } = pin;
    if (releaseDigests !== undefined) {
      // A checkpoint lists at most 32 distinct release approvals.
      if (!Array.isArray(releaseDigests) || releaseDigests.length > 32 || !releaseDigests.every(hex) ||
          new Set(releaseDigests).size !== releaseDigests.length) invalid();
      pinReleases.set(pin.caseId, { digest: pin.digest, releaseDigests: [...releaseDigests] });
    }
    pins.set(pin.caseId, checkpoint);
  }
  const sequences = new Map<string, { owner: number; organization: number }>();
  for (const entry of item.sequences) {
    if (!entry || Object.keys(entry).sort().join(',') !== 'caseId,organization,owner' || !owners.has(entry.caseId) || sequences.has(entry.caseId) ||
        !Number.isSafeInteger(entry.owner) || entry.owner < 0 || !Number.isSafeInteger(entry.organization) || entry.organization < 0) invalid();
    sequences.set(entry.caseId, { owner: entry.owner, organization: entry.organization });
  }
  assertFirmWorkspaceCapacity({ owners, pins, sequences }, item.requests);
  let profile: FirmProfile | null = null;
  if (item.profile !== undefined) {
    try { profile = validFirmProfile(item.profile); } catch { invalid(); }
  }
  if (device && device.privateKey.getFingerprint() === privateKey.getFingerprint()) invalid();
  return { firm: { organizationId: item.organizationId, domain: item.domain, recipientKeyId: item.recipientKeyId, privateKey },
    requests: item.requests.map(request => ({ ...request })), owners, pins, pinReleases, sequences, profile, device, sharedListVersion };
}
