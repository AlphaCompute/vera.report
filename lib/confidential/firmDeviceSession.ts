import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import type { FirmSession } from './firmCase';
import type { FirmIdentity } from './firmKey';
import type { UnlockedVault } from './deviceVault';
import { isPendingDeviceWorkspace, readFirmWorkspace } from './firmWorkspace';
import type { PendingDeviceWorkspace } from './firmWorkspace';
import {
  FirmMemberError, approveMemberDevice, createMemberDeviceKey, enrollApprovedMemberDevice, firmIdentityFromKey,
  listMemberDevices, knownKeyEpoch, registerMemberDevice, openApprovedDevice, publishedOrganizationKey, readDeviceKey, readMemberDeviceStatus,
} from './firmMemberDevices';
import type { DeviceStatus } from './firmMemberDevices';
import { currentFirmDevice, currentFirmVault, restoreFirmDevice, restoreFirmRequests, setFirmDevice, setFirmVault, persistFirmWorkspace } from './firmPortal';

/** Opening a saved legal workspace on this device, including member devices:
 * a device still waiting for approval, a device whose approval has arrived, and
 * a member device whose organization rotated its key since the last visit. */
export class PendingDeviceError extends Error {
  constructor(readonly pending: PendingDeviceWorkspace, readonly status: DeviceStatus | null) {
    super(status?.state === 'removed'
      ? 'This device was removed from your organization. Ask your steward if that is unexpected.'
      : 'This device is still waiting for your organization to approve it.');
    this.name = 'PendingDeviceError';
  }
}
export type OpenedLegalWorkspace = { session: FirmSession; notice: string | null };
type Dependencies = {
  relay: import('./client').ChannelRelay; releaseManifest: string; accessToken: () => Promise<string>;
  start: (firm: FirmIdentity, signal?: AbortSignal) => Promise<FirmSession>;
  published?: (target: { organizationId: string; domain: string }) => Promise<import('../../enclave/src/confidential/pgp').PublicKey>;
};

async function readStatus(deps: Dependencies, organizationId: string): Promise<DeviceStatus> {
  return readMemberDeviceStatus({ relay: deps.relay, releaseManifest: deps.releaseManifest,
    accessToken: await deps.accessToken(), now: Date.now(), organizationId });
}
/** Best effort, for a workspace that already holds the organization key: a failed
 * check only postpones the rotation check to the next visit. */
async function optionalStatus(deps: Dependencies, organizationId: string): Promise<DeviceStatus | null> {
  try { return await readStatus(deps, organizationId); } catch { return null; }
}
const published = (deps: Dependencies, target: { organizationId: string; domain: string }) =>
  async () => deps.published ? deps.published(target) : publishedOrganizationKey(target, {
    relay: deps.relay, releaseManifest: deps.releaseManifest, accessToken: await deps.accessToken(), now: Date.now(),
  });

/** A pending device whose approval arrived: open its envelope against the key the
 * enclave confirms from the approved organization registration and turn it into a full workspace. */
export async function completeApprovedDevice(pending: PendingDeviceWorkspace, deps: Dependencies, vault: UnlockedVault | null,
  signal?: AbortSignal): Promise<OpenedLegalWorkspace> {
  const device = await readDeviceKey(pending.privateKey);
  // A failed check (sign-in expired, service unavailable) propagates as itself:
  // only a definite answer from the service is reported as still waiting.
  const current = await readStatus(deps, pending.organizationId);
  if (current.memberId !== pending.memberId) throw new FirmMemberError('other-account');
  if (current.state === 'none') throw new FirmMemberError('not-registered');
  if (current.state !== 'approved') throw new PendingDeviceError(pending, current);
  const opened = await openApprovedDevice(current, { organizationId: pending.organizationId, device, minimumKeyEpoch: 0,
    published: published(deps, pending) });
  signal?.throwIfAborted();
  const firm = await firmIdentityFromKey(opened.organizationKey, pending);
  await enrollApprovedMemberDevice({ relay: deps.relay, releaseManifest: deps.releaseManifest,
    accessToken: await deps.accessToken(), now: Date.now(), firm, device, memberId: pending.memberId });
  const session = await deps.start(firm, signal);
  setFirmDevice({ memberId: pending.memberId, privateKey: device, keyEpoch: opened.keyEpoch });
  if (vault) { setFirmVault(vault); await persistFirmWorkspace(); }
  return { session, notice: 'Your device was approved. It now holds your organization key.' };
}

/** Any saved legal payload (vault or backup file). */
export async function openLegalWorkspace(payload: unknown, deps: Dependencies, vault: UnlockedVault | null,
  signal?: AbortSignal): Promise<OpenedLegalWorkspace> {
  if (isPendingDeviceWorkspace(payload)) return completeApprovedDevice(payload, deps, vault, signal);
  const restored = await readFirmWorkspace(payload);
  signal?.throwIfAborted();
  let firm = restored.firm, device = restored.device, notice: string | null = null;
  let pendingBootstrap = false;
  if (device) {
    const current = await optionalStatus(deps, firm.organizationId);
    pendingBootstrap = current?.memberId === device.memberId && (current.state === 'none' ||
      (current.state === 'pending' && current.deviceFingerprint === device.privateKey.getFingerprint()));
    if (current?.memberId === device.memberId && current.state === 'approved' && (current.keyEpoch ?? 0) > device.keyEpoch) {
      try {
        const opened = await openApprovedDevice(current, { organizationId: firm.organizationId, device: device.privateKey,
          minimumKeyEpoch: device.keyEpoch, held: firm.privateKey.toPublic(), published: published(deps, firm) });
        firm = await firmIdentityFromKey(opened.organizationKey, firm);
        device = { ...device, keyEpoch: opened.keyEpoch };
        notice = 'Your organization replaced its key, and this device now holds the new one.';
      } catch (error) {
        // The device keeps its current key and epoch, so the next visit checks again.
        notice = error instanceof FirmMemberError && error.code === 'not-confirmed' ? error.message
          : 'Your organization replaced its key, but the new key does not match the approved organization key, so this device kept its current key. Tell your steward.';
      }
    } else if (current?.memberId === device.memberId && current.state === 'removed') {
      notice = 'This device was removed from your organization. Your organization can no longer be reached from it.';
    }
  }
  if (device && !pendingBootstrap) {
    await enrollApprovedMemberDevice({ relay: deps.relay, releaseManifest: deps.releaseManifest,
      accessToken: await deps.accessToken(), now: Date.now(), firm, device: device.privateKey, memberId: device.memberId });
  }
  const session = await deps.start(firm, signal);
  signal?.throwIfAborted();
  // Case pins, owner keys and message floors stay valid across an organization key change.
  session.owners = restored.owners; session.pins = restored.pins;
  session.pinReleases = restored.pinReleases; session.sequences = restored.sequences;
  restoreFirmDevice({ device, sharedListVersion: restored.sharedListVersion });
  if (vault) setFirmVault(vault, restored.requests, restored.profile); else restoreFirmRequests(restored.requests, restored.profile);
  if (pendingBootstrap && vault) await prepareStewardDevice(session, Date.now());
  if (vault && notice && firm !== restored.firm) await persistFirmWorkspace().catch(() => {});
  return { session, notice };
}

/** Payload for a device that has registered but is not approved yet. */
export function pendingDevicePayload(input: { organizationId: string; domain: string; memberId: string; device: PrivateKey;
  registeredAt: number }): PendingDeviceWorkspace {
  return { format: 'vera-legal-device/v1', organizationId: input.organizationId, domain: input.domain, memberId: input.memberId,
    privateKey: input.device.armor(), registeredAt: input.registeredAt };
}

/** Convert an initially enrolled steward into an ordinary approved device, so
 * subsequent visits renew membership without a new platform invitation. The
 * private device key is retained before any network mutation for safe retries. */
export async function prepareStewardDevice(session: FirmSession, now: number) {
  // Automatic registration requires explicitly consented encrypted persistence.
  if (!currentFirmVault()) return null;
  let local = currentFirmDevice();
  const devices = await listMemberDevices(session, now);
  if (!local) {
    local = { memberId: '', privateKey: await createMemberDeviceKey(), keyEpoch: knownKeyEpoch(...devices.map(item => item.keyEpoch)) };
    // Derive the same stable member id the enclave derives from the verified JWT.
    const accessToken = await session.accessToken();
    const payload = accessToken.split('.')[1];
    if (!payload) throw new FirmMemberError('other-account');
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    const { firmMemberId } = await import('../../enclave/src/confidential/firmMembers');
    local.memberId = await firmMemberId(claims.org_id, claims.sub);
    setFirmDevice(local);
  }
  // Also persist on retries: an earlier vault write may have failed.
  await persistFirmWorkspace();
  const status = await registerMemberDevice({ relay: session.relay, releaseManifest: session.releaseManifest,
    accessToken: await session.accessToken(), now, organizationId: session.firm.organizationId,
    organizationPublicKey: session.firm.privateKey.toPublic(), device: local.privateKey,
    profile: { name: 'Organization steward', contact: '' } });
  if (status.memberId !== local.memberId) throw new FirmMemberError('other-account');
  if (status.state === 'pending') {
    const pending = (await listMemberDevices(session, now)).find(item => item.memberId === local!.memberId);
    if (!pending || pending.deviceFingerprint !== local.privateKey.getFingerprint()) throw new FirmMemberError('key-mismatch');
    await approveMemberDevice(session, pending, local.keyEpoch, now);
  } else if (status.state !== 'approved') throw new FirmMemberError('not-approved');
  await enrollApprovedMemberDevice({ relay: session.relay, releaseManifest: session.releaseManifest,
    accessToken: await session.accessToken(), now, firm: session.firm, device: local.privateKey, memberId: local.memberId });
  if (currentFirmVault()) await persistFirmWorkspace();
  return local;
}
