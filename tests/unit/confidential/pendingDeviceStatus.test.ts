import { webcrypto } from 'node:crypto';
import { LegalSignInRequired } from '../../../lib/confidential/legalAuth';
import { ConfidentialUnavailableError } from '../../../lib/confidential/client';
import type { DeviceStatus } from '../../../lib/confidential/firmMemberDevices';

/** A pending device's approval check reports "still waiting" only when the
 * service definitely says so. An expired sign-in or an unavailable service is
 * surfaced as itself, so a lawyer whose device is already approved is told to
 * sign in again (or retry) instead of being told to keep waiting. */
const readMemberDeviceStatus = jest.fn<Promise<DeviceStatus>, [unknown]>();
jest.mock('../../../lib/confidential/firmMemberDevices', () => ({
  ...jest.requireActual('../../../lib/confidential/firmMemberDevices'),
  readMemberDeviceStatus: (input: unknown) => readMemberDeviceStatus(input),
}));

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { completeApprovedDevice, pendingDevicePayload, PendingDeviceError } = require('../../../lib/confidential/firmDeviceSession') as
  typeof import('../../../lib/confidential/firmDeviceSession');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { FirmMemberError, createMemberDeviceKey } = require('../../../lib/confidential/firmMemberDevices') as
  typeof import('../../../lib/confidential/firmMemberDevices');

const MEMBER = 'a'.repeat(64);
const ORG = 'org_firm';
let pending: ReturnType<typeof pendingDevicePayload>;
const deps = { relay: {} as never, releaseManifest: 'manifest', accessToken: async () => 'token',
  start: async () => { throw new Error('must not start a session'); } };
const status = (state: DeviceStatus['state'], memberId = MEMBER): DeviceStatus =>
  ({ memberId, state, deviceFingerprint: state === 'none' ? null : 'f'.repeat(40), envelope: null, keyEpoch: null, continuity: null });

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  pending = pendingDevicePayload({ organizationId: ORG, domain: 'counsel.example', memberId: MEMBER,
    device: await createMemberDeviceKey(), registeredAt: 1 });
}, 60_000);
beforeEach(() => readMemberDeviceStatus.mockReset());

test('an expired sign-in is reported as sign-in required, not as still waiting', async () => {
  readMemberDeviceStatus.mockRejectedValue(new LegalSignInRequired());
  await expect(completeApprovedDevice(pending, deps, null)).rejects.toBeInstanceOf(LegalSignInRequired);
});

test('an expired sign-in while reading the access token is reported as sign-in required', async () => {
  await expect(completeApprovedDevice(pending, { ...deps, accessToken: () => Promise.reject(new LegalSignInRequired()) }, null))
    .rejects.toBeInstanceOf(LegalSignInRequired);
  expect(readMemberDeviceStatus).not.toHaveBeenCalled();
});

test('an unavailable or unverified service is reported as itself, not as still waiting', async () => {
  readMemberDeviceStatus.mockRejectedValue(new ConfidentialUnavailableError());
  const error = await completeApprovedDevice(pending, deps, null).catch(caught => caught);
  expect(error).toBeInstanceOf(ConfidentialUnavailableError);
  expect(error).not.toBeInstanceOf(PendingDeviceError);
});

test('only a definite pending or removed answer is reported as waiting or removed', async () => {
  readMemberDeviceStatus.mockResolvedValue(status('pending'));
  const waiting = await completeApprovedDevice(pending, deps, null).catch(caught => caught);
  expect(waiting).toBeInstanceOf(PendingDeviceError);
  expect(waiting.message).toBe('This device is still waiting for your organization to approve it.');

  readMemberDeviceStatus.mockResolvedValue(status('removed'));
  const removed = await completeApprovedDevice(pending, deps, null).catch(caught => caught);
  expect(removed).toBeInstanceOf(PendingDeviceError);
  expect(removed.status.state).toBe('removed');
});

test('a different signed-in account or a missing registration is named, not reported as waiting', async () => {
  readMemberDeviceStatus.mockResolvedValue(status('approved', 'b'.repeat(64)));
  const other = await completeApprovedDevice(pending, deps, null).catch(caught => caught);
  expect(other).toBeInstanceOf(FirmMemberError);
  expect(other.code).toBe('other-account');

  readMemberDeviceStatus.mockResolvedValue(status('none'));
  const missing = await completeApprovedDevice(pending, deps, null).catch(caught => caught);
  expect(missing).toBeInstanceOf(FirmMemberError);
  expect(missing.code).toBe('not-registered');
});
