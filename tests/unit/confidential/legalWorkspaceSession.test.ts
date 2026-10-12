import { webcrypto } from 'node:crypto';
import { generateFirmIdentity } from '../../../lib/confidential/firmKey';
import type { FirmIdentity } from '../../../lib/confidential/firmKey';
import { createFirmSession } from '../../../lib/confidential/firmCase';
import { currentFirmSession, currentFirmVault, setFirmSession, setFirmVault } from '../../../lib/confidential/firmPortal';
import { firmWorkspace } from '../../../lib/confidential/firmWorkspace';
import { openLegalWorkspace } from '../../../lib/confidential/firmDeviceSession';
import { readMembershipStatus } from '../../../lib/confidential/firmOnboarding';
import { OrganizationKeyPendingError, publishedOrganizationKey } from '../../../lib/confidential/firmMemberDevices';
import { startFirmSession, startFirmSetupSession, validateFirmSession, WorkspaceKeyMismatchError } from '../../../lib/confidential/legalWorkspaceSession';

jest.mock('../../../lib/confidential/config', () => ({
  CONFIDENTIAL_RELEASE_MANIFEST: require('../../fixtures/confidential-release-manifest-vector.json').expected.canonical,
}));
let mockVersion = 1, mockToken = 'account-a';
jest.mock('../../../lib/confidential/legalAuth', () => {
  const listeners = new Set<() => void>();
  return {
    legalIdentityVersion: () => mockVersion,
    legalAccessToken: async () => mockToken,
    subscribeLegalIdentityChange: (listener: () => void) => { listeners.add(listener); return () => listeners.delete(listener); },
    changeIdentity: () => { for (const listener of listeners) listener(); },
    LegalSignInRequired: class extends Error {},
  };
});
jest.mock('../../../lib/confidential/firmOnboarding', () => ({ readMembershipStatus: jest.fn() }));
jest.mock('../../../lib/confidential/firmMemberDevices', () => ({
  ...jest.requireActual('../../../lib/confidential/firmMemberDevices'), publishedOrganizationKey: jest.fn(),
}));
const manifest = require('../../fixtures/confidential-release-manifest-vector.json').expected.canonical;
const config = { domain: 'identity.example', clientId: 'legal', audience: 'legal-api', organization: 'org_a' };
const membership = jest.mocked(readMembershipStatus), published = jest.mocked(publishedOrganizationKey);
let a: FirmIdentity, b: FirmIdentity, replacement: FirmIdentity;

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  [a, b, replacement] = await Promise.all([
    generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'a.example' }),
    generateFirmIdentity({ organizationId: 'b'.repeat(64), domain: 'b.example' }),
    generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'a.example' }),
  ]);
});
beforeEach(() => {
  setFirmSession(null); mockVersion = 1; mockToken = 'account-a'; jest.clearAllMocks();
  membership.mockImplementation(async input => ({ state: 'enrolled', leaseExpiresAt: Date.now() + 60_000, members: 1,
    keyMatches: input.firm.organizationId === a.organizationId && input.firm.recipientKeyId === a.recipientKeyId }));
  published.mockResolvedValue(a.privateKey.toPublic());
});
afterEach(() => setFirmSession(null));

test('publishes a matching key only after membership verification', async () => {
  membership.mockImplementationOnce(async () => {
    expect(currentFirmSession()).toBeNull();
    return { state: 'enrolled', leaseExpiresAt: Date.now() + 60_000, members: 1, keyMatches: true };
  });
  const session = await startFirmSession(config, a);
  expect(currentFirmSession()).toBe(session);
});

test('rejects another organization and an unapproved replacement key', async () => {
  for (const firm of [b, replacement]) {
    await expect(startFirmSession(config, firm)).rejects.toBeInstanceOf(WorkspaceKeyMismatchError);
    expect(currentFirmSession()).toBeNull();
  }
});

test('checks the actual key even when file labels claim the approved fingerprint', async () => {
  await expect(startFirmSession(config, { ...a, privateKey: b.privateKey })).rejects.toBeInstanceOf(WorkspaceKeyMismatchError);
  expect(membership).not.toHaveBeenCalled();
  expect(currentFirmSession()).toBeNull();
});

test.each(['not-enrolled', 'lapsed'] as const)('does not open a workspace with %s membership', async state => {
  membership.mockResolvedValueOnce({ state });
  await expect(startFirmSession(config, a)).rejects.toThrow(/setup/);
  expect(currentFirmSession()).toBeNull();
});

test('verification failure cannot activate or expose a saved key', async () => {
  membership.mockRejectedValueOnce(new Error('The secure connection failed.'));
  await expect(startFirmSession(config, a)).rejects.toThrow('The secure connection failed.');
  expect(currentFirmSession()).toBeNull();
});

test('a sign-in change during verification cannot publish the previous result', async () => {
  membership.mockImplementationOnce(async () => {
    mockVersion++; mockToken = 'account-b';
    return { state: 'enrolled', leaseExpiresAt: Date.now() + 60_000, members: 1, keyMatches: true };
  });
  await expect(startFirmSession(config, a)).rejects.toThrow();
  expect(currentFirmSession()).toBeNull();
});

test('an aborted unlock cannot publish its session', async () => {
  const controller = new AbortController(); controller.abort();
  await expect(startFirmSession(config, a, controller.signal)).rejects.toThrow();
  expect(currentFirmSession()).toBeNull();
});

test('an existing session is checked again and cannot use a different account', async () => {
  const session = await startFirmSession(config, a);
  membership.mockResolvedValueOnce({ state: 'enrolled', leaseExpiresAt: Date.now() + 60_000, members: 1, keyMatches: false });
  await expect(validateFirmSession(config, session)).rejects.toBeInstanceOf(WorkspaceKeyMismatchError);
  mockVersion++;
  await expect(session.accessToken()).rejects.toThrow();
});

test('changing identity clears the current workspace and locks its saved copy', async () => {
  const session = await startFirmSession(config, a);
  const vault = { role: 'legal', lock: jest.fn() };
  setFirmVault(vault as never);
  mockVersion++;
  jest.requireMock('../../../lib/confidential/legalAuth').changeIdentity();
  expect(currentFirmSession()).toBeNull();
  expect(currentFirmVault()).toBeNull();
  expect(vault.lock).toHaveBeenCalledTimes(1);
  await expect(session.accessToken()).rejects.toThrow();
});

test.each([false, true])('rejects another firm before restoring workspace records (vault=%s)', async savedOnDevice => {
  const session = await createFirmSession({ relay: {} as never, releaseManifest: manifest, firm: b, accessToken: async () => 'unused' });
  const payload = firmWorkspace(session, []);
  const vault = savedOnDevice ? { lock: jest.fn() } as never : null;
  await expect(openLegalWorkspace(payload, { relay: session.relay, releaseManifest: manifest, accessToken: async () => mockToken,
    start: (firm, signal) => startFirmSession(config, firm, signal) }, vault)).rejects.toBeInstanceOf(WorkspaceKeyMismatchError);
  expect(currentFirmSession()).toBeNull();
  expect(currentFirmVault()).toBeNull();
});

test('setup still rejects the wrong approved key and failed organization checks', async () => {
  await expect(startFirmSetupSession(config, b)).rejects.toBeInstanceOf(WorkspaceKeyMismatchError);
  published.mockRejectedValueOnce(new Error('Organization verification failed.'));
  await expect(startFirmSetupSession(config, a)).rejects.toThrow('Organization verification failed.');
  expect(currentFirmSession()).toBeNull();
});

test('first-key setup accepts only an explicit pending answer and does not bypass the workspace gate', async () => {
  published.mockRejectedValueOnce(new OrganizationKeyPendingError());
  const session = await startFirmSetupSession(config, a);
  membership.mockResolvedValueOnce({ state: 'not-enrolled' });
  await expect(validateFirmSession(config, session)).rejects.toThrow(/setup/);
});
