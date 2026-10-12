import { forgetParticipantDevice, subscribeDeviceLock } from '../../../lib/confidential/deviceWorkspace';
import { browserVaultStore } from '../../../lib/confidential/deviceVault';
jest.mock('../../../lib/confidential/deviceVault', () => ({ browserVaultStore: jest.fn() }));
function storage(initial: Record<string, string>) {
  const data = new Map(Object.entries(initial));
  return { get length() { return data.size; }, key: (index: number) => [...data.keys()][index] ?? null,
    getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value); },
    removeItem: (key: string) => { data.delete(key); } };
}
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
const originalCaches = Object.getOwnPropertyDescriptor(globalThis, 'caches');
const originalChannel = Object.getOwnPropertyDescriptor(globalThis, 'BroadcastChannel');
afterEach(() => {
  for (const [key, descriptor] of [['window', originalWindow], ['caches', originalCaches], ['BroadcastChannel', originalChannel]] as const) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete (globalThis as any)[key];
  }
});
function install() {
  const local = storage({ 'vera-confidential-pin/v1:case': 'pin', 'vera-confidential-pin/v2:slot': 'sealed', 'vera-legal-requests:org': 'requests',
    'vera-confidential-withdrawals/v1:abcd': '{"sequence":3,"wire":null}', unrelated: 'keep' });
  const session = storage({ 'vera-legal-auth-pending': 'redirect', 'vera-legal-organization': 'org', 'vera-onboarding-auth-pending': 'admin-redirect', 'vera-legal-invitation': 'invite', unrelated: 'keep' });
  const win = Object.assign(new EventTarget(), { localStorage: local, sessionStorage: session });
  Object.defineProperty(globalThis, 'window', { value: win, configurable: true });
  const post = jest.fn();
  Object.defineProperty(globalThis, 'BroadcastChannel', { value: class { postMessage = post; close() {} }, configurable: true });
  const removeCache = jest.fn(async () => true);
  Object.defineProperty(globalThis, 'caches', { value: { keys: async () => ['vera-confidential-test', 'other-cache'], delete: removeCache }, configurable: true });
  return { local, session, post, removeCache };
}
test('forgets only Vera participant data and tells other tabs to lock without identifiers', async () => {
  const env = install(), clear = jest.fn(async () => {});
  jest.mocked(browserVaultStore).mockReturnValue({ clear } as any);
  const locked = jest.fn(), unsubscribe = subscribeDeviceLock(locked);
  await forgetParticipantDevice();
  expect(clear).toHaveBeenCalledTimes(1);
  expect(env.local.length).toBe(2); expect(env.session.length).toBe(1);
  // Nonsecret tombstone prevents in-flight encryption from resurrecting a pin.
  expect(env.local.getItem('vera-confidential-pin-generation/v1')).toMatch(/^[A-Za-z0-9_-]{22}$/);
  expect(env.session.getItem('vera-onboarding-auth-pending')).toBeNull();
  expect(env.local.getItem('unrelated')).toBe('keep');
  // The release withdrawal floor goes too: the browser is then like a fresh device.
  expect(env.local.getItem('vera-confidential-withdrawals/v1:abcd')).toBeNull();
  expect(env.removeCache).toHaveBeenCalledTimes(1); expect(env.removeCache).toHaveBeenCalledWith('vera-confidential-test');
  expect(locked).toHaveBeenCalledTimes(1); expect(env.post).toHaveBeenCalledTimes(1); expect(env.post).toHaveBeenCalledWith('lock');
  unsubscribe();
});
test('partial deletion reports failure instead of claiming history was erased', async () => {
  const env = install();
  jest.mocked(browserVaultStore).mockReturnValue({ clear: async () => { throw new Error('blocked storage'); } } as any);
  await expect(forgetParticipantDevice()).rejects.toThrow('Some VERA device data could not be cleared');
  expect(env.local.getItem('vera-legal-requests:org')).toBeNull();
  expect(env.local.getItem('unrelated')).toBe('keep');
});
