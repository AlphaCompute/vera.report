import { webcrypto } from 'node:crypto';
import { PASSPHRASE_GUIDANCE, passphraseProblem } from '../../../lib/confidential/passphraseStrength';
import type { VaultRecord, VaultStore } from '../../../lib/confidential/deviceVault';

beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
});

test.each(['a'.repeat(16), 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'abababababababab', 'passwordpassword', 'abcdefghijklmnop',
  '1234567890123456', 'ponmlkjihgfedcba', 'aabbccddeeffgghh', 'short', '', '               a', null])('refuses %p', value => {
  expect(passphraseProblem(value)).toBe(PASSPHRASE_GUIDANCE);
});

test.each(['correct horse battery staple', 'seven separate words kept outside this browser', 'a long backup passphrase',
  'Tr0ub4dor&3xyzqwt', 'VERA-FIRM-1.Qm9ndXNSYW5kb21CeXRlc0hlcmVGb3JUZXN0aW5nMTIz'])('accepts %p', value => {
  expect(passphraseProblem(value)).toBeNull();
});

test('oversized pasted secrets are refused before normalization and pattern scanning', () => {
  const normalize = jest.spyOn(String.prototype, 'normalize');
  try {
    expect(passphraseProblem('q'.repeat(1024 * 1024))).toBe(PASSPHRASE_GUIDANCE);
    expect(passphraseProblem('unique words longer than the permitted secret '.repeat(30))).toBe(PASSPHRASE_GUIDANCE);
    expect(normalize).not.toHaveBeenCalled();
  } finally { normalize.mockRestore(); }
});

function memoryStore(): VaultStore {
  const records = new Map<string, VaultRecord>();
  return {
    generation: async () => 0, list: async () => [...records.values()], get: async id => records.get(id) ?? null,
    put: async record => { records.set(record.id, record); }, remove: async id => { records.delete(id); }, clear: async () => records.clear(),
  };
}

test('new workspaces, backups and firm exports refuse a weak passphrase', async () => {
  const { createDeviceVault, exportTemporaryWorkspace } = await import('../../../lib/confidential/deviceVault');
  const { exportFirmIdentity, generateFirmIdentity } = await import('../../../lib/confidential/firmKey');
  const weak = 'x'.repeat(16);
  await expect(createDeviceVault(memoryStore(), 'owner', weak, {})).rejects.toThrow(PASSPHRASE_GUIDANCE);
  await expect(exportTemporaryWorkspace('legal', weak, {})).rejects.toThrow(PASSPHRASE_GUIDANCE);
  const firm = await generateFirmIdentity({ organizationId: 'f'.repeat(64), domain: 'counsel.example' });
  await expect(exportFirmIdentity(firm, weak)).rejects.toThrow(PASSPHRASE_GUIDANCE);
});

test('workspaces saved under the old length-only floor still open', async () => {
  const weak = 'x'.repeat(16), store = memoryStore();
  let id = '';
  await jest.isolateModulesAsync(async () => {
    jest.doMock('../../../lib/confidential/passphraseStrength', () => ({ assertStrongPassphrase: () => undefined, passphraseProblem: () => null }));
    const legacy = await import('../../../lib/confidential/deviceVault');
    id = (await legacy.createDeviceVault(store, 'owner', weak, { saved: 'before' })).id;
    const firmKey = await import('../../../lib/confidential/firmKey');
    const firm = await firmKey.generateFirmIdentity({ organizationId: 'e'.repeat(64), domain: 'counsel.example' });
    const file = await firmKey.exportFirmIdentity(firm, weak);
    jest.dontMock('../../../lib/confidential/passphraseStrength');
    jest.resetModules();
    const current = await import('../../../lib/confidential/firmKey');
    expect((await current.importFirmIdentity(file, weak)).recipientKeyId).toBe(firm.recipientKeyId);
  });
  const { unlockDeviceVault } = await import('../../../lib/confidential/deviceVault');
  expect((await unlockDeviceVault(store, id, 'owner', weak)).read()).toEqual({ saved: 'before' });
});
