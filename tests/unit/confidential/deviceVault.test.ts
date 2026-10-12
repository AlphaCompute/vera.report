import { webcrypto } from 'node:crypto';
import {
  exportTemporaryWorkspace, createDeviceVault, unlockDeviceVault, readVaultBackup, VaultConflictError, VaultLockedError, createDeviceBoundVault, createPasskeyVault,
  unlockDeviceBoundVault, unlockPasskeyVault, exportPassphraseBackup, DEVICE_KEY_FAILURE, PASSKEY_FAILURE,
} from '../../../lib/confidential/deviceVault';
import type { PasskeySecret, VaultRecord, VaultStore } from '../../../lib/confidential/deviceVault';

const password = 'seven separate words kept outside this browser';
const secret = { recoveryCode: 'PRIVATE-OWNER-RECOVERY-SENTINEL', cases: [{ summary: 'PRIVATE-CASE-SENTINEL' }] };
function memoryStore() {
  const records = new Map<string, VaultRecord>();
  let generation = 0;
  const store: VaultStore = {
    generation: async () => generation,
    list: async () => [...records.values()].map(record => ({ ...record })),
    get: async id => records.has(id) ? { ...records.get(id)! } : null,
    put: async (record, expectedVersion, expectedGeneration) => {
      if (generation !== expectedGeneration || (records.get(record.id)?.version ?? null) !== expectedVersion) throw new VaultConflictError();
      records.set(record.id, { ...record });
    },
    remove: async id => { records.delete(id); },
    clear: async () => { generation++; records.clear(); },
  };
  return { records, store };
}
beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
});

test('remembers only ciphertext, restores on return and locks an unlocked handle', async () => {
  const { records, store } = memoryStore();
  const handle = await createDeviceVault(store, 'owner', password, secret);
  const serialized = JSON.stringify([...records.values()]);
  for (const plaintext of [password, secret.recoveryCode, secret.cases[0].summary]) expect(serialized).not.toContain(plaintext);
  const snapshot = handle.read() as typeof secret;
  snapshot.cases[0].summary = 'caller mutation';
  expect(handle.read()).toEqual(secret);
  handle.lock();
  expect(() => handle.read()).toThrow(VaultLockedError);
  await expect(handle.save({})).rejects.toThrow(VaultLockedError);
  const returned = await unlockDeviceVault(store, handle.id, 'owner', password);
  expect(returned.read()).toEqual(secret);
  await returned.save({ ...secret, updated: true });
  returned.lock();
  expect((await unlockDeviceVault(store, handle.id, 'owner', password)).read()).toEqual({ ...secret, updated: true });
});

test('wrong passwords, substituted roles, metadata, and ciphertext cannot unlock', async () => {
  const { records, store } = memoryStore();
  const handle = await createDeviceVault(store, 'legal', password, secret);
  await expect(unlockDeviceVault(store, handle.id, 'legal', 'a different long password')).rejects.toThrow();
  await expect(unlockDeviceVault(store, handle.id, 'owner', password)).rejects.toThrow();
  const original = records.get(handle.id)!;
  for (const patch of [
    { role: 'owner' as const }, { version: 'A'.repeat(22) }, { salt: 'A'.repeat(22) },
    { nonce: 'A'.repeat(16) }, { ciphertext: 'A'.repeat(32) }, { extra: 'unexpected' },
  ]) {
    records.set(handle.id, { ...original, ...patch });
    await expect(unlockDeviceVault(store, handle.id, patch.role ?? 'legal', password)).rejects.toThrow();
  }
});

test('two tabs cannot silently overwrite each other', async () => {
  const { store } = memoryStore();
  const first = await createDeviceVault(store, 'owner', password, secret);
  const second = await unlockDeviceVault(store, first.id, 'owner', password);
  await first.save({ newest: true });
  await expect(second.save({ stale: true })).rejects.toThrow(VaultConflictError);
  expect((await unlockDeviceVault(store, first.id, 'owner', password)).read()).toEqual({ newest: true });
});

test('forget invalidates old handles and an in-flight create cannot recreate forgotten data', async () => {
  const { store, records } = memoryStore();
  const old = await createDeviceVault(store, 'owner', password, secret);
  const capturedGeneration = await store.generation();
  await store.clear();
  await expect(old.save(secret)).rejects.toThrow(VaultConflictError);
  const stale = { ...store, generation: async () => capturedGeneration };
  await expect(createDeviceVault(stale, 'legal', password, secret)).rejects.toThrow(VaultConflictError);
  expect(records.size).toBe(0);
});

test('forget during key derivation cannot reopen a deleted vault', async () => {
  const { store } = memoryStore();
  const old = await createDeviceVault(store, 'owner', password, secret);
  const captured = (await store.get(old.id))!;
  const interrupted = { ...store, get: async () => { await store.clear(); return captured; } };
  await expect(unlockDeviceVault(interrupted, old.id, 'owner', password)).rejects.toThrow(VaultConflictError);
});

test('cancelled enrollment never reports remembered and does not persist a vault', async () => {
  const { store, records } = memoryStore();
  const controller = new AbortController();
  const interrupted = { ...store, put: async (...args: Parameters<VaultStore['put']>) => {
    await store.put(...args); controller.abort();
  } };
  await expect(createDeviceVault(interrupted, 'owner', password, secret, controller.signal)).rejects.toThrow();
  expect(records.size).toBe(0);
});

test('invalid passphrases, oversized data and failed storage do not fall back to plaintext', async () => {
  const { store, records } = memoryStore();
  await expect(createDeviceVault(store, 'owner', 'short', secret)).rejects.toThrow('16 characters');
  await expect(createDeviceVault(store, 'owner', password, { data: 'x'.repeat(1024 * 1024) })).rejects.toThrow('too large');
  const failed = { ...store, put: async () => { throw new Error('Quota exceeded'); } };
  await expect(createDeviceVault(failed, 'owner', password, secret)).rejects.toThrow('Quota exceeded');
  expect(records.size).toBe(0);
});

test('current encrypted backup survives a failed save without claiming device persistence', async () => {
  const { store, records } = memoryStore();
  let failWrites = false;
  const unreliable: VaultStore = { ...store, put: async (...args) => {
    if (failWrites) throw new Error('Quota exceeded');
    await store.put(...args);
  } };
  const vault = await createDeviceVault(unreliable, 'legal', password, secret);
  const original = JSON.stringify([...records.values()]);
  const current = { ...secret, newestPin: 'participant-observed-checkpoint' };
  failWrites = true;
  await expect(vault.save(current)).rejects.toThrow('Quota exceeded');
  const first = await vault.exportBackup(current), second = await vault.exportBackup(current);
  expect(first).not.toBe(second);
  expect(first).not.toContain('PRIVATE');
  expect(await readVaultBackup(first, 'legal', password)).toEqual(current);
  expect(vault.read()).toEqual(secret);
  expect(JSON.stringify([...records.values()])).toBe(original);
  vault.lock();
  await expect(vault.exportBackup(current)).rejects.toThrow(VaultLockedError);
});

test('temporary workspace export needs no device store and authenticates role, secret and contents', async () => {
  const text = await exportTemporaryWorkspace('legal', password, secret);
  expect(text).not.toContain(secret.recoveryCode);
  expect(text).not.toContain(secret.cases[0].summary);
  expect(await readVaultBackup(text, 'legal', password)).toEqual(secret);
  await expect(readVaultBackup(text, 'owner', password)).rejects.toThrow();
  await expect(readVaultBackup(text, 'legal', 'different long backup passphrase')).rejects.toThrow();
  await expect(exportTemporaryWorkspace('legal', 'short', secret)).rejects.toThrow();
  const controller = new AbortController();
  const pending = exportTemporaryWorkspace('legal', password, secret, controller.signal);
  controller.abort();
  await expect(pending).rejects.toThrow();
});

describe('legal organization quick unlock', () => {
  /** Memory store that also keeps device keys, like the IndexedDB store. */
  function keyedStore() {
    const base = memoryStore(), keys = new Map<string, CryptoKey>();
    const store: VaultStore = { ...base.store,
      put: async (record, expectedVersion, generation, deviceKey) => {
        await base.store.put(record, expectedVersion, generation);
        if (deviceKey) keys.set(record.id, deviceKey);
      },
      getKey: async id => keys.get(id) ?? null,
      remove: async id => { await base.store.remove(id); keys.delete(id); },
      clear: async () => { await base.store.clear(); keys.clear(); },
    };
    return { ...base, keys, store };
  }
  const firmSecret = { format: 'vera-legal-workspace/v1', privateKey: 'PRIVATE-FIRM-KEY-SENTINEL' };
  /** Deterministic stand-in for an authenticator's PRF: HMAC(credential secret, salt). */
  function authenticator() {
    const secrets = new Map<string, Uint8Array>();
    return {
      async create(): Promise<PasskeySecret> {
        const credentialId = webcrypto.getRandomValues(new Uint8Array(24)), salt = webcrypto.getRandomValues(new Uint8Array(32));
        secrets.set(Buffer.from(credentialId).toString('hex'), webcrypto.getRandomValues(new Uint8Array(32)));
        return { credentialId, salt, prfOutput: await this.prf(credentialId, salt) };
      },
      async prf(credentialId: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
        const secret = secrets.get(Buffer.from(credentialId).toString('hex'));
        if (!secret) throw new DOMException('Unknown credential', 'NotAllowedError');
        const key = await webcrypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return new Uint8Array(await webcrypto.subtle.sign('HMAC', key, salt));
      },
    };
  }

  test.each(['legal', 'owner'] as const)('keep unlocked (%s): a non-extractable key stays beside the record, never inside it', async role => {
    const { store, records, keys } = keyedStore();
    const vault = await createDeviceBoundVault(store, role, firmSecret);
    expect(vault.protection).toBe('device');
    const record = records.get(vault.id)!;
    expect(record).toMatchObject({ format: 'vera-device-vault/v2', protection: 'device', credentialId: null });
    expect(JSON.stringify(record)).not.toContain('PRIVATE-FIRM-KEY-SENTINEL');
    expect(keys.get(vault.id)!.extractable).toBe(false);
    await expect(webcrypto.subtle.exportKey('raw', keys.get(vault.id)!)).rejects.toThrow();
    vault.lock();
    const reopened = await unlockDeviceBoundVault(store, vault.id, role);
    expect(reopened.read()).toEqual(firmSecret);
    await reopened.save({ ...firmSecret, requests: 1 });
    expect((await unlockDeviceBoundVault(store, vault.id, role)).read()).toEqual({ ...firmSecret, requests: 1 });
    // Forgetting the device removes the key; the ciphertext alone is useless.
    keys.delete(vault.id);
    await expect(unlockDeviceBoundVault(store, vault.id, role)).rejects.toThrow(DEVICE_KEY_FAILURE);
  });

  test('passkey: the PRF output is never stored and only the same credential opens the workspace', async () => {
    const { store, records } = keyedStore(), device = authenticator();
    const secretBytes = await device.create();
    const prfCopy = Buffer.from(secretBytes.prfOutput).toString('base64url');
    const vault = await createPasskeyVault(store, 'legal', firmSecret, secretBytes);
    expect(vault.protection).toBe('passkey');
    const record = records.get(vault.id)!;
    expect(JSON.stringify(record)).not.toContain(prfCopy);
    expect(JSON.stringify(record)).not.toContain('PRIVATE-FIRM-KEY-SENTINEL');
    const prf = jest.fn((id: Uint8Array, salt: Uint8Array) => device.prf(id, salt));
    const reopened = await unlockPasskeyVault(store, vault.id, 'legal', prf);
    expect(reopened.read()).toEqual(firmSecret);
    expect(Buffer.from(prf.mock.calls[0][0])).toEqual(Buffer.from(secretBytes.credentialId));
    await expect(unlockPasskeyVault(store, vault.id, 'legal', async () => webcrypto.getRandomValues(new Uint8Array(32))))
      .rejects.toThrow(PASSKEY_FAILURE);
    await expect(unlockPasskeyVault(store, vault.id, 'legal', async () => { throw new Error('cancelled'); })).rejects.toThrow(PASSKEY_FAILURE);
    // Pointing the record at another credential of the same authenticator does not work.
    const second = await device.create();
    records.set(vault.id, { ...record, credentialId: Buffer.from(second.credentialId).toString('base64url') } as VaultRecord);
    await expect(unlockPasskeyVault(store, vault.id, 'legal', prf)).rejects.toThrow(PASSKEY_FAILURE);
  });

  test('protections and participant roles cannot be swapped; owner passkeys remain unavailable', async () => {
    const { store, records } = keyedStore(), device = authenticator();
    await expect(createPasskeyVault(store, 'owner', secret, await device.create())).rejects.toThrow('Only legal organizations');
    const passphrase = await createDeviceVault(store, 'legal', password, firmSecret);
    await expect(unlockDeviceBoundVault(store, passphrase.id, 'legal')).rejects.toThrow();
    const bound = await createDeviceBoundVault(store, 'legal', firmSecret);
    await expect(unlockDeviceVault(store, bound.id, 'legal', password)).rejects.toThrow();
    await expect(unlockPasskeyVault(store, bound.id, 'legal', device.prf)).rejects.toThrow();
    const original = records.get(bound.id)!;
    for (const patch of [{ protection: 'passkey' }, { role: 'owner' }, { credentialId: 'A'.repeat(22) }, { format: 'vera-device-vault/v1' }]) {
      records.set(bound.id, { ...original, ...patch } as VaultRecord);
      await expect(unlockDeviceBoundVault(store, bound.id, 'legal')).rejects.toThrow();
    }
    const withoutKeys: VaultStore = { ...store, getKey: undefined };
    await expect(createDeviceBoundVault(withoutKeys, 'legal', firmSecret)).rejects.toThrow('cannot keep a workspace unlocked');
  });

  test('backups of browser-bound workspaces need a separate passphrase and open anywhere with it', async () => {
    const { store } = keyedStore();
    const vault = await createDeviceBoundVault(store, 'legal', firmSecret);
    await expect(vault.exportBackup(firmSecret)).rejects.toThrow('backup passphrase');
    await expect(vault.exportBackup(firmSecret, 'short')).rejects.toThrow('16 characters');
    const backup = await vault.exportBackup({ ...firmSecret, newest: true }, password);
    expect(backup).not.toContain('PRIVATE-FIRM-KEY-SENTINEL');
    expect(JSON.parse(backup).format).toBe('vera-device-vault/v1');
    expect(await readVaultBackup(backup, 'legal', password)).toEqual({ ...firmSecret, newest: true });
    expect(await readVaultBackup(await exportPassphraseBackup('legal', firmSecret, password), 'legal', password)).toEqual(firmSecret);
  });
});
