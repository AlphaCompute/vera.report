import { encodeRecoveryCodeV2 } from '../../../enclave/src/confidential/recoveryCode';
import { forgetPin, forgetAllRememberedPins, loadRememberedPin, rememberPin, rememberedPinRequiresRefresh } from '../../../lib/confidential/devicePin';
import { parseRecoveryFile } from '../../../lib/confidential/recoveryFile';

const caseId = 'a'.repeat(64);
const pin = { caseId, ownerFingerprint: 'b'.repeat(40), revision: 3, keyEpoch: 1, digest: 'c'.repeat(64) };

function installStorage(): Map<string, string> {
  const data = new Map<string, string>();
  let lockQueue = Promise.resolve();
  const locks = { request: (_name: string, work: () => Promise<unknown>) => {
    const next = lockQueue.then(work, work); lockQueue = next.then(() => undefined, () => undefined); return next;
  } };
  const storage = {
    get length() { return data.size; },
    key: (index: number) => [...data.keys()][index] ?? null,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => { data.set(key, String(value)); },
    removeItem: (key: string) => { data.delete(key); },
  };
  Object.defineProperty(globalThis, 'window', { value: { localStorage: storage, navigator: { locks } }, configurable: true });
  return data;
}

const code = `VERA-OWNER-1.${caseId}.${'b'.repeat(40)}.${Buffer.alloc(32, 18).toString('base64url')}`;
const otherCode = `VERA-OWNER-1.${caseId}.${'b'.repeat(40)}.${Buffer.alloc(32, 19).toString('base64url')}`;

describe('owner device pin (opt-in)', () => {
  beforeAll(() => {
    if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: require('node:crypto').webcrypto });
  });
  afterEach(() => { delete (globalThis as { window?: unknown }).window; });

  test('stores only a sealed pin under a blinded slot and forgets it on request', async () => {
    const data = installStorage();
    await expect(loadRememberedPin(caseId, code)).resolves.toBeNull();
    await expect(rememberPin(pin, code)).resolves.toBe(true);
    await expect(loadRememberedPin(caseId, code)).resolves.toEqual(pin);
    // Nothing readable on the device names the report or its history.
    const everything = JSON.stringify([...data.entries()]);
    for (const value of [caseId, pin.digest, pin.ownerFingerprint, code, '"revision"']) expect(everything).not.toContain(value);
    expect([...data.keys()].every(key => key.startsWith('vera-confidential-pin/v2:'))).toBe(true);
    expect(Object.keys(JSON.parse([...data.values()][0])).sort()).toEqual(['ciphertext', 'nonce', 'v']);
    // A different recovery code neither finds nor opens it.
    await expect(loadRememberedPin(caseId, otherCode)).resolves.toBeNull();
    expect(data.size).toBe(1);
    await forgetPin(caseId, code);
    await expect(loadRememberedPin(caseId, code)).resolves.toBeNull();
    expect([...data.keys()]).toEqual(['vera-confidential-pin-generation/v1']);
  });

  test('equivalent typed recovery codes retain the same rollback protection', async () => {
    const data = installStorage();
    const canonical = await encodeRecoveryCodeV2(new Uint8Array(32).fill(23));
    await expect(rememberPin(pin, canonical)).resolves.toBe(true);
    const typed = canonical.toLowerCase().replaceAll('-', ' ');
    await expect(loadRememberedPin(caseId, typed)).resolves.toEqual(pin);
    await expect(rememberedPinRequiresRefresh({ ...pin, revision: 2 }, typed)).resolves.toBe(true);
    expect(data.size).toBe(1);
    await forgetPin(caseId, typed);
    expect([...data.keys()]).toEqual(['vera-confidential-pin-generation/v1']);
  });

  test('never moves backwards, including under concurrent writes', async () => {
    installStorage();
    await Promise.all([rememberPin({ ...pin, revision: 5, digest: 'e'.repeat(64) }, code),
      rememberPin({ ...pin, revision: 2, digest: 'd'.repeat(64) }, code)]);
    await expect(loadRememberedPin(caseId, code)).resolves.toMatchObject({ revision: 5 });
    await rememberPin(pin, code);
    await expect(loadRememberedPin(caseId, code)).resolves.toMatchObject({ revision: 5 });
    await expect(rememberPin({ ...pin, digest: 'not-hex' }, code)).resolves.toBe(false);
  });

  test('drops tampered entries and migrates plaintext v1 entries once', async () => {
    const data = installStorage();
    await rememberPin(pin, code);
    const [slot, sealed] = [...data.entries()][0];
    const value = JSON.parse(sealed);
    data.set(slot, JSON.stringify({ ...value, ciphertext: value.ciphertext.slice(0, -2) + (value.ciphertext.endsWith('AA') ? 'AB' : 'AA') }));
    await expect(loadRememberedPin(caseId, code)).resolves.toBeNull();
    expect(data.size).toBe(0);
    // Legacy plaintext entry: taken over, sealed, and the readable copy removed.
    data.set(`vera-confidential-pin/v1:${caseId}`, JSON.stringify(pin));
    await expect(loadRememberedPin(caseId, code)).resolves.toEqual(pin);
    expect(data.has(`vera-confidential-pin/v1:${caseId}`)).toBe(false);
    expect(JSON.stringify([...data.entries()])).not.toContain(caseId);
    // A malformed legacy entry is only removed.
    data.clear();
    data.set(`vera-confidential-pin/v1:${caseId}`, JSON.stringify({ ...pin, recoveryCode: 'VERA-OWNER-1.x' }));
    await expect(loadRememberedPin(caseId, code)).resolves.toBeNull();
    expect(data.size).toBe(0);
  });

  test('a same-revision fork or owner replacement never overwrites the retained pin', async () => {
    installStorage();
    await expect(rememberPin(pin, code)).resolves.toBe(true);
    await expect(rememberPin({ ...pin, digest: 'd'.repeat(64) }, code)).resolves.toBe(false);
    await expect(rememberPin({ ...pin, revision: 4, ownerFingerprint: 'e'.repeat(40) }, code)).resolves.toBe(false);
    await expect(loadRememberedPin(caseId, code)).resolves.toEqual(pin);
  });

  test('mutations require reconciling newer, forked or replaced retained history', async () => {
    installStorage();
    await expect(rememberedPinRequiresRefresh(pin, code)).resolves.toBe(false);
    await rememberPin(pin, code);
    await expect(rememberedPinRequiresRefresh(pin, code)).resolves.toBe(false);
    await expect(rememberedPinRequiresRefresh({ ...pin, revision: 2 }, code)).resolves.toBe(true);
    await expect(rememberedPinRequiresRefresh({ ...pin, digest: 'd'.repeat(64) }, code)).resolves.toBe(true);
    await expect(rememberedPinRequiresRefresh({ ...pin, ownerFingerprint: 'e'.repeat(40) }, code)).resolves.toBe(true);
    await expect(rememberedPinRequiresRefresh({ ...pin, keyEpoch: 2 }, code)).resolves.toBe(true);
    await expect(rememberedPinRequiresRefresh({ ...pin, revision: 4 }, code)).resolves.toBe(false);
  });

  test('Forget invalidates an encryption already in progress and leaves no resurrected pin', async () => {
    const data = installStorage();
    const original = globalThis.crypto.subtle.encrypt.bind(globalThis.crypto.subtle);
    let entered!: () => void, resume!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const paused = new Promise<void>(resolve => { resume = resolve; });
    const encrypt = jest.spyOn(globalThis.crypto.subtle, 'encrypt').mockImplementation(async (...args) => {
      entered(); await paused; return original(...args);
    });
    try {
      const writing = rememberPin(pin, code);
      await started;
      const forgetting = forgetAllRememberedPins();
      resume();
      await expect(writing).resolves.toBe(false);
      await forgetting;
      expect([...data.keys()]).toEqual(['vera-confidential-pin-generation/v1']);
      await expect(loadRememberedPin(caseId, code)).resolves.toBeNull();
    } finally { resume(); encrypt.mockRestore(); }
  });

  test('independent tab module queues cannot overwrite newer history', async () => {
    installStorage();
    let other!: typeof import('../../../lib/confidential/devicePin');
    jest.isolateModules(() => { other = require('../../../lib/confidential/devicePin'); });
    const original = globalThis.crypto.subtle.encrypt.bind(globalThis.crypto.subtle);
    let entered!: () => void, resume!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const paused = new Promise<void>(resolve => { resume = resolve; });
    let first = true;
    const encrypt = jest.spyOn(globalThis.crypto.subtle, 'encrypt').mockImplementation(async (...args) => {
      if (first) { first = false; entered(); await paused; }
      return original(...args);
    });
    try {
      const newer = rememberPin({ ...pin, revision: 5, digest: 'e'.repeat(64) }, code);
      await started;
      const older = other.rememberPin({ ...pin, revision: 2, digest: 'd'.repeat(64) }, code);
      resume();
      await Promise.all([newer, older]);
      await expect(other.loadRememberedPin(caseId, code)).resolves.toMatchObject({ revision: 5 });
    } finally { resume(); encrypt.mockRestore(); }
  });

  test('does not claim a pin was saved when browser atomic locking is unavailable', async () => {
    const data = installStorage();
    delete (window.navigator as unknown as { locks?: unknown }).locks;
    await expect(rememberPin(pin, code)).resolves.toBe(false);
    expect(data.size).toBe(0);
  });

  test('without browser storage it is a no-op', async () => {
    await expect(loadRememberedPin(caseId, code)).resolves.toBeNull();
    await expect(rememberPin(pin, code)).resolves.toBe(false);
    await expect(forgetPin(caseId, code)).resolves.toBeUndefined();
  });
});
