import { assertStrongPassphrase } from './passphraseStrength';
/** Participant-owned device vault. Only authenticated ciphertext is persisted.
 * The passphrase and derived key never go into web storage. This protects locked
 * data at rest, not an unlocked session from malicious same-origin JavaScript.
 * Role, record identity, protection and write version are authenticated with the payload.
 *
 * Three protections:
 * - `passphrase` (v1 records, owner and legal): PBKDF2 from a device passphrase.
 * - `passkey` (v2, legal only): a WebAuthn PRF secret from the organization's
 *   passkey, expanded with HKDF. The PRF output is never stored.
 * - `device` (v2, explicit opt-in, "Keep unlocked on this device"): a random
 *   non-extractable AES key kept in the same browser profile. This is an explicit
 *   convenience choice: anyone who can use this browser profile, and any script
 *   running on this origin, can use that key to decrypt. It only keeps raw key
 *   bytes out of reach of scripts and out of the stored record. Owner passkeys
 *   remain unavailable; a passkey name would reveal VERA use in a synced manager.
 */
export type VaultRole = 'owner' | 'legal';
export type VaultProtection = 'passphrase' | 'device' | 'passkey';
export type PassphraseVaultRecord = {
  format: 'vera-device-vault/v1'; id: string; role: VaultRole; version: string;
  salt: string; nonce: string; ciphertext: string;
};
export type BoundVaultRecord = {
  format: 'vera-device-vault/v2'; id: string; role: VaultRole; protection: 'device' | 'passkey'; version: string;
  salt: string; nonce: string; ciphertext: string; credentialId: string | null;
};
export type VaultRecord = PassphraseVaultRecord | BoundVaultRecord;
export interface VaultStore {
  /** Generation changes on forget-all, preventing stale creates from restoring data. */
  generation(): Promise<number>;
  list(): Promise<VaultRecord[]>;
  get(id: string): Promise<VaultRecord | null>;
  /** `deviceKey` is written in the same transaction as a new `device` record. */
  put(record: VaultRecord, expectedVersion: string | null, generation: number, deviceKey?: CryptoKey): Promise<void>;
  /** The non-extractable key of a `device` record, if this store keeps one. */
  getKey?(id: string): Promise<CryptoKey | null>;
  remove(id: string): Promise<void>;
  clear(): Promise<void>;
}
const FORMAT = 'vera-device-vault/v1';
const FORMAT_V2 = 'vera-device-vault/v2';
const ITERATIONS = 600_000;
const MAX_BYTES = 1024 * 1024;
const MAX_RECORDS = 20;
const FAILURE = 'The saved workspace could not be unlocked. Check your passphrase or use your recovery backup.';
// Public user-facing guidance, not a password or credential.
// nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_password
export const PASSKEY_FAILURE = 'The passkey did not unlock this saved workspace. Try again, or use your key file and recovery code.';
export const DEVICE_KEY_FAILURE = 'This browser no longer holds the key for this saved workspace. Use your key file and recovery code, then choose how to keep it on this device again.';
export class VaultConflictError extends Error {
  constructor() { super('This saved workspace changed in another tab or was forgotten. Unlock it again before saving.'); }
}
export class VaultLockedError extends Error {
  constructor() { super('This workspace is locked.'); }
}
function encode(bytes: Uint8Array): string {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function decode(value: unknown, max: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !value || value.length > Math.ceil(max / 3) * 4 ||
      !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(FAILURE);
  const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
  if (bytes.length > max || encode(bytes) !== value) throw new Error(FAILURE);
  return bytes;
}
function random(size: number): string { return encode(globalThis.crypto.getRandomValues(new Uint8Array(size))); }
function validRole(role: unknown): role is VaultRole { return role === 'owner' || role === 'legal'; }
export function vaultProtection(record: VaultRecord): VaultProtection {
  return record.format === FORMAT_V2 ? record.protection : 'passphrase';
}
function validate(record: VaultRecord): VaultRecord {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error(FAILURE);
  if (record.format === FORMAT_V2) {
    if (Object.keys(record).sort().join(',') !== 'ciphertext,credentialId,format,id,nonce,protection,role,salt,version' ||
        (!validRole(record.role) || (record.protection === 'passkey' && record.role !== 'legal')) || (record.protection !== 'device' && record.protection !== 'passkey') ||
        decode(record.id, 16).length !== 16 || decode(record.version, 16).length !== 16 ||
        decode(record.salt, 32).length !== (record.protection === 'passkey' ? 32 : 16) ||
        decode(record.nonce, 12).length !== 12 || decode(record.ciphertext, MAX_BYTES + 16).length < 16 ||
        (record.protection === 'device' ? record.credentialId !== null : decode(record.credentialId, 1023).length < 16)) throw new Error(FAILURE);
    return { ...record };
  }
  if (Object.keys(record).sort().join(',') !== 'ciphertext,format,id,nonce,role,salt,version' ||
      record.format !== FORMAT || !validRole(record.role) || decode(record.id, 16).length !== 16 ||
      decode(record.version, 16).length !== 16 || decode(record.salt, 16).length !== 16 ||
      decode(record.nonce, 12).length !== 12 || decode(record.ciphertext, MAX_BYTES + 16).length < 16) throw new Error(FAILURE);
  return { ...record };
}
type Header = Omit<PassphraseVaultRecord, 'ciphertext'> | Omit<BoundVaultRecord, 'ciphertext'>;
type Base = Omit<PassphraseVaultRecord, 'ciphertext' | 'version' | 'nonce'> | Omit<BoundVaultRecord, 'ciphertext' | 'version' | 'nonce'>;
function aad(record: Header): Uint8Array<ArrayBuffer> {
  if (record.format === FORMAT_V2) {
    return new TextEncoder().encode(JSON.stringify({ format: FORMAT_V2, id: record.id, role: record.role, protection: record.protection,
      version: record.version, salt: record.salt, nonce: record.nonce, credentialId: record.credentialId }));
  }
  return new TextEncoder().encode(JSON.stringify({ format: FORMAT, id: record.id, role: record.role,
    version: record.version, salt: record.salt, nonce: record.nonce }));
}
function baseOf(record: VaultRecord): Base {
  return record.format === FORMAT_V2
    ? { format: FORMAT_V2, id: record.id, role: record.role, protection: record.protection, salt: record.salt, credentialId: record.credentialId }
    : { format: FORMAT, id: record.id, role: record.role, salt: record.salt };
}
async function derive(passphrase: string, salt: string): Promise<CryptoKey> {
  if (typeof passphrase !== 'string' || passphrase.normalize('NFC').length < 16 || passphrase.length > 1024) {
    throw new Error('Use a unique passphrase of at least 16 characters. Save it separately from this browser.');
  }
  const bytes = new TextEncoder().encode(passphrase.normalize('NFC'));
  try {
    const material = await globalThis.crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await globalThis.crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: decode(salt, 16), iterations: ITERATIONS },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); }
}
/** PRF output -> non-extractable AES key, bound to this record's identity. */
async function derivePasskeyKey(prfOutput: Uint8Array, record: { id: string; salt: string; credentialId: string | null }): Promise<CryptoKey> {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length !== 32) throw new Error(PASSKEY_FAILURE);
  const material = await globalThis.crypto.subtle.importKey('raw', new Uint8Array(prfOutput), 'HKDF', false, ['deriveKey']);
  return globalThis.crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode(record.salt, 32),
    info: new TextEncoder().encode(`${FORMAT_V2}/passkey/${record.id}/${record.credentialId}`) },
  material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(value: unknown, key: CryptoKey, base: Base): Promise<VaultRecord> {
  const json = JSON.stringify(value);
  if (json === undefined) throw new Error('Invalid workspace');
  const bytes = new TextEncoder().encode(json);
  try {
    if (bytes.length > MAX_BYTES) throw new Error('This workspace is too large to remember on this device');
    const header = { ...base, version: random(16), nonce: random(12) } as Header;
    const encrypted = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: decode(header.nonce, 12),
      additionalData: aad(header), tagLength: 128 }, key, bytes);
    return { ...header, ciphertext: encode(new Uint8Array(encrypted)) } as VaultRecord;
  } finally { bytes.fill(0); }
}

/** Portable passphrase backup of a payload (always a v1 record with a fresh
 * identity and salt), readable by `readVaultBackup` on any device. */
export async function exportPassphraseBackup(role: VaultRole, value: unknown, passphrase: string): Promise<string> {
  if (!validRole(role)) throw new Error('Invalid workspace role');
  const base = { format: FORMAT, id: random(16), role, salt: random(16) } as const;
  assertStrongPassphrase(passphrase);
  return JSON.stringify(await seal(structuredClone(value), await derive(passphrase, base.salt), base));
}

/** An unlocked handle holds no passphrase. Lock makes in-flight operations fail;
 * closing over a prior plaintext result in application code is still the caller's
 * responsibility. Callers must clear their views and pending operations too.
 * `exportBackup` needs a backup passphrase for passkey or device vaults, whose
 * keys cannot leave this browser or authenticator. */
export type UnlockedVault = {
  id: string; role: VaultRole; protection: VaultProtection; read(): unknown; save(value: unknown): Promise<void>;
  exportBackup(currentPayload?: unknown, backupPassphrase?: string): Promise<string>; lock(): void;
};
function handle(store: VaultStore, record: VaultRecord, generation: number, initialKey: CryptoKey, initialValue: unknown): UnlockedVault {
  let key: CryptoKey | null = initialKey, value: unknown = initialValue, version = record.version;
  let writing = false;
  const base = baseOf(record), protection = vaultProtection(record);
  return {
    id: record.id, role: record.role, protection,
    read() { if (!key) throw new VaultLockedError(); return structuredClone(value); },
    async save(next: unknown) {
      if (!key) throw new VaultLockedError();
      if (writing) throw new VaultConflictError();
      writing = true;
      try {
        const snapshot = structuredClone(next);
        const encrypted = await seal(snapshot, key, base);
        if (!key) throw new VaultLockedError();
        await store.put(encrypted, version, generation);
        if (!key) throw new VaultLockedError();
        value = snapshot; version = encrypted.version;
      } finally { writing = false; }
    },
    async exportBackup(currentPayload = value, backupPassphrase?: string) {
      if (!key) throw new VaultLockedError();
      if (protection !== 'passphrase') {
        if (typeof backupPassphrase !== 'string') throw new Error('Choose a backup passphrase of at least 16 characters.');
        const text = await exportPassphraseBackup(record.role, currentPayload, backupPassphrase);
        if (!key) throw new VaultLockedError();
        return text;
      }
      // Export the caller's current observation even if storage is unavailable.
      // Fresh nonce/version; never changes the saved value or CAS write version.
      const exported = await seal(structuredClone(currentPayload), key, base);
      if (!key) throw new VaultLockedError();
      return JSON.stringify(exported);
    },
    lock() { key = null; value = undefined; },
  };
}

async function persistNew(store: VaultStore, generation: number, record: VaultRecord, signal?: AbortSignal, deviceKey?: CryptoKey) {
  signal?.throwIfAborted();
  await store.put(record, null, generation, deviceKey);
  if (signal?.aborted) {
    await store.remove(record.id);
    signal.throwIfAborted();
  }
}

export async function createDeviceVault(store: VaultStore, role: VaultRole, passphrase: string, value: unknown,
  signal?: AbortSignal): Promise<UnlockedVault> {
  if (!validRole(role)) throw new Error('Invalid workspace role');
  signal?.throwIfAborted();
  const generation = await store.generation();
  const base = { format: FORMAT, id: random(16), role, salt: random(16) } as const;
  const snapshot = structuredClone(value);
  assertStrongPassphrase(passphrase);
  const key = await derive(passphrase, base.salt);
  const record = await seal(snapshot, key, base);
  await persistNew(store, generation, record, signal);
  return handle(store, record, generation, key, snapshot);
}

/** Export a temporary workspace without touching browser storage. The same
 * authenticated format restores through readVaultBackup on a different device. */
export async function exportTemporaryWorkspace(role: VaultRole, passphrase: string, value: unknown,
  signal?: AbortSignal): Promise<string> {
  if (!validRole(role)) throw new Error('Invalid workspace role');
  signal?.throwIfAborted();
  const snapshot = structuredClone(value);
  const base = { format: FORMAT, id: random(16), role, salt: random(16) } as const;
  assertStrongPassphrase(passphrase);
  const key = await derive(passphrase, base.salt);
  signal?.throwIfAborted();
  const record = await seal(snapshot, key, base);
  signal?.throwIfAborted();
  return JSON.stringify(record);
}

/** "Keep unlocked on this device": the UI must obtain explicit informed opt-in. */
export async function createDeviceBoundVault(store: VaultStore, role: VaultRole, value: unknown, signal?: AbortSignal): Promise<UnlockedVault> {
  if (!validRole(role)) throw new Error(FAILURE);
  if (!store.getKey) throw new Error('This browser cannot keep a workspace unlocked. Use a passkey or a device passphrase.');
  signal?.throwIfAborted();
  const generation = await store.generation();
  const key = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']) as CryptoKey;
  if (key.extractable) throw new Error('Device key must be non-extractable');
  const base = { format: FORMAT_V2, id: random(16), role, protection: 'device', salt: random(16), credentialId: null } as const;
  const snapshot = structuredClone(value);
  const record = await seal(snapshot, key, base);
  await persistNew(store, generation, record, signal, key);
  return handle(store, record, generation, key, snapshot);
}

export type PasskeySecret = { credentialId: Uint8Array; salt: Uint8Array; prfOutput: Uint8Array };
/** Passkey unlock (legal organizations only). `passkey` comes from a PRF-capable credential. */
export async function createPasskeyVault(store: VaultStore, role: VaultRole, value: unknown, passkey: PasskeySecret,
  signal?: AbortSignal): Promise<UnlockedVault> {
  if (role !== 'legal') throw new Error('Only legal organizations can unlock with a passkey');
  if (!(passkey.salt instanceof Uint8Array) || passkey.salt.length !== 32 || !(passkey.credentialId instanceof Uint8Array) ||
      passkey.credentialId.length < 16 || passkey.credentialId.length > 1023) throw new Error(PASSKEY_FAILURE);
  signal?.throwIfAborted();
  const generation = await store.generation();
  const base = { format: FORMAT_V2, id: random(16), role: 'legal', protection: 'passkey', salt: encode(passkey.salt),
    credentialId: encode(passkey.credentialId) } as const;
  const key = await derivePasskeyKey(passkey.prfOutput, base);
  const snapshot = structuredClone(value);
  const record = await seal(snapshot, key, base);
  await persistNew(store, generation, record, signal);
  return handle(store, record, generation, key, snapshot);
}

async function openRecord(store: VaultStore, id: string, role: VaultRole, protection: VaultProtection, failure: string,
  keyFor: (record: VaultRecord) => Promise<CryptoKey>, signal?: AbortSignal): Promise<UnlockedVault> {
  let bytes: Uint8Array | undefined;
  try {
    signal?.throwIfAborted();
    const generation = await store.generation();
    const stored = await store.get(id);
    if (!stored) throw new Error(failure);
    const record = validate(stored);
    if (record.id !== id || record.role !== role || vaultProtection(record) !== protection) throw new Error(failure);
    const key = await keyFor(record);
    bytes = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(record.nonce, 12),
      additionalData: aad(record), tagLength: 128 }, key, decode(record.ciphertext, MAX_BYTES + 16)));
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    signal?.throwIfAborted();
    // A clear/change while the expensive derivation ran must not reopen old data.
    if (await store.generation() !== generation || (await store.get(id))?.version !== record.version) throw new VaultConflictError();
    signal?.throwIfAborted();
    return handle(store, record, generation, key, value);
  } catch (error) {
    if (signal?.aborted) signal.throwIfAborted();
    if (error instanceof VaultConflictError) throw error;
    throw new Error(failure);
  } finally { bytes?.fill(0); }
}

export async function unlockDeviceVault(store: VaultStore, id: string, role: VaultRole, passphrase: string,
  signal?: AbortSignal): Promise<UnlockedVault> {
  return openRecord(store, id, role, 'passphrase', FAILURE, record => derive(passphrase, record.salt), signal);
}

export async function unlockDeviceBoundVault(store: VaultStore, id: string, role: VaultRole, signal?: AbortSignal): Promise<UnlockedVault> {
  return openRecord(store, id, role, 'device', DEVICE_KEY_FAILURE, async () => {
    const key = await store.getKey?.(id);
    if (!key || key.extractable || key.algorithm.name !== 'AES-GCM') throw new Error(DEVICE_KEY_FAILURE);
    return key;
  }, signal);
}

/** `prf` asks the authenticator for this credential's PRF output on `salt`. */
export async function unlockPasskeyVault(store: VaultStore, id: string, role: VaultRole,
  prf: (credentialId: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>) => Promise<Uint8Array>, signal?: AbortSignal): Promise<UnlockedVault> {
  return openRecord(store, id, role, 'passkey', PASSKEY_FAILURE, async record => {
    const bound = record as BoundVaultRecord;
    const output = await prf(decode(bound.credentialId, 1023), decode(bound.salt, 32));
    try { return await derivePasskeyKey(output, bound); } finally { output.fill(0); }
  }, signal);
}
/** Stored credential ID of a passkey record, for the authenticator request. */
export function passkeyCredentialId(record: VaultRecord): Uint8Array<ArrayBuffer> | null {
  return record.format === FORMAT_V2 && record.protection === 'passkey' ? decode(record.credentialId, 1023) : null;
}

const DB = 'vera-confidential-device/v1';
const RECORDS = 'vaults', META = 'meta', KEYS = 'deviceKeys';
/** IndexedDB transactions serialize compare-and-swap and forget across tabs.
 * There is no plaintext/localStorage fallback when persistence is unavailable. */
export function browserVaultStore(): VaultStore {
  function open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      // Version 2 adds the non-extractable device keys for "Keep unlocked on this device".
      const request = indexedDB.open(DB, 2);
      let rejected = false;
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(RECORDS)) db.createObjectStore(RECORDS, { keyPath: 'id' });
        if (!db.objectStoreNames.contains(META)) db.createObjectStore(META);
        if (!db.objectStoreNames.contains(KEYS)) db.createObjectStore(KEYS);
      };
      request.onerror = () => reject(new Error('Device storage is unavailable. Keep your recovery backup and use this device temporarily.'));
      request.onblocked = () => { rejected = true; reject(new Error('Close other VERA tabs before changing device storage.')); };
      request.onsuccess = () => { if (rejected) request.result.close(); else resolve(request.result); };
    });
  }
  async function transaction<T>(mode: IDBTransactionMode, run: (tx: IDBTransaction,
    done: (value: T) => void, fail: (error: Error) => void) => void): Promise<T> {
    const db = await open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const tx = db.transaction([RECORDS, META, KEYS], mode);
        let value: T, error: Error | undefined;
        tx.oncomplete = () => resolve(value);
        tx.onabort = () => reject(error ?? new Error('Device storage could not be saved. Keep your recovery backup.'));
        tx.onerror = () => { /* Abort reports the final transaction outcome. */ };
        const fail = (caught: Error) => { error = caught; tx.abort(); };
        try { run(tx, result => { value = result; }, fail); }
        catch (caught) { fail(caught instanceof Error ? caught : new Error('Device storage unavailable')); }
      });
    } finally { db.close(); }
  }
  return {
    generation: () => transaction<number>('readonly', (tx, done) => {
      const get = tx.objectStore(META).get('generation'); get.onsuccess = () => done(get.result ?? 0);
    }),
    list: () => transaction<VaultRecord[]>('readonly', (tx, done, fail) => {
      const get = tx.objectStore(RECORDS).getAll(undefined, MAX_RECORDS + 1);
      get.onsuccess = () => {
        try {
          if (get.result.length > MAX_RECORDS) throw new Error('Too many saved workspaces');
          done(get.result.map(validate));
        } catch { fail(new Error('Saved workspace data is damaged. Use a recovery backup or forget this device.')); }
      };
    }),
    get: id => transaction<VaultRecord | null>('readonly', (tx, done) => {
      const get = tx.objectStore(RECORDS).get(id); get.onsuccess = () => done(get.result ?? null);
    }),
    getKey: id => transaction<CryptoKey | null>('readonly', (tx, done) => {
      const get = tx.objectStore(KEYS).get(id);
      get.onsuccess = () => done(get.result instanceof CryptoKey ? get.result : null);
    }),
    put: (record, expectedVersion, generation, deviceKey) => transaction<void>('readwrite', (tx, done, fail) => {
      validate(record);
      if ((deviceKey !== undefined) !== (vaultProtection(record) === 'device' && expectedVersion === null) ||
          (deviceKey && deviceKey.extractable)) throw new Error('Device storage could not be saved.');
      const records = tx.objectStore(RECORDS), meta = tx.objectStore(META);
      const getGeneration = meta.get('generation');
      getGeneration.onsuccess = () => {
        if ((getGeneration.result ?? 0) !== generation) { fail(new VaultConflictError()); return; }
        const get = records.get(record.id);
        get.onsuccess = () => {
          if ((get.result?.version ?? null) !== expectedVersion) { fail(new VaultConflictError()); return; }
          const count = records.count();
          count.onsuccess = () => {
            if (expectedVersion === null && count.result >= MAX_RECORDS) { fail(new Error('This browser already has 20 saved workspaces. Keep your recovery backups and use this workspace temporarily.')); return; }
            records.put(record);
            if (deviceKey) tx.objectStore(KEYS).put(deviceKey, record.id);
            done();
          };
        };
      };
    }),
    remove: id => transaction<void>('readwrite', (tx, done) => {
      tx.objectStore(RECORDS).delete(id); tx.objectStore(KEYS).delete(id); done();
    }),
    clear: () => transaction<void>('readwrite', (tx, done, fail) => {
      const meta = tx.objectStore(META), get = meta.get('generation');
      get.onsuccess = () => {
        const generation = get.result ?? 0;
        if (!Number.isSafeInteger(generation) || generation >= Number.MAX_SAFE_INTEGER) { fail(new Error('Invalid device storage generation')); return; }
        meta.put(generation + 1, 'generation'); tx.objectStore(RECORDS).clear(); tx.objectStore(KEYS).clear(); done();
      };
    }),
  };
}

/** Offline encrypted workspace exports use the same authenticated format and
 * device passphrase. Import does not opt the destination device into persistence. */
export async function readVaultBackup(text: string, role: VaultRole, passphrase: string, signal?: AbortSignal): Promise<unknown> {
  if (typeof text !== 'string' || text.length > 1500 * 1024) throw new Error(FAILURE);
  const record = validate(JSON.parse(text));
  const store: VaultStore = {
    generation: async () => 0, get: async id => id === record.id ? record : null, list: async () => [record],
    put: async () => { throw new Error('Read-only backup'); }, remove: async () => {}, clear: async () => {},
  };
  const vault = await unlockDeviceVault(store, record.id, role, passphrase, signal);
  try { return vault.read(); } finally { vault.lock(); }
}
