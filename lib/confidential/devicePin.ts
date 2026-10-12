import { parseRecoveryCode } from '../../enclave/src/confidential/recoveryCode';
import type { CheckpointPin } from '../../enclave/src/confidential/recovery';

/** Optional, explicit opt-in ("Remember this device"). Stores ONLY the owner's
 * last verified checkpoint pin (case ID, owner key fingerprint, revision, key
 * epoch, checkpoint digest) so a later visit can detect a rolled-back or forked
 * case. Never the recovery code, keys, summary or any case content. Default off.
 *
 * At rest the pin is sealed with AES-256-GCM under a key derived from the
 * recovery code, and its storage slot name is an HMAC of the same secret. The
 * browser therefore holds no readable case ID: someone inspecting this device
 * without the recovery code can tell VERA was used, not which report. Earlier
 * plaintext (v1) entries are migrated on first read and removed. */
const LEGACY_PREFIX = 'vera-confidential-pin/v1:';
export const PIN_PREFIX = 'vera-confidential-pin/v2:';
const PIN_LOCK = 'vera-confidential-pin-storage/v2';
const GENERATION_KEY = 'vera-confidential-pin-generation/v1';
const SALT = new TextEncoder().encode('vera-device-pin/v2');

function storage(): Storage | null {
  try { return typeof window === 'undefined' ? null : window.localStorage; } catch { return null; }
}
function valid(value: unknown, caseId: string): value is CheckpointPin {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const pin = value as Record<string, unknown>;
  return Object.keys(pin).sort().join(',') === 'caseId,digest,keyEpoch,ownerFingerprint,revision' &&
    pin.caseId === caseId && typeof pin.digest === 'string' && /^[a-f0-9]{64}$/.test(pin.digest) &&
    typeof pin.ownerFingerprint === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(pin.ownerFingerprint) &&
    Number.isSafeInteger(pin.revision) && (pin.revision as number) > 0 &&
    Number.isSafeInteger(pin.keyEpoch) && (pin.keyEpoch as number) > 0;
}
function copy(pin: CheckpointPin): CheckpointPin {
  return { caseId: pin.caseId, ownerFingerprint: pin.ownerFingerprint, revision: pin.revision, keyEpoch: pin.keyEpoch, digest: pin.digest };
}
function encode(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function decode(value: unknown, max: number): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== 'string' || !value || value.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
  return bytes.length <= max && encode(bytes) === value ? bytes : null;
}

type PinKeys = { slot: string; key: CryptoKey };
/** Slot and sealing key for one recovery code. The code is a random secret, so
 * HKDF (not a password KDF) is sufficient; the derived bytes are cleared. */
async function pinKeys(recoveryCode: string): Promise<PinKeys> {
  // Equivalent typed spellings must find the same retained history.
  const parsed = await parseRecoveryCode(recoveryCode);
  const secret = new TextEncoder().encode(parsed.code);
  parsed.secret.fill(0);
  let slotBytes: Uint8Array | undefined, keyBytes: Uint8Array | undefined;
  try {
    const material = await globalThis.crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    const derive = async (info: string) => new Uint8Array(await globalThis.crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: SALT, info: new TextEncoder().encode(info) }, material, 256));
    slotBytes = await derive('slot');
    keyBytes = await derive('seal');
    const key = await globalThis.crypto.subtle.importKey('raw', keyBytes as Uint8Array<ArrayBuffer>, 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { slot: PIN_PREFIX + encode(slotBytes.subarray(0, 24)), key };
  } finally { secret.fill(0); slotBytes?.fill(0); keyBytes?.fill(0); }
}
async function seal(keys: PinKeys, pin: CheckpointPin): Promise<string> {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(copy(pin)));
  try {
    const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
      additionalData: new TextEncoder().encode(keys.slot), tagLength: 128 }, keys.key, plaintext));
    return JSON.stringify({ v: 2, nonce: encode(nonce), ciphertext: encode(ciphertext) });
  } finally { plaintext.fill(0); }
}
async function open(keys: PinKeys, raw: string, caseId: string): Promise<CheckpointPin | null> {
  let plaintext: Uint8Array | undefined;
  try {
    if (raw.length > 4096) return null;
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'ciphertext,nonce,v' ||
        value.v !== 2) return null;
    const nonce = decode(value.nonce, 12), ciphertext = decode(value.ciphertext, 1024);
    if (!nonce || nonce.length !== 12 || !ciphertext) return null;
    plaintext = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce,
      additionalData: new TextEncoder().encode(keys.slot), tagLength: 128 }, keys.key, ciphertext));
    const pin: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    return valid(pin, caseId) ? copy(pin) : null;
  } catch { return null; } finally { plaintext?.fill(0); }
}

// Web Locks serialize read/compare/write across tabs; the local queue also
// preserves call order within this realm. Missing atomic locking fails closed.
let queue: Promise<unknown> = Promise.resolve();
function serialized<T>(work: () => Promise<T>): Promise<T> {
  const locked = () => {
    const locks = typeof window === 'undefined' ? undefined : window.navigator?.locks;
    if (!locks) throw new Error('Atomic device pin storage unavailable');
    return locks.request(PIN_LOCK, work);
  };
  const next = queue.then(locked, locked);
  queue = next.catch(() => undefined);
  return next;
}

function generation(store: Storage): string { return store.getItem(GENERATION_KEY) ?? ''; }
function checkGeneration(store: Storage, expected: string): void {
  if (generation(store) !== expected) throw new Error('Device pins were forgotten');
}
function invalidatePending(store: Storage): void {
  store.setItem(GENERATION_KEY, encode(globalThis.crypto.getRandomValues(new Uint8Array(16))));
}

async function readPin(store: Storage, keys: PinKeys, caseId: string, expected: string): Promise<CheckpointPin | null> {
  const raw = store.getItem(keys.slot);
  let pin = raw === null ? null : await open(keys, raw, caseId);
  checkGeneration(store, expected);
  if (raw !== null && !pin) store.removeItem(keys.slot);
  // One-time migration of a plaintext v1 entry for this case.
  const legacyRaw = store.getItem(LEGACY_PREFIX + caseId);
  if (legacyRaw !== null) {
    let legacy: unknown = null;
    try { legacy = JSON.parse(legacyRaw); } catch { /* removed below */ }
    if (valid(legacy, caseId) && (!pin || legacy.revision > pin.revision)) {
      pin = copy(legacy);
      const sealed = await seal(keys, pin);
      checkGeneration(store, expected);
      store.setItem(keys.slot, sealed);
    }
    store.removeItem(LEGACY_PREFIX + caseId);
  }
  return pin;
}

export function loadRememberedPin(caseId: string, recoveryCode: string): Promise<CheckpointPin | null> {
  const initial = storage();
  let expected: string;
  try { if (!initial) return Promise.resolve(null); expected = generation(initial); } catch { return Promise.resolve(null); }
  return serialized(async () => {
    const store = storage();
    if (!store || !/^[a-f0-9]{64}$/.test(caseId)) return null;
    try { checkGeneration(store, expected); return await readPin(store, await pinKeys(recoveryCode), caseId, expected); }
    catch { return null; } // Unreadable storage behaves as not remembered.
  }).catch(() => null);
}

/** Only ever moves forward: a lower revision never overwrites a remembered pin. */
export function rememberPin(pin: CheckpointPin, recoveryCode: string): Promise<boolean> {
  const initial = storage();
  let expected: string;
  try { if (!initial) return Promise.resolve(false); expected = generation(initial); } catch { return Promise.resolve(false); }
  return serialized(async () => {
    const store = storage();
    if (!store || !valid(pin, pin.caseId)) return false;
    try {
      const keys = await pinKeys(recoveryCode);
      const existing = await readPin(store, keys, pin.caseId, expected);
      // A different owner key, a same-revision fork, or a key epoch that moves
      // backwards is a conflict: never overwrite the remembered pin with it.
      if (existing && (existing.ownerFingerprint !== pin.ownerFingerprint ||
          (existing.revision === pin.revision && (existing.digest !== pin.digest || existing.keyEpoch !== pin.keyEpoch)) ||
          (existing.revision < pin.revision && existing.keyEpoch > pin.keyEpoch))) return false;
      if (existing && existing.revision > pin.revision) return true;
      const sealed = await seal(keys, pin);
      checkGeneration(store, expected);
      store.setItem(keys.slot, sealed);
      return true;
    } catch { return false; }
  }).catch(() => false);
}

export function forgetPin(caseId: string, recoveryCode: string): Promise<void> {
  const initial = storage();
  if (!initial) return Promise.resolve();
  try { invalidatePending(initial); } catch { return Promise.reject(new Error('Device pins could not be cleared')); }
  return serialized(async () => {
    const store = storage();
    if (!store) return;
    try { store.removeItem(LEGACY_PREFIX + caseId); } catch { /* Nothing stored. */ }
    try { store.removeItem((await pinKeys(recoveryCode)).slot); } catch { /* Nothing stored. */ }
  });
}

/** Invalidates already-started writes before awaiting any lock or crypto. The
 * nonsecret generation tombstone survives Forget to prevent resurrection. */
export async function forgetAllRememberedPins(): Promise<void> {
  const store = storage();
  if (!store) return;
  invalidatePending(store);
  const remove = async () => {
    const keys = Array.from({ length: store.length }, (_, index) => store.key(index));
    for (const key of keys) if (key && devicePinKey(key)) {
      store.removeItem(key);
      if (store.getItem(key) !== null) throw new Error('Device pins could not be cleared');
    }
  };
  if (typeof window !== 'undefined' && window.navigator?.locks) await serialized(remove);
  else await remove(); // Writes fail closed without Web Locks.
}

/** Storage keys this module may own, for "forget this device". */
export function devicePinKey(key: string): boolean {
  return key.startsWith(PIN_PREFIX) || key.startsWith(LEGACY_PREFIX);
}

/** A retained newer/conflicting pin must be reconciled before another mutation.
 * Missing storage is not proof of conflict and remains an explicit recovery warning. */
export async function rememberedPinRequiresRefresh(pin: CheckpointPin, recoveryCode: string): Promise<boolean> {
  const prior = await loadRememberedPin(pin.caseId, recoveryCode);
  return prior !== null && (prior.ownerFingerprint !== pin.ownerFingerprint || prior.revision > pin.revision ||
    prior.keyEpoch > pin.keyEpoch || (prior.revision === pin.revision && (prior.digest !== pin.digest || prior.keyEpoch !== pin.keyEpoch)));
}
