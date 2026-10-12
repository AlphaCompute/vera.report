import type { OwnerSession } from './ownerCase';
import type { CheckpointPin } from '../../enclave/src/confidential/recovery';
import { browserVaultStore } from './deviceVault';
import { recoveryFileText } from './recoveryFile';
import { forgetAllRememberedPins } from './devicePin';

// OpenPGP (via recovery.ts) loads on first use, not with /report or /status.
const recovery = () => import('../../enclave/src/confidential/recovery');

export type OwnerWorkspace = {
  format: 'vera-owner-workspace/v1'; recoveryCode: string; recoveryPackage: string; pin: CheckpointPin;
};
export async function ownerWorkspace(session: OwnerSession): Promise<OwnerWorkspace> {
  // Snapshot before awaiting crypto so a concurrent checkpoint advance cannot
  // pair a new pin with an older package.
  const code = session.recoveryCode, checkpoint = session.pinnedCheckpoint, pin = { ...session.pin };
  const saved = await (await recovery()).refreshOwnerRecovery(code, session.owner, checkpoint, pin);
  return { format: 'vera-owner-workspace/v1', recoveryCode: code, recoveryPackage: saved.encryptedPackage, pin: saved.pin };
}
export function ownerRecoveryText(value: OwnerWorkspace, statusUrl?: string): string {
  return recoveryFileText({ recoveryCode: value.recoveryCode, recoveryPackage: value.recoveryPackage, statusUrl });
}
export async function readOwnerWorkspace(value: unknown): Promise<OwnerWorkspace> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'format,pin,recoveryCode,recoveryPackage') throw new Error('Invalid saved report');
  const input = value as OwnerWorkspace;
  if (input.format !== 'vera-owner-workspace/v1' || typeof input.recoveryCode !== 'string' ||
      typeof input.recoveryPackage !== 'string') throw new Error('Invalid saved report');
  const restored = await (await recovery()).restoreOwnerRecovery(input.recoveryCode, input.recoveryPackage, input.pin);
  if (restored.pin.digest !== input.pin.digest) throw new Error('Saved report history does not match');
  return { format: input.format, recoveryCode: input.recoveryCode, recoveryPackage: input.recoveryPackage, pin: restored.pin };
}

const LOCK_EVENT = 'vera-participant-lock';
const LOCK_CHANNEL = 'vera-participant-device/v1';
export type ParticipantLockReason = 'manual' | 'automatic';
function broadcastParticipantLock(reason: ParticipantLockReason): void {
  // No credentials, identifiers or case metadata travel over the channel.
  window.dispatchEvent(new CustomEvent(LOCK_EVENT, { detail: reason }));
  if (typeof BroadcastChannel !== 'undefined') {
    const channel = new BroadcastChannel(LOCK_CHANNEL);
    channel.postMessage(reason === 'automatic' ? 'automatic-lock' : 'lock'); channel.close();
  }
}
/** An explicit lock (including Forget this device) clears unsaved tabs too. */
export function lockParticipantTabs(): void { broadcastParticipantLock('manual'); }
export function automaticallyLockParticipantTabs(): void { broadcastParticipantLock('automatic'); }
// This tab's own lock subscribers, so sign-out can stop listening before it
// broadcasts (a BroadcastChannel also reaches other channels in the same tab).
const tabSubscriptions = new Set<() => void>();
export function subscribeDeviceLock(listener: (reason: ParticipantLockReason) => void): () => void {
  const local = (event: Event) => listener((event as CustomEvent).detail === 'automatic' ? 'automatic' : 'manual');
  window.addEventListener(LOCK_EVENT, local);
  const channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(LOCK_CHANNEL);
  if (channel) channel.onmessage = event => {
    if (event.data === 'lock') listener('manual');
    else if (event.data === 'automatic-lock') listener('automatic');
  };
  const unsubscribe = () => { tabSubscriptions.delete(unsubscribe); window.removeEventListener(LOCK_EVENT, local); channel?.close(); };
  tabSubscriptions.add(unsubscribe);
  return unsubscribe;
}
/** Sign-out: lock every other participant tab (an explicit lock, so unsaved tabs
 * clear too) and mark this tab locked so a workspace kept unlocked on this device
 * waits for a click when the tab returns. This tab stops listening first so its
 * own lock redirect cannot race the sign-out redirect the caller starts next. */
export function lockParticipantTabsForSignOut(): void {
  markDeviceLocked();
  for (const unsubscribe of Array.from(tabSubscriptions)) unsubscribe();
  broadcastParticipantLock('manual');
}
/** Per-tab marker: after a lock, a workspace kept unlocked on this device waits
 * for a click instead of reopening by itself. Holds no identifier or secret. */
const DEVICE_LOCKED = 'vera-legal-device-locked';
export function markDeviceLocked(): void {
  try { window.sessionStorage.setItem(DEVICE_LOCKED, '1'); } catch { /* Then the workspace simply waits for a click. */ }
}
export function clearDeviceLocked(): void {
  try { window.sessionStorage.removeItem(DEVICE_LOCKED); } catch { /* Nothing to clear. */ }
}
export function deviceLockedInThisTab(): boolean {
  try { return window.sessionStorage.getItem(DEVICE_LOCKED) !== null; } catch { return true; }
}
/** Same as WITHDRAWAL_FLOOR_PREFIX in releaseWithdrawals.ts (kept literal so this
 * module does not load the OpenPGP verifier). */
const WITHDRAWAL_FLOOR_PREFIX = 'vera-confidential-withdrawals/v1:';
function participantKey(key: string): boolean {
  return key.startsWith('vera-legal-requests:') || key.startsWith(WITHDRAWAL_FLOOR_PREFIX) || key === DEVICE_LOCKED ||
    key === 'vera-legal-organization' || key === 'vera-legal-invitation' || key === 'vera-legal-auth-pending' || key === 'vera-onboarding-auth-pending';
}
/** Clear only participant-owned app data. Failure is visible to the caller.
 * The generation tombstone remains in IndexedDB to reject stale writes.
 * Downloads, browser history and copies on other devices cannot be erased here. */
export async function forgetParticipantDevice(): Promise<void> {
  const errors: unknown[] = [];
  try { await forgetAllRememberedPins(); } catch (error) { errors.push(error); }
  try { await browserVaultStore().clear(); } catch (error) { errors.push(error); }
  for (const kind of ['localStorage', 'sessionStorage'] as const) {
    try {
      const storage = window[kind];
      const keys = Array.from({ length: storage.length }, (_, index) => storage.key(index)).filter((key): key is string => key !== null && participantKey(key));
      for (const key of keys) {
        storage.removeItem(key);
        if (storage.getItem(key) !== null) throw new Error('Device data was not removed');
      }
    } catch (error) { errors.push(error); }
  }
  try {
    if (typeof caches !== 'undefined') {
      for (const name of await caches.keys()) {
        if (name.startsWith('vera-confidential-') && !await caches.delete(name)) throw new Error('Private cache was not removed');
      }
    }
  } catch (error) { errors.push(error); }
  if (errors.length) throw new Error('Some VERA device data could not be cleared. Lock this workspace, then clear this site’s data in your browser settings.');
  lockParticipantTabs();
}
