import { EXPLICIT_PARTICIPANT_DISCARD } from '../useReceiptNavigationGuard';
import { useEffect } from 'react';
import { confidentialCasesEnabled } from './config';
import { automaticallyLockParticipantTabs, markDeviceLocked, subscribeDeviceLock } from './deviceWorkspace';

export type ParticipantLockDestination = '/status' | '/legal';
export const PARTICIPANT_IDLE_LOCK_MS = 15 * 60 * 1000;

/** The shared /status lock exists only for confidential participant workspaces.
 * With confidential mode off, /status and /report are legacy pages holding
 * unsaved drafts and receipts; a lock broadcast there would silently discard
 * them. /legal pages are confidential-only and always keep the lock. */
export function participantLockEnabled(destination: ParticipantLockDestination): boolean {
  return destination === '/legal' || confidentialCasesEnabled();
}

/** Whether /status holds an unlocked confidential workspace. Only a confidential
 * recovery code counts; a legacy VRA/VRC credential lookup never does. */
export function statusWorkspaceUnlocked(recoveryCode: string | null): boolean {
  return confidentialCasesEnabled() && recoveryCode !== null;
}

/** Fired just before a lock replaces the page. In-progress work that normally
 * asks before the page unloads (an evidence upload) stands down, so the lock
 * is never left waiting on a "Leave site?" dialog with the private view open. */
export const PARTICIPANT_LOCK_NAVIGATION = 'vera:participant-lock-navigation';

// One broadcast reaches this tab through both its local event and its own
// BroadcastChannel subscriber. A receipt can also mount two lock hooks. Start
// only one navigation per Window, or a second replace aborts the first one.
// The replacement page has a fresh Window/JS realm and can lock normally.
const navigatingWindows = new WeakSet<Window>();

// Count of in-progress transfers (encrypt, upload, commit) on this page. While
// any is held, automatic locks are deferred; they run as soon as the last ends.
let workHolds = 0;
const workFinishedListeners = new Set<() => void>();

/** Defers automatic locks until the returned release is called. Explicit Lock
 * and Forget requests are never deferred. */
export function holdParticipantLock(): () => void {
  workHolds += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    workHolds -= 1;
    if (workHolds === 0) for (const listener of Array.from(workFinishedListeners)) listener();
  };
}
export function participantWorkInProgress(): boolean { return workHolds > 0; }
function onParticipantWorkFinished(listener: () => void): () => void {
  workFinishedListeners.add(listener);
  return () => { workFinishedListeners.delete(listener); };
}
/** Treats `active` work (an evidence encrypt/upload/commit, or a file download
 * and decrypt) as activity: the idle lock cannot navigate away mid-transfer. */
export function useParticipantLockHold(active: boolean): void {
  useEffect(() => active ? holdParticipantLock() : undefined, [active]);
}

/** Asks "Leave site?" before the page unloads while `active` work has its only
 * copy in this tab, but stands down when a participant lock navigates: a lock
 * must clear the private view instead of waiting on a dialog. */
export function useLockAwareUnloadPrompt(active: boolean): void {
  useEffect(() => {
    if (!active) return undefined;
    const unload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    const locking = () => window.removeEventListener('beforeunload', unload);
    window.addEventListener('beforeunload', unload);
    window.addEventListener(PARTICIPANT_LOCK_NAVIGATION, locking);
    return () => { window.removeEventListener('beforeunload', unload); window.removeEventListener(PARTICIPANT_LOCK_NAVIGATION, locking); };
  }, [active]);
}

/** A hard navigation clears the JS realm as well as the currently rendered
 * private view. No secret is included in the destination. Other participant tabs
 * receive the same lock signal. Browser history/downloads are unaffected.
 *
 * Unsaved drafts/receipts may opt out of automatic locking to avoid losing the
 * only copy. Explicit Lock and Forget requests always clear confidential tabs.
 * Automatic locks wait for in-progress work (see holdParticipantLock) and then
 * lock immediately if the idle time passed meanwhile. */
export function useParticipantLock(destination: ParticipantLockDestination, unlocked: boolean, followAutomatic = true): void {
  const enabled = participantLockEnabled(destination);
  useEffect(() => {
    if (!enabled) return undefined;
    let deferred = false;
    const lock = (reason: 'manual' | 'automatic') => {
      if (navigatingWindows.has(window)) return;
      navigatingWindows.add(window);
      markDeviceLocked();
      if (reason === 'manual') window.dispatchEvent(new Event(EXPLICIT_PARTICIPANT_DISCARD));
      window.dispatchEvent(new Event(PARTICIPANT_LOCK_NAVIGATION));
      try { window.location.replace(destination); }
      catch (error) { navigatingWindows.delete(window); throw error; }
    };
    const unsubscribe = subscribeDeviceLock(reason => {
      if (reason === 'manual') { lock('manual'); return; }
      if (!followAutomatic) return;
      if (participantWorkInProgress()) { deferred = true; return; }
      lock('automatic');
    });
    const finished = onParticipantWorkFinished(() => { if (deferred) { deferred = false; lock('automatic'); } });
    return () => { unsubscribe(); finished(); };
  }, [destination, enabled, followAutomatic]);
  useEffect(() => {
    if (!enabled || !unlocked || !followAutomatic) return;
    let timer: ReturnType<typeof setTimeout>;
    let idlePassed = false;
    const expire = () => {
      if (participantWorkInProgress()) { idlePassed = true; return; }
      automaticallyLockParticipantTabs();
    };
    const reset = () => { idlePassed = false; clearTimeout(timer); timer = setTimeout(expire, PARTICIPANT_IDLE_LOCK_MS); };
    reset();
    const finished = onParticipantWorkFinished(() => { if (idlePassed) { idlePassed = false; automaticallyLockParticipantTabs(); } });
    window.addEventListener('pointerdown', reset); window.addEventListener('keydown', reset);
    // Revisited back/forward cache entries must not resurrect an unlocked view.
    const restored = (event: PageTransitionEvent) => { if (event.persisted) automaticallyLockParticipantTabs(); };
    window.addEventListener('pageshow', restored);
    return () => { clearTimeout(timer); finished(); window.removeEventListener('pointerdown', reset); window.removeEventListener('keydown', reset);
      window.removeEventListener('pageshow', restored); };
  }, [enabled, unlocked, followAutomatic]);
}
