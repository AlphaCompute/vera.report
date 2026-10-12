import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Run effects synchronously so the hook can be exercised without a DOM renderer.
const cleanups: (() => void)[] = [];
jest.mock('react', () => ({ ...jest.requireActual('react'),
  useEffect: (effect: () => void | (() => void)) => { const cleanup = effect(); if (cleanup) cleanups.push(cleanup); } }));
jest.mock('../../../lib/confidential/deviceVault', () => ({ browserVaultStore: jest.fn() }));

import { participantLockEnabled, statusWorkspaceUnlocked, useParticipantLock, PARTICIPANT_IDLE_LOCK_MS,
  PARTICIPANT_LOCK_NAVIGATION, holdParticipantLock, useParticipantLockHold, useLockAwareUnloadPrompt } from '../../../lib/confidential/participantLock';
import { automaticallyLockParticipantTabs, deviceLockedInThisTab, lockParticipantTabs, lockParticipantTabsForSignOut,
  subscribeDeviceLock } from '../../../lib/confidential/deviceWorkspace';

const original = process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
const originalChannel = Object.getOwnPropertyDescriptor(globalThis, 'BroadcastChannel');
let replace: jest.Mock, posted: jest.Mock;

beforeEach(() => {
  jest.useFakeTimers();
  replace = jest.fn(); posted = jest.fn();
  Object.defineProperty(globalThis, 'window', { value: Object.assign(new EventTarget(), { location: { replace } }), configurable: true });
  // Every tab of the origin shares one channel: a post reaches all other subscribers.
  const tabs = new Set<{ onmessage: ((event: { data: unknown }) => void) | null }>();
  Object.defineProperty(globalThis, 'BroadcastChannel', { configurable: true, value: class {
    onmessage: ((event: { data: unknown }) => void) | null = null;
    constructor() { tabs.add(this); }
    postMessage(data: unknown) { posted(data); for (const tab of tabs) if (tab !== this) tab.onmessage?.({ data }); }
    close() { tabs.delete(this); }
  } });
});
afterEach(() => {
  while (cleanups.length) cleanups.pop()!();
  jest.useRealTimers();
  if (original === undefined) delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES; else process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = original;
  for (const [key, descriptor] of [['window', originalWindow], ['BroadcastChannel', originalChannel]] as const) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete (globalThis as Record<string, unknown>)[key];
  }
});

describe('confidential mode off', () => {
  beforeEach(() => { process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0'; });

  test('legacy /status and /report neither subscribe to nor broadcast the participant lock', () => {
    expect(participantLockEnabled('/status')).toBe(false);
    useParticipantLock('/status', false);                                  // /status before any lookup
    useParticipantLock('/status', statusWorkspaceUnlocked(null));         // /status after a legacy lookup
    expect(cleanups).toHaveLength(0);
    jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS * 2);
    window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: true }));
    lockParticipantTabs();                                                  // e.g. a /legal tab locking
    expect(posted).toHaveBeenCalledTimes(1);
    expect(replace).not.toHaveBeenCalled();
  });

  test('a legacy credential never counts as an unlocked workspace', () => {
    expect(statusWorkspaceUnlocked(null)).toBe(false);
    expect(statusWorkspaceUnlocked('VRA-LEGACY-CREDENTIAL')).toBe(false);
    // /status must derive the lock from the confidential recovery code only.
    const source = readFileSync(join(__dirname, '../../../pages/status.tsx'), 'utf8');
    const call = source.match(/useParticipantLock\(([^;]*)\);/)?.[1] ?? '';
    expect(call).toContain('statusWorkspaceUnlocked(recoveryCode)');
    expect(call).not.toContain('activeCredential');
  });

  test('/legal pages keep their lock', () => {
    expect(participantLockEnabled('/legal')).toBe(true);
    useParticipantLock('/legal', true);
    jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS);
    expect(replace).toHaveBeenCalledWith('/legal');
  });
});

describe('confidential mode on', () => {
  beforeEach(() => { process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '1'; });

  test('an unlocked recovery workspace locks every subscribed tab after idling', () => {
    expect(statusWorkspaceUnlocked('recovery-code')).toBe(true);
    useParticipantLock('/status', statusWorkspaceUnlocked('recovery-code'));
    jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS - 1);
    expect(replace).not.toHaveBeenCalled();
    jest.advanceTimersByTime(1);
    expect(replace).toHaveBeenCalledWith('/status');
  });

  test('unsaved drafts and receipts ignore automatic locks but honor explicit locks', () => {
    const report = readFileSync(join(__dirname, '../../../pages/report.tsx'), 'utf8');
    expect(report).toContain("useParticipantLock('/status', false, false);");
    const receipt = readFileSync(join(__dirname, '../../../components/vera/confidential/RecoveryReceipt.tsx'), 'utf8');
    expect(receipt).toContain("useParticipantLock('/status', verified, verified);");
    useParticipantLock('/status', false, false);
    const discard = jest.fn(); window.addEventListener('vera:explicit-participant-discard', discard);
    automaticallyLockParticipantTabs();
    jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS * 2);
    window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: true }));
    expect(replace).not.toHaveBeenCalled();
    expect(discard).not.toHaveBeenCalled();
    lockParticipantTabs();
    expect(discard).toHaveBeenCalled();
    expect(replace).toHaveBeenCalledWith('/status');
  });

  test('one local lock navigates once despite channel echo and multiple hooks, while other tabs still receive it', () => {
    useParticipantLock('/status', false, false); // Parent intake page.
    useParticipantLock('/status', true);        // Its saved receipt.
    const remote = new BroadcastChannel('vera-participant-device/v1');
    const remoteLock = jest.fn(); remote.onmessage = event => remoteLock(event.data);
    const discard = jest.fn(), standDown = jest.fn();
    window.addEventListener('vera:explicit-participant-discard', discard);
    window.addEventListener(PARTICIPANT_LOCK_NAVIGATION, standDown);
    lockParticipantTabs(); // Local event plus echo to each same-tab subscriber.
    expect(replace).toHaveBeenCalledTimes(1);
    expect(replace).toHaveBeenCalledWith('/status');
    expect(discard).toHaveBeenCalledTimes(1);
    expect(standDown).toHaveBeenCalledTimes(1);
    expect(remoteLock).toHaveBeenCalledWith('lock');
    remote.postMessage('lock'); // A late remote signal cannot abort this navigation either.
    expect(replace).toHaveBeenCalledTimes(1);
    remote.close();
  });

  test('other-tab explicit locks clear an unsaved receipt; automatic broadcasts do not', () => {
    useParticipantLock('/status', false, false);
    const channel = new BroadcastChannel('vera-participant-device/v1');
    channel.postMessage('automatic-lock');
    expect(replace).not.toHaveBeenCalled();
    channel.postMessage('lock');
    expect(replace).toHaveBeenCalledWith('/status');
    channel.close();
  });

  test('Sign out on /legal locks every other tab and leaves this tab locked without racing the sign-out redirect', () => {
    const stored = new Map<string, string>();
    Object.assign(window, { sessionStorage: { getItem: (key: string) => stored.get(key) ?? null,
      setItem: (key: string, value: string) => { stored.set(key, value); }, removeItem: (key: string) => { stored.delete(key); } } });
    useParticipantLock('/legal', true);                                     // this tab
    const otherTab = new BroadcastChannel('vera-participant-device/v1');     // another open /legal tab
    const otherTabLocked = jest.fn(); otherTab.onmessage = event => otherTabLocked(event.data);
    expect(deviceLockedInThisTab()).toBe(false);
    lockParticipantTabsForSignOut();
    expect(otherTabLocked).toHaveBeenCalledWith('lock');                     // explicit lock, not the idle one
    expect(replace).not.toHaveBeenCalled();                                   // the sign-out redirect stays in charge
    expect(deviceLockedInThisTab()).toBe(true);                               // a kept-unlocked workspace waits for a click
    otherTab.close();
    const portal = readFileSync(join(__dirname, '../../../components/vera/confidential/LegalPortal.tsx'), 'utf8');
    expect(portal).toMatch(/lockParticipantTabsForSignOut\(\); signOutLegal\(gate\.config\);/);
  });

  test('a restored back/forward cache entry locks', () => {
    useParticipantLock('/status', true);
    window.dispatchEvent(Object.assign(new Event('pageshow'), { persisted: true }));
    expect(replace).toHaveBeenCalledWith('/status');
  });
  describe('in-progress evidence work', () => {
    test('the idle lock waits for an upload and locks as soon as it ends if the idle time passed', () => {
      useParticipantLock('/status', true);
      const release = holdParticipantLock();                                  // encrypt/upload/commit running
      jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS * 3);               // a long upload with no input
      expect(replace).not.toHaveBeenCalled();
      release();
      expect(replace).toHaveBeenCalledWith('/status');
    });

    test('work that ends before the idle time does not lock early, and the timer still runs', () => {
      useParticipantLock('/status', true);
      const release = holdParticipantLock();
      jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS / 2);
      release(); release();                                                 // a double release is harmless
      expect(replace).not.toHaveBeenCalled();
      jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS / 2);
      expect(replace).toHaveBeenCalledWith('/status');
    });

    test('input during the work restarts the idle time instead of locking at the end', () => {
      useParticipantLock('/status', true);
      const release = holdParticipantLock();
      jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS);
      window.dispatchEvent(new Event('pointerdown'));
      release();
      expect(replace).not.toHaveBeenCalled();
    });

    test("another tab's automatic lock is deferred until the work ends", () => {
      useParticipantLock('/status', true);
      const release = holdParticipantLock();
      const channel = new BroadcastChannel('vera-participant-device/v1');
      channel.postMessage('automatic-lock');
      expect(replace).not.toHaveBeenCalled();
      release();
      expect(replace).toHaveBeenCalledWith('/status');
      channel.close();
    });

    test('an explicit lock never waits for the work', () => {
      useParticipantLock('/status', true);
      const release = holdParticipantLock();
      lockParticipantTabs();
      expect(replace).toHaveBeenCalledWith('/status');
      release();
    });

    test('the lock tells upload guards to stand down before navigating', () => {
      useParticipantLock('/status', true);
      const order: string[] = [];
      window.addEventListener(PARTICIPANT_LOCK_NAVIGATION, () => order.push('stand down'));
      replace.mockImplementation(() => order.push('navigate'));
      automaticallyLockParticipantTabs();
      expect(order.slice(0, 2)).toEqual(['stand down', 'navigate']);
    });

    test('a long /legal file download is not cut off by the idle lock, but Lock still ends it', () => {
      useParticipantLock('/legal', true);
      useParticipantLockHold(true);                                          // a chunked download streaming
      jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS * 4);               // a large video on a slow link, no input
      expect(replace).not.toHaveBeenCalled();
      const channel = new BroadcastChannel('vera-participant-device/v1');
      channel.postMessage('automatic-lock');                                // another tab went idle
      expect(replace).not.toHaveBeenCalled();
      channel.postMessage('lock');                                          // another tab's explicit Lock
      expect(replace).toHaveBeenCalledWith('/legal');
      channel.close();
      replace.mockClear();
      lockParticipantTabs();                                                // navigation is already in flight
      expect(replace).not.toHaveBeenCalled();
    });

    test('the download controls hold the lock while a transfer or decrypt is running', () => {
      const root = join(__dirname, '../../../components/vera/confidential');
      const button = readFileSync(join(root, 'EvidenceDownloadButton.tsx'), 'utf8');
      expect(button).toContain('useParticipantLockHold(phase.kind === "running");');   // paused downloads do not hold
      const report = readFileSync(join(root, 'LegalReportView.tsx'), 'utf8');
      expect(report).toMatch(/function FileRow[\s\S]*?useParticipantLockHold\(busy\);[\s\S]*?function ChunkedFileRow/);
      expect(report).toMatch(/function ChunkedFileRow[\s\S]*?<EvidenceDownloadButton/);
    });

    test('a key replacement waits out the idle lock, and Finish locks without a Leave site? prompt', () => {
      const leaving = () => {
        const event = new Event('beforeunload', { cancelable: true });
        // Node Event exposes a readonly legacy boolean; browser BeforeUnloadEvent
        // has a writable string. Model that interface without changing runtime code.
        Object.defineProperty(event, 'returnValue', { value: '', writable: true });
        window.dispatchEvent(event); return event.defaultPrevented;
      };
      useParticipantLock('/legal', true);
      useLockAwareUnloadPrompt(true);                                       // the rotation checklist is open
      useParticipantLockHold(true);
      expect(leaving()).toBe(true);                                         // closing the tab asks first
      jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS * 3);               // waiting for IT to publish the file
      expect(replace).not.toHaveBeenCalled();
      replace.mockImplementation(() => { expect(leaving()).toBe(false); }); // the lock navigation is never held up
      lockParticipantTabs();                                                // Finish and lock (or Lock anyway)
      expect(replace).toHaveBeenCalledWith('/legal');
      const members = readFileSync(join(__dirname, '../../../pages/legal/members.tsx'), 'utf8');
      const checklist = members.slice(members.indexOf('function RotationChecklist'), members.indexOf('function Members'));
      expect(checklist).toContain('useLockAwareUnloadPrompt(true);');
      expect(checklist).toContain('useParticipantLockHold(true);');
      expect(members).not.toContain('"beforeunload"');
    });

    test('an inactive unload prompt never asks', () => {
      useLockAwareUnloadPrompt(false);
      const event = new Event('beforeunload', { cancelable: true });
      window.dispatchEvent(event);
      expect(event.defaultPrevented).toBe(false);
    });

    test('the Add evidence panel holds the lock while working and drops its unload prompt on lock', () => {
      useParticipantLockHold(true);
      useParticipantLock('/status', true);
      jest.advanceTimersByTime(PARTICIPANT_IDLE_LOCK_MS);
      expect(replace).not.toHaveBeenCalled();
      cleanups.shift()!();                                                  // the panel's work ends (effect cleanup)
      expect(replace).toHaveBeenCalledWith('/status');
      const panel = readFileSync(join(__dirname, '../../../components/vera/confidential/ConfidentialCaseStatus.tsx'), 'utf8');
      expect(panel).toContain('useParticipantLockHold(working);');
      expect(panel).toMatch(/addEventListener\(PARTICIPANT_LOCK_NAVIGATION, locking\)/);
    });
  });
});
