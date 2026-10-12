import { copyText } from '../copyText';

/** Copy a recovery code and clear the clipboard again after a minute.
 * Browsers only allow clipboard writes while the page has focus, so if the
 * participant has moved to another app the clear waits until they come back.
 * Nothing can clear it after this page is closed; the UI says so. */
export const CLIPBOARD_CLEAR_MS = 60_000;
/** Stop waiting for focus after this long: an old code may have been replaced by then. */
const MAX_WAIT_MS = 30 * 60_000;

export type ClipboardClearState = 'idle' | 'copied' | 'cleared' | 'clear-failed';
export type ClipboardEnvironment = {
  copy: (text: string) => Promise<boolean>;
  clear: () => Promise<boolean>;
  hasFocus: () => boolean;
  onFocus: (listener: () => void) => () => void;
  setTimer: (callback: () => void, ms: number) => unknown;
  clearTimer: (handle: unknown) => void;
  now: () => number;
};

function browserEnvironment(): ClipboardEnvironment {
  return {
    copy: copyText,
    clear: async () => {
      try { await navigator.clipboard.writeText(''); return true; } catch { return copyText(' '); }
    },
    hasFocus: () => typeof document !== 'undefined' && document.hasFocus(),
    onFocus: listener => {
      window.addEventListener('focus', listener);
      return () => window.removeEventListener('focus', listener);
    },
    setTimer: (callback, ms) => setTimeout(callback, ms),
    clearTimer: handle => clearTimeout(handle as ReturnType<typeof setTimeout>),
    now: () => Date.now(),
  };
}

/** One pending clear at a time: copying again restarts the minute. */
export function createClipboardGuard(onChange: (state: ClipboardClearState) => void,
  env: ClipboardEnvironment = browserEnvironment(), delayMs = CLIPBOARD_CLEAR_MS) {
  let timer: unknown = null, stopFocus: (() => void) | null = null, generation = 0;
  let notify = onChange;
  const reset = () => {
    if (timer !== null) env.clearTimer(timer);
    timer = null; stopFocus?.(); stopFocus = null;
  };
  const clearNow = async (current: number, deadline: number) => {
    if (current !== generation) return;
    if (!env.hasFocus()) {
      if (env.now() > deadline) { reset(); notify('clear-failed'); return; }
      stopFocus?.();
      stopFocus = env.onFocus(() => { void clearNow(current, deadline); });
      return;
    }
    reset();
    const cleared = await env.clear().catch(() => false);
    if (current === generation) notify(cleared ? 'cleared' : 'clear-failed');
  };
  return {
    async copy(text: string): Promise<boolean> {
      reset();
      const current = ++generation;
      const copied = await env.copy(text).catch(() => false);
      if (current !== generation) return copied;
      if (!copied) { notify('idle'); return false; }
      notify('copied');
      const deadline = env.now() + delayMs + MAX_WAIT_MS;
      timer = env.setTimer(() => { timer = null; void clearNow(current, deadline); }, delayMs);
      return true;
    },
    /** Stop reporting (the component went away). A pending clear still runs
     * while the page stays open, so the code does not linger in the clipboard. */
    detach(): void { notify = () => {}; },
  };
}
