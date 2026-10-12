import { createClipboardGuard } from '../../../lib/confidential/clipboard';
import type { ClipboardClearState, ClipboardEnvironment } from '../../../lib/confidential/clipboard';

function environment(options: { focused?: boolean; copyOk?: boolean; clearOk?: boolean } = {}) {
  let clock = 0, focused = options.focused ?? true;
  const timers: { at: number; callback: () => void; id: number }[] = [];
  const focusListeners = new Set<() => void>();
  let nextId = 1;
  const board: { value: string | null } = { value: null };
  const env: ClipboardEnvironment = {
    copy: async text => { if (options.copyOk === false) return false; board.value = text; return true; },
    clear: async () => { if (options.clearOk === false) return false; board.value = ''; return true; },
    hasFocus: () => focused,
    onFocus: listener => { focusListeners.add(listener); return () => focusListeners.delete(listener); },
    setTimer: (callback, ms) => { const id = nextId++; timers.push({ at: clock + ms, callback, id }); return id; },
    clearTimer: handle => { const index = timers.findIndex(timer => timer.id === handle); if (index >= 0) timers.splice(index, 1); },
    now: () => clock,
  };
  return {
    env, board, focusListeners,
    advance: async (ms: number) => {
      clock += ms;
      for (const timer of timers.filter(item => item.at <= clock)) { timers.splice(timers.indexOf(timer), 1); timer.callback(); }
      await new Promise(resolve => setImmediate(resolve));
    },
    focus: async () => { focused = true; for (const listener of [...focusListeners]) listener(); await new Promise(resolve => setImmediate(resolve)); },
    blur: () => { focused = false; },
  };
}

describe('recovery code clipboard auto-clear', () => {
  test('clears after one minute and reports each step', async () => {
    const states: ClipboardClearState[] = [];
    const world = environment();
    const guard = createClipboardGuard(state => states.push(state), world.env);
    expect(await guard.copy('CODE')).toBe(true);
    expect(world.board.value).toBe('CODE');
    await world.advance(59_000);
    expect(world.board.value).toBe('CODE');
    await world.advance(1_000);
    expect(world.board.value).toBe('');
    expect(states).toEqual(['copied', 'cleared']);
  });

  test('waits for the page to regain focus before clearing', async () => {
    const states: ClipboardClearState[] = [];
    const world = environment();
    const guard = createClipboardGuard(state => states.push(state), world.env);
    await guard.copy('CODE');
    world.blur();
    await world.advance(60_000);
    expect(world.board.value).toBe('CODE');
    await world.focus();
    expect(world.board.value).toBe('');
    expect(states).toEqual(['copied', 'cleared']);
    expect(world.focusListeners.size).toBe(0);
  });

  test('gives up (and says so) rather than overwriting the clipboard much later', async () => {
    const states: ClipboardClearState[] = [];
    const world = environment();
    const guard = createClipboardGuard(state => states.push(state), world.env);
    await guard.copy('CODE');
    world.blur();
    await world.advance(60_000 + 31 * 60_000);
    await world.focus();
    expect(world.board.value).toBe('CODE');
    expect(states).toEqual(['copied', 'clear-failed']);
  });

  test('copying again restarts the minute; a failed copy or clear is reported', async () => {
    const states: ClipboardClearState[] = [];
    const world = environment();
    const guard = createClipboardGuard(state => states.push(state), world.env);
    await guard.copy('ONE');
    await world.advance(50_000);
    await guard.copy('TWO');
    await world.advance(50_000);
    expect(world.board.value).toBe('TWO');
    await world.advance(10_000);
    expect(world.board.value).toBe('');
    const failing = environment({ copyOk: false });
    const failedStates: ClipboardClearState[] = [];
    expect(await createClipboardGuard(state => failedStates.push(state), failing.env).copy('X')).toBe(false);
    expect(failedStates).toEqual(['idle']);
    const stuck = environment({ clearOk: false });
    const stuckStates: ClipboardClearState[] = [];
    await createClipboardGuard(state => stuckStates.push(state), stuck.env).copy('X');
    await stuck.advance(60_000);
    expect(stuckStates).toEqual(['copied', 'clear-failed']);
  });

  test('a detached guard (component gone) still clears but stops reporting', async () => {
    const states: ClipboardClearState[] = [];
    const world = environment();
    const guard = createClipboardGuard(state => states.push(state), world.env);
    await guard.copy('CODE');
    guard.detach();
    await world.advance(60_000);
    expect(world.board.value).toBe('');
    expect(states).toEqual(['copied']);
  });
});
