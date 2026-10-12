const cleanups: (() => void)[] = [];
jest.mock('react', () => ({
  useRef: (value: unknown) => ({ current: value }),
  useState: (value: unknown) => [value, jest.fn()],
  useEffect: (effect: () => () => void) => cleanups.push(effect()),
}));
import { EXPLICIT_PARTICIPANT_DISCARD, useReceiptNavigationGuard } from '../../../lib/useReceiptNavigationGuard';

test('explicit participant discard bypasses receipt unload prevention, including route errors', () => {
  const priorWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const priorDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
  const events = new Map<string, (...args: any[]) => void>();
  Object.defineProperty(globalThis, 'window', { configurable: true, value: Object.assign(new EventTarget(), {
    location: { href: 'https://vera.example/report' }, history: { state: {}, pushState: jest.fn() },
  }) });
  Object.defineProperty(globalThis, 'document', { configurable: true, value: new EventTarget() });
  try {
    useReceiptNavigationGuard({ beforePopState: jest.fn(), events: {
      on: (name: string, handler: (...args: any[]) => void) => events.set(name, handler), off: jest.fn(),
    } } as any, true);
    const before = new Event('beforeunload', { cancelable: true });
    Object.defineProperty(before, 'returnValue', { writable: true, value: '' });
    window.dispatchEvent(before); expect(before.defaultPrevented).toBe(true);
    window.dispatchEvent(new Event(EXPLICIT_PARTICIPANT_DISCARD));
    events.get('routeChangeError')?.();
    const after = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(after); expect(after.defaultPrevented).toBe(false);
  } finally {
    while (cleanups.length) cleanups.pop()!();
    for (const [name, descriptor] of [['window', priorWindow], ['document', priorDocument]] as const) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete (globalThis as Record<string, unknown>)[name];
    }
  }
});
