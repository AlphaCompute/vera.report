import { readFileSync } from 'node:fs';
import path from 'node:path';

const cleanups: (() => void)[] = [];
jest.mock('react', () => ({
  useRef: (value: unknown) => ({ current: value }),
  useState: (value: unknown) => [value, jest.fn()],
  useEffect: (effect: () => (() => void) | void) => { const cleanup = effect(); if (cleanup) cleanups.push(cleanup); },
}));
import { reportDraftAtRisk } from '../../../lib/reportDraft';
import { EXPLICIT_PARTICIPANT_DISCARD, useReceiptNavigationGuard } from '../../../lib/useReceiptNavigationGuard';

const report = readFileSync(path.resolve(__dirname, '../../../pages/report.tsx'), 'utf8');
const empty = { description: '', typed: '', files: 0, summary: '', contacts: { email: '', signal: '', imessage: '' } };

describe('report draft guard', () => {
  test('any typed narrative, unsent text, file, summary or contact between contact and confirm is at risk', () => {
    for (const step of ['report', 'files', 'details', 'jurisdiction', 'summary', 'confirm', 'contact', 'rewards-contact', 'category']) {
      expect(reportDraftAtRisk(step, empty)).toBe(false);
      expect(reportDraftAtRisk(step, { ...empty, description: 'What happened' })).toBe(true);
      expect(reportDraftAtRisk(step, { ...empty, typed: 'Half-typed' })).toBe(true);
      expect(reportDraftAtRisk(step, { ...empty, files: 1 })).toBe(true);
      expect(reportDraftAtRisk(step, { ...empty, summary: 'Summary' })).toBe(true);
      expect(reportDraftAtRisk(step, { ...empty, contacts: { ...empty.contacts, signal: '+1 555 555 0100' } })).toBe(true);
    }
    expect(reportDraftAtRisk('contact', { ...empty, contacts: { email: '  ', signal: '', imessage: '' } })).toBe(false);
    expect(reportDraftAtRisk('report', { ...empty, description: '   \n' })).toBe(false);
    // Before writing starts, and once sent (the receipt guard takes over), there is no draft to lose.
    for (const step of ['intro', 'rewards', 'submitting', 'submitted']) {
      expect(reportDraftAtRisk(step, { description: 'x', typed: 'x', files: 2, summary: 'x', contacts: { email: 'a@example.com', signal: '', imessage: '' } })).toBe(false);
    }
  });

  test('a reload with a draft asks first, but an explicit Lock clears the page without the prompt', () => {
    const priorWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
    const priorDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
    Object.defineProperty(globalThis, 'window', { configurable: true, value: Object.assign(new EventTarget(), {
      location: { href: 'https://vera.example/report' }, history: { state: {}, pushState: jest.fn() },
    }) });
    Object.defineProperty(globalThis, 'document', { configurable: true, value: new EventTarget() });
    const unload = () => {
      const event = new Event('beforeunload', { cancelable: true });
      Object.defineProperty(event, 'returnValue', { writable: true, value: '' });
      window.dispatchEvent(event);
      return event.defaultPrevented;
    };
    try {
      const router = { beforePopState: jest.fn(), events: { on: jest.fn(), off: jest.fn(), emit: jest.fn() } } as any;
      useReceiptNavigationGuard(router, reportDraftAtRisk('details', { ...empty, description: 'Long narrative' }));
      expect(unload()).toBe(true);
      window.dispatchEvent(new Event(EXPLICIT_PARTICIPANT_DISCARD));
      expect(unload()).toBe(false);
    } finally {
      while (cleanups.length) cleanups.pop()!();
      for (const [name, descriptor] of [['window', priorWindow], ['document', priorDocument]] as const) {
        if (descriptor) Object.defineProperty(globalThis, name, descriptor);
        else delete (globalThis as Record<string, unknown>)[name];
      }
    }
  });

  test('the report page wires the guard to the whole draft and keeps the upload prompt', () => {
    expect(report).toMatch(/const draftAtRisk = reportDraftAtRisk\(step, \{\s*description: formData\.description, typed: textInput, files: files\.length, summary: listingDraft\.summary, contacts: formData\.contacts,\s*\}\);/);
    expect(report).toContain('const draftGuard = useReceiptNavigationGuard(router, draftAtRisk);');
    expect(report).toContain('<AlertDialog open={draftGuard.open}');
    expect(report).toContain('onClick={draftGuard.leave}');
    expect(report).toContain('useLockAwareUnloadPrompt(uploadInProgress);');
    expect(report).not.toContain("addEventListener('beforeunload'");
  });

  test('a failed secure-service check is retried in place, never by a reload that clears the draft', () => {
    expect(report).not.toMatch(/Reload the page to try again/);
    const start = report.indexOf('data-testid="release-identity-failed"');
    expect(start).toBeGreaterThan(0);
    const block = report.slice(start, report.indexOf('</div>', start));
    expect(block).toContain('Your draft is still on this page.');
    expect(block).not.toMatch(/window\.location|router\.reload/);
    expect(block).toMatch(/onClick=\{\(\) => setReleaseIdentityAttempt\(n => n \+ 1\)\}>\s*Try again/);
    expect(report).toMatch(/\}, \[confidential, releaseIdentityAttempt\]\);/);
  });
});
