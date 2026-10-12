import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const CASE_ID = 'ab'.repeat(32);

function fakeWindow() {
  const values = new Map<string, string>();
  return { sessionStorage: {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  }, values };
}

describe('legal case selection keeps case IDs out of URLs', () => {
  afterEach(() => { delete (globalThis as { window?: unknown }).window; jest.resetModules(); });

  test('selection survives a reload in the same tab through sessionStorage only', async () => {
    const win = fakeWindow();
    (globalThis as { window?: unknown }).window = win;
    const selection = await import('../../../lib/confidential/legalCaseSelection');
    selection.selectLegalCase(CASE_ID);
    expect([...win.values.values()]).toEqual([CASE_ID]);
    jest.resetModules();
    const reloaded = await import('../../../lib/confidential/legalCaseSelection');
    expect(reloaded.selectedLegalCase()).toBe(CASE_ID);
    reloaded.clearSelectedLegalCase();
    expect(reloaded.selectedLegalCase()).toBeNull();
  });

  test('rejects malformed IDs and tampered storage', async () => {
    const win = fakeWindow();
    (globalThis as { window?: unknown }).window = win;
    const selection = await import('../../../lib/confidential/legalCaseSelection');
    expect(() => selection.selectLegalCase('../admin')).toThrow();
    win.sessionStorage.setItem('vera-legal-open-case', 'not-a-case');
    expect(selection.selectedLegalCase()).toBeNull();
  });

  test('falls back to memory when storage is unavailable', async () => {
    (globalThis as { window?: unknown }).window = { get sessionStorage(): Storage { throw new Error('blocked'); } };
    const selection = await import('../../../lib/confidential/legalCaseSelection');
    selection.selectLegalCase(CASE_ID);
    expect(selection.selectedLegalCase()).toBe(CASE_ID);
  });

  test('no legal page puts a case ID in a route, link or return path', () => {
    const root = path.join(__dirname, '../../../pages/legal');
    const files: string[] = [];
    (function walk(dir: string) {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name);
        if (statSync(full).isDirectory()) walk(full); else files.push(full);
      }
    })(root);
    // No dynamic route: a case ID never appears in a legal page path.
    expect(files.filter(file => /\[.*\]/.test(path.basename(file)))).toEqual([]);
    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      expect(source).not.toMatch(/\/legal\/cases?\/\$\{/);
      expect(source).not.toMatch(/router\.query\.caseId/);
      expect(source).not.toMatch(/returnPath=\{`[^`]*\$\{/);
      expect(source).not.toMatch(/legalCaseHref\(/);
    }
  });
});
