import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ts from 'typescript';

function compile(path: string) {
  return ts.transpileModule(readFileSync(resolve(__dirname, '../..', path), 'utf8'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
  }).outputText;
}

// The report reference arrives only in a fragment (older bookmarks). The page
// moves it into tab-scoped storage and replaces the history entry with the bare
// /legal/report, so it is never sent, shown in the address bar or kept in history.
const SELECTION_KEY = 'vera-legal-open-case';
const BARE_REPORT = /\/legal\/report$/;

test('report fragment is never transmitted and is removed from the address bar and history', async ({ page }) => {
  const caseId = 'ab'.repeat(32);
  const requests: string[] = [];
  page.on('request', request => requests.push(request.url(), request.postData() ?? ''));
  await page.goto('/legal');
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await page.goto(`/legal/report#${caseId}`);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page).toHaveURL(BARE_REPORT);
  expect(await page.evaluate(() => location.hash)).toBe('');
  expect(await page.evaluate(key => sessionStorage.getItem(key), SELECTION_KEY)).toBe(caseId);
  // Reload keeps the selection without the reference coming back into the URL.
  await page.reload();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  await expect(page).toHaveURL(BARE_REPORT);
  expect(await page.evaluate(key => sessionStorage.getItem(key), SELECTION_KEY)).toBe(caseId);
  // History holds the bare path in place of the fragment link.
  await page.goto('/status');
  await page.goBack();
  await expect(page).toHaveURL(BARE_REPORT);
  expect(await page.evaluate(() => location.hash)).toBe('');
  await page.goBack();
  await expect(page).toHaveURL(/\/legal$/);
  expect(requests.length).toBeGreaterThan(0);
  expect(requests.join('\n')).not.toContain(caseId);
  expect(requests.join('\n')).not.toContain('/legal/cases/');
});

test('decrypted active content is an opaque sanitized download, never executed', async ({ page }) => {
  // Exercise the actual exported download function; unused React/auth imports
  // are inert stubs, while filename handling is the real source module.
  const source = compile('components/vera/confidential/LegalPortal.tsx');
  const safe = compile('lib/confidential/safeDownload.ts');
  await page.goto('/legal');
  await page.evaluate(({ source, safe }) => {
    const load = (code: string, require: (id: string) => unknown) => {
      const exports = {};
      new Function('exports', 'require', code)(exports, require);
      return exports as any;
    };
    const safeApi = load(safe, () => ({}));
    (window as any).downloadApi = load(source, id => id === '@/lib/confidential/safeDownload' ? safeApi : {});
    const original = URL.createObjectURL.bind(URL);
    URL.createObjectURL = blob => {
      (window as any).downloadMime = (blob as Blob).type;
      return original(blob);
    };
  }, { source, safe });
  const payload = '<html><script>window.evidenceExecuted = true</script><body>synthetic evidence</body></html>';
  const download = page.waitForEvent('download');
  await page.evaluate(payload => (window as any).downloadApi.downloadBytes(payload, '../../unsafe\u202efile.html'), payload);
  const file = await download;
  expect(file.suggestedFilename()).toBe('unsafe_file.html');
  expect(readFileSync((await file.path())!, 'utf8')).toBe(payload);
  expect(await page.evaluate(() => (window as any).downloadMime)).toBe('application/octet-stream');
  expect(await page.evaluate(() => (window as any).evidenceExecuted)).toBeUndefined();
  await expect(page).toHaveURL(/\/legal$/);
});

test('Next navigation into the legal family loads a new document with its own CSP', async ({ page }) => {
  await page.goto('/status');
  await expect.poll(() => page.evaluate(() => !!(window as any).next?.router?.isReady)).toBe(true);
  const document = page.waitForResponse(response => response.request().isNavigationRequest() && new URL(response.url()).pathname === '/legal');
  await page.evaluate(() => { void (window as any).next.router.push('/legal').catch(() => {}); });
  const response = await document;
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  expect(response.headers()['content-security-policy']).toContain('https://identity.example');
  expect(response.headers()['referrer-policy']).toBe('no-referrer');
});
