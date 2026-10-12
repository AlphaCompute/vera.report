import { test, expect } from '@playwright/test';
import { bundleFixture } from './support/fixtureBundle';

// The component fixtures (legal-report-view, legal-request-status) depend on
// this bundler failing loudly instead of silently skipping their checks.
const render = 'window.value = subject.value;';

test('an unmapped import fails with the import and its importer named', async () => {
  await expect(bundleFixture({ entry: 'qa/local-tests/support/samples/unmapped.ts', render, stubs: {} }))
    .rejects.toThrow(/unmapped imports:\n  '@\/lib\/confidential\/doesNotExist' imported by qa\/local-tests\/support\/samples\/unmapped\.ts/);
});

test('a module with network I/O cannot be bundled without a stub', async () => {
  await expect(bundleFixture({ entry: 'qa/local-tests/support/samples/network.ts', render, stubs: {} }))
    .rejects.toThrow(/reaches network modules without a stub:\n  qa\/local-tests\/support\/samples\/network\.ts -> lib\/confidential\/legalAuth\.ts/);
});

test('stale stubs are refused, whether missing from the repository or no longer imported', async () => {
  const stubs = { 'lib/confidential/legalAuth.ts': 'exports.legalAuthConfig = () => null;' };
  await expect(bundleFixture({ entry: 'qa/local-tests/support/samples/network.ts', render,
    stubs: { ...stubs, 'lib/confidential/removedModule.ts': '' } })).rejects.toThrow(/'lib\/confidential\/removedModule\.ts' does not exist/);
  await expect(bundleFixture({ entry: 'qa/local-tests/support/samples/network.ts', render,
    stubs: { ...stubs, 'lib/confidential/firmCase.ts': '' } })).rejects.toThrow(/never imports these stubbed modules: lib\/confidential\/firmCase\.ts/);
});

test('real imports resolve and only the named stub replaces a module', async ({ page }) => {
  const bundle = await bundleFixture({ entry: 'qa/local-tests/support/samples/network.ts', render,
    stubs: { 'lib/confidential/legalAuth.ts': 'exports.legalAuthConfig = () => "stubbed";' } });
  await page.setContent('<html><body></body></html>');
  await page.addScriptTag({ content: bundle });
  expect(await page.evaluate(() => (window as any).value.legalAuthConfig())).toBe('stubbed');
  expect(await page.evaluate(() => (window as any).value.selectedLegalCase())).toBeNull();
});
