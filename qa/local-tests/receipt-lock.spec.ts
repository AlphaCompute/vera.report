import { acknowledgeReportEntry } from '../support/report-entry';
import { expect, test } from '@playwright/test';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import ts from 'typescript';
import { bundleFixture } from './support/fixtureBundle';
import { encodeRecoveryCodeV2 } from '../../enclave/src/confidential/recoveryCode';

let bundle: string;
let warningBundle: string;
test.beforeAll(async () => {
  const temporary = mkdtempSync(join(tmpdir(), 'vera-receipt-lock-'));
  try {
    const modules: Record<string, string> = {};
    for (const [name, path] of Object.entries({ guard: 'lib/useReceiptNavigationGuard.ts',
      lock: 'lib/confidential/participantLock.ts', workspace: 'lib/confidential/deviceWorkspace.ts' })) {
      modules[name] = ts.transpileModule(readFileSync(resolve(__dirname, '../..', path), 'utf8'), {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
      }).outputText;
    }
    // Real receipt/lock hooks and broadcast handler, synthetic unsaved receipt.
    // Crypto and storage imports are unused: this does not claim submission acceptance.
    writeFileSync(join(temporary, 'entry.js'), `
      const React = require('react');
      const sources = ${JSON.stringify(modules)}, cache = {};
      function load(name) {
        if (cache[name]) return cache[name];
        const exports = cache[name] = {};
        new Function('exports', 'require', sources[name])(exports, id => {
          if (id === 'react') return React;
          if (id === '../useReceiptNavigationGuard') return load('guard');
          if (id === './deviceWorkspace') return load('workspace');
          if (id === './config') return { confidentialCasesEnabled: () => true };
          return {};
        });
        return exports;
      }
      window.receiptLocks = load('workspace');
      function Receipt() {
        const guard = load('guard').useReceiptNavigationGuard(window.next.router, true);
        load('lock').useParticipantLock('/status', false, false);
        return React.createElement('div', null, 'Synthetic unsaved recovery secret',
          guard.open ? React.createElement('div', { role: 'alertdialog' }, 'Save before leaving') : null);
      }
      require('react-dom/client').createRoot(document.getElementById('lock-fixture')).render(React.createElement(Receipt));
    `);
    const { webpack } = require('next/dist/compiled/webpack/webpack');
    await new Promise<void>((yes, no) => {
      const compiler = webpack({ mode: 'development', devtool: false, target: 'web', entry: join(temporary, 'entry.js'),
        output: { path: temporary, filename: 'bundle.js' }, resolve: { modules: [resolve(__dirname, '../../node_modules')] } });
      compiler.run((error: Error | null, stats: any) => compiler.close((closeError: Error | null) => {
        if (error || closeError || stats?.hasErrors()) no(error ?? closeError ?? new Error(stats.toString())); else yes();
      }));
    });
    bundle = readFileSync(join(temporary, 'bundle.js'), 'utf8');
  } finally { rmSync(temporary, { force: true, recursive: true }); }
  const guard = ts.transpileModule(readFileSync(resolve(__dirname, '../../lib/useReceiptNavigationGuard.ts'), 'utf8'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  warningBundle = await bundleFixture({ entry: 'components/vera/confidential/RecoveryLeaveDialog.tsx', stubs: {}, render: `
    const React = require('react');
    const guard = {};
    new Function('exports', 'require', ${JSON.stringify(guard)})(guard, () => React);
    function ReceiptWarning() {
      const navigation = guard.useReceiptNavigationGuard(window.next.router, true);
      return React.createElement(React.Fragment, null,
        React.createElement('a', { href: '/status' }, 'Open synthetic report status'),
        React.createElement(subject.RecoveryLeaveDialog, { open: navigation.open, recoveryCode: window.syntheticRecoveryCode,
          onStay: navigation.stay, onLeave: navigation.leave }));
    }
    require('react-dom/client').createRoot(document.getElementById('warning-fixture')).render(React.createElement(ReceiptWarning));
  ` });
});

for (const navigation of ['link', 'back'] as const) {
  test(`recovery warning stays usable on a small screen after ${navigation} navigation`, async ({ page, context }) => {
    const code = await encodeRecoveryCodeV2(new Uint8Array(32).fill(19));
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.setViewportSize({ width: 390, height: 650 });
    await page.goto(navigation === 'back' ? '/report?before-receipt=1' : '/report');
    await acknowledgeReportEntry(page);
    await expect.poll(() => page.evaluate(() => !!(window as any).next?.router?.isReady)).toBe(true);
    // beforePopState handles same-document Back. A document-level departure
    // uses the browser's beforeunload prompt instead of a custom React dialog.
    if (navigation === 'back') {
      await page.evaluate(() => (window as any).next.router.push('/report'));
      await acknowledgeReportEntry(page);
    }
    await page.evaluate(code => {
      (window as any).syntheticRecoveryCode = code;
      const root = document.createElement('div'); root.id = 'warning-fixture'; document.body.appendChild(root);
      Object.defineProperty(navigator.clipboard, 'writeText', { configurable: true, value: async () => { throw new Error('Synthetic clipboard API denial'); } });
    }, code);
    await page.evaluate(script => { new Function(script)(); }, warningBundle);
    await expect(page.getByRole('link', { name: 'Open synthetic report status' })).toBeVisible();
    if (navigation === 'link') await page.getByRole('link', { name: 'Open synthetic report status' }).click();
    else await page.evaluate(() => history.back());
    const dialog = page.getByRole('alertdialog');
    await expect(dialog.getByRole('heading', { name: 'Save your recovery code before leaving' })).toBeVisible();
    await expect(page).toHaveURL(/\/report$/);
    await dialog.getByRole('button', { name: 'Copy recovery code', exact: true }).click();
    await expect(dialog.getByRole('button', { name: 'Copied', exact: true })).toBeVisible();
    expect(await page.evaluate(async code => (await navigator.clipboard.readText()) === code, code)).toBe(true);
    await page.evaluate(() => { document.execCommand = () => false; });
    await dialog.getByRole('button', { name: 'Copied', exact: true }).click();
    await expect(dialog.getByRole('alert').filter({ hasText: 'Copy failed.' })).toBeVisible();
    await expect(dialog.getByLabel('Recovery code to copy')).toHaveValue(code);
    await dialog.getByRole('button', { name: 'Stay on this page', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await page.getByRole('link', { name: 'Open synthetic report status' }).click();
    await expect(dialog).toBeVisible();
    const nativeDialogs: string[] = [];
    page.on('dialog', async dialog => { nativeDialogs.push(dialog.type()); await dialog.dismiss(); });
    await dialog.getByRole('button', { name: 'I saved my recovery code, leave', exact: true }).click();
    await expect(page).toHaveURL(/\/status$/);
    expect(nativeDialogs).toEqual([]);
  });
}

test('automatic lock preserves an unsaved receipt; explicit lock clears it despite the navigation guard', async ({ page }) => {
  await page.goto('/report');
  await acknowledgeReportEntry(page);
  await page.evaluate(() => { const root = document.createElement('div'); root.id = 'lock-fixture'; document.body.appendChild(root); });
  await page.evaluate(code => { new Function(code)(); }, bundle);
  await expect(page.getByText('Synthetic unsaved recovery secret', { exact: true })).toBeVisible();
  await page.evaluate(() => { void (window as any).next.router.push('/status').catch(() => {}); });
  await expect(page.getByRole('alertdialog')).toBeVisible();
  await page.evaluate(() => (window as any).receiptLocks.automaticallyLockParticipantTabs());
  await expect(page.getByRole('alertdialog')).toBeVisible();
  await expect(page).toHaveURL(/\/report$/);
  const nativeDialogs: string[] = [];
  page.on('dialog', async dialog => { nativeDialogs.push(dialog.type()); await dialog.dismiss(); });
  await page.evaluate(() => (window as any).receiptLocks.lockParticipantTabs());
  await expect(page).toHaveURL(/\/status$/);
  await expect(page.getByText('Synthetic unsaved recovery secret', { exact: true })).toHaveCount(0);
  expect(nativeDialogs).toEqual([]);
});
