import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import ts from 'typescript';
import { createCaseOwner, createOwnerRecovery, restoreOwnerRecovery } from '../../enclave/src/confidential/recovery';
import { signOwnerStatement } from '../../enclave/src/confidential/authorization';
import { recoveryFileText } from '../../lib/confidential/recoveryFile';
import { generateFirmIdentity } from '../../lib/confidential/firmKey';

// Synthetic fixtures use a fresh passphrase for each worker; no stored credential.
const password = randomBytes(32).toString('base64url');
test.beforeEach(async ({ page }) => {
  await page.route('**/api/monitoring/client', route => route.fulfill({ status: 204 }));
  await page.addInitScript(() => {
    Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true });
  });
});
const compiled = ts.transpileModule(readFileSync(resolve(__dirname, '../../lib/confidential/deviceVault.ts'), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const policy = ts.transpileModule(readFileSync(resolve(__dirname, '../../lib/confidential/passphraseStrength.ts'), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const script = `(() => {
  const policy = (() => { const exports = {}; ${policy}; return exports; })();
  const require = name => { if (name === './passphraseStrength') return policy; throw new Error('Unbundled vault dependency: ' + name); };
  const exports = {}; ${compiled}; window.vaultApi = exports;
})();`;
async function seed(page: Page, role: 'owner' | 'legal', value: unknown) {
  await page.evaluate(script);
  await page.evaluate(async ({ role, value, password }) => {
    const api = (window as any).vaultApi;
    await api.createDeviceVault(api.browserVaultStore(), role, password, value);
  }, { role, value, password });
}
async function ownerFixture() {
  const owner = await createCaseOwner();
  const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1,
    keyEpoch: 1, previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: Date.now() }, owner.privateKey);
  const recovery = await createOwnerRecovery(owner, checkpoint);
  return { owner, value: { format: 'vera-owner-workspace/v1', recoveryCode: recovery.recoveryCode,
    recoveryPackage: recovery.encryptedPackage, pin: recovery.pin } };
}

test('owner returns, downloads a working recovery file offline, opens an older backup, and forgets across tabs', async ({ page, context, browser }) => {
  const { value } = await ownerFixture();
  const sent: string[] = [];
  page.on('request', request => { sent.push(request.url(), request.postData() ?? ''); });
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Offline for this test' }));
  await page.goto('/status');
  await seed(page, 'owner', value);
  await page.evaluate(() => localStorage.setItem('unrelated-setting', 'preserve'));
  await page.reload();
  await page.getByLabel('Device passphrase', { exact: true }).fill('incorrect but long password');
  await page.getByRole('button', { name: 'Open saved report' }).click();
  await expect(page.getByText('The saved report could not be unlocked.', { exact: false })).toBeVisible();
  await page.getByLabel('Device passphrase', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Open saved report' }).click();
  await expect(page.getByRole('button', { name: 'Download recovery file', exact: true })).toBeVisible();
  // One "This device" panel with a single choice; the recovery file is the only backup.
  await expect(page.getByRole('heading', { name: 'This device', exact: true })).toHaveCount(1);
  await expect(page.getByRole('radio', { name: /My report, protected by a device passphrase/ })).toBeChecked();
  await expect(page.getByText(/workspace|case references|key file/i)).toHaveCount(0);
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download recovery file', exact: true }).click();
  const text = readFileSync((await (await downloaded).path())!, 'utf8');
  expect(text).toContain(value.recoveryCode);
  const line = text.split('\n').find(line => line.startsWith('{"format":"vera-owner-recovery/v'))!;
  expect((await restoreOwnerRecovery(value.recoveryCode, line)).pin).toEqual(value.pin);
  expect(sent.join('\n')).not.toContain(value.recoveryCode);

  // Encrypted backup files from an earlier version of the page still open, without saving anything.
  const fresh = await browser.newContext();
  const other = await fresh.newPage();
  await other.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Offline' }));
  await other.goto(new URL('/status', page.url()).href);
  await other.evaluate(script);
  const older = await other.evaluate(async ({ value, password }) =>
    (window as any).vaultApi.exportTemporaryWorkspace('owner', password, value), { value, password });
  expect(older).not.toContain(value.recoveryCode);
  await other.getByText('Other ways to open', { exact: true }).click();
  await expect(other.getByRole('heading', { name: 'Open an older encrypted backup file', exact: true })).toBeVisible();
  await other.getByLabel('Encrypted backup file', { exact: true }).setInputFiles({ name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(older) });
  await other.getByLabel('Backup passphrase', { exact: true }).fill(password);
  await other.getByRole('button', { name: 'Open backup', exact: true }).click();
  await expect(other.getByRole('radio', { name: /Nothing \(default\)/ })).toBeChecked();
  expect(await other.evaluate(() => (window as any).vaultApi.browserVaultStore().list())).toEqual([]);
  await fresh.close();

  const second = await context.newPage(); await second.goto('/status');
  await expect(second.getByRole('button', { name: 'Open saved report' })).toBeVisible();
  // Inspect each tab in the foreground; background navigation may pause rendering.
  await page.bringToFront();
  await page.getByRole('button', { name: 'Forget this device', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm: forget this device' }).click();
  // Empty saved-report sections are intentionally omitted. Verify the actual
  // cross-tab deletion and cleared private view, not obsolete empty-state copy.
  for (const tab of [page, second]) {
    await tab.bringToFront();
    await expect(tab.getByRole('button', { name: 'Open saved report', exact: true })).toHaveCount(0);
    await expect(tab.getByLabel('Recovery code', { exact: true })).toBeVisible();
    await expect(tab.getByRole('button', { name: 'Download recovery file', exact: true })).toHaveCount(0);
    await tab.evaluate(script);
    expect(await tab.evaluate(() => (window as any).vaultApi.browserVaultStore().list())).toEqual([]);
  }
  expect(await page.evaluate(() => localStorage.getItem('unrelated-setting'))).toBe('preserve');
});

test('v2 recovery file opens locally and QR and print never transmit the secret', async ({ page }) => {
  const { value } = await ownerFixture();
  expect(value.recoveryCode.split('-')).toHaveLength(14);
  const sent: string[] = [];
  page.on('request', request => { sent.push(request.url(), request.postData() ?? ''); });
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Offline' }));
  await page.goto('/status');
  // The file input exists in SSR HTML before React attaches its change handler.
  // Use the hydrated, user-visible picker so a fast upload cannot be lost.
  await expect.poll(() => page.evaluate(() => !!(window as any).next?.router?.isReady)).toBe(true);
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Open recovery file', exact: true }).click();
  await (await chooser).setFiles({ name: 'wrong.txt', mimeType: 'text/plain', buffer: Buffer.from('not a recovery file') });
  const input = page.locator('input[type="file"][accept=".txt,text/plain"]');
  await expect(page.getByRole('alert').filter({ hasText: 'does not contain a VERA recovery code' })).toBeVisible();
  await input.setInputFiles({ name: 'vera-private-recovery.txt', mimeType: 'text/plain',
    buffer: Buffer.from(recoveryFileText({ recoveryCode: value.recoveryCode, recoveryPackage: value.recoveryPackage })) });
  await expect(page.getByRole('button', { name: 'Download recovery file', exact: true })).toBeVisible();
  await page.getByText('Show recovery code and printable sheet', { exact: true }).click();
  await expect(page.getByRole('button', { name: 'Copy', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Print recovery sheet', exact: true })).toBeVisible();
  await page.evaluate(() => { window.print = () => {
    (window as any).printedRecoverySheet = document.querySelector('.vera-print-sheet')?.textContent;
    (window as any).printedRecoveryQr = document.querySelector('.vera-print-sheet svg[role="img"]') !== null;
  }; });
  await page.getByRole('button', { name: 'Print recovery sheet', exact: true }).click();
  const printed = await page.evaluate(() => ({ text: (window as any).printedRecoverySheet, qr: (window as any).printedRecoveryQr }));
  expect(printed.text).toContain('Anyone who has it can open your report');
  expect(printed.qr).toBe(true);
  for (const group of value.recoveryCode.split('-')) expect(printed.text).toContain(group);
  await page.evaluate(() => window.dispatchEvent(new Event('afterprint')));
  await expect(page.locator('.vera-print-sheet')).toHaveCount(0);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download recovery file', exact: true }).click();
  const saved = readFileSync((await (await download).path())!, 'utf8');
  const packageText = saved.split('\n').find(line => line.startsWith('{"format":"vera-owner-recovery/v'))!;
  expect((await restoreOwnerRecovery(value.recoveryCode, packageText)).pin).toEqual(value.pin);
  expect(sent.join('\n')).not.toContain(value.recoveryCode);
  expect(sent.join('\n')).not.toContain(value.recoveryCode.replace(/-/g, ''));
  expect(sent.some(url => url.includes('/api/whistleblower/'))).toBe(false);
});

test('recovery Save As preserves the exact backup and handles cancel and failed writes', async ({ page }) => {
  const { value } = await ownerFixture();
  const sent: string[] = [];
  page.on('request', request => sent.push(request.url(), request.postData() ?? ''));
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Offline' }));
  await page.goto('/status');
  await seed(page, 'owner', value);
  await page.reload();
  await page.getByLabel('Device passphrase', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Open saved report' }).click();
  const download = page.getByRole('button', { name: 'Download recovery file', exact: true });
  await expect(download).toBeVisible();
  await page.evaluate(() => {
    const state = (window as any).recoverySave = { mode: 'cancel', text: '', closed: false, aborted: false, gesture: false, name: '' };
    Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: async (options: { suggestedName: string }) => {
      state.gesture = navigator.userActivation.isActive;
      state.name = options.suggestedName;
      if (state.mode === 'cancel') throw new DOMException('Cancelled', 'AbortError');
      return { createWritable: async () => ({
        write: async (text: string) => { if (state.mode === 'fail') throw new Error('Synthetic disk failure'); state.text = text; },
        close: async () => { state.closed = true; }, abort: async () => { state.aborted = true; },
      }) };
    } });
  });
  await download.click();
  await expect(page.getByRole('status').filter({ hasText: 'Save cancelled.' })).toBeVisible();
  await page.evaluate(() => { (window as any).recoverySave.mode = 'fail'; });
  await download.click();
  await expect(page.getByRole('alert').filter({ hasText: 'This browser could not save the file.' })).toBeVisible();
  expect(await page.evaluate(() => (window as any).recoverySave.aborted)).toBe(true);
  await page.evaluate(() => { (window as any).recoverySave.mode = 'save'; });
  await download.click();
  await expect(page.getByRole('status').filter({ hasText: 'Recovery file saved.' })).toBeVisible();
  const saved = await page.evaluate(() => (window as any).recoverySave);
  expect(saved.gesture).toBe(true);
  expect(saved.closed).toBe(true);
  expect(saved.name).toBe('vera-private-recovery.txt');
  const packageText = saved.text.split('\n').find((line: string) => line.startsWith('{"format":"vera-owner-recovery/v'))!;
  expect((await restoreOwnerRecovery(value.recoveryCode, packageText)).pin).toEqual(value.pin);
  await page.getByText('Download not starting? Save a copy manually', { exact: true }).click();
  await expect(page.getByLabel('Private recovery file contents', { exact: true })).toHaveValue(saved.text);
  const fallback = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Use browser download instead', exact: true }).click();
  expect(readFileSync((await (await fallback).path())!, 'utf8')).toBe(saved.text);
  expect(sent.join('\n')).not.toContain(value.recoveryCode);
});

test('blocked clipboard leaves the clean recovery code selectable without group labels', async ({ page }) => {
  const { value } = await ownerFixture();
  const sent: string[] = [];
  page.on('request', request => sent.push(request.url(), request.postData() ?? ''));
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
      writeText: async () => { throw new Error('Synthetic clipboard denial'); },
    } });
    document.execCommand = () => false;
  });
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Offline' }));
  await page.goto('/status');
  await seed(page, 'owner', value);
  await page.reload();
  await page.getByLabel('Device passphrase', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Open saved report' }).click();
  await page.getByText('Show recovery code and printable sheet', { exact: true }).click();
  await page.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Copy failed.' })).toBeVisible();
  const field = page.getByLabel('Recovery code to copy', { exact: true });
  await expect(field).toHaveValue(value.recoveryCode);
  await field.focus();
  expect(await field.evaluate((input: HTMLInputElement) => input.value.slice(input.selectionStart ?? 0, input.selectionEnd ?? 0)))
    .toBe(value.recoveryCode);
  expect(sent.join('\n')).not.toContain(value.recoveryCode);
});

test('legal return keeps its saved case index locked when membership cannot be verified', async ({ page }) => {
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const { owner } = await ownerFixture();
  const value = { format: 'vera-legal-workspace/v1', organizationId: firm.organizationId, domain: firm.domain,
    recipientKeyId: firm.recipientKeyId, privateKey: firm.privateKey.armor(),
    requests: [{ caseId: owner.trust.caseId, requestId: 'b'.repeat(64), ownerPublicKey: owner.trust.ownerPublicKey.armor(),
      summary: 'SYNTHETIC RETURNING FIRM CASE', requestedAt: Date.now() }], owners: [], pins: [], sequences: [] };
  await page.clock.install({ time: new Date() });
  await page.route('https://identity.example/oauth/token', route => route.fulfill({ status: 200,
    headers: { 'Access-Control-Allow-Origin': '*' }, contentType: 'application/json',
    body: JSON.stringify({ access_token: 'synthetic-browser-identity-only', token_type: 'Bearer', expires_in: 300 }) }));
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'Backend unavailable, no grant bypass' }));
  await page.goto('/legal');
  await seed(page, 'legal', value);
  await page.evaluate(() => sessionStorage.setItem('vera-legal-auth-pending', JSON.stringify({ state: 'test-state', verifier: 'test-verifier', returnPath: '/legal', binding: JSON.stringify([location.origin, 'identity.example', 'legal-test-client', 'https://legal.example']), organization: null })));
  await page.goto('/legal?code=synthetic&state=test-state');
  await page.getByLabel('Device passphrase', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Unlock saved workspace' }).click();
  // Decryption alone is no longer authority to expose cached confidential data.
  // Successful restoration is covered by the enrolled real-stack journeys.
  await expect(page.getByRole('alert').filter({ hasText: /secure connection/i })).toBeVisible();
  await expect(page.getByText('SYNTHETIC RETURNING FIRM CASE', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('region', { name: "Your organization's requests" })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open report', exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).not.toContain('SYNTHETIC RETURNING FIRM CASE');
  expect(page.url()).not.toContain(owner.trust.caseId);
});

test('legal onboarding requires reopening the backup before Continue and offers encrypted device memory', async ({ page }) => {
  // Approved organization details come from the setup link, never typed in.
  await page.goto(`/legal/enroll#organization=${'c'.repeat(64)}&domain=onboarding.example`);
  await expect(page.getByText('onboarding.example', { exact: false }).first()).toBeVisible();
  await page.getByRole('button', { name: 'Create key', exact: true }).click();
  const continueButton = page.getByRole('button', { name: 'Continue to workspace', exact: true });
  await expect(continueButton).toBeDisabled();
  await page.getByLabel('Recovery code (or replace with a passphrase of at least 16 characters)').fill(password);
  await page.getByText('Download not starting? Save a copy manually', { exact: true }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Use browser download instead' }).click();
  const file = readFileSync((await (await download).path())!);
  await expect(continueButton).toBeDisabled();
  await page.getByLabel('Saved encrypted key file').setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: file });
  await page.getByLabel('Saved recovery code or passphrase').fill('wrong but sufficiently long secret');
  await page.getByRole('button', { name: 'Verify saved backup' }).click();
  await expect(page.getByText('That file and recovery code did not restore', { exact: false })).toBeVisible();
  await expect(continueButton).toBeDisabled();
  await page.getByLabel('Saved recovery code or passphrase').fill(password);
  await page.getByRole('button', { name: 'Verify saved backup' }).click();
  await expect(page.getByText('Backup verified.', { exact: true })).toBeVisible();
  // A checked backup is the only gate before activation; staff still sign the key.
  await expect(continueButton).toBeEnabled();
  await page.getByText('Remember this workspace on this device (optional)', { exact: true }).click();
  await page.getByRole('button', { name: 'Keep this workspace on this device' }).click();
  await page.getByRole('radio', { name: /Device passphrase/ }).check();
  await page.getByLabel('New device passphrase', { exact: true }).fill(password);
  await page.getByLabel('Confirm device passphrase').fill(password);
  await page.getByRole('button', { name: 'Save encrypted workspace', exact: true }).click();
  await expect(page.getByText('An encrypted copy is saved in this browser.', { exact: false })).toBeVisible();
  await page.evaluate(script);
  const records = await page.evaluate(() => (window as any).vaultApi.browserVaultStore().list());
  expect(records).toHaveLength(1);
  expect(JSON.stringify(records)).not.toContain('onboarding.example');
  expect(JSON.stringify(records)).not.toContain(password);
});

test('invitation renewal keeps the encrypted workspace locked without verified organization binding', async ({ page }) => {
  const firm = await generateFirmIdentity({ organizationId: 'd'.repeat(64), domain: 'renewal.example' });
  await page.route('https://identity.example/oauth/token', route => route.fulfill({ status: 200,
    headers: { 'Access-Control-Allow-Origin': '*' }, contentType: 'application/json',
    body: JSON.stringify({ access_token: 'synthetic-browser-renewal-only', token_type: 'Bearer', expires_in: 300 }) }));
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'No backend acceptance in this test' }));
  await page.goto('/legal');
  await seed(page, 'legal', { format: 'vera-legal-workspace/v1', organizationId: firm.organizationId, domain: firm.domain,
    recipientKeyId: firm.recipientKeyId, privateKey: firm.privateKey.armor(), requests: [], owners: [], pins: [], sequences: [] });
  await page.evaluate(() => {
    sessionStorage.setItem('vera-legal-invitation', 'a'.repeat(43));
    sessionStorage.setItem('vera-legal-auth-pending', JSON.stringify({ state: 'renew-state', verifier: 'renew-verifier', returnPath: '/legal/enroll', binding: JSON.stringify([location.origin, 'identity.example', 'legal-test-client', 'https://legal.example']), organization: null }));
  });
  await page.goto('/legal?code=synthetic&state=renew-state');
  await expect(page).toHaveURL(/\/legal\/enroll$/);
  await page.getByRole('button', { name: 'Use our existing key file' }).click();
  await page.getByLabel('Device passphrase', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Unlock saved workspace' }).click();
  // Even enrollment must verify the organization binding before opening a key.
  // The unavailable attested backend cannot establish that binding.
  await expect(page.getByRole('alert').filter({ hasText: 'Your approved organization key could not be confirmed.' })).toBeVisible();
  await expect(page.getByText('Organization key unlocked on this device', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Try activation again', exact: true })).toHaveCount(0);
  await expect(page.getByText('Your account is enrolled for your organization.')).toHaveCount(0);
});

test('a join link leaves no fragment in the address bar and asks the lawyer to sign in first', async ({ page }) => {
  const organizationId = 'e'.repeat(64);
  await page.goto(`/legal/join#organization=${organizationId}&domain=join.example`);
  await expect(page.getByText('Sign in with the account your organization uses for VERA.', { exact: false })).toBeVisible();
  await expect(page).toHaveURL(/\/legal\/join$/);
  expect(await page.evaluate(() => sessionStorage.getItem('vera-legal-join'))).toContain(organizationId);
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
});

test('the steward page withholds membership controls until the saved workspace is verified', async ({ page }) => {
  const firm = await generateFirmIdentity({ organizationId: 'f'.repeat(64), domain: 'steward.example' });
  await page.route('https://identity.example/oauth/token', route => route.fulfill({ status: 200,
    headers: { 'Access-Control-Allow-Origin': '*' }, contentType: 'application/json',
    body: JSON.stringify({ access_token: 'synthetic-browser-steward-only', token_type: 'Bearer', expires_in: 300 }) }));
  await page.route('**/api/confidential/**', route => route.fulfill({ status: 503, body: 'No backend in this test' }));
  await page.goto('/legal');
  await seed(page, 'legal', { format: 'vera-legal-workspace/v1', organizationId: firm.organizationId, domain: firm.domain,
    recipientKeyId: firm.recipientKeyId, privateKey: firm.privateKey.armor(), requests: [], owners: [], pins: [], sequences: [] });
  await page.evaluate(() => sessionStorage.setItem('vera-legal-auth-pending',
    JSON.stringify({ state: 'members-state', verifier: 'members-verifier', returnPath: '/legal/members', binding: JSON.stringify([location.origin, 'identity.example', 'legal-test-client', 'https://legal.example']), organization: null })));
  await page.goto('/legal?code=synthetic&state=members-state');
  await expect(page).toHaveURL(/\/legal\/members$/);
  await page.getByLabel('Device passphrase', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Unlock saved workspace' }).click();
  await expect(page.getByRole('alert').filter({ hasText: /secure connection/i })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Add a lawyer' })).toHaveCount(0);
  await expect(page.getByLabel('Join link')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Replace the key…' })).toHaveCount(0);
});

test('application backup errors stay beside the fields and allow a correct retry', async ({ page }) => {
  await page.goto('/legal/apply');
  for (const [label, value] of Object.entries({
    'Legal organization': 'SYNTHETIC QA FIRM', 'Organization website domain': 'backup.example',
    'Organization email': 'qa@backup.example', 'Registered lawyer name': 'QA Test',
    'Licensing jurisdiction': 'Test jurisdiction', 'Bar or registration number': 'QA-ONLY',
  })) await page.getByLabel(label, { exact: true }).fill(value);
  await page.getByRole('button', { name: 'Continue to key backup' }).click();
  await page.getByRole('button', { name: 'Create key', exact: true }).click();
  const code = await page.getByLabel('Recovery code — save separately').inputValue();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download encrypted key file', exact: true }).click();
  const bytes = readFileSync((await (await download).path())!);
  const input = page.getByLabel('Saved encrypted key file');
  const verify = page.getByRole('button', { name: 'Verify saved backup' });
  const submit = page.getByRole('button', { name: 'Submit firm and key for approval' });
  const error = page.locator('#backup-check-error');
  await input.setInputFiles({ name: 'wrong.txt', mimeType: 'text/plain', buffer: Buffer.from('not a key') });
  await expect(error).toContainText('unsupported or damaged');
  await expect(error).toBeInViewport();
  await expect(input).toHaveAttribute('aria-describedby', 'backup-check-error');
  await expect(verify).toBeDisabled();
  await expect(submit).toBeDisabled();
  await input.setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: bytes });
  await page.getByLabel('Saved recovery code', { exact: true }).fill('wrong but sufficiently long secret');
  await verify.click();
  await expect(error).toContainText('do not restore this key');
  await expect(error).toBeInViewport();
  await expect(submit).toBeDisabled();
  await page.getByLabel('Saved recovery code', { exact: true }).fill(code);
  await verify.click();
  await expect(page.getByText('Backup verified.', { exact: true })).toBeVisible();
  await expect(submit).toBeEnabled();
});
