import { test, expect } from '@playwright/test';
import type { BrowserContext, Locator, Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { newParticipant, recordTraffic, signInAs } from '../support/browser';
import { firmDownloads, firmOpensReport, firmPortal, onboardFirm, seedExistingRequest, resumeFirmSignIn } from '../support/firm';
import type { Firm, LeakWatch } from '../support/firm';
import { leakedSecrets, recoveryFileSecrets, organizationKeyFileSecrets } from '../support/leaks';
import { firmBindingDocument, importFirmIdentity } from '../../../lib/confidential/firmKey';
import { openWithRecoveryCode, submitConfidentialReport } from '../support/owner';
import type { SubmittedReport } from '../support/owner';
import { sweptFromHost } from '../support/state';

// Two legal organizations on one report, independent of the journey (its own
// organizations, domains and reporter): both onboard through the full setup
// checklist, both ask for access, and the reporter allows one of them files
// added later and the other a 30-day grant of current files only. A file added
// after submission then reaches only the first. Revoking the first denies it at
// the enclave while the second keeps opening the older files under the re-keyed
// case. Finally a fresh desktop browser restores from the recovery file and
// shows the reporter the "ends soon" and "ended" notices for the 30-day grant
// (only the reporter's browser clock is moved forward, after the report is open,
// so the notices are checked as rendered; access-expiry.spec.ts moves the whole
// stack's time and checks that an ended grant is enforced).
test.describe.configure({ mode: 'serial' });

const DAY = 86_400_000;
const NORTH = { name: 'North Counsel LLP', domain: 'north-counsel.example',
  steward: { subject: 'auth0|e2e-north-steward', providerOrganizationId: 'org_e2enorth' } };
const SOUTH = { name: 'South Counsel LLP', domain: 'south-counsel.example',
  steward: { subject: 'auth0|e2e-south-steward', providerOrganizationId: 'org_e2esouth' } };

// Synthetic sentinels: only the reporter and the organizations allowed to read them may ever show them.
const NARRATIVE = 'SENTINEL-TWOFIRM-NARRATIVE: the tender panel was told the winner before bids opened.';
const SUMMARY = 'A procurement panel appears to have picked a tender winner before the bids were opened.';
const ORIGINAL_FILE = { name: 'panel-minutes.csv', mimeType: 'text/csv', buffer: Buffer.from('SENTINEL-TWOFIRM-EVIDENCE-ORIGINAL,1\n') };
const LATER_FILE = { name: 'bid-log.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\nSENTINEL-TWOFIRM-EVIDENCE-LATER\n%%EOF\n') };
const SENTINELS = ['SENTINEL-TWOFIRM-NARRATIVE', 'SENTINEL-TWOFIRM-EVIDENCE'];

/** Everything every participant (reporter, owner devices, stewards, onboarding
 * operator) sent to the host, and the secrets that never leave their devices:
 * the recovery code and file, organization key files and their codes. */
const watch: LeakWatch = { traffic: [], deviceSecrets: [] };
const hostTraffic = watch.traffic;
/** The host saw only ciphertext for everything the participants exchanged. */
function expectHostSawOnlyCiphertext() {
  expect(hostTraffic.length).toBeGreaterThan(0);
  expect(leakedSecrets(hostTraffic, sweptFromHost([...SENTINELS, ...watch.deviceSecrets]))).toEqual([]);
}

let admin: BrowserContext, ownerDevice: BrowserContext;
let north: Firm, south: Firm;
let ownerPage: Page;
let report: SubmittedReport;

test.afterAll(async () => { for (const context of [admin, north?.context, south?.context, ownerDevice]) await context?.close(); });

/** The reporter's "Who has access" row for one organization, with "Manage access" open. */
async function manageAccess(page: Page, name: string): Promise<Locator> {
  const row = page.getByRole('region', { name: 'Who has access' }).getByRole('listitem')
    .filter({ has: page.getByText(name, { exact: true }) }).first();
  const details = row.locator('details').filter({ has: page.getByText('Manage access', { exact: true }) });
  if (!(await details.evaluate(element => (element as HTMLDetailsElement).open))) await details.getByText('Manage access', { exact: true }).click();
  return row;
}

test('two legal organizations onboard: verified backup, optional second holder, terms, signed key approval and membership', async ({ browser }) => {
  admin = await newParticipant(browser, { admin: true });
  north = await onboardFirm(browser, admin, NORTH, watch);
  south = await onboardFirm(browser, admin, SOUTH, watch);
  expectHostSawOnlyCiphertext();
});

test('a signed-in firm cannot activate the other firm key, and can retry with its own key', async ({ browser }) => {
  for (const [signedIn, other] of [[north, south], [south, north]]) {
    const context = await newParticipant(browser);
    recordTraffic(context, hostTraffic);
    signInAs(context, signedIn.steward);
    try {
      const page = await context.newPage();
      await page.goto('/legal');
      await page.getByRole('button', { name: /^Sign in(?: with email)?$/ }).click();
      const key = page.getByLabel('Encrypted private key file', { exact: true });
      await key.setInputFiles({ name: 'other-firm.txt', mimeType: 'text/plain', buffer: Buffer.from(other.keyFile) });
      await page.getByLabel('Recovery passphrase or code', { exact: true }).fill(other.code);
      await page.getByRole('button', { name: 'Open organization', exact: true }).click();
      await expect(page.getByRole('region', { name: 'Open your organization', exact: true }).getByRole('alert'))
        .toContainText('This key does not match your signed-in organization or its approved key.');
      await expect(page.getByRole('link', { name: 'Requests and reports', exact: true })).toHaveCount(0);
      await key.setInputFiles({ name: 'my-firm.txt', mimeType: 'text/plain', buffer: Buffer.from(signedIn.keyFile) });
      await page.getByLabel('Recovery passphrase or code', { exact: true }).fill(signedIn.code);
      await page.getByRole('button', { name: 'Open organization', exact: true }).click();
      await expect(page.getByRole('link', { name: 'Requests and reports', exact: true })).toBeVisible();
      await expect(page.getByRole('group', { name: 'Legal report board', exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Available reports', exact: true })).toHaveCount(0);
      await expect(page.getByText('Organization key unlocked on this device', { exact: true })).toBeVisible();
      // A popup renewal can return a different signed-in account. Its arrival
      // must clear the old key and private view instead of inheriting them.
      await page.clock.setFixedTime(Date.now() + 360_000);
      signInAs(context, other.steward);
      await page.getByRole('button', { name: 'Sign in again', exact: true }).click();
      await expect(page.getByRole('button', { name: /^Sign in(?: with email)?$/ })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Requests and reports', exact: true })).toHaveCount(0);
      await expect(page.getByText('Organization key unlocked on this device', { exact: true })).toHaveCount(0);
    } finally { await context.close(); }
  }
  expectHostSawOnlyCiphertext();
});

test('an enrolled firm cannot open an unencrypted key file, and returns with a new encrypted backup and its code', async ({ browser }) => {
  const context = await newParticipant(browser);
  recordTraffic(context, hostTraffic); signInAs(context, north.steward);
  try {
    const firm = await importFirmIdentity(north.keyFile, north.code);
    // An unencrypted key file is not an accepted format and must never open,
    // even for an enrolled member with the right recovery code.
    const plaintext = JSON.stringify({ format: 'vera-firm-private-key/v1', organizationId: firm.organizationId,
      domain: firm.domain, recipientKeyId: firm.recipientKeyId, privateKey: firm.privateKey.armor(),
      bindingDocument: await firmBindingDocument(firm, Date.now()) });
    watch.deviceSecrets.push(plaintext);
    const page = await context.newPage();
    await page.goto('/legal');
    await page.getByRole('button', { name: /^Sign in(?: with email)?$/ }).click();
    const key = page.getByLabel('Encrypted private key file', { exact: true });
    const passphrase = page.getByLabel('Recovery passphrase or code', { exact: true });
    const open = page.getByRole('button', { name: 'Open organization', exact: true });
    const unlocked = page.getByText('Organization key unlocked on this device', { exact: true });
    await key.setInputFiles({ name: 'unprotected.txt', mimeType: 'text/plain', buffer: Buffer.from(plaintext) });
    await expect(open).toBeDisabled();
    await passphrase.fill(north.code);
    await open.click();
    await expect(page.getByRole('region', { name: 'Open your organization', exact: true }).getByRole('alert')).toContainText('do not match');
    await expect(unlocked).toHaveCount(0);
    await key.setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(north.keyFile) });
    await passphrase.fill(north.code);
    await open.click();
    await expect(unlocked).toBeVisible();
    await page.locator('summary').filter({ hasText: 'Key backup and device settings' }).click();
    await page.getByRole('button', { name: 'Create encrypted backup', exact: true }).click();
    const code = await page.getByLabel(/^Backup recovery code/).inputValue();
    await page.getByText('Download not starting? Save a copy manually', { exact: true }).click();
    const download = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Use browser download instead' }).click();
    const converted = readFileSync((await (await download).path())!, 'utf8');
    watch.deviceSecrets.push(...await organizationKeyFileSecrets(converted, code));
    expect((await importFirmIdentity(converted, code)).recipientKeyId).toBe(firm.recipientKeyId);
    expect(converted).not.toContain(code);
    expect(converted).not.toContain('BEGIN PGP PRIVATE KEY BLOCK');
    await page.getByRole('button', { name: 'Lock key', exact: true }).click();
    await page.getByRole('button', { name: /^Sign in(?: with email)?$/ }).click();
    await key.setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(converted) });
    await expect(open).toBeDisabled();
    await passphrase.fill(code);
    await open.click();
    await expect(unlocked).toBeVisible();
    expectHostSawOnlyCiphertext();
  } finally { await context.close(); }
});

test('an enrolled firm restores its saved workspace, downloads an encrypted copy, and locks it', async ({ browser }) => {
  const context = await newParticipant(browser);
  recordTraffic(context, hostTraffic); signInAs(context, north.steward);
  const password = `workspace-${north.code}`;
  watch.deviceSecrets.push(password);
  try {
    const page = await context.newPage();
    await page.goto('/legal');
    await page.getByRole('button', { name: /^Sign in(?: with email)?$/ }).click();
    await page.getByLabel('Encrypted private key file', { exact: true }).setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(north.keyFile) });
    await page.getByLabel('Recovery passphrase or code', { exact: true }).fill(north.code);
    await page.getByRole('button', { name: 'Open organization', exact: true }).click();
    const unlocked = page.getByText('Organization key unlocked on this device', { exact: true });
    await expect(unlocked).toBeVisible();
    await page.getByText('Key backup and device settings', { exact: true }).click();
    await page.getByRole('button', { name: 'Keep this workspace on this device' }).click();
    await page.getByRole('radio', { name: /Device passphrase/ }).check();
    await page.getByLabel('New device passphrase', { exact: true }).fill(password);
    await page.getByLabel('Confirm device passphrase').fill(password);
    await page.getByRole('button', { name: 'Save encrypted workspace', exact: true }).click();
    await expect(page.getByText('An encrypted copy is saved in this browser.', { exact: false })).toBeVisible();
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download encrypted workspace backup' }).click();
    const backup = readFileSync((await (await download).path())!, 'utf8');
    expect(backup).not.toContain((await importFirmIdentity(north.keyFile, north.code)).privateKey.armor());
    expect(backup).not.toContain(password);
    await page.reload();
    await page.getByRole('button', { name: /^Sign in(?: with email)?$/ }).click();
    await page.getByLabel('Device passphrase', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Unlock saved workspace' }).click();
    await expect(unlocked).toBeVisible();
    await page.getByText('Key backup and device settings', { exact: true }).click();
    await page.getByRole('button', { name: 'Lock workspace', exact: true }).click();
    await expect(unlocked).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^Sign in(?: with email)?$/ })).toBeVisible();
    expectHostSawOnlyCiphertext();
  } finally { await context.close(); }
});

test('an enrolled firm returns with its passkey and retains the private key fallback', async ({ browser }) => {
  const context = await newParticipant(browser);
  recordTraffic(context, hostTraffic); signInAs(context, north.steward);
  try {
    const page = await context.newPage(), cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    const signIn = () => page.getByRole('button', { name: /^Sign in(?: with email)?$/ }).click();
    const unlocked = page.getByText('Organization key unlocked on this device', { exact: true });
    const openKey = async () => {
      await page.getByLabel('Encrypted private key file', { exact: true }).setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(north.keyFile) });
      await page.getByLabel('Recovery passphrase or code', { exact: true }).fill(north.code);
      await page.getByRole('button', { name: 'Open organization', exact: true }).click();
      await expect(unlocked).toBeVisible();
    };
    await page.goto('/legal'); await signIn(); await openKey();
    await page.locator('summary').filter({ hasText: 'Key backup and device settings' }).click();
    await page.getByRole('button', { name: 'Keep this workspace on this device' }).click();
    await expect(page.getByRole('radio', { name: /Passkey \(recommended\)/ })).toBeChecked();
    await page.getByRole('button', { name: 'Create passkey and save' }).click();
    await expect(page.getByText('Opens with your passkey', { exact: false })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Download encrypted workspace backup' })).toBeDisabled();
    expect((await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials).toHaveLength(1);
    const stored = await page.evaluate(() => new Promise<{ records: Record<string, unknown>[]; keys: number }>((resolve, reject) => {
      const request = indexedDB.open('vera-confidential-device/v1', 2);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result, tx = db.transaction(['vaults', 'deviceKeys']);
        const records = tx.objectStore('vaults').getAll(), keys = tx.objectStore('deviceKeys').getAll();
        tx.oncomplete = () => { db.close(); resolve({ records: records.result, keys: keys.result.length }); };
      };
    }));
    expect(stored.records).toHaveLength(1);
    expect(stored.records[0]).toMatchObject({ format: 'vera-device-vault/v2', protection: 'passkey' });
    expect(stored.keys).toBe(0);
    await page.getByRole('button', { name: 'Lock key', exact: true }).click(); await signIn();
    await page.getByRole('button', { name: 'Unlock with passkey' }).click();
    await expect(unlocked).toBeVisible();
    await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
    await page.getByRole('button', { name: 'Lock key', exact: true }).click(); await signIn();
    await page.getByRole('button', { name: 'Unlock with passkey' }).click();
    await expect(page.getByRole('alert').first()).toContainText(/passkey/i);
    await expect(unlocked).toHaveCount(0);
    await openKey();
    expectHostSawOnlyCiphertext();
  } finally { await context.close(); }
});

test('the reporter submits and both organizations have pre-existing requests for the report and files', async ({ browser }) => {
  const context = await newParticipant(browser);
  const page = await context.newPage();
  const traffic = recordTraffic(page);
  report = await submitConfidentialReport(page, { narrative: NARRATIVE, summary: SUMMARY, files: [ORIGINAL_FILE] });
  watch.deviceSecrets.push(...recoveryFileSecrets(report.recoveryFile, report.recoveryCode));
  hostTraffic.push(...traffic);
  await context.close();
  for (const firm of [north, south]) await seedExistingRequest(firm, SUMMARY, ['Report', 'Files']);
});

test('on a fresh device the reporter allows North files added later, and South 30 days of current files', async ({ browser }) => {
  ownerDevice = await newParticipant(browser);
  recordTraffic(ownerDevice, hostTraffic);
  ownerPage = await ownerDevice.newPage();
  await openWithRecoveryCode(ownerPage, report.recoveryCode);
  await expect(ownerPage.getByRole('button', { name: 'Allow website checks for this visit' })).toHaveCount(0);

  const northRequest = ownerPage.getByRole('region', { name: `${NORTH.name} requests access` });
  await northRequest.getByRole('button', { name: 'Choose what to share' }).click();
  await northRequest.getByRole('radio', { name: /Share my report/ }).check();
  await northRequest.getByRole('radio', { name: 'All files (1)' }).check();
  const later = northRequest.getByRole('checkbox', { name: /Also share files I add later/ });
  await expect(later).not.toBeChecked(); // Current material only, unless the reporter chooses otherwise.
  await later.check();
  await northRequest.getByRole('radio', { name: /Until I revoke it/ }).check();
  await expect(northRequest.getByText(`${NORTH.name} will be able to read your report, all your evidence files, files you add later, until you revoke access.`)).toBeVisible();
  await northRequest.getByRole('button', { name: 'Allow access' }).click();
  await expect(ownerPage.getByText(`${NORTH.name} can now open what you chose.`, { exact: false })).toBeVisible({ timeout: 120_000 });

  const southRequest = ownerPage.getByRole('region', { name: `${SOUTH.name} requests access` });
  await southRequest.getByRole('button', { name: 'Choose what to share' }).click();
  await southRequest.getByRole('radio', { name: /Share my report/ }).check();
  await southRequest.getByRole('radio', { name: 'All files (1)' }).check();
  await expect(southRequest.getByRole('checkbox', { name: /Also share files I add later/ })).not.toBeChecked();
  await southRequest.getByRole('radio', { name: '30 days', exact: true }).check();
  await expect(southRequest.getByText(`${SOUTH.name} will be able to read your report, all your evidence files, for 30 days.`)).toBeVisible();
  await southRequest.getByRole('button', { name: 'Allow access' }).click();
  await expect(ownerPage.getByText(`${SOUTH.name} can now open what you chose.`, { exact: false })).toBeVisible({ timeout: 120_000 });

  const access = ownerPage.getByRole('region', { name: 'Who has access' });
  const northRow = access.getByRole('listitem').filter({ has: ownerPage.getByText(NORTH.name, { exact: true }) }).first();
  const southRow = access.getByRole('listitem').filter({ has: ownerPage.getByText(SOUTH.name, { exact: true }) }).first();
  await expect(northRow.getByText('Can read: ', { exact: false })).toContainText('files you add later');
  await expect(northRow.getByText('Until you revoke it', { exact: true })).toBeVisible();
  await expect(southRow.getByText('Can read: ', { exact: false })).not.toContainText('files you add later');
  await expect(southRow.getByText(/^Until .+ \((29|30) days left\)$/)).toBeVisible();

  // Both organizations open the report with the one original file.
  for (const firm of [north, south]) {
    await firmOpensReport(firm, NARRATIVE);
    await expect(firm.page.getByRole('region', { name: 'Files' }).getByRole('listitem')).toHaveCount(1);
  }
  const southAccess = south.page.getByText(/^The reporter shared .+ Access ends .+ unless the reporter renews it\.$/);
  await expect(southAccess).toBeVisible();
  expectHostSawOnlyCiphertext();
});

test('a file added after submission reaches only the organization allowed files added later', async () => {
  const add = ownerPage.getByRole('region', { name: 'Add evidence' });
  await expect(add.getByText(`They will be shared with ${NORTH.name}, because you allowed access to files you add later.`, { exact: false })).toBeVisible();
  await expect(add.getByText(`To also share them with ${SOUTH.name}, use "Change what they can read"`, { exact: false })).toBeVisible();
  await expect(add.getByRole('button', { name: 'Choose files' })).toBeVisible();
  await add.getByLabel('Choose evidence files').setInputFiles(LATER_FILE);
  await expect(add.getByText(LATER_FILE.name, { exact: false })).toBeVisible();
  await expect(add.getByRole('button', { name: 'Change files' })).toBeVisible();
  await expect(add.getByRole('button', { name: 'Clear' })).toBeVisible();

  // Hold chunk staging so the report can change under a still-prepared upload.
  // Commit then hits EvidenceStaleError, which discards prepared work: Change
  // files/Clear must stay available (the bare file input is gone).
  let releaseChunks!: () => void;
  const chunksHeld = new Promise<void>(resolve => { releaseChunks = resolve; });
  await ownerPage.route('**/api/confidential/chunks', async route => {
    if (route.request().method() === 'POST') await chunksHeld;
    await route.continue();
  });
  await add.getByRole('button', { name: 'Encrypt and add' }).click();
  await expect(add.getByRole('button', { name: 'Pause upload' })).toBeVisible({ timeout: 60_000 });
  await expect(add.getByRole('button', { name: 'Change files' })).toHaveCount(0);
  const southRow = await manageAccess(ownerPage, SOUTH.name);
  // Keep the finite grant used by the expiry checks later in this journey.
  await southRow.getByRole('combobox', { name: 'New end' }).selectOption({ label: '30 days from today' });
  await southRow.getByRole('group', { name: 'Renew access' }).getByRole('button', { name: 'Renew access', exact: true }).click();
  await expect(ownerPage.getByText(`Access for ${SOUTH.name} was renewed.`, { exact: false })).toBeVisible({ timeout: 120_000 });
  releaseChunks();
  await expect(add.getByText('Your report changed while the files were uploading. Choose Encrypt and add to try again.', { exact: true }))
    .toBeVisible({ timeout: 180_000 });
  await expect(add.getByRole('button', { name: 'Change files' })).toBeVisible();
  await expect(add.getByRole('button', { name: 'Clear' })).toBeVisible();
  await add.getByRole('button', { name: 'Clear' }).click();
  await expect(add.getByRole('button', { name: 'Choose files' })).toBeVisible();
  await ownerPage.unroute('**/api/confidential/chunks');

  await add.getByLabel('Choose evidence files').setInputFiles(LATER_FILE);
  await expect(add.getByText(LATER_FILE.name, { exact: false })).toBeVisible();
  await add.getByRole('button', { name: 'Encrypt and add' }).click();
  await expect(ownerPage.getByText(`Files added. Shared with ${NORTH.name}.`, { exact: true })).toBeVisible({ timeout: 180_000 });
  await expect(ownerPage.getByRole('region', { name: 'Your files' }).getByRole('listitem').filter({ hasText: LATER_FILE.name }))
    .toContainText('Added later', { timeout: 120_000 });
  // South's row now says a file is not shared with it.
  await expect(ownerPage.getByText(`Some of your files are not shared with ${SOUTH.name}.`, { exact: false })).toBeVisible();

  // North receives it without any further step by the reporter, and decrypts the exact bytes.
  await firmOpensReport(north, NARRATIVE);
  await expect(north.page.getByRole('region', { name: 'Files' }).getByRole('listitem')).toHaveCount(2, { timeout: 120_000 });
  const saved = await firmDownloads(north, 1);
  expect(saved).toEqual({ name: LATER_FILE.name, text: LATER_FILE.buffer.toString('utf8') });

  // South still has only the original file.
  await firmOpensReport(south, NARRATIVE);
  await expect(south.page.getByRole('region', { name: 'Files' }).getByRole('listitem')).toHaveCount(1);
  await expect(south.page.getByText(LATER_FILE.name)).toHaveCount(0);
  expectHostSawOnlyCiphertext();
});

test('revoking North denies it at the enclave; South keeps opening the older file', async () => {
  const row = await manageAccess(ownerPage, NORTH.name);
  await row.getByRole('button', { name: 'Revoke access' }).click();
  await row.getByRole('button', { name: 'Confirm: revoke access' }).click();
  await expect(ownerPage.getByText(`${NORTH.name} no longer has access to new information.`)).toBeVisible({ timeout: 120_000 });
  await expect(ownerPage.getByRole('region', { name: 'Who has access' }).getByText(NORTH.name, { exact: true })).toHaveCount(0);

  // North's requests list says access ended and no longer offers to open the report.
  const { requests } = await firmPortal(north);
  await requests.getByRole('button', { name: 'Refresh' }).click();
  await expect(requests.getByText('Access ended', { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(requests.getByRole('button', { name: 'Open report' })).toHaveCount(0);
  await expect(north.page.getByRole('region', { name: 'Available reports', exact: true })).toHaveCount(0);
  // Revisit the previously selected report anyway: the enclave refuses it and nothing decrypts.
  await north.page.goto('/legal/report');
  await resumeFirmSignIn(north, north.page.getByText('Your organization does not have access to this report', { exact: true }));
  await expect(north.page.getByText('Access ended', { exact: true })).toBeVisible();
  await expect(north.page.getByText(NARRATIVE)).toHaveCount(0);
  await expect(north.page.getByRole('region', { name: 'Files' })).toHaveCount(0);

  // Revoking North re-keyed the case for South; the file from before the revocation still opens.
  await firmOpensReport(south, NARRATIVE);
  await expect(south.page.getByRole('region', { name: 'Files' }).getByRole('listitem')).toHaveCount(1);
  const saved = await firmDownloads(south, 0);
  expect(saved).toEqual({ name: ORIGINAL_FILE.name, text: ORIGINAL_FILE.buffer.toString('utf8') });
  expectHostSawOnlyCiphertext();
});

test('restored from the recovery file on a fresh browser, the reporter sees "ends soon" and "ended" notices', async ({ browser }) => {
  const context = await newParticipant(browser);
  recordTraffic(context, hostTraffic);
  try {
    const page = await context.newPage();
    // Real time while the report opens (attestation checks the browser clock);
    // time is moved forward only once everything is loaded.
    await page.clock.install();
    await page.goto('/status');
    const chooser = page.waitForEvent('filechooser');
    await page.getByRole('button', { name: 'Open recovery file' }).click();
    await (await chooser).setFiles({ name: 'vera-private-recovery.txt', mimeType: 'text/plain', buffer: Buffer.from(report.recoveryFile) });
    await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
    await expect(page.getByRole('region', { name: 'Summary for legal review' }).getByText(SUMMARY)).toBeVisible();

    const access = page.getByRole('region', { name: 'Who has access' });
    const southRow = access.getByRole('listitem').filter({ has: page.getByText(SOUTH.name, { exact: true }) }).first();
    await expect(southRow.getByText(/^Until .+ \((29|30) days left\)$/)).toBeVisible();
    await expect(page.getByText(`Access for ${SOUTH.name} ends on`, { exact: false })).toHaveCount(0);

    // "Show recovery code" is a local toggle: it re-renders the report without contacting the service.
    const toggle = page.getByRole('region', { name: 'Recovery code and file' }).getByText('Show recovery code and printable sheet');
    const start = await page.evaluate(() => Date.now());
    await page.clock.setSystemTime(start + 17 * DAY);
    await toggle.click();
    await expect(page.getByText(new RegExp(`^Access for ${SOUTH.name} ends on .+\\. Renew it under "Who has access" if you want it to continue\\.$`)))
      .toBeVisible();
    await expect(southRow.getByText(/^Until .+ \(1[0-4] days left\)$/)).toBeVisible();

    await page.clock.setSystemTime(start + 31 * DAY);
    await toggle.click();
    await expect(page.getByText(new RegExp(`^Access for ${SOUTH.name} ended on .+\\. Renew it, or revoke it to remove it from your list\\.$`)))
      .toBeVisible();
    await expect(southRow.getByText(/^Ended on /)).toBeVisible();
    expectHostSawOnlyCiphertext();
  } finally { await context.close(); }
});
