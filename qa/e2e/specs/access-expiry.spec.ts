import { test, expect } from '@playwright/test';
import type { Browser, BrowserContext, Locator, Page } from '@playwright/test';
import { SECOND_FIRM_DOMAIN, newParticipant, recordTraffic } from '../support/browser';
import { firmOpensReport, firmPortal, issueInvitation, onboardFirm, seedExistingRequest } from '../support/firm';
import type { Firm, LeakWatch } from '../support/firm';
import { leakedSecrets, recoveryFileSecrets } from '../support/leaks';
import { openWithRecoveryCode, submitConfidentialReport } from '../support/owner';
import type { SubmittedReport } from '../support/owner';
import { sweptFromHost } from '../support/state';
import { advanceStackTime } from '../support/time';

// A firm whose access has ended is refused. The reporter allows access for 30
// days (the shortest end the UI offers); the stack's time then moves 31 days
// forward (stack/timeShift.ts: synthetic NSM timestamps, the enclave's trusted
// clock, identity tokens and browser clocks together). The firm, invited again
// because its seven-day membership lease lapsed too, can no longer open the
// report; once the reporter renews, it can. Runs after every other spec
// (playwright.e2e.config.ts `time-shifted`): time never moves back.
test.describe.configure({ mode: 'serial' });

const DAY = 86_400_000;
const TIDELINE = { name: 'Tideline Counsel LLP', domain: SECOND_FIRM_DOMAIN,
  steward: { subject: 'auth0|e2e-expiry-steward', providerOrganizationId: 'org_e2eexpiry' } };
// Synthetic sentinel: only the reporter and an organization while it has access may show it.
const NARRATIVE = 'SENTINEL-EXPIRY-NARRATIVE: the depot kept billing for maintenance crews it had already dismissed.';
const SUMMARY = 'A transit depot appears to have billed for maintenance crews that no longer worked there.';

const watch: LeakWatch = { traffic: [], deviceSecrets: [] };
const hostTraffic = watch.traffic;
let admin: BrowserContext, ownerDevice: BrowserContext;
let firm: Firm;
let ownerPage: Page;
let report: SubmittedReport;

test.afterAll(async () => { for (const context of [admin, firm?.context, ownerDevice]) await context?.close(); });

/** The steward redeems a new invitation in a fresh tab, unlocking with the organization key file. */
async function reenroll(browser: Browser) {
  const invitation = await issueInvitation(browser, firm, firm.steward.subject, watch);
  const page = await firm.context.newPage();
  await firm.page.close({ runBeforeUnload: false });
  firm.page = page;
  await page.goto(invitation);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('button', { name: 'Use our existing key file' }).click();
  await page.getByLabel('Encrypted private key file').setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(firm.keyFile) });
  await page.getByLabel('Recovery passphrase or code').fill(firm.code);
  await page.getByRole('button', { name: 'Open organization', exact: true }).click();
  await expect(page.getByText('Your account is enrolled for your organization.')).toBeVisible();
  await page.getByRole('link', { name: 'Open workspace', exact: true }).click();
}

/** This organization's entry for the report on its requests list, status re-checked. */
async function requestItem(): Promise<Locator> {
  const { requests } = await firmPortal(firm);
  await requests.getByRole('button', { name: 'Refresh' }).click();
  return requests.getByRole('listitem').filter({ hasText: SUMMARY });
}

/** The reporter's "Who has access" row for the organization, with "Manage access" open. */
async function manageAccess(): Promise<Locator> {
  const row = ownerPage.getByRole('region', { name: 'Who has access' }).getByRole('listitem')
    .filter({ has: ownerPage.getByText(TIDELINE.name, { exact: true }) }).first();
  const details = row.locator('details').filter({ has: ownerPage.getByText('Manage access', { exact: true }) });
  if (!(await details.evaluate(element => (element as HTMLDetailsElement).open))) await details.getByText('Manage access', { exact: true }).click();
  return row;
}

test('an organization completes setup with a pre-existing request to read a report', async ({ browser }) => {
  admin = await newParticipant(browser, { admin: true });
  firm = await onboardFirm(browser, admin, TIDELINE, watch);
  const context = await newParticipant(browser);
  const page = await context.newPage();
  const traffic = recordTraffic(page);
  report = await submitConfidentialReport(page, { narrative: NARRATIVE, summary: SUMMARY });
  watch.deviceSecrets.push(...recoveryFileSecrets(report.recoveryFile, report.recoveryCode));
  hostTraffic.push(...traffic);
  await context.close();
  await seedExistingRequest(firm, SUMMARY, ['Report']);
});

test('the reporter allows access for 30 days and the firm opens the report', async ({ browser }) => {
  ownerDevice = await newParticipant(browser);
  recordTraffic(ownerDevice, hostTraffic);
  ownerPage = await ownerDevice.newPage();
  await openWithRecoveryCode(ownerPage, report.recoveryCode);
  const request = ownerPage.getByRole('region', { name: `${TIDELINE.name} requests access` });
  await request.getByRole('button', { name: 'Choose what to share' }).click();
  await request.getByRole('radio', { name: /Share my report/ }).check();
  await request.getByRole('radio', { name: '30 days', exact: true }).check();
  await expect(request.getByText(/, for 30 days\.$/)).toBeVisible();
  await request.getByRole('button', { name: 'Allow access' }).click();
  await expect(ownerPage.getByText(`${TIDELINE.name} can now open what you chose.`, { exact: false })).toBeVisible({ timeout: 120_000 });
  await expect((await manageAccess()).getByText(/^Until .+ \((29|30) days left\)$/)).toBeVisible();

  await expect((await requestItem()).getByText(/^Access ends .+ unless the reporter renews it\./)).toBeVisible({ timeout: 120_000 });
  await firmOpensReport(firm, NARRATIVE);
});

test('31 days later the firm is refused: it sees access ended and cannot open the report', async ({ browser }) => {
  await advanceStackTime(31 * DAY, [firm.context, ownerDevice]);
  // The seven-day membership lease lapsed as well: the steward is invited again,
  // so what follows is refused on the grant's end date, not on membership.
  await reenroll(browser);

  // The case-key cache also aged out. The batched board check leaves locked
  // reports unconfirmed instead of trying to unlock every report in the
  // background. Only this explicit click offers the firm's key; the enclave
  // must refuse it because the grant expired, without showing private content.
  let item = await requestItem();
  await expect(item.getByText('Access not yet checked', { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(firm.page.getByRole('region', { name: 'Needs attention' }).getByRole('listitem').filter({ hasText: SUMMARY })).toBeVisible();
  await expect(item.getByRole('button', { name: 'Open report', exact: true })).toHaveCount(0);
  await expect(firm.page.getByRole('region', { name: 'Shared with you' }).getByText(SUMMARY)).toHaveCount(0);
  await expect(firm.page.getByText(NARRATIVE)).toHaveCount(0);
  await item.getByRole('button', { name: 'Check report access', exact: true }).click();
  await expect(firm.page.getByText('Your organization does not have access to this report', { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(firm.page.getByText('Access ended', { exact: true })).toBeVisible();
  await expect(firm.page.getByRole('button', { name: 'Ask to renew', exact: true })).toBeVisible();
  await expect(firm.page.getByRole('article', { name: 'Report details', exact: true })).toHaveCount(0);
  await expect(firm.page.getByRole('region', { name: 'Files', exact: true })).toHaveCount(0);
  await expect(firm.page.getByText(NARRATIVE)).toHaveCount(0);

  // The reporter's device, on the same time, shows the end and unlocks the report.
  await ownerPage.getByRole('button', { name: 'Check for updates' }).click();
  await expect(ownerPage.getByText(`Access for ${TIDELINE.name} ended on `, { exact: false })).toBeVisible({ timeout: 120_000 });
  // With the report unlocked the enclave answers for the grant itself: ended.
  item = await requestItem();
  await expect(item.getByText('Access ended', { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(item.getByRole('button', { name: 'Ask to renew', exact: true })).toBeVisible();
  await expect(item.getByRole('button', { name: /^(Open report|Check report access)$/ })).toHaveCount(0);
  await expect(firm.page.getByText(NARRATIVE)).toHaveCount(0);
});

test('once the reporter renews, the firm opens the report again', async () => {
  const access = await manageAccess();
  const renew = access.getByRole('group', { name: 'Renew access' });
  await renew.getByLabel('New end').selectOption({ label: 'Until I revoke it' });
  await renew.getByRole('button', { name: 'Renew access', exact: true }).click();
  await expect(access.getByText('Until you revoke it', { exact: true })).toBeVisible({ timeout: 120_000 });

  await expect((await requestItem()).getByText('Access lasts until the reporter revokes it.', { exact: false })).toBeVisible({ timeout: 120_000 });
  await firmOpensReport(firm, NARRATIVE);
  expect(leakedSecrets(hostTraffic, sweptFromHost(['SENTINEL-EXPIRY', ...watch.deviceSecrets]))).toEqual([]);
});
