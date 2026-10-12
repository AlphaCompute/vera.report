import { approveApplicationInSlack, waitForRegistrationApproval } from '../support/legalApplications';
import { test, expect } from '@playwright/test';
import type { BrowserContext, Locator, Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { openWithRecoveryCode, submitConfidentialReport } from '../support/owner';
import type { SubmittedReport } from '../support/owner';
import { FIRM_DOMAIN, ONBOARDING_ORG, newParticipant, recordTraffic, signInAs } from '../support/browser';
import { leakedSecrets, recoveryCodeForms, recoveryFileSecrets, organizationKeyFileSecrets } from '../support/leaks';
import { stackState, sweptFromHost } from '../support/state';
import { seedExistingRequest } from '../support/firm';
import { RENEW_PURPOSE } from '../../../lib/confidential/firmCaseView';
import { encodeRecoveryCodeV2, formatRecoveryCode } from '../../../enclave/src/confidential/recoveryCode';

// One end-to-end journey, in order: a reporter submits BEFORE any legal organization joins,
// then the firm applies and VERA approves its organization and lawyer together,
// the firm sets up its key, the onboarding operator invites it, the steward adds
// a lawyer, a pre-existing request is seeded through the encrypted protocol, the reporter restores
// on a fresh device and allows it, the firm opens the report and evidence,
// retired message controls stay absent; the reporter renews access, shares and stops sharing
// contact details and adds a file, the steward removes the lawyer (new
// organization key) and asks again, the reporter allows the new key, then
// revokes, declines the firm's renewal request, edits the summary and closes the
// report. Each step is its own test in one serial block; later steps use what
// earlier ones produced.
test.describe.configure({ mode: 'serial' });

const STEWARD = { subject: 'auth0|e2e-steward', providerOrganizationId: 'org_e2ecounsel' };
const ASSOCIATE = { subject: 'auth0|e2e-associate', providerOrganizationId: 'org_e2ecounsel' };
const OPERATOR = { subject: 'auth0|e2e-operator', providerOrganizationId: ONBOARDING_ORG };
const FIRM_NAME = 'Harbor Counsel LLP';

const journey: {
  organizationId?: string;
  firmKeyFile?: string; firmCode?: string;
  invitation?: string;
  report?: SubmittedReport;
  caseId?: string;
} = {};

// Synthetic sentinels: they may appear only on the reporter's and the allowed firm's screens.
const NARRATIVE = 'SENTINEL-NARRATIVE-7Q: the regional office approved invoices for audits that never happened.';
const SUMMARY = 'An accounting firm appears to have billed a public agency for audits that were never carried out.';
const SHARED_FILE = { name: 'ledger-extract.csv', mimeType: 'text/csv', buffer: Buffer.from('SENTINEL-EVIDENCE-SHARED,1,2\n') };
const PRIVATE_FILE = { name: 'private-notes.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\nSENTINEL-EVIDENCE-PRIVATE only for me\n%%EOF\n') };
const CONTACT = 'sentinel-contact-7q@reporter.example';
const LATER_FILE = { name: 'later-invoice.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\nSENTINEL-EVIDENCE-LATER\n%%EOF\n') };
const RENEWAL_REASON = 'SENTINEL-RENEWAL: we are preparing the filing and need the report for two more weeks.';
const EDITED_SUMMARY = 'A contractor appears to have invoiced a public agency for inspections that did not take place.';
const SENTINELS = ['SENTINEL-NARRATIVE-7Q', 'SENTINEL-EVIDENCE', 'sentinel-contact-7q', 'SENTINEL-RENEWAL'];

let reporter: BrowserContext, ownerDevice: BrowserContext;
let ownerPage: Page;
/** Everything every participant (reporter, owner device, steward, lawyer,
 * onboarding operator) sent to the host, recorded per browser context so pages
 * that replace one another are all covered. */
const hostTraffic: string[] = [];
/** Secrets that never leave a participant's device: the reporter's recovery
 * code and file, every organization key file and its recovery code, device codes. */
const deviceSecrets: string[] = [];
function keepPrivate(...values: (string | undefined)[]) {
  for (const value of values) if (value) deviceSecrets.push(...recoveryCodeForms(value), value);
}
/** The host saw only ciphertext for everything the participants exchanged. */
function expectHostSawOnlyCiphertext() {
  expect(hostTraffic.length).toBeGreaterThan(0);
  expect(leakedSecrets(hostTraffic, sweptFromHost([...SENTINELS, ...deviceSecrets]))).toEqual([]);
}

let admin: BrowserContext, steward: BrowserContext;
let stewardPage: Page;

test.afterAll(async () => { for (const context of [admin, steward, reporter, ownerDevice]) await context?.close(); });

/** "Manage access" for the one organization with access, opened if it is closed. */
async function manageAccess(page: Page): Promise<Locator> {
  const access = page.getByRole('region', { name: 'Who has access' });
  const details = access.locator('details').filter({ has: page.getByText('Manage access', { exact: true }) }).first();
  if (!(await details.evaluate(element => (element as HTMLDetailsElement).open))) {
    await details.getByText('Manage access', { exact: true }).click();
  }
  return access;
}

/** The structured details every access (or renewal) request carries. */
async function fillRequestDetails(form: Locator, options: { signedProfile?: boolean } = {}) {
  await form.getByRole('radio', { name: 'We have checked and found no conflict' }).check();
  await form.getByLabel('Fees').selectOption({ label: 'No fee (pro bono)' });
  await form.getByLabel('Expected reply').selectOption({ label: 'Within 2 days' });
  // The request carries the approved signed profile, never one typed here.
  await expect(options.signedProfile === false
    ? form.getByText('No approved signed profile is available, so this request is sent without one.', { exact: false })
    : form.getByText('Sent with this request exactly as your organization signed it.', { exact: false })).toBeVisible();
}

/** Long reporter steps may outlast the short synthetic login. Follow only the
 * actual sign-in/key gates, never retry a failed report operation or alter token
 * expiry. A redirect loses the memory-only key, so restore the saved key file
 * through the same UI a returning steward uses. */
async function resumeFirmSignIn(page: Page, ready: Locator): Promise<void> {
  const signIn = page.getByRole('button', { name: 'Sign in', exact: true });
  const renew = page.getByRole('button', { name: 'Sign in again', exact: true });
  const keyFile = page.getByLabel('Encrypted private key file', { exact: true });
  await expect(ready.or(signIn).or(renew).or(keyFile).first()).toBeVisible({ timeout: 120_000 });
  if (await renew.isVisible()) {
    await renew.click(); // Normal popup renewal preserves this tab and its key.
    await expect(page.getByText('Your sign-in has expired.', { exact: false })).toHaveCount(0, { timeout: 120_000 });
  } else if (await signIn.isVisible()) {
    await signIn.click();
    await expect(ready.or(keyFile).first()).toBeVisible({ timeout: 120_000 });
  }
  if (await keyFile.isVisible()) {
    expect(journey.firmKeyFile).toBeTruthy();
    expect(journey.firmCode).toBeTruthy();
    await keyFile.setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(journey.firmKeyFile!) });
    await page.getByLabel('Recovery passphrase or code').fill(journey.firmCode!);
    await page.getByRole('button', { name: 'Open organization', exact: true }).click();
  }
  await expect(ready).toBeVisible({ timeout: 120_000 });
}

/** The firm's portal home, with the requests list and fresh shared-report checks. A
 * reload would lock the organization key in this tab, so navigate in place. */
async function firmPortal(): Promise<{ requests: Locator }> {
  const page = stewardPage;
  await resumeFirmSignIn(page, page.getByRole('navigation', { name: 'Legal portal' }));
  const back = page.getByRole('link', { name: 'Back to the portal' }).first();
  if (await back.count()) await back.click();
  await page.getByRole('navigation', { name: 'Legal portal' }).getByRole('link', { name: 'Lawyers and devices' }).click();
  await resumeFirmSignIn(page, page.getByRole('heading', { name: 'Lawyers and devices', level: 1 }));
  await page.getByRole('navigation', { name: 'Legal portal' }).getByRole('link', { name: 'Requests and reports', exact: true }).click();
  const requests = page.getByRole('region', { name: "Your organization's requests", exact: true });
  await resumeFirmSignIn(page, requests);
  await expect(page.getByText('Checking for shared reports…', { exact: true })).toHaveCount(0, { timeout: 120_000 });
  await expect(page.getByRole('region', { name: 'Available reports', exact: true })).toHaveCount(0);
  return { requests };
}

/** The firm opens the report from its requests list (status re-checked first). */
async function firmOpensReport(): Promise<Page> {
  const { requests } = await firmPortal();
  await requests.getByRole('button', { name: 'Refresh' }).click();
  await requests.getByRole('button', { name: 'Open report' }).click();
  await resumeFirmSignIn(stewardPage, stewardPage.getByText(NARRATIVE));
  return stewardPage;
}

/** The steward redeems an invitation, unlocking with the organization key file. */
async function acceptInvitation(page: Page) {
  await page.goto(journey.invitation!);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('button', { name: 'Use our existing key file' }).click();
  await page.getByLabel('Encrypted private key file').setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(journey.firmKeyFile!) });
  await page.getByLabel('Recovery passphrase or code').fill(journey.firmCode!);
  await page.getByRole('button', { name: 'Open organization', exact: true }).click();
  await expect(page.getByText('Your account is enrolled for your organization.')).toBeVisible();
  await page.getByRole('link', { name: 'Open workspace', exact: true }).click();
}

test('reporter submits a confidential report and saves the recovery file', async ({ browser }) => {
  reporter = await newParticipant(browser);
  const page = await reporter.newPage();
  const traffic = recordTraffic(page);
  journey.report = await submitConfidentialReport(page, { narrative: NARRATIVE, summary: SUMMARY, files: [SHARED_FILE, PRIVATE_FILE], contact: CONTACT });
  await page.screenshot({ path: test.info().outputPath('recovery-receipt.png'), fullPage: true });
  // The recovery code and file never leave the device, in any form (URL, header,
  // body; any case, with or without separators, decoded); nothing private goes out in the clear.
  deviceSecrets.push(...recoveryFileSecrets(journey.report.recoveryFile, journey.report.recoveryCode));
  expect(leakedSecrets(traffic, sweptFromHost([...SENTINELS, ...deviceSecrets]))).toEqual([]);
  hostTraffic.push(...traffic);
  await reporter.close();
});

test('reporter explicitly remembers a private device, returns without a code, locks and erases saved access', async ({ browser }) => {
  const context = await newParticipant(browser);
  recordTraffic(context, hostTraffic);
  const page = await context.newPage();
  await openWithRecoveryCode(page, journey.report!.recoveryCode);
  const device = page.getByRole('region', { name: 'This device' });
  await expect(device.getByRole('radio', { name: /Nothing \(default\)/ })).toBeChecked();
  await expect(page.getByRole('heading', { name: 'Who can see what', exact: true })).toBeVisible();
  await expect(page.getByText(/NOT CONFIDENTIAL: VERA administrators and approved legal organizations/)).toBeVisible();
  await device.getByRole('radio', { name: /Keep unlocked on this private device/ }).check();
  await expect(device.getByText(/Not private from other people using this browser/)).toBeVisible();
  await page.screenshot({ path: test.info().outputPath('remember-private-device-warning.png'), fullPage: true });
  await device.getByRole('button', { name: 'I understand — keep unlocked on this device' }).click();
  await expect(device.getByText(/Your report is saved in this browser and opens without a code/)).toBeVisible();
  await expect(page.getByLabel('Recovery code', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Manage your report and choose which law firms can read it. Use Leave for now when you are done on this device.')).toBeVisible();
  await page.getByRole('button', { name: 'Leave for now', exact: true }).click();
  await expect(page.getByLabel('Recovery code', { exact: true })).toHaveValue('');
  await expect(page.getByRole('button', { name: 'Check for updates' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Open on this device', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });


  await page.reload();
  await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
  const second = await context.newPage();
  await second.goto('/status');
  await expect(second.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
  await page.getByRole('button', { name: 'Lock report', exact: true }).click();
  for (const tab of [page, second]) {
    await expect(tab.getByRole('button', { name: 'Open on this device', exact: true })).toBeVisible();
    await expect(tab.getByRole('button', { name: 'Check for updates' })).toHaveCount(0);
  }
  await page.reload();
  await expect(page.getByRole('button', { name: 'Open on this device', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Check for updates' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Open on this device', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
  await page.getByRole('button', { name: 'Forget this device', exact: true }).click();
  await expect(page.getByText(/password-manager entries or copies held by others/)).toBeVisible();
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'domcontentloaded' }),
    page.getByRole('button', { name: 'Confirm: forget this device' }).click(),
  ]);
  await expect(page.getByLabel('Recovery code', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('button', { name: 'Open recovery file' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Reports saved on this device' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Check for updates' })).toHaveCount(0);

  // Forget removes this browser's keys, not the submitted report. The portable
  // recovery file still opens it without typing or transmitting its contents.
  const chooser = page.waitForEvent('filechooser');
  await page.getByRole('button', { name: 'Open recovery file' }).click();
  await (await chooser).setFiles({ name: 'vera-private-recovery.txt', mimeType: 'text/plain', buffer: Buffer.from(journey.report!.recoveryFile) });
  await expect(page.getByRole('button', { name: 'Check for updates' })).toBeVisible({ timeout: 180_000 });
  await expect(page.getByRole('region', { name: 'Summary for legal review' }).getByText(SUMMARY)).toBeVisible();
  expectHostSawOnlyCiphertext();
  await context.close();
});

test('firm applies once and staff approves the application in Slack', async ({ browser }, testInfo) => {
  const applicant = await newParticipant(browser);
  const application = await applicant.newPage();
  await application.goto('/legal/apply');
  await application.getByLabel('Legal organization', { exact: true }).fill(FIRM_NAME);
  await application.getByLabel('Organization website domain').fill(FIRM_DOMAIN);
  await application.getByLabel('Organization email').fill(`lawyer@${FIRM_DOMAIN}`);
  await application.getByLabel('Registered lawyer name').fill('Synthetic Steward');
  await application.getByLabel('Licensing jurisdiction').fill('Synthetic jurisdiction');
  await application.getByLabel('Bar or registration number').fill('SYNTHETIC-123');
  await expect(application.getByText(/Not confidential. Do not include whistleblower or report details/)).toHaveCSS('font-weight', '700');
  await application.screenshot({ path: testInfo.outputPath('legal-application.png'), fullPage: true });
  expect((await applicant.request.post('/api/legal-applications', { data: {
    displayName: FIRM_NAME, domain: FIRM_DOMAIN, email: `lawyer@${FIRM_DOMAIN}`, lawyerName: 'Synthetic Steward',
    jurisdiction: 'Synthetic jurisdiction', registrationNumber: 'SYNTHETIC-123',
  } })).status()).toBe(202);
  await applicant.close();

  admin = await newParticipant(browser, { admin: true });
  const page = await admin.newPage();
  const approved = await approveApplicationInSlack(admin, FIRM_DOMAIN);
  journey.organizationId = approved.organizationId!;
  expect(journey.organizationId).toMatch(/^[a-f0-9]{64}$/);
  const roster = await admin.request.get('/api/admin/confidential/legal/organizations');
  const organization = (await roster.json()).organizations.find((value: { organizationId: string }) => value.organizationId === journey.organizationId);
  expect(organization.status).toBe('awaiting-registration');
  STEWARD.providerOrganizationId = organization.providerOrganizationId;
  ASSOCIATE.providerOrganizationId = organization.providerOrganizationId;
  await page.close();
});

test('firm onboarding checklist: key, backup, public key submission', async ({ browser }) => {
  steward = await newParticipant(browser);
  recordTraffic(steward, hostTraffic);
  signInAs(steward, STEWARD);
  stewardPage = await steward.newPage();
  const page = stewardPage;
  await page.goto(`/legal/enroll#${new URLSearchParams({ organization: journey.organizationId!, domain: FIRM_DOMAIN })}`);
  await expect(page.getByLabel('Organization ID (from VERA onboarding)')).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Create your organization key' })).toContainText(FIRM_DOMAIN);
  await expect(page).toHaveURL(/\/legal\/enroll$/);
  await page.getByRole('button', { name: 'Create key', exact: true }).click();

  const code = page.getByLabel('Recovery code (or replace with a passphrase of at least 16 characters)');
  journey.firmCode = await code.inputValue();
  await page.getByText('Download not starting? Save a copy manually', { exact: true }).click();
  const keyDownload = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Use browser download instead', exact: true }).click();
  journey.firmKeyFile = readFileSync((await (await keyDownload).path())!, 'utf8');
  keepPrivate(...await organizationKeyFileSecrets(journey.firmKeyFile, journey.firmCode));
  await page.getByLabel('Saved encrypted key file').setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(journey.firmKeyFile) });
  await page.getByLabel('Saved recovery code or passphrase').fill(journey.firmCode);
  await page.getByRole('button', { name: 'Verify saved backup' }).click();
  await page.getByRole('button', {name:'Continue to workspace',exact:true}).click();
  await page.getByRole('checkbox', { name: 'Whistleblower representation' }).check();
  await page.getByLabel('Jurisdiction').fill('England and Wales');
  await page.getByLabel('Website').fill(FIRM_DOMAIN);
  await page.getByRole('button', { name: 'Submit organization profile' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Your public key and profile have been submitted.' })).toBeVisible();
  // This journey uses a legacy assigned ID; its next step is the independent
  // administrator invitation below. New key-derived applications use Slack.
  await expect(page.getByLabel('Private Finish setup link')).toBeVisible();
});

/** The onboarding operator's page: roster from the VERA admin session, key read
 * from VERA, independent readback, separate onboarding sign-in, authority key on device. */
async function issueInvitation(browser: import('@playwright/test').Browser, subject: string, options: { replacedKey?: boolean } = {}): Promise<string> {
  const context = await newParticipant(browser, { admin: true });
  signInAs(context, OPERATOR, 'onboarding');
  const page = await context.newPage();
  const traffic = recordTraffic(page);
  recordTraffic(context, hostTraffic);
  const state = stackState();
  await page.goto('/legal/administration');
  await expect(page.getByRole('heading', { name: 'Legal onboarding' })).toBeVisible();
  const organization = page.getByLabel('Organization', { exact: true });
  await organization.selectOption(journey.organizationId!);
  await expect(page.getByText(`Key ID submitted by ${FIRM_DOMAIN}:`)).toBeVisible();
  await page.getByRole('button', { name: 'Sign in with the onboarding account' }).click();
  await expect(page.getByText('Signed in with the onboarding account.', { exact: false })).toBeVisible();
  await expect(organization).toHaveValue(journey.organizationId!);
  if (options.replacedKey) {
    // The firm replaced its key: the operator replaces the registered one explicitly.
    await expect(page.getByText('This is not the registered key.')).toBeVisible();
    await page.getByRole('checkbox', { name: 'Replace the registered key with the submitted one' }).check();
  }
  // Readback comes from the firm's saved backup, independently of the admin candidate row.
  const keyId = JSON.parse(journey.firmKeyFile!.split('\n').find(line => line.startsWith('{"format":'))!).recipientKeyId;
  await page.getByLabel('Key ID read back by the organization').fill(keyId);
  await page.getByRole('checkbox', { name: /I confirmed this Key ID/ }).check();
  await expect(page.getByLabel('Their user ID in the legal sign-in tenant')).toHaveValue('');
  await page.getByLabel('Their user ID in the legal sign-in tenant').fill(subject);
  await page.getByRole('checkbox', { name: /I independently verified this person/ }).check();
  await page.getByLabel('Encrypted onboarding authority key file').setInputFiles({ name: 'authority.txt', mimeType: 'text/plain', buffer: Buffer.from(state.authorityKeyFile) });
  await page.getByLabel('Key recovery code').fill(state.authorityCode);
  await page.getByRole('button', { name: 'Issue invitation', exact: true }).click();
  const link = page.getByLabel('Invitation link');
  await expect(link).toHaveValue(/\/legal\/enroll#invitation=[A-Za-z0-9_-]{43}$/);
  const value = await link.inputValue();
  // The authority key and its code never leave the page.
  expect(leakedSecrets(traffic, sweptFromHost([...recoveryCodeForms(state.authorityCode), state.authorityKeyFile]))).toEqual([]);
  await context.close();
  return value;
}

test('onboarding operator issues a recipient-bound invitation', async ({ browser }) => {
  journey.invitation = await issueInvitation(browser, STEWARD.subject);
});

test('steward accepts the invitation with the organization key', async () => {
  const page = await steward.newPage();
  await stewardPage.close();
  stewardPage = page;
  await acceptInvitation(page);
  // The sole key holder acknowledges terms; second-holder custody is optional.
  await expect(page.getByRole('heading', { name: 'Finish organization setup to request or open reports' })).toBeVisible();
  const checklist = page.getByRole('region', { name: 'Organization setup' });
  // Optional custody step: a second key holder's copy is checked on this device before the terms.
  const custody = checklist.locator('summary').filter({ hasText: 'Second key holder (optional)' });
  await custody.click();
  await checklist.getByLabel("Second key holder's key file").setInputFiles({ name: 'second-key.txt', mimeType: 'text/plain', buffer: Buffer.from(journey.firmKeyFile!) });
  await checklist.getByLabel('Their recovery code or passphrase').fill(journey.firmCode!);
  await checklist.getByRole('checkbox', { name: 'This copy is kept by a second authorized person, stored apart from mine.' }).check();
  await checklist.getByRole('button', { name: 'Check their copy' }).click();
  await expect(custody).toContainText('Complete');
  await checklist.locator('summary').filter({ hasText: 'Onboarding terms acknowledged' }).click();
  await checklist.getByRole('checkbox', { name: 'I have read these and my organization will follow them.' }).check();
  await checklist.getByRole('button', { name: 'Acknowledge' }).click();
  // Required setup is complete; adding another lawyer is optional.
  await expect(page.getByText('Organization setup complete. Show details or change your profile', { exact: true })).toBeVisible();
  await expect(page.getByRole('group', { name: 'Legal report board' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Available reports' })).toHaveCount(0);
});

test('added colleague signs in through the join link and still needs device approval', async ({ browser }) => {
  await stewardPage.getByRole('navigation', { name: 'Legal portal' }).getByRole('link', { name: 'Lawyers and devices' }).click();
  await stewardPage.getByLabel("Colleague's work email").fill(`avery@${FIRM_DOMAIN}`);
  await stewardPage.getByRole('button', { name: 'Add colleague', exact: true }).click();
  await expect(stewardPage.getByText('Colleague added.', { exact: false })).toBeVisible();
  const joinLink = await stewardPage.getByLabel('Join link', { exact: true }).inputValue();

  const associate = await newParticipant(browser);
  recordTraffic(associate, hostTraffic);
  // Since #1087 the membership worker prepares the colleague's unverified
  // account and membership within a few seconds of being added (no email is
  // sent). Report access still requires the device approval below.
  await expect.poll(async () => {
    const state = await (await associate.request.get('/__e2e/legal-applications')).json();
    return state.memberships.filter((entry: any) => entry.organization_id === ASSOCIATE.providerOrganizationId &&
      entry.email === `avery@${FIRM_DOMAIN}` && !entry.blocked);
  }).toEqual([expect.objectContaining({ roles: ['rol_legal'], email_verified: false })]);
  const snapshot = await (await associate.request.get('/__e2e/legal-applications')).json();
  const identityOrganization = snapshot.organizations.find((entry: any) => entry.id === ASSOCIATE.providerOrganizationId);
  expect(snapshot.users.filter((entry: any) => entry.email === `avery@${FIRM_DOMAIN}`)).toEqual([
    expect.objectContaining({ email_verified: false, blocked: false }),
  ]);
  expect(snapshot.emails.filter((entry: any) => entry.email === `avery@${FIRM_DOMAIN}`)).toEqual([]);
  expect(snapshot.invitations.filter((entry: any) => entry.invitee?.email === `avery@${FIRM_DOMAIN}`)).toEqual([]);
  expect(identityOrganization.metadata).toMatchObject({ vera_application_id: journey.organizationId, vera_domain: FIRM_DOMAIN });
  await waitForRegistrationApproval(associate, `avery@${FIRM_DOMAIN}`, ASSOCIATE.providerOrganizationId);
  // Synthetic Auth0 returns the same setup hints the real Action derives from
  // platform-managed organization metadata. The enclave remains authoritative.
  signInAs(associate, { ...ASSOCIATE, nativeEmail: `avery@${FIRM_DOMAIN}`, setup: { organizationId: identityOrganization.metadata.vera_application_id,
    providerOrganizationId: identityOrganization.id, domain: identityOrganization.metadata.vera_domain, displayName: FIRM_NAME } });
  const lawyer = await associate.newPage();
  await lawyer.goto(joinLink);
  await lawyer.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(lawyer.getByRole('button', { name: 'Create a new organization key' })).toHaveCount(0);
  await lawyer.getByLabel('Your name').fill('Avery Associate');
  await lawyer.getByRole('button', { name: 'Create key and ask for approval' }).click();
  const shown = lawyer.getByLabel(/^Device code /);
  await expect(shown).toBeVisible();
  const code = (await shown.innerText()).trim();
  deviceSecrets.push(code);

  // Reloading would lock the organization key in this tab; check in place.
  const pending = stewardPage.getByRole('region', { name: 'Waiting for approval' });
  await pending.getByRole('button', { name: 'Check for new devices' }).click();
  await expect(pending.getByText('Avery Associate')).toBeVisible();
  await pending.getByRole('button', { name: 'Review and approve' }).click();
  await expect(pending.getByLabel(/^Device code /)).toHaveText(code);
  await pending.getByRole('checkbox', { name: /I compared this code/ }).check();
  await pending.getByRole('button', { name: 'Approve device' }).click();
  await expect(stewardPage.getByText("Avery Associate's device is approved.", { exact: false })).toBeVisible();

  await lawyer.getByRole('button', { name: 'Check now' }).click();
  await expect(lawyer.getByRole('heading', { name: 'Your device is approved' })).toBeVisible();
  // Save this device credential, then continue without a VERA-issued membership link.
  await expect(lawyer.getByRole('button', { name: 'Open workspace', exact: true })).toBeDisabled();
  await lawyer.getByRole('button', { name: 'Keep this workspace on this device' }).click();
  await lawyer.getByRole('radio', { name: /Keep unlocked on this device/ }).check();
  await lawyer.getByRole('button', { name: 'Keep unlocked on this device', exact: true }).click();
  await expect(lawyer.getByText('Opens on this device after you sign in', { exact: false })).toBeVisible();
  await lawyer.getByRole('link', { name: 'Open workspace', exact: true }).click();
  await expect(lawyer.getByRole('navigation', { name: 'Legal portal' })).toBeVisible();
  await expect(lawyer.getByText('Private membership link', { exact: true })).toHaveCount(0);
  await associate.close();

  await stewardPage.getByRole('navigation', { name: 'Legal portal' }).getByRole('link', { name: 'Requests and reports', exact: true }).click();
  await expect(stewardPage.getByText('Organization setup complete. Show details or change your profile', { exact: true })).toBeVisible();
});

test('a request sent before directory removal remains visible without displaying unshared submissions', async () => {
  await firmPortal();
  await expect(stewardPage.getByText(SUMMARY, { exact: true })).toHaveCount(0);
  await expect(stewardPage.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
  const seeded = await seedExistingRequest({ page: stewardPage, name: FIRM_NAME, steward: STEWARD,
    keyFile: journey.firmKeyFile!, code: journey.firmCode! }, SUMMARY, ['Report', 'Files']);
  journey.caseId = seeded.caseId;
  const { requests } = await firmPortal();
  await expect(requests.getByText(SUMMARY)).toBeVisible();
  await expect(requests.getByRole('button', { name: 'Withdraw request' })).toBeVisible();
});

test('the reporter restores on a fresh device and sees the request', async ({ browser }) => {
  ownerDevice = await newParticipant(browser);
  recordTraffic(ownerDevice, hostTraffic);
  ownerPage = await ownerDevice.newPage();
  await openWithRecoveryCode(ownerPage, journey.report!.recoveryCode);
  expectHostSawOnlyCiphertext();
  const request = ownerPage.getByRole('region', { name: `${FIRM_NAME} requests access` });
  await expect(request).toBeVisible();
  await expect(request.getByText(`Website: ${FIRM_DOMAIN}`)).toBeVisible();
  await expect(request.getByText('Checked: they say they have no conflict')).toBeVisible();
  await expect(request.getByText('No fee (pro bono)')).toBeVisible();
});

test('the reporter allows access with the chooser: report and one file only', async () => {
  const page = ownerPage;
  const request = page.getByRole('region', { name: `${FIRM_NAME} requests access` });
  await request.getByRole('button', { name: 'Choose what to share' }).click();
  await request.getByRole('radio', { name: /Share my report/ }).check();
  await request.getByRole('radio', { name: 'Only some files' }).check();
  // Names stay encrypted on a fresh device, so files are numbered; share only the first.
  await request.getByRole('checkbox', { name: /File 1 \(sent with your report\)/ }).check();
  await request.getByRole('checkbox', { name: /File 2 \(sent with your report\)/ }).uncheck();
  await request.getByRole('radio', { name: /Until I revoke it/ }).check();
  await expect(request.getByText(`${FIRM_NAME} will be able to read your report, 1 evidence file, until you revoke access.`)).toBeVisible();
  await request.getByRole('button', { name: 'Allow access' }).click();
  await expect(page.getByText(`${FIRM_NAME} can now open what you chose.`, { exact: false })).toBeVisible({ timeout: 120_000 });
  const access = page.getByRole('region', { name: 'Who has access' });
  await expect(access.getByText(FIRM_NAME, { exact: true }).first()).toBeVisible();
  await expect(access.getByText(/^Can read: /)).toBeVisible();
});

test('the firm opens the report and downloads only the shared evidence', async () => {
  const page = stewardPage;
  const requests = page.getByRole('region', { name: "Your organization's requests", exact: true });
  await resumeFirmSignIn(page, requests);
  await requests.getByRole('button', { name: 'Refresh' }).click();
  await ownerPage.getByRole('button', { name: 'Check for updates' }).click();
  await expect(ownerPage.getByText(`${FIRM_NAME} first opened your report`)).toHaveCount(0);
  await requests.getByRole('button', { name: 'Open report' }).click();
  await resumeFirmSignIn(page, page.getByText(NARRATIVE));
  await expect(page.getByText('The reporter can see that your organization opened this report.')).toBeVisible();
  // Apply after any normal sign-in redirect/key restore, which replaces window.
  await page.evaluate(() => { Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true }); });
  const files = page.getByRole('region', { name: 'Files' });
  await expect(files.getByRole('listitem')).toHaveCount(1);
  const download = page.waitForEvent('download');
  await files.getByRole('button', { name: /^Download / }).click();
  const saved = await download;
  expect(saved.suggestedFilename()).toBe(SHARED_FILE.name);
  expect(readFileSync((await saved.path())!, 'utf8')).toBe(SHARED_FILE.buffer.toString('utf8'));
});

async function expectResponsiveBoard(page: Page, label: string, columns: number) {
  const original = page.viewportSize();
  const board = page.getByRole('group', { name: label });
  await expect(board).toBeVisible();
  const lanes = board.locator(':scope > section');
  await expect(lanes).toHaveCount(columns);
  await page.setViewportSize({ width: 1480, height: 1000 });
  expect(new Set(await lanes.evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().y))).size).toBe(1);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(new Set(await lanes.evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().y))).size).toBe(columns);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  if (original) await page.setViewportSize(original);
}

test('report sharing works without a private conversation on either side', async () => {
  await expect(stewardPage.getByRole('heading', { name: 'Report details', exact: true })).toBeVisible();
  await expect(stewardPage.getByRole('link', { name: 'Conversation', exact: true })).toHaveCount(0);
  await expect(stewardPage.getByRole('region', { name: 'Messages with the reporter' })).toHaveCount(0);
  await expect(stewardPage.getByLabel('Reply to the reporter')).toHaveCount(0);
  await ownerPage.getByRole('button', { name: 'Check for updates' }).click();
  await expect(ownerPage.getByText(`${FIRM_NAME} first opened your report`, { exact: true })).toHaveCount(1);
  await expect(ownerPage.getByRole('article', { name: 'Your submitted report' }).getByText(NARRATIVE, { exact: true })).toBeVisible();
  await expectResponsiveBoard(ownerPage, 'Report status board', 2);
  await expect(ownerPage.getByRole('heading', { name: 'Conversations', exact: true })).toHaveCount(0);
  await expect(ownerPage.getByText('Open conversation', { exact: true })).toHaveCount(0);
});

test('the reporter renews access with a new end date, then back to until revoked', async () => {
  const access = await manageAccess(ownerPage);
  const renew = access.getByRole('group', { name: 'Renew access' });
  await renew.getByLabel('New end').selectOption({ label: '1 year from today' });
  await renew.getByRole('button', { name: 'Renew access', exact: true }).click();
  await expect(ownerPage.getByText(`Access for ${FIRM_NAME} was renewed.`)).toBeVisible({ timeout: 120_000 });
  await expect(access.getByText(/^Until .+ \(36[56] days left\)$/)).toBeVisible();

  // The firm sees the new end date on its requests list.
  const { requests } = await firmPortal();
  await requests.getByRole('button', { name: 'Refresh' }).click();
  await expect(requests.getByText(/^Access ends .+ unless the reporter renews it\./)).toBeVisible({ timeout: 120_000 });

  const again = await manageAccess(ownerPage);
  await again.getByRole('group', { name: 'Renew access' }).getByLabel('New end').selectOption({ label: 'Until I revoke it' });
  await again.getByRole('group', { name: 'Renew access' }).getByRole('button', { name: 'Renew access', exact: true }).click();
  await expect(again.getByText('Until you revoke it', { exact: true })).toBeVisible({ timeout: 120_000 });
  await requests.getByRole('button', { name: 'Refresh' }).click();
  await expect(requests.getByText('Access lasts until the reporter revokes it.', { exact: false })).toBeVisible({ timeout: 120_000 });
});

test('the reporter shares contact details, the firm reads them, and the reporter stops sharing', async () => {
  const access = await manageAccess(ownerPage);
  await expect(access.getByText(`Not shared. ${FIRM_NAME} cannot see how to reach you.`)).toBeVisible();
  await access.getByRole('button', { name: `Share my contact details with ${FIRM_NAME}` }).click();
  await access.getByRole('button', { name: 'Share my contact details', exact: true }).click();
  await expect(ownerPage.getByText(`${FIRM_NAME} can now read your contact details.`)).toBeVisible({ timeout: 120_000 });
  await expect(access.getByText(`You are sharing your contact details with ${FIRM_NAME}.`)).toBeVisible();

  const firm = await firmOpensReport();
  await expect(firm.getByText(CONTACT)).toBeVisible({ timeout: 120_000 });

  const again = await manageAccess(ownerPage);
  await again.getByRole('button', { name: 'Stop sharing contact details' }).click();
  await again.getByRole('button', { name: 'Confirm: stop sharing' }).click();
  await expect(ownerPage.getByText(`You stopped sharing your contact details with ${FIRM_NAME}.`)).toBeVisible({ timeout: 120_000 });
  await expect(again.getByText(`Not shared. ${FIRM_NAME} cannot see how to reach you.`)).toBeVisible();

  await firmOpensReport();
  await expect(firm.getByText(CONTACT)).toHaveCount(0);
});

test('the reporter adds a file after submitting; the firm gets it only once shared', async () => {
  const add = ownerPage.getByRole('region', { name: 'Add evidence' });
  await add.getByLabel('Choose evidence files').setInputFiles(LATER_FILE);
  await expect(add.getByText(LATER_FILE.name, { exact: false })).toBeVisible();
  await add.getByRole('button', { name: 'Encrypt and add' }).click();
  await expect(ownerPage.getByText('Files added. No legal organization can open them yet.', { exact: false })).toBeVisible({ timeout: 180_000 });
  const files = ownerPage.getByRole('region', { name: 'Your files' });
  await expect(files.getByRole('listitem').filter({ hasText: LATER_FILE.name })).toContainText('Added later', { timeout: 120_000 });

  // The organization still has only the file it was given.
  const firm = await firmOpensReport();
  await expect(firm.getByRole('region', { name: 'Files' }).getByRole('listitem')).toHaveCount(1);

  // The reporter shares the new file under "Who has access".
  const access = await manageAccess(ownerPage);
  await access.getByRole('button', { name: 'Change what they can read' }).click();
  await access.getByRole('checkbox', { name: new RegExp(LATER_FILE.name.replace('.', '\\.')) }).check();
  await access.getByRole('button', { name: 'Save what they can read' }).click();
  await expect(ownerPage.getByText(`${FIRM_NAME} can now open what you chose.`, { exact: true })).toBeVisible({ timeout: 120_000 });

  await firmOpensReport();
  const shared = firm.getByRole('region', { name: 'Files' });
  await expect(shared.getByRole('listitem')).toHaveCount(2, { timeout: 120_000 });
  await firm.evaluate(() => { Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true }); });
  const download = firm.waitForEvent('download');
  await shared.getByRole('button', { name: /^Download / }).nth(1).click();
  const saved = await download;
  expect(saved.suggestedFilename()).toBe(LATER_FILE.name);
  expect(readFileSync((await saved.path())!, 'utf8')).toBe(LATER_FILE.buffer.toString('utf8'));
});

test('the steward removes a lawyer, replaces the organization key and asks for a new invitation', async ({ browser }) => {
  const page = stewardPage;
  await firmPortal();
  await page.getByRole('navigation', { name: 'Legal portal' }).getByRole('link', { name: 'Lawyers and devices' }).click();
  await page.getByRole('button', { name: 'Remove Avery Associate' }).click();
  const wizard = page.getByRole('region', { name: 'Remove Avery Associate' });
  const code = await wizard.getByLabel(/^Recovery code for the new key file/).inputValue();
  expect(code.length).toBeGreaterThanOrEqual(16);
  await wizard.getByRole('checkbox', { name: /I saved this recovery code/ }).check();
  const keyDownload = page.waitForEvent('download');
  await wizard.getByRole('button', { name: 'Remove and create the new key' }).click();
  const keyFile = readFileSync((await (await keyDownload).path())!, 'utf8');

  const checklist = page.getByRole('region', { name: 'New key created. Finish these steps' });
  await expect(checklist.getByText('Removed: Avery Associate.')).toBeVisible({ timeout: 120_000 });
  await checklist.getByRole('checkbox', { name: /The new key file is saved/ }).check();
  await checklist.getByRole('button', { name: 'Send the new key' }).click();
  await expect(checklist.getByText(/The new key was sent to \d+ approved devices?, and your request list moved to it\./)).toBeVisible({ timeout: 120_000 });
  await checklist.getByRole('button', { name: 'Submit new key', exact: true }).click();
  await expect(checklist.getByText('New public key submitted for approval.')).toBeVisible();
  // The checklist warns before leaving while the new key is only in this tab.
  page.on('dialog', dialog => void dialog.accept());
  await checklist.getByRole('button', { name: 'Finish and lock' }).click();
  journey.firmKeyFile = keyFile;
  journey.firmCode = code;
  keepPrivate(...await organizationKeyFileSecrets(keyFile, code));
  // Every lawyer, the steward included, needs an invitation for the new key.
  journey.invitation = await issueInvitation(browser, STEWARD.subject, { replacedKey: true });
});

test('after the key change the firm asks again and the reporter allows the new key', async () => {
  const page = await steward.newPage();
  await stewardPage.close({ runBeforeUnload: false });
  stewardPage = page;
  await acceptInvitation(page);
  // Replacement does not require optional custody. Current terms are re-signed
  // for the replacement key; a new reporter grant is still required below.
  // Previously acknowledged current terms are re-signed for this key by the setup flow.
  await expect(page.getByText('Organization setup complete. Show details or change your profile', { exact: true })).toBeVisible();
  await expect(page.getByText('Finish organization setup to request or open reports', { exact: true })).toHaveCount(0);
  const requests = page.getByRole('region', { name: "Your organization's requests", exact: true });
  const item = requests.getByRole('listitem').filter({ hasText: SUMMARY });
  await expect(item.getByText('Needs new access')).toBeVisible({ timeout: 120_000 });
  await item.getByRole('button', { name: 'Ask the reporter to allow access again' }).click();
  const form = item.getByRole('form', { name: 'Ask to renew access' });
  await expect(form.getByLabel('Why you need access to continue')).toHaveValue(RENEW_PURPOSE);
  // The replacement public key carries no profile until the firm submits one again.
  await fillRequestDetails(form, { signedProfile: false });
  await form.getByRole('button', { name: 'Send renewal request' }).click();
  await expect(form).toHaveCount(0, { timeout: 120_000 });

  await ownerPage.getByRole('button', { name: 'Check for updates' }).click();
  const request = ownerPage.getByRole('region', { name: `${FIRM_NAME} asks to renew access` });
  await expect(request).toBeVisible({ timeout: 120_000 });
  await expect(request.getByText(`The key of ${FIRM_NAME} has changed since you allowed access.`, { exact: false })).toBeVisible();
  await request.getByRole('button', { name: 'Choose what to share' }).click();
  await request.getByRole('button', { name: 'Allow and replace current access' }).click();
  await expect(ownerPage.getByText(`${FIRM_NAME} can now open what you chose. You can change or revoke this under "Who has access".`))
    .toBeVisible({ timeout: 120_000 });
  await expect(request).toHaveCount(0);

  // The organization opens the report again under its new key.
  await firmOpensReport();
});

test('the reporter revokes access and the firm loses it', async () => {
  const access = await manageAccess(ownerPage);
  await access.getByRole('button', { name: 'Revoke access' }).click();
  await access.getByRole('button', { name: 'Confirm: revoke access' }).click();
  await expect(ownerPage.getByText(`${FIRM_NAME} no longer has access to new information.`)).toBeVisible({ timeout: 120_000 });

  const { requests } = await firmPortal();
  await requests.getByRole('button', { name: 'Refresh' }).click();
  await expect(requests.getByText('Access ended', { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(requests.getByRole('button', { name: 'Open report' })).toHaveCount(0);
  // The host saw only ciphertext for everything the participants exchanged,
  // the firm's side (messages, requests, enrollment, member keys, evidence reads) included.
  expectHostSawOnlyCiphertext();
});

test('the firm asks to renew and the reporter declines', async () => {
  const { requests } = await firmPortal();
  const item = requests.getByRole('listitem').filter({ hasText: SUMMARY });
  await item.getByRole('button', { name: 'Ask to renew' }).click();
  const form = item.getByRole('form', { name: 'Ask to renew access' });
  await form.getByLabel('Why you need access to continue').fill(RENEWAL_REASON);
  await fillRequestDetails(form, { signedProfile: false });
  await form.getByRole('button', { name: 'Send renewal request' }).click();
  await expect(form).toHaveCount(0, { timeout: 120_000 });
  await requests.getByRole('button', { name: 'Refresh' }).click();
  await expect(item.getByText('Waiting for reporter', { exact: true })).toBeVisible({ timeout: 120_000 });

  await ownerPage.getByRole('button', { name: 'Check for updates' }).click();
  const request = ownerPage.getByRole('region', { name: `${FIRM_NAME} asks to renew access` });
  await expect(request.getByText(RENEWAL_REASON)).toBeVisible({ timeout: 120_000 });
  await request.getByRole('button', { name: 'Decline', exact: true }).click();
  await expect(request.getByText(`${FIRM_NAME} will see that the request was declined, with no reason and no date.`, { exact: false })).toBeVisible();
  await request.getByRole('button', { name: 'Confirm: decline' }).click();
  await expect(ownerPage.getByText(`You declined the request from ${FIRM_NAME}.`)).toBeVisible({ timeout: 120_000 });
  await expect(request).toHaveCount(0);

  await requests.getByRole('button', { name: 'Refresh' }).click();
  await expect(item.getByText('Declined', { exact: true })).toBeVisible({ timeout: 120_000 });
  await expect(item.getByRole('button', { name: 'Open report' })).toHaveCount(0);
  expectHostSawOnlyCiphertext();
});

test('the authorized directory API exposes only the approved public projection', async () => {
  // Preserve the privacy boundary assertion after retirement of the dashboard.
  // Cursors are opaque case IDs and must remain in request bodies, not URLs.
  let after: string | null = null;
  let publicCaseId: string | undefined;
  const seen = new Set<string>();
  do {
    const response = await admin.request.post('/api/admin/confidential/listings', {
      data: { limit: 100, ...(after ? { after } : {}) },
    });
    expect(response.status()).toBe(200);
    const text = await response.text();
    const responseBodies = [text];
    expect(leakedSecrets(responseBodies, sweptFromHost([...SENTINELS, ...deviceSecrets]))).toEqual([]);
    const body = JSON.parse(text);
    expect(body.success).toBe(true);
    expect(Array.isArray(body.listings)).toBe(true);
    for (const row of body.listings) {
      expect(Object.keys(row).every(key => ['caseId', 'summary', 'publishedAt', 'hasAttachments', 'hidden'].includes(key))).toBe(true);
      for (const secret of SENTINELS) expect(JSON.stringify(row)).not.toContain(secret);
      if (row.summary === SUMMARY) publicCaseId = row.caseId;
    }
    after = body.next;
    if (after !== null) {
      expect(after).toMatch(/^[a-f0-9]{64}$/);
      expect(seen.has(after)).toBe(false);
      seen.add(after);
      expect(seen.size).toBeLessThan(100);
    }
  } while (after);
  expect(publicCaseId).toMatch(/^[a-f0-9]{64}$/);
  expect(publicCaseId).toBe(journey.caseId);
});

test('legacy routes reject confidential case IDs and recovery codes before any lookup', async ({ browser }) => {
  const context = await newParticipant(browser);
  const page = await context.newPage();
  // A probe in the reporter's recovery code format, never the reporter's own
  // code: this test sends it in a URL and a header on purpose, and request
  // lines reach the host's logs, which the teardown sweep checks.
  const code = formatRecoveryCode(await encodeRecoveryCodeV2(new Uint8Array(randomBytes(32)))), caseId = journey.caseId!;
  expect(code).not.toBe(journey.report!.recoveryCode);
  // BACKEND_URL points at a closed port in this stack: a 400 proves the Next
  // route refused the identifier before forwarding it to the legacy backend.
  for (const path of [`/api/whistleblower/status/${caseId}`, `/api/whistleblower/status/${encodeURIComponent(code)}`]) {
    const response = await page.request.get(path);
    expect(response.status(), path).toBe(400);
    expect(await response.text()).not.toContain(caseId);
  }
  // The legacy evidence and reward-contact readers need an admin; even a VERA
  // admin session is refused a confidential case ID there.
  for (const path of [`/api/whistleblower/evidence/${caseId}/evidence.pdf`, `/api/whistleblower/reward-contact/${caseId}`]) {
    expect((await page.request.get(path)).status(), path).toBe(401);
    const response = await admin.request.get(path);
    expect(response.status(), path).toBe(400);
    expect(await response.text()).not.toContain(caseId);
  }
  const credential = await page.request.get('/api/whistleblower/status/VRC-0123456789abcdef', { headers: { 'X-Reporter-Credential': code } });
  expect(credential.status()).toBe(400);
  const submit = await page.request.post('/api/whistleblower/submit', { data: { description: 'legacy plaintext intake' } });
  expect(submit.status()).toBe(409);
  expect(await submit.json()).toMatchObject({ error: 'confidential_intake_required' });

  // The status page treats a case ID as a (wrong) recovery code, checked on the device.
  const legacy: string[] = [];
  page.on('request', request => { if (request.url().includes('/api/whistleblower/')) legacy.push(request.url()); });
  await page.goto('/status');
  await page.getByLabel('Recovery code').fill(caseId);
  await page.getByRole('button', { name: 'Retrieve report status' }).click();
  await expect(page.locator('#report-id-error')).toBeVisible();
  expect(legacy).toEqual([]);
  // Drain asset route.fetch handlers before closing: otherwise an in-flight
  // response can append to the API network trace while Playwright zips it.
  await context.unrouteAll({ behavior: 'wait' });
  await context.close();
});

test('the reporter edits the summary and closes the report; the saved request follows', async () => {
  const summary = ownerPage.getByRole('region', { name: 'Summary for legal review' });
  await summary.getByRole('button', { name: 'Edit summary' }).click();
  await summary.getByRole('textbox', { name: 'Summary for legal review' }).fill(EDITED_SUMMARY);
  await summary.getByRole('button', { name: 'Save summary' }).click();
  await expect(ownerPage.getByText('Your summary was updated.')).toBeVisible({ timeout: 120_000 });
  await expect(summary.getByText(EDITED_SUMMARY)).toBeVisible();
  await firmPortal();
  await expect(stewardPage.getByRole('region', { name: 'Needs attention' }).getByRole('listitem').filter({ hasText: EDITED_SUMMARY })).toBeVisible();
  await expect(stewardPage.getByRole('region', { name: 'Available reports' })).toHaveCount(0);

  await summary.getByRole('button', { name: 'Close report' }).click();
  await expect(summary.getByRole('group', { name: 'Confirm report closure' })).toBeVisible();
  await summary.getByRole('button', { name: 'Confirm: close report' }).click();
  await expect(ownerPage.getByText('Report closed. Your summary is hidden and all firm access has ended.')).toBeVisible({ timeout: 120_000 });
  await expect(summary.getByRole('button', { name: 'Reopen report' })).toBeVisible();
  await firmPortal();
  await expect(stewardPage.getByRole('region', { name: 'Shared with you' }).getByText(EDITED_SUMMARY)).toHaveCount(0);
  expectHostSawOnlyCiphertext();
});

test('the reporter shares proactively; the firm opens the signed listing without requesting access', async ({ browser }) => {
  const summary = 'A supplier appears to have billed for public infrastructure work that was never completed.';
  const narrative = 'SENTINEL-DIRECT-NARRATIVE: the supporting inspection never took place.';
  const contact = 'sentinel-direct-contact@reporter.example';
  const context = await newParticipant(browser);
  recordTraffic(context, hostTraffic);
  deviceSecrets.push(narrative, contact);
  try {
    const page = await context.newPage();
    const report = await submitConfidentialReport(page, { narrative, summary, contact, files: [PRIVATE_FILE] });
    deviceSecrets.push(...recoveryFileSecrets(report.recoveryFile, report.recoveryCode));
    await openWithRecoveryCode(page, report.recoveryCode);

    // An unshared submission has no card or request action in the legal UI.
    let { requests } = await firmPortal();
    await expect(stewardPage.getByRole('region', { name: 'Shared with you' }).getByText(summary, { exact: true })).toHaveCount(0);
    await expect(stewardPage.getByText(summary, { exact: true })).toHaveCount(0);
    await expect(stewardPage.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
    await expect(stewardPage.getByText(narrative, { exact: true })).toHaveCount(0);

    const direct = page.getByRole('region', { name: 'Available law firms' }).getByRole('listitem').filter({ hasText: FIRM_NAME });
    await expect(direct.getByText('Not shared', { exact: true })).toBeVisible();
    await expect(direct.getByRole('link', { name: FIRM_DOMAIN, exact: true })).toBeVisible();
    await direct.getByRole('button', { name: 'Select organization', exact: true }).click();
    const share = direct.getByRole('button', { name: 'Submit', exact: true });
    await expect(share).toBeEnabled();
    await expect(direct.getByRole('checkbox', { name: 'Also share all current files' })).not.toBeChecked();
    await expect(direct.getByRole('checkbox', { name: 'Allow encrypted messages' })).toHaveCount(0);
    await share.click();
    await expect(page.getByText('Access granted. Tell the organization your report check code', { exact: false })).toBeVisible();
    await expect(direct.getByText('Previously submitted', { exact: true })).toBeVisible();
    await expect(direct.getByRole('button', { name: 'Select organization', exact: true })).toHaveCount(0);
    await expect(direct.getByRole('link', { name: 'Manage access' })).toBeVisible();
    const firmAccessCard = page.getByRole('region', { name: 'Who has access' }).getByRole('listitem').filter({ hasText: FIRM_NAME });
    await expect(firmAccessCard.getByText('Access active', { exact: true })).toBeVisible();
    await expect(firmAccessCard.getByText('Manage access', { exact: true })).toBeVisible();

    // Opening uses the signed listing and owner key, without inventing a request
    // or disclosing a plaintext case-to-organization routing record to the host.
    ({ requests } = await firmPortal());
    const directRow = requests.getByRole('listitem').filter({ hasText: summary });
    await expect(directRow.getByText('Shared directly by the reporter', { exact: true })).toBeVisible();
    await expect(directRow.getByText('Access allowed', { exact: true })).toBeVisible();
    await expectResponsiveBoard(stewardPage, 'Legal report board', 3);
    await expect(directRow.getByRole('button', { name: /Request access|Withdraw|Remove/ })).toHaveCount(0);
    await expect(requests.getByRole('listitem').filter({ hasText: summary })).toHaveCount(1);
    await directRow.getByRole('button', { name: 'Open report', exact: true }).click();
    await resumeFirmSignIn(stewardPage, stewardPage.getByText(narrative, { exact: true }));
    await expect(stewardPage.getByText('The reporter has not shared files with your organization.', { exact: true })).toBeVisible();
    await expect(stewardPage.getByRole('region', { name: 'Messages with the reporter' })).toHaveCount(0);
    await expect(stewardPage.getByText(contact, { exact: true })).toHaveCount(0);
    await expect(stewardPage.getByText(PRIVATE_FILE.name, { exact: true })).toHaveCount(0);
    const manage = page.getByRole('region', { name: 'Summary for legal review' });
    await manage.getByRole('button', { name: 'Close report', exact: true }).click();
    await expect(manage.getByRole('group', { name: 'Confirm report closure' })).toContainText('Stop every firm');
    await manage.getByRole('button', { name: 'Keep report open' }).click();
    await expect(firmAccessCard.getByText('Access active', { exact: true })).toBeVisible();
    await manage.getByRole('button', { name: 'Close report', exact: true }).click();
    await manage.getByRole('button', { name: 'Confirm: close report' }).click();
    await expect(page.getByText('Report closed. Your summary is hidden and all firm access has ended.')).toBeVisible({ timeout: 120_000 });
    await expect(page.getByRole('region', { name: 'Available law firms' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Select organization', exact: true })).toHaveCount(0);
    // Closing removes both discoverability and the shared card. Separate
    // protocol tests also retry reads and messages with both firms' old keys.
    await firmPortal();
    await expect(stewardPage.getByText(summary, { exact: true })).toHaveCount(0);
    await expect(stewardPage.getByRole('region', { name: 'Shared with you' }).getByText(summary, { exact: true })).toHaveCount(0);
    await expect(stewardPage.getByText(narrative, { exact: true })).toHaveCount(0);
    await manage.getByRole('button', { name: 'Reopen report' }).click();
    await expect(manage.getByRole('textbox', { name: 'Summary for legal review' })).toHaveValue(summary);
    await manage.getByRole('button', { name: 'Publish summary and reopen' }).click();
    await expect(page.getByText('Report reopened. Your summary is visible again. No firm has been given access.')).toBeVisible({ timeout: 120_000 });
    await firmPortal();
    await expect(stewardPage.getByRole('region', { name: 'Shared with you' }).getByText(summary, { exact: true })).toHaveCount(0);
    await expect(stewardPage.getByText(summary, { exact: true })).toHaveCount(0);
    await expect(stewardPage.getByRole('button', { name: 'Request access', exact: true })).toHaveCount(0);
    expectHostSawOnlyCiphertext();
  } finally {
    await context.close();
  }
});
