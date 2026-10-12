import { expect } from '@playwright/test';
import type { Browser, BrowserContext, Locator, Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { ONBOARDING_ORG, newParticipant, recordTraffic, signInAs, existingRequestToken } from './browser';
import { existingRequestClient } from './existingRequest';
import type { Persona } from './browser';
import { leakedSecrets, recoveryCodeForms, organizationKeyFileSecrets } from './leaks';
import { stackState, sweptFromHost } from './state';

// A legal organization as specs that need their own firms drive it: fixture
// registration, then its steward sets up the organization key (backup, second key
// holder, terms, signed VERA key approval), the onboarding operator issues an invitation and
// the steward redeems it. The same pages and steps as the journey's firm.

const OPERATOR: Persona = { subject: 'auth0|e2e-operator', providerOrganizationId: ONBOARDING_ORG };

export type Firm = {
  name: string; domain: string; steward: Persona;
  organizationId: string;
  /** The organization key file and its recovery code: device secrets. */
  keyFile: string; code: string;
  context: BrowserContext; page: Page;
};

/** Collects what participants send and the secrets that must never leave their devices. */
export type LeakWatch = { traffic: string[]; deviceSecrets: string[] };
export function keepPrivate(watch: LeakWatch, ...values: string[]) {
  for (const value of values) watch.deviceSecrets.push(...recoveryCodeForms(value), value);
}

/** Fixture organization setup through the authenticated API. The retired
 * /admin page is not part of the legal journeys. Returns the organization ID. */
export async function addOrganization(admin: BrowserContext, firm: { name: string; domain: string; steward: Persona }): Promise<string> {
  const response = await admin.request.post('/api/admin/confidential/legal/organizations', { data: {
    displayName: firm.name, domain: firm.domain, providerOrganizationId: firm.steward.providerOrganizationId,
  } });
  expect(response.ok()).toBe(true);
  const { organization: { organizationId } } = await response.json();
  expect(organizationId).toMatch(/^[a-f0-9]{64}$/);
  return organizationId;
}

/** The onboarding operator's page issues a recipient-bound invitation. */
export async function issueInvitation(browser: Browser, firm: Pick<Firm, 'organizationId' | 'domain' | 'keyFile'>, subject: string, watch: LeakWatch): Promise<string> {
  const context = await newParticipant(browser, { admin: true });
  signInAs(context, OPERATOR, 'onboarding');
  recordTraffic(context, watch.traffic);
  const state = stackState();
  try {
    const page = await context.newPage();
    const traffic = recordTraffic(page);
    await page.goto('/legal/administration');
    await expect(page.getByRole('heading', { name: 'Legal onboarding' })).toBeVisible();
    const organization = page.getByLabel('Organization', { exact: true });
    await organization.selectOption(firm.organizationId);
    await expect(page.getByText(`Key ID submitted by ${firm.domain}:`)).toBeVisible();
    await page.getByRole('button', { name: 'Sign in with the onboarding account' }).click();
    await expect(page.getByText('Signed in with the onboarding account.', { exact: false })).toBeVisible();
    await expect(organization).toHaveValue(firm.organizationId);
    // The readback comes from the firm's saved backup, not the host's candidate row.
    const keyId = JSON.parse(firm.keyFile.split('\n').find(line => line.startsWith('{"format":'))!).recipientKeyId;
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
    // The authority key and its code never leave the page.
    expect(leakedSecrets(traffic, sweptFromHost([...recoveryCodeForms(state.authorityCode), state.authorityKeyFile]))).toEqual([]);
    return await link.inputValue();
  } finally { await context.close(); }
}

/** Registration, verified key backup, signed key approval and account enrollment:
 * the organization's portal is open at the end. No firm website is contacted. */
export async function onboardFirm(browser: Browser, admin: BrowserContext, input: { name: string; domain: string; steward: Persona },
  watch: LeakWatch): Promise<Firm> {
  const organizationId = await addOrganization(admin, input);
  const context = await newParticipant(browser);
  recordTraffic(context, watch.traffic);
  signInAs(context, input.steward);
  let page = await context.newPage();
  await page.goto(`/legal/enroll#${new URLSearchParams({ organization: organizationId, domain: input.domain })}`);
  await expect(page.getByLabel('Organization ID (from VERA onboarding)')).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Create your organization key' })).toContainText(input.domain);
  await expect(page).toHaveURL(/\/legal\/enroll$/);
  await page.getByRole('button', { name: 'Create key', exact: true }).click();

  const code = await page.getByLabel('Recovery code (or replace with a passphrase of at least 16 characters)').inputValue();
  await page.getByText('Download not starting? Save a copy manually', { exact: true }).click();
  const keyDownload = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Use browser download instead' }).click();
  const keyFile = readFileSync((await (await keyDownload).path())!, 'utf8');
  keepPrivate(watch, ...await organizationKeyFileSecrets(keyFile, code));
  const key = { name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(keyFile) };
  await page.getByLabel('Saved encrypted key file').setInputFiles(key);
  await page.getByLabel('Saved recovery code or passphrase').fill(code);
  await page.getByRole('button', { name: 'Verify saved backup' }).click();
  await page.getByRole('button', { name: 'Continue to workspace', exact: true }).click();
  await page.getByRole('checkbox', { name: 'Whistleblower representation' }).check();
  await page.getByLabel('Jurisdiction').fill('England and Wales');
  await page.getByLabel('Website').fill(input.domain);
  await page.getByRole('button', { name: 'Submit organization profile' }).click();
  await expect(page.getByText('Your public key and profile have been submitted.', { exact: false })).toBeVisible();

  const firm: Firm = { ...input, organizationId, keyFile, code, context, page };
  const invitation = await issueInvitation(browser, firm, input.steward.subject, watch);
  // The invitation opens in a new tab; the steward unlocks with the key file.
  page = await context.newPage();
  await firm.page.close();
  firm.page = page;
  await page.goto(invitation);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('button', { name: 'Use our existing key file' }).click();
  await page.getByLabel('Encrypted private key file').setInputFiles(key);
  await page.getByLabel('Recovery passphrase or code').fill(code);
  await page.getByRole('button', { name: 'Open organization', exact: true }).click();
  await expect(page.getByText('Your account is enrolled for your organization.')).toBeVisible();
  await page.getByRole('link', { name: 'Open workspace', exact: true }).click();
  // A sole holder needs signed terms, not a second custody copy.
  const workspaceSetup = page.getByRole('region', { name: 'Organization setup' });
  // Membership must settle before its setup check can disable the form.
  await expect(workspaceSetup.locator('summary').filter({ hasText: 'Invitation accepted' })).toContainText('(done)');
  await workspaceSetup.locator('summary').filter({ hasText: 'Onboarding terms acknowledged' }).click();
  await workspaceSetup.getByRole('checkbox', { name: 'I have read these and my organization will follow them.' }).check();
  await workspaceSetup.getByRole('button', { name: 'Acknowledge' }).click();
  await expect(page.getByText('Organization setup complete. Show details or change your profile', { exact: true })).toBeVisible();
  return firm;
}

/** Follow only the sign-in and key gates of a long-lived firm tab: renew an
 * expired sign-in, sign in, or restore the memory-only key from its file. */
export async function resumeFirmSignIn(firm: Firm, ready: Locator): Promise<void> {
  const page = firm.page;
  const signIn = page.getByRole('button', { name: 'Sign in', exact: true });
  const renew = page.getByRole('button', { name: 'Sign in again', exact: true });
  const keyFile = page.getByLabel('Encrypted private key file', { exact: true });
  await expect(ready.or(signIn).or(renew).or(keyFile).first()).toBeVisible({ timeout: 120_000 });
  if (await renew.isVisible()) {
    await renew.click();
    await expect(page.getByText('Your sign-in has expired.', { exact: false })).toHaveCount(0, { timeout: 120_000 });
  } else if (await signIn.isVisible()) {
    await signIn.click();
    await expect(ready.or(keyFile).first()).toBeVisible({ timeout: 120_000 });
  }
  if (await keyFile.isVisible()) {
    await keyFile.setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(firm.keyFile) });
    await page.getByLabel('Recovery passphrase or code').fill(firm.code);
    await page.getByRole('button', { name: 'Open organization', exact: true }).click();
  }
  // A report view that failed only because the sign-in had expired keeps saying
  // so after the sign-in is renewed; the lawyer then chooses "Try again".
  const signInFailure = page.getByText('Please sign in again to continue.', { exact: true });
  await expect(ready.or(signInFailure).first()).toBeVisible({ timeout: 120_000 });
  if (!(await ready.isVisible()) && await signInFailure.isVisible()) {
    const expired = page.getByRole('button', { name: 'Sign in again', exact: true });
    if (await expired.isVisible()) {
      await expired.click();
      await expect(expired).toHaveCount(0, { timeout: 120_000 });
    }
    await page.getByRole('button', { name: 'Try again', exact: true }).click();
  }
  await expect(ready).toBeVisible({ timeout: 120_000 });
}

/** The portal home with freshly checked shared reports. A reload would lock the
 * organization key in this tab, so navigate in place. */
export async function firmPortal(firm: Firm): Promise<{ requests: Locator }> {
  const page = firm.page;
  await resumeFirmSignIn(firm, page.getByRole('navigation', { name: 'Legal portal' }));
  const back = page.getByRole('link', { name: 'Back to the portal' }).first();
  if (await back.count()) await back.click();
  await page.getByRole('navigation', { name: 'Legal portal' }).getByRole('link', { name: 'Lawyers and devices' }).click();
  await resumeFirmSignIn(firm, page.getByRole('heading', { name: 'Lawyers and devices', level: 1 }));
  await page.getByRole('navigation', { name: 'Legal portal' }).getByRole('link', { name: 'Requests and reports', exact: true }).click();
  const requests = page.getByRole('region', { name: "Your organization's requests", exact: true });
  await resumeFirmSignIn(firm, requests);
  await expect(page.getByText('Checking for shared reports…', { exact: true })).toHaveCount(0, { timeout: 120_000 });
  await expect(page.getByRole('region', { name: 'Available reports', exact: true })).toHaveCount(0);
  return { requests };
}

/** Preserve compatibility coverage for requests already sent before directory
 * browsing was removed. New users share from the reporter UI (journey spec).
 * Setup uses the real encrypted protocol; all subsequent actions use real pages. */
export async function seedExistingRequest(firm: Pick<Firm, 'keyFile' | 'code' | 'name' | 'steward' | 'page'>,
  summary: string, scopes: ('Report' | 'Files')[]) {
  await expect(firm.page.getByRole('region', { name: 'Available reports', exact: true })).toHaveCount(0);
  const seed = await existingRequestClient();
  const { baseURL, releaseManifest } = stackState();
  return seed({ baseURL, releaseManifest, keyFile: firm.keyFile, code: firm.code, name: firm.name,
    token: await existingRequestToken(firm.steward), summary, scopes });
}

/** The firm opens the report from its requests list, status re-checked first. */
export async function firmOpensReport(firm: Firm, narrative: string): Promise<Page> {
  const { requests } = await firmPortal(firm);
  await requests.getByRole('button', { name: 'Refresh' }).click();
  // Each organization in these specs has asked about one report.
  await requests.getByRole('button', { name: 'Open report' }).click();
  await resumeFirmSignIn(firm, firm.page.getByText(narrative));
  // Downloads fall back to the browser download (no File System Access picker).
  await firm.page.evaluate(() => { Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true }); });
  return firm.page;
}

/** Downloads the evidence file at this position in the firm's "Files" list. */
export async function firmDownloads(firm: Firm, index: number): Promise<{ name: string; text: string }> {
  const files = firm.page.getByRole('region', { name: 'Files' });
  const download = firm.page.waitForEvent('download');
  await files.getByRole('button', { name: /^Download / }).nth(index).click();
  const saved = await download;
  return { name: saved.suggestedFilename(), text: readFileSync((await saved.path())!, 'utf8') };
}
