import { approveApplicationInSlack } from '../support/legalApplications';
import { issueInvitation } from '../support/firm';
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { newParticipant, signInAs } from '../support/browser';
import { APPLICATION_FIRM_DOMAIN as domain, IDENTITY_DOMAIN, ONBOARDING_ORG } from '../stack/stack';
import { stackState, sweptFromHost } from '../support/state';
import { importFirmIdentity } from '../../../lib/confidential/firmKey';

test('approved applicant finishes key submission and signed membership setup in the same tab', async ({ browser }) => {
  const applicant = await newParticipant(browser), admin = await newParticipant(browser, { admin: true });
  const page = await applicant.newPage();
  const displayName = 'Approved Application Counsel';
  // Legacy assigned IDs require the independent administrator's key approval.
  const existingUser = await admin.request.post('/__e2e/existing-email', {
    headers: { 'x-e2e-review-key': stackState().adminCookie }, data: { email: `lawyer@${domain}` },
  });
  expect(existingUser.status()).toBe(200);
  expect((await applicant.request.post('/api/legal-applications', { data: {
    displayName, domain, email: `lawyer@${domain}`, lawyerName: 'Synthetic Applicant', jurisdiction: 'Synthetic jurisdiction', registrationNumber: 'TEST-SETUP',
  } })).status()).toBe(202);
  await approveApplicationInSlack(admin, domain);
  const organizations = await (await admin.request.get('/api/admin/confidential/legal/organizations')).json();
  const org = organizations.organizations.find((value: { domain: string }) => value.domain === domain);
  expect(org).toMatchObject({ publicKey: null, activeMembers: 0 });
  const fixture = await (await applicant.request.get('/__e2e/legal-applications')).json();
  const subject = fixture.users.find((user: any) => user.email === `lawyer@${domain}`).user_id;
  // Auth0 is synthetic; context matches the organization created by the real worker.
  signInAs(applicant, { subject, providerOrganizationId: org.providerOrganizationId, setup: {
    organizationId: org.organizationId, providerOrganizationId: org.providerOrganizationId, domain, displayName,
  } });
  // A direct visit has no in-memory identity context (also true after a reload
  // or expiry). Renewing must re-read setup claims, rather than leave Create key
  // permanently disabled with the initial null context captured in a closure.
  await page.goto('/legal/enroll');
  await expect(page.getByRole('heading', { name: 'Load your approved organization.' })).toBeVisible();
  await page.getByRole('button', { name: 'Sign in and load organization' }).click();
  await expect(page.getByRole('heading', { name: 'Finish setup', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Create a new organization key' }).click();
  await expect(page.getByLabel('Organization ID (from VERA onboarding)')).toHaveCount(0);
  await expect(page.getByLabel("Your organization's domain")).toHaveCount(0);
  await page.getByRole('button', { name: 'Create key', exact: true }).click();
  const proceed = page.getByRole('button', { name: 'Continue to workspace', exact: true });
  await expect(proceed).toBeDisabled();
  const code = await page.getByLabel('Recovery code (or replace with a passphrase of at least 16 characters)').inputValue();
  // A cancelled or failed native save must not claim success or allow setup.
  await page.evaluate(() => {
    (window as any).showSaveFilePicker = async () => { throw new DOMException('Cancelled', 'AbortError'); };
  });
  await page.getByRole('button', { name: 'Download encrypted key file' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Save cancelled.' })).toBeVisible();
  await expect(proceed).toBeDisabled();
  await page.evaluate(() => {
    (window as any).showSaveFilePicker = async () => ({ createWritable: async () => ({
      write: async () => {}, close: async () => { throw new Error('Disk full'); }, abort: async () => {},
    }) });
  });
  await page.getByRole('button', { name: 'Download encrypted key file' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'This browser could not save the file.' })).toBeVisible();
  await expect(proceed).toBeDisabled();
  await page.evaluate(() => {
    (window as any).showSaveFilePicker = async () => ({ createWritable: async () => ({
      write: async (text: string) => { (window as any).__savedEncryptedBackup = text; },
      close: async () => {}, abort: async () => {},
    }) });
  });
  await page.getByRole('button', { name: 'Download encrypted key file' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Encrypted key file saved.' })).toBeVisible();
  await expect(proceed).toBeDisabled();
  // The manual fallback is the same encrypted export, usable even in browsers
  // whose embedded download manager cannot save blob URLs. Verification below
  // restores these manually saved bytes, rather than trusting a download click.
  await page.getByText('Download not starting? Save a copy manually', { exact: true }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Use browser download instead' }).click();
  const file = readFileSync((await (await download).path())!, 'utf8');
  const manualFile = await page.getByLabel('Encrypted key backup', { exact: true }).inputValue();
  expect(manualFile).toBe(file);
  expect(await page.evaluate(() => (window as any).__savedEncryptedBackup)).toBe(file);
  await page.evaluate(() => { delete (window as any).__savedEncryptedBackup; });
  expect(manualFile).not.toContain(code);
  expect(manualFile).not.toMatch(/BEGIN PGP PRIVATE KEY BLOCK/);
  await expect(importFirmIdentity(file, '')).rejects.toThrow();
  const restored = await importFirmIdentity(file, code);
  sweptFromHost([file, code, restored.privateKey.armor(), JSON.stringify(restored.privateKey.armor()).slice(1, -1)]);
  await expect(proceed).toBeDisabled();
  await page.getByLabel('Saved encrypted key file').setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(manualFile) });
  await expect(page.getByRole('button', { name: 'Verify saved backup' })).toBeDisabled();
  await page.getByLabel('Saved recovery code or passphrase').fill('wrong but sufficiently long secret');
  await page.getByRole('button', { name: 'Verify saved backup' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'That file and recovery code did not restore' })).toBeVisible();
  await expect(proceed).toBeDisabled();
  await page.getByLabel('Saved recovery code or passphrase').fill(code);
  await page.getByRole('button', { name: 'Verify saved backup' }).click();
  await expect(page.getByText('Backup verified.', { exact: false })).toBeVisible();
  await expect(proceed).toBeEnabled();
  // Onboarding approval may take longer than the five-minute identity session.
  // Expire only this document's login check. Restore real time before the
  // identity redirect proceeds; context-wide fake clocks also affect new
  // documents and can invalidate the real attestation freshness checks.
  await page.evaluate(() => {
    const realNow = Date.now;
    (window as any).__restoreSetupClock = () => { Date.now = realNow; };
    Date.now = () => realNow() + 300_000;
  });
  await applicant.route(`https://${IDENTITY_DOMAIN}/authorize*`, async route => {
    await page.evaluate(() => {
      (window as any).__restoreSetupClock();
      delete (window as any).__restoreSetupClock;
    });
    await route.fallback();
  }, { times: 1 });
  const renewal = page.waitForEvent('popup', { timeout: 20_000 });
  await proceed.click();
  await renewal;
  await page.getByRole('checkbox', { name: 'Whistleblower representation' }).check();
  await page.getByLabel('Jurisdiction').fill('Synthetic jurisdiction');
  await page.getByLabel('Website').fill(domain);
  await page.getByRole('button', { name: 'Submit organization profile' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Your public key and profile have been submitted.' })).toBeVisible();
  await expect(page.getByLabel('Private Finish setup link')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download public key', exact: true })).toHaveCount(0);
  const invitation = await issueInvitation(browser, { organizationId: org.organizationId, domain, keyFile: file }, subject,
    { traffic: [], deviceSecrets: [] });
  await page.getByLabel('Private Finish setup link').fill(invitation);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await page.getByRole('link', { name: 'Open workspace' }).click();
  await expect(page).toHaveURL(/\/legal$/, { timeout: 90000 });
  await expect(page.getByLabel('Private Finish setup link')).toHaveCount(0);
  await expect(page.getByText('Organization key unlocked on this device', { exact: true })).toBeVisible();
  await applicant.close(); await admin.close();
});
