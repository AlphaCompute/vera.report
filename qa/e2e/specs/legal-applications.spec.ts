import { approveFirmAndKeyInSlack, waitForRegistrationApproval } from '../support/legalApplications';
import { test, expect } from '@playwright/test';
import { newParticipant, signInAs } from '../support/browser';
import { createHmac } from 'node:crypto';
import { applicationFixtures } from '../stack/legalApplications';
import { sweptFromHost } from '../support/state';

test('Slack approval adds membership silently; sign-in sends the code and activates only the reviewed key', async ({ browser }) => {
  const applicant = await newParticipant(browser);
  const domain = `application-${Date.now()}.example`, displayName = `Synthetic Application Counsel ${Date.now()}`;
  const page = await applicant.newPage();
  await page.goto('/legal/apply');
  await page.getByLabel('Legal organization', { exact: true }).fill(displayName);
  await page.getByLabel('Organization website domain').fill(domain);
  await page.getByLabel('Organization email').fill(`lawyer@${domain}`);
  await page.getByLabel('Registered lawyer name').fill('Synthetic Applicant');
  await page.getByLabel('Licensing jurisdiction').fill('Synthetic jurisdiction');
  await page.getByLabel('Bar or registration number').fill('TEST-123');
  await page.getByRole('button', { name: 'Continue to key backup' }).click();
  await page.getByRole('button', { name: 'Create key', exact: true }).click();
  const submit = page.getByRole('button', { name: 'Submit firm and key for approval' });
  await expect(submit).toBeDisabled();
  const code = await page.getByLabel('Recovery code — save separately', { exact: true }).inputValue();
  await page.getByText('Download not starting? Save a copy manually', { exact: true }).click();
  const file = await page.getByLabel('Encrypted key backup', { exact: true }).inputValue();
  sweptFromHost([code, file]);
  await page.getByLabel('Saved encrypted key file').setInputFiles({ name: 'key.txt', mimeType: 'text/plain', buffer: Buffer.from(file) });
  await page.getByLabel('Saved recovery code', { exact: true }).fill(code);
  await page.getByRole('button', { name: 'Verify saved backup' }).click();
  await expect(page.getByText('Backup verified.', { exact: true })).toBeVisible();
  await page.getByRole('checkbox', { name: 'Whistleblower representation', exact: true }).check();
  await submit.click();
  await expect(page.getByRole('status')).toContainText('Application and public key submitted');
  const denied = await applicant.request.post('/api/admin/confidential/legal-applications', { data: { action: 'list' } });
  expect([401, 403]).toContain(denied.status());
  const pending = await (await applicant.request.get('/__e2e/legal-applications')).json();
  expect(pending.organizations.filter((org: any) => org.metadata.vera_domain === domain)).toEqual([
    expect.objectContaining({ metadata: expect.objectContaining({ vera_application_version: '1', vera_approval_status: 'pending',
      vera_display_name: displayName, vera_email: `lawyer@${domain}` }) }),
  ]);
  expect(pending.users.filter((user: any) => user.email === `lawyer@${domain}`)).toEqual([]);
  expect(pending.emails.filter((email: any) => email.email === `lawyer@${domain}`)).toEqual([]);

  const admin = await newParticipant(browser, { admin: true });
  expect((await applicant.request.get('/legal/applications')).status()).toBe(404);
  expect((await admin.request.get('/legal/applications')).status()).toBe(404);
  const application = await approveFirmAndKeyInSlack(admin, domain, true);
  const organizations = await admin.request.get('/api/admin/confidential/legal/organizations');
  expect(organizations.ok()).toBe(true);
  const organization = (await organizations.json()).organizations.find((org: { domain: string }) => org.domain === domain);
  expect(organization).toMatchObject({ status: 'awaiting-registration', publicKey: null, activeMembers: 0 });
  expect(organization.providerOrganizationId).toMatch(/^org_fixture/);
  await expect.poll(async () => {
    const state = await (await applicant.request.get('/__e2e/legal-applications')).json();
    return state.memberships.filter((member: any) => member.organization_id === organization.providerOrganizationId && !member.blocked);
  }).toEqual([expect.objectContaining({ email: `lawyer@${domain}`, roles: ['rol_legal'], email_verified: false })]);
  const snapshot = await (await applicant.request.get('/__e2e/legal-applications')).json();
  expect(snapshot.organizations.find((org: any) => org.metadata.vera_domain === domain)).toMatchObject({
    id: organization.providerOrganizationId, metadata: { vera_approval_status: 'approved', vera_provisioning_status: 'ready' },
  });
  expect(snapshot.users.filter((user: any) => user.email === `lawyer@${domain}`)).toEqual([
    expect.objectContaining({ email_verified: false, blocked: false }),
  ]);
  expect(snapshot.emails.filter((email: any) => email.email === `lawyer@${domain}`)).toEqual([]);
  expect(snapshot.invitations).toEqual([]);
  await waitForRegistrationApproval(applicant, `lawyer@${domain}`, organization.providerOrganizationId);
  signInAs(applicant, { subject: 'not-created', nativeEmail: `lawyer@${domain}`, providerOrganizationId: organization.providerOrganizationId, setup: {
    organizationId: application.id, providerOrganizationId: organization.providerOrganizationId, domain, displayName,
  } });
  await page.getByRole('button', { name: 'Sign in and open workspace' }).click();
  await expect(page).toHaveURL(/\/legal$/, { timeout: 90000 });
  await expect(page.getByLabel('Private Finish setup link')).toHaveCount(0);
  await expect(page.getByText('Organization key unlocked on this device', { exact: true })).toBeVisible();
  const signedIn = await (await applicant.request.get('/__e2e/legal-applications')).json();
  expect(signedIn.memberships.filter((member: any) => member.organization_id === organization.providerOrganizationId)).toEqual([
    expect.objectContaining({ email: `lawyer@${domain}`, roles: ['rol_legal'], email_verified: true }),
  ]);
  expect(signedIn.invitations).toEqual([]);
  expect(signedIn.emails.filter((email: any) => email.email === `lawyer@${domain}`)).toEqual([{ email: `lawyer@${domain}`, kind: 'code' }]);
  const after = (await (await admin.request.get('/api/admin/confidential/legal/organizations')).json()).organizations.find((org: any) => org.domain === domain);
  expect(after).toMatchObject({ activeMembers: 1 });
  // A sole key holder can finish setup; the optional second backup is not a gate.
  const setup = page.getByRole('region', { name: 'Organization setup', exact: true });
  await setup.locator('summary').filter({ hasText: 'Onboarding terms acknowledged' }).click();
  await setup.getByRole('checkbox', { name: 'I have read these and my organization will follow them.' }).check();
  await setup.getByRole('button', { name: 'Acknowledge', exact: true }).click();
  await expect(page.getByText('Organization setup complete. Show details or change your profile', { exact: true })).toBeVisible();
  await page.getByText('Organization setup complete. Show details or change your profile', { exact: true }).click();
  await expect(setup.locator('summary').filter({ hasText: 'Second key holder (optional)' })).toContainText('Optional');
  await expect(page.getByText('Finish organization setup to request or open reports', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('group', { name: 'Legal report board', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Available reports', exact: true })).toHaveCount(0);
  await applicant.close(); await admin.close();
});

test('Auth0 invitation opens organization sign-in with PKCE and returns to key setup', async ({ browser }) => {
  const applicant = await newParticipant(browser);
  signInAs(applicant, { subject: 'auth0|invitedlawyer', providerOrganizationId: 'org_invited' });
  const page = await applicant.newPage();
  const authorization = page.waitForRequest(request => new URL(request.url()).pathname === '/authorize');
  await page.goto('/legal?invitation=synthetic-invitation&organization=org_invited');
  const url = new URL((await authorization).url());
  expect(url.origin).toBe('https://identity.example');
  expect(url.searchParams.get('organization')).toBe('org_invited');
  expect(url.searchParams.get('invitation')).toBe('synthetic-invitation');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  await expect(page).toHaveURL(/\/legal\/enroll$/);
  expect(await page.evaluate(() => JSON.stringify(sessionStorage))).not.toContain('synthetic-invitation');
  await applicant.close();
});

test('Slack notification buttons require an allowed reviewer; approval provisions once and denial never provisions', async ({ browser }) => {
  const applicant = await newParticipant(browser), admin = await newParticipant(browser, { admin: true });
  const approvedDomain = `slack-approved-${Date.now()}.example`, deniedDomain = `slack-denied-${Date.now()}.example`;
  const input = (domain: string) => ({ displayName: domain, domain, email: `lawyer@${domain}`, lawyerName: 'Test Lawyer',
    jurisdiction: 'Test', registrationNumber: 'TEST' });
  for (const domain of [approvedDomain, deniedDomain]) {
    expect((await applicant.request.post('/api/legal-applications', { data: input(domain) })).status()).toBe(202);
  }
  const listing = await admin.request.post('/api/admin/confidential/legal-applications', { data: { action: 'list' } });
  const rows = (await listing.json()).applications;
  const approved = rows.find((row: { domain: string }) => row.domain === approvedDomain);
  const denied = rows.find((row: { domain: string }) => row.domain === deniedDomain);
  await expect.poll(async () => {
    const snapshot = await (await applicant.request.get('/__e2e/legal-applications')).json();
    return snapshot.messages.some((message: any) => message.blocks.some((block: any) => block.elements?.some((element: any) => element.value === approved.id)));
  }, { timeout: 60_000 }).toBe(true);
  const decide = async (id: string, status: string, user = 'UTEST') => {
    const raw = new URLSearchParams({ payload: JSON.stringify({ type: 'block_actions', team: { id: 'TTEST' }, user: { id: user },
      response_url: 'https://hooks.slack.com/actions/TTEST/TEST/SYNTHETIC', actions: [{ action_id: `vera_application_${status}`, value: id }] }) }).toString();
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = 'v0=' + createHmac('sha256', applicationFixtures.frontend.SLACK_APPLICATION_SIGNING_SECRET).update(`v0:${timestamp}:${raw}`).digest('hex');
    return applicant.request.post('/api/legal-applications/slack', { data: raw, headers: {
      'Content-Type': 'application/x-www-form-urlencoded', 'x-slack-request-timestamp': timestamp, 'x-slack-signature': signature,
    } });
  };
  expect((await decide(approved.id, 'approve', 'UFOREIGN')).status()).toBe(403);
  expect((await decide(approved.id, 'approve')).status()).toBe(200);
  // HTTP acknowledgment precedes persistence; establish the durable first choice
  // before exercising replay and a conflicting click.
  await expect.poll(async () => {
    const response = await admin.request.post('/api/admin/confidential/legal-applications', { data: { action: 'list' } });
    return (await response.json()).applications.find((row: { id: string }) => row.id === approved.id)?.status;
  }).toBe('approved');
  expect((await decide(approved.id, 'approve')).status()).toBe(200);
  expect((await decide(approved.id, 'deny')).status()).toBe(200);
  expect((await decide(denied.id, 'deny')).status()).toBe(200);
  await expect.poll(async () => {
    const response = await admin.request.post('/api/admin/confidential/legal-applications', { data: { action: 'list' } });
    return (await response.json()).applications.find((row: { id: string }) => row.id === denied.id)?.status;
  }).toBe('denied');
  await expect.poll(async () => {
    const response = await admin.request.post('/api/admin/confidential/legal-applications', { data: { action: 'list' } });
    return (await response.json()).applications.find((row: { id: string }) => row.id === approved.id)?.provisioningStatus;
  }, { timeout: 60_000 }).toBe('ready');
  // Readiness includes completion of the membership job, without signing in.
  await expect.poll(async () => {
    const snapshot = await (await applicant.request.get('/__e2e/legal-applications')).json();
    return snapshot.memberships.filter((row: any) => row.email === `lawyer@${approvedDomain}`);
  }, { timeout: 60_000 }).toEqual([
    expect.objectContaining({ email: `lawyer@${approvedDomain}`, roles: ['rol_legal'], email_verified: false, blocked: false }),
  ]);
  const snapshot = await (await applicant.request.get('/__e2e/legal-applications')).json();
  expect(snapshot.organizations.filter((row: any) => row.metadata.vera_application_id === approved.id)).toHaveLength(1);
  expect(snapshot.organizations.filter((row: any) => row.metadata.vera_application_id === denied.id)).toEqual([
    expect.objectContaining({ metadata: expect.objectContaining({ vera_approval_status: 'denied', vera_email: `lawyer@${deniedDomain}` }) }),
  ]);
  const organization = snapshot.organizations.find((row: any) => row.metadata.vera_application_id === approved.id);
  const members = snapshot.memberships.filter((row: any) => row.email === `lawyer@${approvedDomain}`);
  expect(members).toEqual([
    expect.objectContaining({ organization_id: organization.id, roles: ['rol_legal'], email_verified: false, blocked: false }),
  ]);
  expect(snapshot.users.filter((row: any) => row.email === `lawyer@${approvedDomain}`)).toEqual([
    expect.objectContaining({ user_id: members[0].user_id, email_verified: false, blocked: false }),
  ]);
  expect(snapshot.memberships.filter((row: any) => row.email === `lawyer@${deniedDomain}`)).toHaveLength(0);
  expect(snapshot.users.filter((row: any) => row.email === `lawyer@${deniedDomain}`)).toHaveLength(0);
  expect(snapshot.emails.filter((row: any) => [input(approvedDomain).email, input(deniedDomain).email].includes(row.email))).toEqual([]);
  expect(snapshot.invitations).toEqual([]);
  await applicant.close(); await admin.close();
});
