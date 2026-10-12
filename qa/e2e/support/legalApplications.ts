import { expect } from '@playwright/test';
import type { BrowserContext } from '@playwright/test';
import { createHash, createHmac } from 'node:crypto';
import { applicationFixtures } from '../stack/legalApplications';
import type { LegalApplicationView } from '../../../src/utils/legalApplications';
import { stackState } from './state';

/** Wait for the actual approval worker to publish the registration hint. */
export async function waitForRegistrationApproval(context: BrowserContext, email: string, organizationId: string) {
  const hint = `vera_entry_${createHash('sha256').update(email).digest('hex').slice(0, 39)}`;
  await expect.poll(async () => {
    const snapshot = await (await context.request.get('/__e2e/legal-applications')).json();
    const organization = snapshot.organizations.find((row: { id: string }) => row.id === organizationId);
    return Number(organization?.metadata?.[hint]) > Date.now();
  }, { timeout: 60_000 }).toBe(true);
}

/** Synthetic Slack transport into the real signed callback and durable worker. */
export async function approveApplicationInSlack(admin: BrowserContext, domain: string): Promise<LegalApplicationView> {
  const listing = async (): Promise<LegalApplicationView[]> => {
    const response = await admin.request.post('/api/admin/confidential/legal-applications', { data: { action: 'list' } });
    expect(response.ok()).toBe(true);
    return (await response.json()).applications;
  };
  const pending = (await listing()).find(row => row.domain === domain);
  expect(pending?.status).toBe('pending');
  const timestamp = String(Math.floor(Date.now() / 1000));
  const raw = new URLSearchParams({ payload: JSON.stringify({ type: 'block_actions', team: { id: 'TTEST' }, user: { id: 'UTEST' },
    response_url: 'https://hooks.slack.com/actions/TTEST/BTEST/synthetic',
    actions: [{ action_id: 'vera_application_approve', value: pending!.id }] }) }).toString();
  const signature = 'v0=' + createHmac('sha256', applicationFixtures.frontend.SLACK_APPLICATION_SIGNING_SECRET)
    .update(`v0:${timestamp}:${raw}`).digest('hex');
  const response = await admin.request.post('/api/legal-applications/slack', { data: raw, headers: {
    'Content-Type': 'application/x-www-form-urlencoded', 'x-slack-request-timestamp': timestamp, 'x-slack-signature': signature,
  } });
  expect(response.status()).toBe(200);
  await expect.poll(async () => (await listing()).find(row => row.id === pending!.id)?.provisioningStatus, { timeout: 60_000 }).toBe('ready');
  const approved = (await listing()).find(row => row.id === pending!.id)!;
  expect(approved.status).toBe('approved');
  expect(approved.decidedBy).toBe('slack:TTEST:UTEST');
  return approved;
}
/** Authenticated synthetic Socket Mode delivery; never exposed by production. */
export async function approveFirmAndKeyInSlack(admin: import('@playwright/test').BrowserContext, domain: string, waitingForFirstSignIn = false) {
  const listing = await (await admin.request.post('/api/admin/confidential/legal-applications', { data: { action: 'list' } })).json();
  const application = listing.applications.find((row: { domain: string }) => row.domain === domain);
  let value = '';
  await expect.poll(async () => {
    const snapshot = await (await admin.request.get('/__e2e/legal-applications')).json();
    value = snapshot.messages.flatMap((message: any) => message.blocks.flatMap((block: any) => block.elements || []))
      .find((button: any) => button.action_id === 'vera_application_approve' && button.value.startsWith(`v2:${application.id}:`))?.value || '';
    return !!value;
  }, { timeout: 60000 }).toBe(true);
  const payload = (user: string, key: string | null = application.enrollment.recipientKeyId) => ({ type: 'block_actions',
    team: { id: 'TTEST' }, user: { id: user }, actions: [{ action_id: 'vera_application_approve',
      value: key === null ? value.split(':').slice(0, 3).join(':') : value.replace(/:[a-f0-9]{64}$/, `:${key}`) }] });
  const headers = { 'x-e2e-review-key': stackState().adminCookie };
  expect((await admin.request.post('/__e2e/combined-approval', { headers, data: { type: 'block_actions', team: { id: 'TTEST' },
    user: { id: 'UTEST' }, actions: [{ action_id: 'vera_application_approve', value: value.replace(/^v2:/, 'v1:').split(':').slice(0, 3).join(':') }] } })).status()).toBe(403);
  expect((await admin.request.post('/__e2e/combined-approval', { headers, data: payload('UFOREIGN') })).status()).toBe(403);
  expect((await admin.request.post('/__e2e/combined-approval', { headers, data: payload('UTEST', null) })).status()).toBe(403);
  expect((await admin.request.post('/__e2e/combined-approval', { headers, data: payload('UTEST', '0'.repeat(64)) })).status()).toBe(409);
  expect((await admin.request.post('/__e2e/combined-approval', { headers, data: payload('UTEST') })).status()).toBe(200);
  await expect.poll(async () => (await (await admin.request.post('/api/legal-applications/status', { data: { id: application.id } })).json()).state,
    { timeout: 60000 }).toBe(waitingForFirstSignIn ? 'sign-in-ready' : 'ready');
  return application;
}
