/**
 * /api/confidential/* and /api/admin/confidential/* must not leave bodies,
 * nonces, ciphertext, digests, cursors or case IDs in request, flow, error or
 * telemetry logs. The app below uses the same middleware, in the same order, as
 * src/api/server.ts around the confidential routers.
 */
import express from 'express';
import bodyParser from 'body-parser';
import request from 'supertest';
import { addRequestId } from '../../../src/utils/errorResponse';
import { ErrorMonitor } from '../../../src/utils/errorMonitor';
import { runtimeTelemetry } from '../../../src/utils/runtimeTelemetry';
import { trackDataFlow, getDataFlowLogs, clearDataFlowLogs } from '../../../src/middleware/dataFlowTracking';
import { securityErrorHandler, validateRequestBody } from '../../../src/middleware/security';
import { privateRequest, telemetryPath } from '../../../src/utils/requestPrivacy';
import { createConfidentialObjectRouter } from '../../../src/api/confidentialObjects';
import { createConfidentialChannelRouter } from '../../../src/api/confidentialChannel';
import { createConfidentialAdminListingRouter } from '../../../src/api/confidentialAdminListings';
import { createConfidentialLegalOnboardingRouter } from '../../../src/api/confidentialLegalOnboarding';
import type { LegalOnboardingSource } from '../../../src/api/confidentialLegalOnboarding';

import { notifyOperationalEvent } from '../../../src/services/submissionWebhook';
import { emailNotificationService } from '../../../src/services/emailNotification';

jest.mock('../../../src/services/submissionWebhook', () => ({ notifyOperationalEvent: jest.fn() }));
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { notifyErrorThreshold: jest.fn() } }));

const NONCE = 'a1'.repeat(32);
const CASE_ID = 'c3'.repeat(32);
const CIPHERTEXT = 'SENTINEL-CIPHERTEXT-BODY';
const ARMORED = `-----BEGIN PGP MESSAGE-----\n\nSENTINELARMOR\n-----END PGP MESSAGE-----\n`;
const DIGEST = '8b7e1f0f6f1a3a0e1d0f1b5e0a7a2f0c6d9b4e3c2a1f0e9d8c7b6a5f4e3d2c1b'; // Not a real digest; must not appear.
const SENTINELS = [NONCE, CASE_ID, CIPHERTEXT, 'SENTINELARMOR', DIGEST, 'SENTINEL-JSON', 'SENTINEL-FIRM-DOMAIN', 'sentinel-firm-domain', 'auth0|sentinel-lawyer'];

const monitor = new ErrorMonitor();
function makeApp(fail = false) {
  const app = express();
  app.use(addRequestId);
  app.use(monitor.middleware());
  app.use(runtimeTelemetry);
  app.use(bodyParser.json({ limit: '10mb' }));
  app.use(validateRequestBody);
  app.use(trackDataFlow);
  app.use('/api/confidential', createConfidentialObjectRouter({ async stageObject() { if (fail) throw new Error(`store failed ${CASE_ID}`); },
    async stageChunk() { if (fail) throw new Error(`chunk store failed ${CASE_ID}`); } }));
  app.use('/api/confidential', createConfidentialChannelRouter(async () => {
    if (fail) throw new Error(`enclave failed ${NONCE} ${CIPHERTEXT}`);
    return { ciphertext: CIPHERTEXT, document: 'doc', publicKey: 'key' };
  }));
  app.use('/api/admin/confidential', createConfidentialAdminListingRouter(async () => ({ async listListingWires() {
    if (fail) throw new Error(`mongo failed ${CASE_ID}`);
    return [];
  } })));
  const failing = async () => { if (fail) throw new Error(`mongo failed ${CASE_ID} SENTINEL-FIRM-DOMAIN`); return []; };
  app.use('/api/admin/confidential/legal', createConfidentialLegalOnboardingRouter(async () => ({
    listLegalOrganizationRecords: failing, countLegalOnboarding: async () => ({}), getLegalOrganizationRecord: async () => null,
    listLegalInvitationRecords: failing, listLegalMemberRecords: failing, listLegalAudit: failing,
    async createLegalOrganization() { if (fail) throw new Error(`mongo failed SENTINEL-FIRM-DOMAIN`); },
    async revokeLegalOrganization() { if (fail) throw new Error(`mongo failed ${CASE_ID}`); return { invitationsRevoked: 0, membersRemoved: 0 }; },
    async revokeLegalInvitation() { if (fail) throw new Error(`mongo failed ${CASE_ID}`); },
    async removeLegalMember() { if (fail) throw new Error(`mongo failed ${CASE_ID}`); },
  }) as LegalOnboardingSource));
  app.use(securityErrorHandler);
  return app;
}

test('confidential routes are a private telemetry family', () => {
  for (const url of [`/api/confidential/channel/call?nonce=${NONCE}`, `/api/admin/confidential/listings?after=${CASE_ID}`,
    `/api/admin/confidential/legal/organizations/${CASE_ID}/revoke`, `/api/admin/confidential/legal/audit?organizationId=${CASE_ID}`,
    '/api/confidential/objects', `/api/%63onfidential/${DIGEST}`]) {
    expect(privateRequest(url)).toBe(true);
    expect(telemetryPath(url)).toBe('/confidential/[redacted]');
  }
  // Unknown non-family paths still never carry 64-hex digests or owner codes.
  expect(telemetryPath(`/api/other/${DIGEST}/VERA-OWNER-1.${CASE_ID}.x`)).not.toMatch(new RegExp(`${DIGEST}|${CASE_ID}`));
  // Short recovery codes, grouped or not, are redacted from unknown paths too.
  const short = '7K3M-9QXA-R2D8-WV4N-J6TC-P1HZ-5GBE-0SKY-M8FQ-3XAW-T7VN-2CJD-H9RB-4PZE';
  for (const form of [short, short.replace(/-/g, ''), short.toLowerCase(), ...['_', '·', '–', '—', '  '].map(separator => short.replace(/-/g, separator)), 'A'.repeat(56), short.slice(0, -1)]) {
    const redacted = telemetryPath(`/api/other/${form}`);
    expect(redacted).toBe('/api/other/[redacted]');
  }
});

test('legal portal, onboarding and key ceremonies never produce browser telemetry', () => {
  for (const path of ['/legal', '/legal/enroll#invitation=synthetic-private-token',
    `/legal/cases/${CASE_ID}`, `/legal/report#${CASE_ID}`, "/legal/case", '/legal/keys', '/legal/administration?code=synthetic-oauth-code', '/%6cegal/keys']) {
    expect(privateRequest(path)).toBe(true);
    expect(telemetryPath(path)).toBe('/legal/[redacted]');
  }
  expect(privateRequest('/legality')).toBe(false);
});

test.each([false, true])('no sentinel reaches any log (backend failure: %s)', async fail => {
  process.env.INTERNAL_API_SECRET = 'synthetic-log-secret';
  process.env.NODE_ENV = 'test';
  clearDataFlowLogs();
  const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(level => jest.spyOn(console, level).mockImplementation(() => undefined));
  const logError = jest.spyOn(monitor, 'logError');
  const app = makeApp(fail);
  await request(app).post('/api/confidential/channel/open').set('x-request-id', CASE_ID).send({ nonce: NONCE });
  await request(app).post('/api/confidential/channel/call').send({ nonce: NONCE, ciphertext: CIPHERTEXT });
  await request(app).post('/api/confidential/channel/call').send({ nonce: NONCE, ciphertext: CIPHERTEXT, extra: CASE_ID });
  await request(app).post('/api/confidential/objects').set('Content-Type', 'application/pgp-encrypted').send(ARMORED);
  await request(app).post(`/api/confidential/objects?digest=${DIGEST}`).set('Content-Type', 'application/pgp-encrypted').send(ARMORED);
  // Malformed JSON: the parser error message quotes the raw body.
  await request(app).post('/api/confidential/channel/call').set('Content-Type', 'application/json')
    .send(`{"nonce":"${NONCE}","ciphertext":"SENTINEL-JSON`);
  await request(app).get(`/api/admin/confidential/listings?after=${CASE_ID}`).set('x-internal-secret', 'synthetic-log-secret');
  await request(app).get(`/api/admin/confidential/listings?after=${CASE_ID}&x=${DIGEST}`).set('x-internal-secret', 'synthetic-log-secret');
  await request(app).post('/api/admin/confidential/listings').send({ after: CASE_ID }).set('x-internal-secret', 'synthetic-log-secret');
  await request(app).post('/api/admin/confidential/listings').send({ after: CASE_ID, x: DIGEST }).set('x-internal-secret', 'synthetic-log-secret');
  // Legal onboarding roster: identifiers, domains and people must not reach logs either.
  const legal = (method: 'get' | 'post', path: string) => request(app)[method](`/api/admin/confidential/legal/${path}`).set('x-internal-secret', 'synthetic-log-secret');
  await legal('get', `organizations/${CASE_ID}`);
  await legal('get', `audit?organizationId=${CASE_ID}&x=${DIGEST}`);
  await legal('post', 'organizations').send({ displayName: 'Sentinel Firm', domain: 'sentinel-firm-domain.example', providerOrganizationId: 'org_sentinel', actor: 'admin@example.test' });
  await legal('post', `organizations/${CASE_ID}/members/remove`).send({ subject: 'auth0|sentinel-lawyer', actor: 'admin@example.test' });
  await legal('post', `organizations/${CASE_ID}/revoke`).send({ actor: 'admin@example.test' });
  await legal('post', `organizations/${CASE_ID}/revoke`).set('Content-Type', 'application/json').send(`{"actor":"SENTINEL-JSON`);

  const recorded = JSON.stringify([getDataFlowLogs(), logError.mock.calls, ...spies.map(spy => spy.mock.calls)]);
  for (const sentinel of SENTINELS) expect(recorded).not.toContain(sentinel);
  // Even redacted timestamps could correlate source visits. Retain no flow rows.
  expect(getDataFlowLogs()).toEqual([]);
  expect(logError).not.toHaveBeenCalled();
  for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  // Runtime telemetry emits nothing for the family (no operation names or timing).
  expect(recorded).not.toContain('veraTelemetry');
  for (const spy of spies) spy.mockRestore();
  logError.mockRestore();
  clearDataFlowLogs();
});


test('legacy proof failures reach alert thresholds even on HTTP 200, without reporter data', async () => {
  const app = express();
  const legacyMonitor = new ErrorMonitor();
  app.use(legacyMonitor.middleware());
  app.post('/api/whistleblower/submit', (req: any, res) => {
    req.logError(`Proof failed ${CASE_ID} ${CIPHERTEXT}`, 'critical', { ip: '203.0.113.27', requestId: CASE_ID, stack: CIPHERTEXT });
    res.status(200).json({ success: true });
  });
  app.get('/api/packets/:token', () => { throw Object.assign(new Error(CIPHERTEXT), { status: 503 }); });
  app.use(securityErrorHandler);
  const output = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  try {
    // Five critical failures reach the critical-error alert threshold.
    for (let i = 0; i < 5; i++) {
      await request(app).post(`/api/whistleblower/submit?private=${CASE_ID}`).set('x-request-id', CASE_ID).send(CIPHERTEXT).expect(200);
    }
    await request(app).get(`/api/packets/${CASE_ID}`).expect(503);
    await legacyMonitor.close();
    expect(notifyOperationalEvent).toHaveBeenCalledWith('operations.error_threshold');
    expect(emailNotificationService.notifyErrorThreshold).toHaveBeenCalledWith(5);
    const retainedEvent = { message: 'Private request failed', type: 'critical',
      endpoint: 'POST /whistleblower/[redacted]', context: { endpoint: 'POST /whistleblower/[redacted]' } };
    expect(legacyMonitor.getStats()).toMatchObject({ total: 5, criticalCount: 5,
      byEndpoint: { 'POST /whistleblower/[redacted]': 5 },
      recent: Array(5).fill(retainedEvent)
    });
    expect(output.mock.calls).toContainEqual([
      '[SECURITY ERROR] Private request failed', { routeFamily: 'packets', status: 503 }
    ]);
    const recorded = JSON.stringify([legacyMonitor.getStats(), output.mock.calls,
      (notifyOperationalEvent as jest.Mock).mock.calls,
      (emailNotificationService.notifyErrorThreshold as jest.Mock).mock.calls]);
    for (const secret of [CASE_ID, CIPHERTEXT, '203.0.113.27']) expect(recorded).not.toContain(secret);
    const retained = legacyMonitor.getStats().recent[0];
    expect(retained.stack).toBeUndefined();
    expect(retained.userId).toBeUndefined();
    expect(retained.requestId).toBeUndefined();
  } finally { output.mockRestore(); await legacyMonitor.close(); }
});
