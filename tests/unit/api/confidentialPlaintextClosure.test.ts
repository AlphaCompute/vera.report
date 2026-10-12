import express from 'express';
import request from 'supertest';

// Keep the real router, intake guard, admission and multipart parser. Only the
// downstream services are doubled: no real proof, storage or metadata process.
jest.mock('../../../src/services/shroudClient', () => ({ isShroudConfigured: () => false }));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
jest.mock('../../../src/services/reportScoringWorker', () => ({ reportScoringWorker: { tick: jest.fn(async () => {}) } }));
jest.mock('../../../src/services/submissionNotificationWorker', () => ({ notifySubmission: jest.fn(async () => {}) }));
jest.mock('../../../src/services/attestedNarrative', () => ({ attestedNarrativeConfiguration: () => ({ writes: false }) }));
jest.mock('../../../src/services/evidenceEncryption', () => ({ evidenceEncryptionService: {
  encryptEvidence: jest.fn(async () => ({ encryptedData: 'ZmFrZQ==', encryptionMetadata: { salt: 'cw==', iv: 'aXY=', authTag: 'dGFn' }, contentMetadata: { hash: 'a'.repeat(64), size: 4 } })),
} }));
jest.mock('../../../src/services/metadataWorker', () => ({ extractMetadataIsolated: jest.fn(async () => ({ items: [], summary: { riskLevel: 'low' } })) }));
jest.mock('../../../src/services/submissionEvidence', () => ({ persistSubmissionEvidence: jest.fn(async () => []) }));
jest.mock('../../../src/services/reportPersistence', () => ({ reportPersistenceService: { upsert: jest.fn(async () => {}), get: jest.fn(async () => null) } }));

import router from '../../../src/api/whistleblower';
import { confidentialIntakeOnly } from '../../../src/middleware/confidentialIntakeOnly';
import { securityHeaders } from '../../../src/middleware/security';
import { extractMetadataIsolated } from '../../../src/services/metadataWorker';
import { persistSubmissionEvidence } from '../../../src/services/submissionEvidence';
import { reportPersistenceService } from '../../../src/services/reportPersistence';

const originalEnv = { ...process.env };
beforeEach(() => {
  jest.clearAllMocks();
  delete process.env.CONFIDENTIAL_CASES_ENABLED;
  delete process.env.CONFIDENTIAL_INTAKE_REQUIRED;
  delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
  delete process.env.NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST;
});
afterEach(() => { process.env = { ...originalEnv }; });

describe.each([undefined, 'false'])('explicit legacy deployment, backend enabled=%s', enabled => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0';
    if (enabled !== undefined) process.env.CONFIDENTIAL_CASES_ENABLED = enabled;
  });
  test.each(['submit', 'analyze'])('%s reaches its real handler', async endpoint => {
    const app = express();
    app.post(['/api/whistleblower/submit', '/api/whistleblower/analyze'], confidentialIntakeOnly);
    app.use('/api/whistleblower', router);
    const response = await request(app).post(`/api/whistleblower/${endpoint}`)
      .field('description', 'Synthetic legacy availability regression')
      .field('wantsReward', 'false')
      .attach('files', Buffer.from('record,value\nSYNTHETIC,1\n'), { filename: 'evidence.csv', contentType: 'text/csv' });
    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    if (endpoint === 'analyze') expect(extractMetadataIsolated).toHaveBeenCalledTimes(1);
    else {
      expect(persistSubmissionEvidence).toHaveBeenCalledTimes(1);
      expect(reportPersistenceService.upsert).toHaveBeenCalledTimes(1);
      expect(response.body.trackingId).toMatch(/^VRC-/);
    }
  });
});

describe.each(['submit', 'analyze'])('direct Express /%s', endpoint => {
  test.each([['CONFIDENTIAL_CASES_ENABLED', 'true'], ['CONFIDENTIAL_INTAKE_REQUIRED', 'true']])('server cutover %s overrides explicit legacy mode', async (flag, value) => {
    process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0';
    process.env[flag] = value;
    const app = express();
    app.use('/api/whistleblower', router);
    await request(app).post(`/api/whistleblower/${endpoint}`).field('description', 'SYNTHETIC').expect(409);
    expect(extractMetadataIsolated).not.toHaveBeenCalled();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });

  test.each(['', '1', 'true', 'false', 'invalid'])('frontend mode %s refuses plaintext without server cutover flags', async mode => {
    process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = mode;
    const app = express();
    app.use('/api/whistleblower', router);
    await request(app).post(`/api/whistleblower/${endpoint}`).field('description', 'SYNTHETIC').expect(409);
    expect(extractMetadataIsolated).not.toHaveBeenCalled();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });
  test.each([undefined, 'false', '0', 'true'])('refuses multipart plaintext regardless of cutover flags (%s)', async value => {
    if (value !== undefined) {
      process.env.CONFIDENTIAL_CASES_ENABLED = value;
      process.env.CONFIDENTIAL_INTAKE_REQUIRED = value;
    }
    // Mount the actual router directly too: both public entry points must close.
    const app = express();
    app.use('/api/whistleblower', router);
    const response = await request(app).post(`/api/whistleblower/${endpoint}`)
      .field('description', 'Synthetic plaintext submission must not be accepted')
      .attach('files', Buffer.from('record,value\nSYNTHETIC-PRIVATE-EVIDENCE,1\n'), { filename: 'evidence.csv', contentType: 'text/csv' });
    expect({ status: response.status, body: response.body, metadataCalls: jest.mocked(extractMetadataIsolated).mock.calls.length }).toMatchObject({
      status: 409, body: { success: false, error: 'confidential_intake_required' }, metadataCalls: 0,
    });
    expect(response.headers['cache-control']).toBe('no-store');
    expect(extractMetadataIsolated).not.toHaveBeenCalled();
    expect(persistSubmissionEvidence).not.toHaveBeenCalled();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });

  test('the API ingress refuses before parsers or telemetry, with no frontend configuration present', async () => {
    const parsed = jest.fn(), telemetry = jest.fn((_req, _res, next) => next());
    const app = express();
    // Same ordering as src/api/server.ts; frontend build settings are deliberately absent.
    app.use(securityHeaders);
    app.post(['/api/whistleblower/submit', '/api/whistleblower/analyze'], confidentialIntakeOnly);
    app.use(express.json({ verify: parsed }));
    app.use(telemetry);
    app.use('/api/whistleblower', router);
    const response = await request(app).post(`/api/whistleblower/${endpoint}`).send({ description: 'SYNTHETIC-PRIVATE-NARRATIVE' });
    expect(response.status).toBe(409);
    expect(response.body.error).toBe('confidential_intake_required');
    expect(parsed).not.toHaveBeenCalled();
    expect(telemetry).not.toHaveBeenCalled();
  });
});
