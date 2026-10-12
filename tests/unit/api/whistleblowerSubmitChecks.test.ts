/**
 * Tests for /api/whistleblower/submit request handling before and after the
 * upload path: malformed retry keys are refused before multer buffers
 * evidence, durable attempts recover their receipt, and accepted submissions
 * notify in order.
 */

import express from 'express';
import request from 'supertest';

// Rate limits have separate tests; these cases isolate submission outcomes.
jest.mock('express-rate-limit', () => {
  const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
  return { __esModule: true, ...actual, default: () => (_req: unknown, _res: unknown, next: () => void) => next() };
});

// Heavy service deps mocked the same way as the auth tests so the
// whistleblower router can be loaded without real network/db.
jest.mock('../../../src/services/evidenceEncryption', () => ({
  evidenceEncryptionService: { decryptEvidence: jest.fn(), encryptEvidence: jest.fn().mockResolvedValue({ encryptedData: 'ZmFrZQ==', encryptionMetadata: { algorithm: 'aes-256-gcm', salt: 'cw==', iv: 'aXY=', authTag: 'dGFn', keyVersion: 'v1.0' }, contentMetadata: { hash: 'a'.repeat(64), size: 4 } }) },
}));
jest.mock('../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: { upload: jest.fn() },
}));
jest.mock('../../../src/services/veniceAI', () => ({
  veniceAIService: { analyzeReport: jest.fn() },
}));
jest.mock('../../../src/services/reportScoring', () => ({
  verifyReport: jest.fn(),
}));
jest.mock('../../../src/services/shroudClient', () => ({
  shroudChat: jest.fn(),
  isShroudConfigured: jest.fn(() => false),
}));
jest.mock('../../../src/services/metadataExtractor', () => ({
  metadataExtractorService: { extract: jest.fn() },
}));
jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: {
    get: jest.fn(async () => null),
    getEvidenceParams: jest.fn(async () => null),
    saveEvidenceParams: jest.fn(),
    save: jest.fn(),
    upsert: jest.fn(async () => undefined),
    patch: jest.fn(),
  },
}));
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: {
    middleware: () => (_req: any, _res: any, next: () => void) => next(),
    logError: jest.fn(),
  },
}));

jest.mock('../../../src/services/reportFieldCrypto', () => ({
  encryptContactValue: jest.fn(() => 'encrypted'),
}));
jest.mock('../../../src/services/emailNotification', () => ({
  emailNotificationService: { notifyNewReport: jest.fn(async () => undefined) },
}));
jest.mock('../../../src/services/submissionNotificationWorker', () => ({
  notifySubmission: jest.fn(async () => 'delivered'),
}));

const mockAttemptGet = jest.fn(async () => null);
const mockCompleteIntake = jest.fn(async () => undefined);
jest.mock('../../../src/services/submissionAttempt', () => {
  const actual = jest.requireActual('../../../src/services/submissionAttempt') as typeof import('../../../src/services/submissionAttempt');
  return {
    ...actual,
    submissionAttemptStore: {
      get: (...args: unknown[]) => mockAttemptGet(...args),
      completeIntake: (...args: unknown[]) => mockCompleteIntake(...args),
      reserve: jest.fn(),
      claimRetry: jest.fn(async () => null),
      claimUnsubmitted: jest.fn(async () => null),
      claimResolved: jest.fn(async () => null),
      release: jest.fn(),
      acceptIntake: jest.fn(),
      close: jest.fn(),
    },
  };
});

import { notifySubmission } from '../../../src/services/submissionNotificationWorker';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { submissionKeyHash, submissionPayloadHash } from '../../../src/services/submissionAttempt';
import { INTAKE_CONSENT_VERSION } from '../../../src/utils/intakeConsent';


import whistleblowerRouter from '../../../src/api/whistleblower';

function makeApp(): express.Application {
  const app = express();
  app.use(express.json());
  app.use('/api/whistleblower', whistleblowerRouter);
  return app;
}

describe('POST /api/whistleblower/submit — pre-upload checks', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (reportPersistenceService.upsert as jest.Mock).mockResolvedValue(undefined);
    (reportPersistenceService.get as jest.Mock).mockResolvedValue(null);
    mockAttemptGet.mockResolvedValue(null);
  });

  it('rejects a malformed idempotency key before the upload path', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/api/whistleblower/submit')
      .set('X-Idempotency-Key', 'arbitrary')
      .field('description', 'malformed key must not reach the upload path')
      .attach('files', Buffer.from('evidence-bytes'), {
        filename: 'note.txt',
        contentType: 'text/plain',
      });

    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      success: false,
      error: 'invalid_idempotency_key',
      message: 'Invalid submission retry key.',
    });
    expect(mockAttemptGet).not.toHaveBeenCalled();
    expect(notifySubmission).not.toHaveBeenCalled();
  });

  it('recovers an accepted receipt for a durable attempt', async () => {
    const retryKey = 'b'.repeat(64);
    const trackingId = 'VRA-RECOVERED000001';
    const body = {
      description: 'recover an accepted receipt',
      evidenceType: 'other',
      urgency: 'low',
      wantsReward: 'false',
    };
    mockAttemptGet.mockResolvedValue({
      keyHash: submissionKeyHash(retryKey),
      payloadHash: submissionPayloadHash(body, []),
      trackingId,
      state: 'accepted',
      createdAt: new Date(),
    });
    (reportPersistenceService.get as jest.Mock).mockResolvedValue({
      trackingId,
      evidenceHash: 'e'.repeat(64),
      evidenceHashVersion: 'sha256-concat-v1',
      status: 'submitted',
      zkProof: null,
    });

    const app = makeApp();
    const res = await request(app)
      .post('/api/whistleblower/submit')
      .set('X-Idempotency-Key', retryKey)
      .field('description', body.description)
      .field('evidenceType', body.evidenceType)
      .field('urgency', body.urgency)
      .field('wantsReward', body.wantsReward);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.trackingId).toBe(trackingId);
    expect(mockCompleteIntake).toHaveBeenCalledWith(submissionKeyHash(retryKey));
    expect(notifySubmission).not.toHaveBeenCalled();
  });

  it('accepts a submission without a blockchain proof', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/api/whistleblower/submit')
      .field('description', 'accepted without a proof')
      .field('evidenceType', 'other')
      .field('urgency', 'low')
      .field('wantsReward', 'false');

    expect(res.status).toBe(200);
    expect(res.body.trackingId).toMatch(/^VRC-[A-F0-9]{64}$/);
    // The receipt says no blockchain proof is issued.
    expect(res.body.proofStatus).toBe('not_applicable');
    expect(res.body.zkProof).toBeNull();
  });
});


describe('accepted-submission webhook ordering', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (reportPersistenceService.upsert as jest.Mock).mockResolvedValue(undefined);
  });
  const submit = () => request(makeApp()).post('/api/whistleblower/submit')
    .field('description', 'test report').field('evidenceType', 'other');

  it('persists Slack intent alongside independent SES intent without an n8n URL', async () => {
    const original = process.env;
    process.env = { ...original, SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/T/B/synthetic' };
    delete process.env.WEBHOOK_URL;
    try {
      expect((await submit()).status).toBe(200);
      const saved = (reportPersistenceService.upsert as jest.Mock).mock.calls[0][0];
      expect(saved.submissionNotification).toMatchObject({ state: 'pending', source: 'web', attempts: 0 });
      expect(saved.adminNotification).toMatchObject({ state: 'pending', attempts: 0 });
    } finally { process.env = original; }
  });

  it.each(['delivered', 'disabled', 'failed'])('returns success when webhook result is %s', async result => {
    (notifySubmission as jest.Mock).mockResolvedValue(result);
    const res = await submit();
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(notifySubmission).toHaveBeenCalledWith((reportPersistenceService.upsert as jest.Mock).mock.calls[0][0].trackingId, expect.any(Date), 'web');
    expect((reportPersistenceService.upsert as jest.Mock).mock.invocationCallOrder[0])
      .toBeLessThan((notifySubmission as jest.Mock).mock.invocationCallOrder[0]);
  });
  it('does not accept forged automatic sharing permissions or recipients', async () => {
    const res = await request(makeApp()).post('/api/whistleblower/submit')
      .field('description', 'test report').field('evidenceType', 'other')
      .field('consentPsst', 'true').field('consentLegalReview', 'true').field('consentPress', 'true')
      .field('disseminationRecipients', '["whistleblower-org"]');
    expect(res.status).toBe(200);
    const saved = (reportPersistenceService.upsert as jest.Mock).mock.calls[0][0];
    expect(saved.consent).toMatchObject({ psst: { granted: false }, agency: false, legalReview: true, press: false });
    expect(saved.disseminationRecipients).toBeUndefined();
  });
  it.each([
    [{ consentLegalReview: true }], [{ consentLegalReview: 'true' }],
    // Clients before #926 sent the legal-review election under the agency name.
    [{ consentAgency: true }], [{ consentAgency: 'true' }],
  ])('records legal review, never agency dispatch, from the reviewed-sharing notice (%j)', async (election) => {
    const res = await request(makeApp()).post('/api/whistleblower/submit')
      .send({ description: 'Synthetic legal-review report', ...election });
    expect(res.status).toBe(200);
    const saved = (reportPersistenceService.upsert as jest.Mock).mock.calls[0][0];
    expect(saved.consent).toEqual({
      psst: { granted: false }, agency: false, legalReview: true, press: false,
      capturedAt: expect.any(Date), textVersion: INTAKE_CONSENT_VERSION,
    });
    expect(saved.disseminationRecipients).toBeUndefined();
  });
  it.each([
    [{}], [{ consentLegalReview: false }], [{ consentLegalReview: 'false' }], [{ consentAgency: 'false' }],
    [{ consentLegalReview: 'false', consentAgency: 'true' }],
  ])('fails closed without an explicit legal-review election (%j)', async (election) => {
    const res = await request(makeApp()).post('/api/whistleblower/submit')
      .send({ description: 'Synthetic report with no sharing permission', ...election });
    expect(res.status).toBe(200);
    expect((reportPersistenceService.upsert as jest.Mock).mock.calls[0][0].consent).toMatchObject({ agency: false, legalReview: false });
  });
  it.each([{ consentLegalReview: null }, { consentLegalReview: 'yes' }, { consentAgency: null }, { consentAgency: ['true', 'false'] }])('rejects malformed consent instead of granting access (%j)', async (election) => {
    const res = await request(makeApp()).post('/api/whistleblower/submit')
      .send({ description: 'Synthetic invalid consent', ...election });
    expect(res.status).toBe(400);
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });
  it('does not notify when persistence rejects', async () => {
    (reportPersistenceService.upsert as jest.Mock).mockRejectedValueOnce(new Error('database unavailable'));
    expect((await submit()).status).toBe(500);
    expect(notifySubmission).not.toHaveBeenCalled();
  });
  it('does not notify on invalid input', async () => {
    const res = await request(makeApp()).post('/api/whistleblower/submit').field('evidenceType', 'other');
    expect(res.status).toBe(400);
    expect(notifySubmission).not.toHaveBeenCalled();
  });
});


it('returns the accepted web response while notification delivery is still pending', async () => {
  jest.clearAllMocks();
  (reportPersistenceService.upsert as jest.Mock).mockResolvedValue(undefined);
  let finish!: () => void;
  const notification = new Promise<void>(resolve => { finish = resolve; });
  jest.mocked(notifySubmission).mockReturnValueOnce(notification);
  try {
    const res = await request(makeApp()).post('/api/whistleblower/submit')
      .field('description', 'test report').field('evidenceType', 'other')
      .timeout({ deadline: 10_000 });
    expect(notifySubmission).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  } finally {
    finish();
  }
});

  it.each(['eu', 'other'])('rejects explicit %s jurisdiction before persisting a new report', async jurisdiction => {
    jest.clearAllMocks();
    const res = await request(makeApp()).post('/api/whistleblower/submit')
      .field('description', 'Synthetic jurisdiction test')
      .field('evidenceType', 'other').field('jurisdiction', jurisdiction);
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('United States');
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });
