/**
 * Intake without Midnight: a report is accepted and stored without a proof
 * job, its receipt says no proof is coming, and historical proof states read
 * as they did once proving was switched off (#1013).
 */

import express from 'express';
import request from 'supertest';

jest.mock('express-rate-limit', () => {
  const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
  return { __esModule: true, ...actual, default: () => (_req: unknown, _res: unknown, next: () => void) => next() };
});
jest.mock('../../../src/services/evidenceEncryption', () => ({
  evidenceEncryptionService: { decryptEvidence: jest.fn(), encryptEvidence: jest.fn().mockResolvedValue({ encryptedData: 'ZmFrZQ==', encryptionMetadata: { algorithm: 'aes-256-gcm', salt: 'cw==', iv: 'aXY=', authTag: 'dGFn', keyVersion: 'v1.0' }, contentMetadata: { hash: 'a'.repeat(64), size: 4 } }) },
}));
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: { upload: jest.fn() } }));
jest.mock('../../../src/services/veniceAI', () => ({ veniceAIService: { analyzeReport: jest.fn() } }));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
jest.mock('../../../src/services/shroudClient', () => ({ shroudChat: jest.fn(), isShroudConfigured: jest.fn(() => false) }));
jest.mock('../../../src/services/metadataExtractor', () => ({ metadataExtractorService: { extract: jest.fn() } }));
jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: {
    get: jest.fn(async () => null),
    getForReporter: jest.fn(async () => null),
    getEvidenceParams: jest.fn(async () => null),
    upsert: jest.fn(async () => undefined),
    patch: jest.fn(),
  },
}));
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: { middleware: () => (_req: unknown, _res: unknown, next: () => void) => next(), logError: jest.fn() },
}));
jest.mock('../../../src/services/reportFieldCrypto', () => ({ encryptContactValue: jest.fn(() => 'encrypted') }));
jest.mock('../../../src/services/submissionNotificationWorker', () => ({ notifySubmission: jest.fn(async () => 'delivered') }));
jest.mock('../../../src/services/dissemination/disseminationService', () => ({ disseminationService: { status: jest.fn(async () => []) } }));
jest.mock('../../../src/services/dissemination/relayService', () => ({ relayService: { getThread: jest.fn(async () => []) } }));
import { reportPersistenceService, type ReportRecord } from '../../../src/services/reportPersistence';
import whistleblowerRouter from '../../../src/api/whistleblower';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/whistleblower', whistleblowerRouter);
  return app;
}

const submit = () => request(makeApp()).post('/api/whistleblower/submit')
  .field('description', 'report accepted without a blockchain proof')
  .field('evidenceType', 'other')
  .field('urgency', 'low')
  .field('wantsReward', 'false');

beforeEach(() => {
  jest.clearAllMocks();
});

it('accepts a report without a proof job and returns a not-applicable receipt', async () => {
  const res = await submit();

  expect(res.status).toBe(200);
  expect(res.body).toMatchObject({ success: true, proofStatus: 'not_applicable', zkProof: null });
  expect(res.body.trackingId).toMatch(/^VRC-[A-F0-9]{64}$/);

  const stored = (reportPersistenceService.upsert as jest.Mock).mock.calls[0][0] as ReportRecord;
  expect(stored.proofGeneration?.state).toBe('not_applicable');
  expect(stored.zkProof).toBeUndefined();
  // Everything else about intake is unchanged.
  expect(stored.scoringJob?.state).toBe('pending');
  expect(stored.adminNotification?.state).toBe('pending');
  expect(stored.evidenceHash).toMatch(/^[a-f0-9]{64}$/);
});

it('reports the stored not-applicable state on the status endpoint', async () => {
  const trackingId = 'VRA-0123456789ABCDEF';
  (reportPersistenceService.getForReporter as jest.Mock).mockResolvedValue({
    trackingId, status: 'pending', processingStatus: 'completed', createdAt: new Date(), updatedAt: new Date(),
    proofGeneration: { state: 'not_applicable', attempts: 0, nextAttemptAt: new Date(), userId: 'a'.repeat(64) },
  });

  const res = await request(makeApp()).get(`/api/whistleblower/status/${trackingId}`);

  expect(res.status).toBe(200);
  expect(res.body).toMatchObject({ proofStatus: 'not_applicable', zkProof: null });
});

it.each([
  ['pending', 'not_applicable'], ['proving', 'not_applicable'], ['failed', 'failed'],
] as const)('reads a historical %s proof state as %s', async (state, expected) => {
  (reportPersistenceService.getForReporter as jest.Mock).mockResolvedValue({
    trackingId: 'VRA-0123456789ABCDEF', status: 'pending', createdAt: new Date(), updatedAt: new Date(),
    proofGeneration: { state, attempts: 1, nextAttemptAt: new Date(), userId: 'a'.repeat(64) },
  });

  const res = await request(makeApp()).get('/api/whistleblower/status/VRA-0123456789ABCDEF');

  expect(res.status).toBe(200);
  expect(res.body.proofStatus).toBe(expected);
});

it('keeps an attached historical proof visible on the status endpoint', async () => {
  (reportPersistenceService.getForReporter as jest.Mock).mockResolvedValue({
    trackingId: 'VRA-0123456789ABCDEF', status: 'pending', createdAt: new Date(), updatedAt: new Date(),
    zkProof: { proofHash: 'b'.repeat(64), nullifier: 'c'.repeat(64), publicSignals: [], verified: true,
      proofType: 'compact_circuit', contractAddress: 'd'.repeat(64), txHash: 'e'.repeat(64), network: 'preprod' },
  });

  const res = await request(makeApp()).get('/api/whistleblower/status/VRA-0123456789ABCDEF');

  expect(res.status).toBe(200);
  expect(res.body.proofStatus).toBe('attached');
  expect(res.body.zkProof).toMatchObject({ proofHash: 'b'.repeat(64), txHash: 'e'.repeat(64), network: 'preprod', verified: true });
  expect(res.body.zkProof).not.toHaveProperty('nullifier');
});
