/**
 * Public enclave attestation endpoint: live PCR0, 200 `{ available: false }`
 * when no enclave can answer, 502 only for an invalid attestation — never a
 * hard-coded hash and never the raw NSM document.
 */

import express from 'express';
import request from 'supertest';

const fetchLive = jest.fn();

jest.mock('../../../src/services/enclaveAttestation', () => ({
  getCachedEnclaveAttestation: (...args: unknown[]) => fetchLive(...args),
}));

jest.mock('../../../src/services/evidenceEncryption', () => ({
  evidenceEncryptionService: { decryptEvidence: jest.fn(), encryptEvidence: jest.fn() },
}));
jest.mock('../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: { upload: jest.fn(), readCiphertext: jest.fn() },
}));
jest.mock('../../../src/services/veniceAI', () => ({
  veniceAIService: { analyzeReport: jest.fn(), isConfigured: () => false },
}));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
jest.mock('../../../src/services/shroudClient', () => ({
  shroudChat: jest.fn(),
  isShroudConfigured: jest.fn(() => false),
}));
jest.mock('../../../src/services/metadataExtractor', () => ({
  metadataExtractorService: { extract: jest.fn() },
}));
jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: { get: jest.fn(), save: jest.fn() },
}));
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: { middleware: () => (_r: unknown, _s: unknown, n: () => void) => n() },
}));
jest.mock('../../../src/services/submissionAttempt', () => ({
  submissionAttemptStore: {},
  submissionPayloadHash: jest.fn(),
  submissionKeyHash: jest.fn(),
  IntakeLeaseLostError: class extends Error {},
}));
jest.mock('../../../src/services/submissionEvidence', () => ({
  persistSubmissionEvidence: jest.fn(),
}));
jest.mock('../../../src/services/submissionNotificationWorker', () => ({
  notifySubmission: jest.fn(),
}));
jest.mock('../../../src/services/submissionWebhook', () => ({
  submissionNotificationsEnabled: () => false,
}));
jest.mock('../../../src/services/reportScoringWorker', () => ({
  reportScoringWorker: {},
}));
jest.mock('../../../src/services/metadataWorker', () => ({
  extractMetadataIsolated: jest.fn(),
}));
jest.mock('../../../src/middleware/evidenceUpload', () => ({
  evidenceUpload: { array: () => (_r: unknown, _s: unknown, n: () => void) => n() },
}));
jest.mock('../../../src/middleware/uploadBudget', () => ({
  reserveUpload: (_r: unknown, _s: unknown, n: () => void) => n(),
  reserveIntake: (_r: unknown, _s: unknown, n: () => void) => n(),
  withUploadBudget: (fn: unknown) => fn,
}));

import whistleblowerRouter from '../../../src/api/whistleblower';

function makeApp() {
  const app = express();
  app.use('/api/whistleblower', whistleblowerRouter);
  return app;
}

describe('GET /api/whistleblower/enclave/attestation', () => {
  beforeEach(() => {
    fetchLive.mockReset();
  });

  it('returns only available and pcr0 when the enclave answers', async () => {
    // Even if the service layer ever carried more, the route must not forward it.
    fetchLive.mockResolvedValue({
      available: true,
      pcr0: 'ab'.repeat(48),
      document: Buffer.from('doc').toString('base64'),
      module_id: 'i-0123456789abcdef0-enc0123456789abcdef',
    });
    const res = await request(makeApp()).get('/api/whistleblower/enclave/attestation');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ available: true, pcr0: 'ab'.repeat(48) });
    expect(res.headers['cache-control']).toMatch(/no-store/);
  });

  it('returns 200 { available: false } when no enclave can answer', async () => {
    fetchLive.mockResolvedValue({ available: false });
    const res = await request(makeApp()).get('/api/whistleblower/enclave/attestation');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ available: false });
    expect(res.headers['cache-control']).toMatch(/no-store/);
  });

  it('returns 502 only for a genuine attestation fault', async () => {
    fetchLive.mockRejectedValue(new Error('Attestation nonce mismatch'));
    const res = await request(makeApp()).get('/api/whistleblower/enclave/attestation');
    expect(res.status).toBe(502);
    expect(res.body).toEqual({ error: 'enclave_attestation_invalid' });
    expect(res.headers['cache-control']).toMatch(/no-store/);
  });
});
