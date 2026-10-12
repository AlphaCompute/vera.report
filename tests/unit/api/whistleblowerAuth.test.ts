/**
 * Unit tests for /api/whistleblower auth gating on sensitive endpoints.
 *
 * Regression coverage for issue #250 — `/evidence/:trackingId/:filename`
 * and `/reward-contact/:trackingId` previously returned decrypted evidence
 * files and decrypted PII to any caller who could reach the Express
 * backend (e.g. from inside the VPC), even though the Next.js admin proxy
 * gates them at Auth0. The fix requires the `x-internal-secret` header
 * so the backend cannot be bypassed by reaching it directly.
 *
 * We do NOT exercise the IPFS / decryption path here — these tests only
 * verify the auth gate runs before the handler. To avoid relying on the
 * tracking-ID format validator changing later, we mock the heavy service
 * deps so a request with a valid secret reaches a deterministic path.
 */

import express from 'express';
import request from 'supertest';

const SECRET = 'test-internal-secret-for-whistleblower';

process.env.INTERNAL_API_SECRET = SECRET;

// Minimal mocks so the router loads without trying real network/db.
jest.mock('../../../src/services/evidenceEncryption', () => ({
  evidenceEncryptionService: { decryptEvidence: jest.fn(), encryptEvidence: jest.fn().mockResolvedValue({ encryptedData: 'ZmFrZQ==', encryptionMetadata: { algorithm: 'aes-256-gcm', salt: 'cw==', iv: 'aXY=', authTag: 'dGFn', keyVersion: 'v1.0' }, contentMetadata: { hash: 'a'.repeat(64), size: 4 } }) },
}));
jest.mock('../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: { upload: jest.fn(), readCiphertext: jest.fn() },
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
}));jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: {
    get: jest.fn(async () => null), // Report not found — gives us a deterministic 404
    getEvidenceParams: jest.fn(async () => null),
    saveEvidenceParams: jest.fn(),
    save: jest.fn(),
  },
}));
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: { middleware: () => (_req: any, _res: any, next: () => void) => next() },
}));

import whistleblowerRouter from '../../../src/api/whistleblower';

function makeApp(logError?: jest.Mock): express.Application {
  const app = express();
  app.use(express.json());
  if (logError) app.use((req, _res, next) => { req.logError = logError; next(); });
  app.use('/api/whistleblower', whistleblowerRouter);
  return app;
}

const VALID_TRACKING_ID = 'VRA-0123456789ABCDEF';

describe('/api/whistleblower/evidence/:trackingId/:filename — auth', () => {
  it('returns 401 when x-internal-secret is missing', async () => {
    const app = makeApp();
    const res = await request(app).get(
      `/api/whistleblower/evidence/${VALID_TRACKING_ID}/file.pdf`,
    );
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ success: false, error: 'Unauthorized' });
  });

  it('returns 401 when x-internal-secret is wrong', async () => {
    const app = makeApp();
    const res = await request(app)
      .get(`/api/whistleblower/evidence/${VALID_TRACKING_ID}/file.pdf`)
      .set('x-internal-secret', 'definitely-not-the-secret');
    expect(res.status).toBe(401);
  });

  it('passes the gate with the correct secret (reaches handler, returns 404 for unknown evidence)', async () => {
    const app = makeApp();
    const res = await request(app)
      .get(`/api/whistleblower/evidence/${VALID_TRACKING_ID}/file.pdf`)
      .set('x-internal-secret', SECRET);
    // No evidence in cache, mongo, or eliza → handler returns 404.
    // The point is: the response is NOT 401 — the middleware let us through.
    expect(res.status).not.toBe(401);
    expect(res.status).toBe(404);
  });

  it('still 400s on a malformed tracking ID — only after passing auth', async () => {
    const app = makeApp();
    const res = await request(app)
      .get('/api/whistleblower/evidence/not-a-tracking-id/file.pdf')
      .set('x-internal-secret', SECRET);
    expect(res.status).toBe(400);
  });
});

describe('/api/whistleblower/reward-contact/:trackingId — auth', () => {
  it('returns 401 when x-internal-secret is missing', async () => {
    const app = makeApp();
    const res = await request(app).get(
      `/api/whistleblower/reward-contact/${VALID_TRACKING_ID}`,
    );
    expect(res.status).toBe(401);
  });

  it('returns 401 when x-internal-secret is wrong', async () => {
    const app = makeApp();
    const res = await request(app)
      .get(`/api/whistleblower/reward-contact/${VALID_TRACKING_ID}`)
      .set('x-internal-secret', 'wrong');
    expect(res.status).toBe(401);
  });

  it('passes the gate with the correct secret (reaches handler, returns 404 for unknown report)', async () => {
    const app = makeApp();
    const res = await request(app)
      .get(`/api/whistleblower/reward-contact/${VALID_TRACKING_ID}`)
      .set('x-internal-secret', SECRET);
    expect(res.status).toBe(404);
  });
});

describe('/api/whistleblower public endpoints — still public', () => {
  // Confirm that the broader router isn't accidentally locked down — only
  // the two sensitive endpoints should require the internal secret.

  it('/status/:trackingId does not require x-internal-secret', async () => {
    const app = makeApp();
    const res = await request(app).get(`/api/whistleblower/status/${VALID_TRACKING_ID}`);
    // No report exists, so 404 — but crucially, not 401.
    expect(res.status).not.toBe(401);
  });

  it('/health does not require x-internal-secret', async () => {
    const app = makeApp();
    const res = await request(app).get('/api/whistleblower/health');
    expect(res.status).not.toBe(401);
  });
  it.each(['get', 'post'] as const)('protects reporter %s responses from caching and referrers', async method => {
    const path = `/api/whistleblower/status/${VALID_TRACKING_ID}${method === 'post' ? '/relay' : ''}`;
    const res = await request(makeApp())[method](path);
    expect(res.headers['cache-control']).toBe('private, no-store');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
  });

});


describe('metadata selection input', () => {
  it('rejects malformed selections without logging or returning reporter-controlled JSON', async () => {
    const logError = jest.fn();
    // Omit X-Idempotency-Key so pre-upload admission does not touch the attempt
    // store (a malformed key is rejected before stripSelection validation).
    const response = await request(makeApp(logError)).post('/api/whistleblower/submit')
      .send({ description: 'Synthetic report', stripSelection: 'identity-canary-invalid-json' });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('stripSelection must be a JSON object of boolean values.');
    expect(logError).toHaveBeenCalledWith('Invalid metadata selection format', 'error');
    expect(JSON.stringify(logError.mock.calls)).not.toContain('identity-canary');
    expect(JSON.stringify(response.body)).not.toContain('identity-canary');
  });
});

it('rejects an employee triage reference at both reporter endpoints', async () => {
  const { sealTriageReference } = await import('../../../lib/triageReference');
  const reference = sealTriageReference(VALID_TRACKING_ID);
  const app = makeApp();
  expect((await request(app).get(`/api/whistleblower/status/${reference}`)).status).toBe(400);
  expect((await request(app).post(`/api/whistleblower/status/${reference}/relay`).send({ message: 'impersonation' })).status).toBe(400);
});

describe('evidence plaintext integrity enforcement', () => {
  it.each(['matching', 'mismatch', 'size-mismatch', 'legacy', 'short-tag'])('handles %s with both real encryption layers', async mode => {
    const crypto = await import('node:crypto');
    const { reportPersistenceService } = await import('../../../src/services/reportPersistence');
    const { evidenceStorageService } = await import('../../../src/services/evidenceStorage');
    const { evidenceEncryptionService } = await import('../../../src/services/evidenceEncryption');
    const { EvidenceEncryptionService } = jest.requireActual<typeof import('../../../src/services/evidenceEncryption')>('../../../src/services/evidenceEncryption');
    const realEncryption = new EvidenceEncryptionService();
    const iv = crypto.randomBytes(12), salt = crypto.randomBytes(16), secret = 'synthetic';
    const inner = await realEncryption.encryptEvidence('private evidence', 'text/plain', secret);
    const cipher = crypto.createCipheriv('aes-256-gcm', crypto.scryptSync(secret, salt, 32), iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(inner.encryptedData, 'base64')), cipher.final()]);
    const hash = mode === 'legacy' ? undefined : mode === 'mismatch' ? '0'.repeat(64) : inner.contentMetadata.hash;
    const size = mode === 'legacy' ? undefined : mode === 'size-mismatch' ? 0 : inner.contentMetadata.size;
    jest.mocked(reportPersistenceService.getEvidenceParams).mockResolvedValueOnce({
      encryptionKey: secret, originalCID: 'cid', pinataSalt: salt.toString('base64'),
      pinataIv: iv.toString('base64'), pinataAuthTag: cipher.getAuthTag().toString('base64'),
      evidenceSalt: inner.encryptionMetadata.salt, evidenceIv: inner.encryptionMetadata.iv,
      evidenceAuthTag: mode === 'short-tag' ? Buffer.from(inner.encryptionMetadata.authTag, 'base64').subarray(0, 12).toString('base64') : inner.encryptionMetadata.authTag,
      mimetype: 'text/plain', contentHash: hash, contentSize: size,
    });
    jest.mocked(evidenceStorageService.readCiphertext).mockResolvedValueOnce(encrypted);
    jest.mocked(evidenceEncryptionService.decryptEvidence).mockImplementationOnce(realEncryption.decryptEvidence.bind(realEncryption));
    const { logger } = await import('../../../src/utils/logger');
    const log = jest.spyOn(logger, 'error').mockImplementation(() => undefined);
    const result = await request(makeApp()).get(`/api/whistleblower/evidence/${VALID_TRACKING_ID}/file.txt`).set('x-internal-secret', SECRET);
    const succeeds = mode === 'matching' || mode === 'legacy';
    expect(result.status).toBe(succeeds ? 200 : 500);
    expect(log.mock.calls).toEqual(succeeds ? [] : [['Evidence read failed: decrypt']]);
    log.mockRestore();
    if (succeeds) expect(result.body).toEqual(Buffer.from('private evidence'));
    else expect(result.text).not.toContain('private evidence');
    const supplied = jest.mocked(evidenceEncryptionService.decryptEvidence).mock.calls.at(-1)![0];
    expect(supplied.contentMetadata.hash).toBe(hash);
    expect(supplied.contentMetadata.size).toBe(size);
  });
});

describe('evidence storage failure logging', () => {
  it.each([
    ['storage', new Error('Local IPFS request failed')],
    ['not-found', Object.assign(new Error('The specified key does not exist.'), { name: 'NoSuchKey' })],
  ])('logs a stable %s category without identifiers and keeps the 500 response', async (kind, error) => {
    const { reportPersistenceService } = await import('../../../src/services/reportPersistence');
    const { evidenceStorageService } = await import('../../../src/services/evidenceStorage');
    const { logger } = await import('../../../src/utils/logger');
    const cid = 'QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN';
    jest.mocked(reportPersistenceService.getEvidenceParams).mockResolvedValueOnce({ encryptionKey: 'synthetic', originalCID: cid } as any);
    jest.mocked(evidenceStorageService.readCiphertext).mockRejectedValueOnce(error);
    const log = jest.spyOn(logger, 'error').mockImplementation(() => undefined);
    const result = await request(makeApp()).get(`/api/whistleblower/evidence/${VALID_TRACKING_ID}/file.txt`).set('x-internal-secret', SECRET);
    expect(result.status).toBe(500);
    expect(log.mock.calls).toEqual([[`Evidence read failed: ${kind}`]]);
    expect(JSON.stringify(log.mock.calls)).not.toMatch(new RegExp(`${cid}|${VALID_TRACKING_ID}|file\\.txt`));
    log.mockRestore();
  });
});
