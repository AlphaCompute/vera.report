const mockNarrativeMode = { enabled: false };
const mockNarrativeEncrypt = jest.fn();
jest.mock('../../../src/services/attestedNarrative', () => ({ attestedNarrativeConfiguration: () => ({ writes: mockNarrativeMode.enabled, reader: { encrypt: mockNarrativeEncrypt } }) }));
import express from 'express';
import { EvidenceStorageError } from '../../../src/services/evidenceStorageError';
import { maxIncidentDate } from '../../../src/utils/reportIntakeRules';
import request from 'supertest';
import { decryptRewardContact } from '../../../src/services/rewardContact';
import { keyEnvelope } from '../../../src/services/keyEnvelope';

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
}));jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: {
    get: jest.fn(async () => null),
    getEvidenceParams: jest.fn(async () => null),
    saveEvidenceParams: jest.fn(),
    upsert: jest.fn(),
    patch: jest.fn(),
  },
}));
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: {
    middleware: () => (_req: any, _res: any, next: () => void) => next(),
    logError: jest.fn(),
  },
}));


jest.mock('../../../src/services/submissionEvidence', () => ({ persistSubmissionEvidence: jest.fn() }));
jest.mock('../../../src/services/reportFieldCrypto', () => ({ encryptContactValue: () => 'encrypted' }));
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { notifyNewReport: jest.fn(async () => {}) } }));
jest.mock('express-rate-limit', () => {
  const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
  return { __esModule: true, ...actual, default: () => (_req: any, _res: any, next: any) => next() };
});
import { persistSubmissionEvidence } from '../../../src/services/submissionEvidence';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import whistleblowerRouter from '../../../src/api/whistleblower';

function makeApp(): express.Application {
  const app = express();
  app.use(express.json());
  app.use('/api/whistleblower', whistleblowerRouter);
  return app;
}

describe('Submission receipt durability boundary', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockNarrativeMode.enabled = false;
    jest.mocked(persistSubmissionEvidence).mockResolvedValue([]);
    jest.mocked(reportPersistenceService.upsert).mockResolvedValue();
  });
  const submit = () => request(makeApp()).post('/api/whistleblower/submit')
    .field('description', 'Report with important evidence').field('wantsReward', 'false');

  const submitReward = () => request(makeApp()).post('/api/whistleblower/submit')
    .field('description', 'Synthetic report with reward follow-up')
    .field('wantsReward', 'true').field('contactMethod', 'email').field('contactValue', 'reward@example.test');

  it('writes reward contacts with a report-bound wrapped key through the mounted intake route', async () => {
    const response = await submitReward();
    expect(response.status).toBe(200);
    const row = jest.mocked(reportPersistenceService.upsert).mock.calls[0][0];
    const contact = { ciphertext: row.reward!.encryptedContactValue!, wrappedKey: row.reward!.contactKeyWrapped! };
    expect(contact.wrappedKey).toMatch(/^enc:(?:kms:v2|local:v1):/);
    expect(JSON.stringify(row)).not.toContain('reward@example.test');
    expect(await decryptRewardContact(contact, row.trackingId)).toBe('reward@example.test');
    await expect(decryptRewardContact(contact, 'VRA-0000000000000000')).rejects.toThrow();
  });

  it('does not acknowledge or store a report when reward-key wrapping fails', async () => {
    const wrap = jest.spyOn(keyEnvelope, 'wrap').mockRejectedValueOnce(new Error('synthetic KMS outage'));
    try {
      const response = await submitReward();
      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(response.body.trackingId).toBeUndefined();
      expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
      expect(wrap).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ purpose: 'reward' }));
    } finally { wrap.mockRestore(); }
  });

  it('rejects a request without a body as a missing description', async () => {
    const response = await request(makeApp()).post('/api/whistleblower/submit');
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      success: false,
      error: 'Please provide a description, even when attaching evidence files.',
    });
    expect(persistSubmissionEvidence).not.toHaveBeenCalled();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });

  describe.each([false, true])('required description (attachments: %s)', (withFiles) => {
    it.each([
      ['missing', undefined],
      ['empty', ''],
      ['whitespace', ' \t\r\n '],
      ['Unicode whitespace', '\u00a0\u2003'],
    ])('rejects a %s description before storing evidence or accepting the report', async (_name, description) => {
      const pending = request(makeApp()).post('/api/whistleblower/submit').field('wantsReward', 'false');
      if (description !== undefined) pending.field('description', description);
      if (withFiles)
        pending.attach('files', Buffer.from('item,value\nsynthetic,1\n'), {
          filename: 'evidence.csv',
          contentType: 'text/csv',
        });
      const response = await pending;
      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        success: false,
        error: 'Please provide a description, even when attaching evidence files.',
      });
      expect(persistSubmissionEvidence).not.toHaveBeenCalled();
      expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    });

    it('accepts a nonblank description', async () => {
      const pending = request(makeApp())
        .post('/api/whistleblower/submit')
        .field('description', 'A')
        .field('wantsReward', 'false');
      if (withFiles)
        pending.attach('files', Buffer.from('item,value\nsynthetic,1\n'), {
          filename: 'evidence.csv',
          contentType: 'text/csv',
        });
      const response = await pending;
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({ success: true, proofStatus: 'not_applicable' });
      expect(reportPersistenceService.upsert).toHaveBeenCalledTimes(1);
      expect(jest.mocked(persistSubmissionEvidence).mock.calls[0][1]).toHaveLength(withFiles ? 1 : 0);
    });
  });

  it.each([null, false, 0, ['description'], { text: 'description' }].map((description) => ({ description })))(
    'rejects a non-string description: $description',
    async ({ description }) => {
      const response = await request(makeApp()).post('/api/whistleblower/submit').send({ description });
      expect(response.status).toBe(400);
      expect(response.body).toEqual({ success: false, error: 'Description must be a string' });
      expect(persistSubmissionEvidence).not.toHaveBeenCalled();
      expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    },
  );

  it('rejects repeated multipart description fields instead of coercing them to text', async () => {
    const response = await submit().field('description', 'A second description');
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('Description must be a string');
    expect(persistSubmissionEvidence).not.toHaveBeenCalled();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });

  it('rejects an incident date in the future before storing anything (#853)', async () => {
    const response = await submit().field('dateOfIncident', '2099-12-31');
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      success: false,
      error: 'Date of incident cannot be in the future.',
    });
    expect(persistSubmissionEvidence).not.toHaveBeenCalled();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });

  it.each(['2026-01-20 to 2026-01-10', '2026-01-10 to 2099-01-01', '2026-02-30 to 2026-03-01', '2026-01-10 to '])('rejects invalid incident ranges before storage', async timeframe => {
    const response = await submit().field('dateOfIncident', timeframe);
    expect(response.status).toBe(400);
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    expect(persistSubmissionEvidence).not.toHaveBeenCalled();
  });

  it('persists both ends of an incident range', async () => {
    const response = await submit().field('dateOfIncident', '2026-01-10 to 2026-01-20');
    expect(response.status).toBe(200);
    expect(reportPersistenceService.upsert).toHaveBeenCalledWith(expect.objectContaining({ dateOfIncident: '2026-01-10 to 2026-01-20' }));
  });

  it('accepts today as an incident date', async () => {
    const response = await submit().field('dateOfIncident', maxIncidentDate());
    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
  });

  it('leaves an unparseable incident date alone rather than rejecting it', async () => {
    const response = await submit().field('dateOfIncident', 'sometime last spring');
    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
  });

  it('accepts the 50,000-character description boundary', async () => {
    const response = await request(makeApp()).post('/api/whistleblower/submit').field('description', 'x'.repeat(50000));
    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(reportPersistenceService.upsert).toHaveBeenCalledTimes(1);
  });

  it('rejects descriptions over 50,000 characters before storing anything', async () => {
    const response = await request(makeApp()).post('/api/whistleblower/submit').field('description', 'x'.repeat(50001));
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('Description exceeds maximum length (50,000 characters)');
    expect(persistSubmissionEvidence).not.toHaveBeenCalled();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });

  it('does not publish a report or receipt when an attachment or key write fails', async () => {
    jest.mocked(persistSubmissionEvidence).mockRejectedValue(new Error('key write failed'));
    const response = await submit();
    expect(response.status).toBe(500);
    expect(response.body.success).toBe(false);
    expect(response.body.trackingId).toBeUndefined();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
  });

  it.each(['evidence_encryption_unavailable', 'evidence_upload_unavailable', 'evidence_upload_auth_unavailable', 'evidence_key_write_unavailable'] as const)(
    'returns a safe %s code without exposing a provider error or accepting an incomplete report', async code => {
      jest.mocked(persistSubmissionEvidence).mockRejectedValueOnce(new EvidenceStorageError(code, new Error('PRIVATE_PROVIDER_DETAIL')));
      const response = await submit();
      expect(response.status).toBe(503);
      expect(response.body).toEqual({ success: false, error: code,
        message: 'We could not save your attached files. Keep this page open and retry the same submission.' });
      expect(JSON.stringify(response.body)).not.toContain('PRIVATE_PROVIDER_DETAIL');
      expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    },
  );

  it('rejects identified submissions without explicit disclosure consent before storing anything', async () => {
    const response = await submit().field('submitterMode', 'identified').field('submitterName', 'Alex Example')
      .field('submitterContactMethod', 'email').field('submitterContactValue', 'alex@example.invalid');
    expect(response.status).toBe(400);
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    expect(persistSubmissionEvidence).not.toHaveBeenCalled();
  });

  it('stores a consented identity encrypted even when reward follow-up is declined', async () => {
    const response = await submit().field('submitterMode', 'identified').field('submitterConsent', 'true')
      .field('submitterName', 'Alex Example').field('submitterContactMethod', 'email').field('submitterContactValue', 'alex@example.invalid');
    expect(response.status).toBe(200);
    const stored = jest.mocked(reportPersistenceService.upsert).mock.calls[0][0];
    expect(stored.submitter).toMatchObject({ mode: 'identified', consent: { shareWithRecipients: true, textVersion: 'submitter-disclosure-v1' } });
    expect(JSON.stringify(stored)).not.toContain('Alex Example');
    expect(JSON.stringify(stored)).not.toContain('alex@example.invalid');
    expect(JSON.stringify(response.body)).not.toContain('submitter');
  });

  it('ignores leftover identity fields when the submitter chooses anonymity', async () => {
    const response = await submit().field('submitterMode', 'anonymous').field('submitterConsent', 'true')
      .field('submitterName', 'Alex Example').field('submitterContactValue', 'alex@example.invalid');
    expect(response.status).toBe(200);
    expect(jest.mocked(reportPersistenceService.upsert).mock.calls[0][0].submitter).toEqual({ mode: 'anonymous' });
  });

  it('does not return success when the report write fails', async () => {
    jest.mocked(reportPersistenceService.upsert).mockRejectedValue(new Error('database unavailable'));
    const response = await submit();
    expect(response.status).toBe(500);
    expect(response.body.success).toBe(false);
    expect(response.body.trackingId).toBeUndefined();
  });

  it('waits for all evidence writes before publishing the report and receipt', async () => {
    let release!: () => void;
    let started!: () => void;
    const reached = new Promise<void>(resolve => { started = resolve; });
    jest.mocked(persistSubmissionEvidence).mockImplementation(async () => {
      started();
      await new Promise<void>(resolve => { release = resolve; });
      return [{ fileKey: 'file', ipfsHash: 'cid' }];
    });
    const responsePromise = submit().then(response => response);
    await reached;
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    release();
    const response = await responsePromise;
    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(reportPersistenceService.upsert).toHaveBeenCalledWith(expect.objectContaining({ ipfsHash: 'cid' }));
  });
});

describe('PNG structural validation over HTTP', () => {
  it('rejects malformed PNG before any accepted report or error log', async () => {
    jest.clearAllMocks();
    const actual = jest.requireActual('../../../src/services/evidenceEncryption');
    jest.mocked(persistSubmissionEvidence).mockImplementationOnce(async (_id, files) => {
      await actual.evidenceEncryptionService.encryptEvidence(files[0].buffer, 'image/png', 'synthetic-key');
      throw new Error('Malformed file was unexpectedly accepted');
    });
    const log = jest.fn();
    const app = express(); app.use(express.json());
    app.use((req, _res, next) => { req.logError = log; next(); });
    app.use('/api/whistleblower', whistleblowerRouter);
    const response = await request(app).post('/api/whistleblower/submit')
      .field('description', 'Synthetic malformed evidence').field('wantsReward', 'false')
      .attach('files', Buffer.from('private-malformed-png-sentinel'), { filename: 'example.png', contentType: 'image/png' });
    expect(response.status).toBe(422);
    expect(response.body.error).toBe('invalid_evidence_file');
    expect(response.body.restartAllowed).toBe(true);
    expect(JSON.stringify(response.body)).not.toContain('private-malformed-png-sentinel');
    expect(response.body.trackingId).toBeUndefined();
    expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
    expect(reportPersistenceService.saveEvidenceParams).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });
});

it('keeps an encryption runtime failure as a server error without leaking its detail', async () => {
  jest.clearAllMocks();
  jest.mocked(persistSubmissionEvidence).mockRejectedValueOnce(new Error('private crypto provider failure'));
  const response = await request(makeApp()).post('/api/whistleblower/submit')
    .field('description', 'Synthetic report').field('wantsReward', 'false');
  expect(response.status).toBe(500);
  expect(JSON.stringify(response.body)).not.toContain('private crypto provider failure');
  expect(reportPersistenceService.upsert).not.toHaveBeenCalled();
});


describe('Recipient narrative intake selection', () => {
  beforeEach(() => {
    jest.clearAllMocks(); mockNarrativeMode.enabled = true;
    jest.mocked(persistSubmissionEvidence).mockResolvedValue([]);
    jest.mocked(reportPersistenceService.upsert).mockResolvedValue();
  });
  afterEach(() => { mockNarrativeMode.enabled = false; });
  it('persists the attested envelope from the actual mounted multipart route and keeps access receipt', async () => {
    mockNarrativeEncrypt.mockImplementation(async (trackingId: string) => ({ format: 'recipient-narrative:v1', trackingId, purpose: 'narrative', key: 'enc:kms:recipient:v1:YWJj', iv: Buffer.alloc(12).toString('base64'), tag: Buffer.alloc(16).toString('base64'), data: 'YWJj' }));
    const response = await request(makeApp()).post('/api/whistleblower/submit').field('description','Explicit offline intake evidence').field('wantsReward','false');
    expect(response.status).toBe(200);expect(response.body.success).toBe(true);
    const row=jest.mocked(reportPersistenceService.upsert).mock.calls[0][0];
    expect(row.encryptedNarrative).toMatchObject({format:'recipient-narrative:v1',trackingId:row.trackingId});expect(row.encryptedDescription).toBeUndefined();
    expect(mockNarrativeEncrypt).toHaveBeenCalledWith(row.trackingId,'Explicit offline intake evidence',expect.any(AbortSignal));
  });
  it('rejects recipient failure without accepting a report or falling back to host encryption', async () => {
    mockNarrativeEncrypt.mockRejectedValue(new Error('Narrative unavailable'));
    const response=await request(makeApp()).post('/api/whistleblower/submit').field('description','Explicit offline intake evidence');
    expect(response.status).toBe(500);expect(reportPersistenceService.upsert).not.toHaveBeenCalled();expect(mockNarrativeEncrypt).toHaveBeenCalledTimes(1);
  });
});
