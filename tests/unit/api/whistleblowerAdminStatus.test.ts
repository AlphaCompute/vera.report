/**
 * Unit tests for PATCH /api/whistleblower/admin/reports/:trackingId/status —
 * the admin triage status mutation, now persisted to MongoDB (replaces the
 * legacy ElizaOS PATCH). Verifies the internal-secret gate, status-vocabulary
 * validation, the not-found path, and that a valid update calls
 * reportPersistenceService.setAdminStatus with the dashboard status.
 */

import express from 'express';
import request from 'supertest';

const SECRET = 'test-internal-secret-for-status';
process.env.INTERNAL_API_SECRET = SECRET;

// Minimal mocks so the router loads without real network/db.
jest.mock('../../../src/services/evidenceEncryption', () => ({
  evidenceEncryptionService: { decryptEvidence: jest.fn(), encryptEvidence: jest.fn().mockResolvedValue({ encryptedData: 'ZmFrZQ==', encryptionMetadata: { algorithm: 'aes-256-gcm', salt: 'cw==', iv: 'aXY=', authTag: 'dGFn', keyVersion: 'v1.0' }, contentMetadata: { hash: 'a'.repeat(64), size: 4 } }) },
}));
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: { upload: jest.fn() } }));
jest.mock('../../../src/services/veniceAI', () => ({
  veniceAIService: { isConfigured: jest.fn(() => false) },
}));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
jest.mock('../../../src/services/shroudClient', () => ({
  shroudChat: jest.fn(),
  isShroudConfigured: jest.fn(() => false),
}));
jest.mock('../../../src/services/metadataExtractor', () => ({
  metadataExtractorService: { extract: jest.fn() },
}));
const mockAddNote = jest.fn();
const mockListNotes = jest.fn();
const mockGet = jest.fn();
const mockSetAdminStatus = jest.fn();
const mockPatch = jest.fn(async (..._args: any[]) => undefined);
jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: {
    addInternalNote: (...a: unknown[]) => mockAddNote(...a),
    listInternalNotes: (...a: unknown[]) => mockListNotes(...a),
    get: (...a: unknown[]) => mockGet(...a),
    getForReporter: (...a: unknown[]) => mockGet(...a),
    setAdminStatus: (...a: unknown[]) => mockSetAdminStatus(...a),
    patch: (...a: unknown[]) => mockPatch(...a),
    list: jest.fn(async () => []),
    searchAdmin: jest.fn(async () => []),
    listEvidenceByTrackingIds: jest.fn(async () => []),
    getEvidenceParams: jest.fn(async () => null),
    saveEvidenceParams: jest.fn(),
    upsert: jest.fn(),
  },
}));
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: { middleware: () => (_req: any, _res: any, next: () => void) => next() },
}));

jest.mock('../../../src/services/dissemination/disseminationService', () => ({ disseminationService: { status: jest.fn(async () => []) } }));
jest.mock('../../../src/services/dissemination/relayService', () => ({ relayService: { getThread: jest.fn(async () => []) } }));

import whistleblowerRouter from '../../../src/api/whistleblower';
import { verifyReport } from '../../../src/services/reportScoring';
import { isShroudConfigured } from '../../../src/services/shroudClient';
import { mapReports } from '../../../src/services/dashboardReportsMapper';

function makeApp(): express.Application {
  const app = express();
  app.use(express.json());
  app.use('/api/whistleblower', whistleblowerRouter);
  return app;
}

const TID = 'VRA-0123456789ABCDEF';
const URL = `/api/whistleblower/admin/reports/${TID}/status`;

beforeEach(() => {
  mockGet.mockReset();
  mockSetAdminStatus.mockReset();
  mockPatch.mockReset();
  mockPatch.mockResolvedValue(undefined);
});

describe('PATCH /admin/reports/:trackingId/status', () => {
  it('401s without the internal secret (cannot bypass the Next proxy)', async () => {
    const res = await request(makeApp()).patch(URL).send({ status: 'reviewing' });
    expect(res.status).toBe(401);
    expect(mockSetAdminStatus).not.toHaveBeenCalled();
  });

  it('400s on a status outside the admin vocabulary', async () => {
    // 'processing' is a submit/AI-pipeline value, not admin-settable.
    const res = await request(makeApp()).patch(URL).set('x-internal-secret', SECRET).send({ status: 'processing' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ success: false, error: 'invalid_status' });
    expect(mockGet).not.toHaveBeenCalled();
    expect(mockSetAdminStatus).not.toHaveBeenCalled();
  });

  it('400s when status is missing', async () => {
    const res = await request(makeApp()).patch(URL).set('x-internal-secret', SECRET).send({});
    expect(res.status).toBe(400);
    expect(mockSetAdminStatus).not.toHaveBeenCalled();
  });

  it('404s when the report does not exist', async () => {
    mockGet.mockResolvedValueOnce(null);
    const res = await request(makeApp()).patch(URL).set('x-internal-secret', SECRET).send({ status: 'resolved' });
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ success: false, error: 'report_not_found' });
    expect(mockSetAdminStatus).not.toHaveBeenCalled();
  });

  it.each(['investigating', 'resolved'])('returns the reloaded %s status and matching activity', async persistedStatus => {
    const timestamp = '2026-09-22T10:15:30.000Z';
    mockGet.mockResolvedValueOnce({ trackingId: TID, status: 'pending' }).mockResolvedValueOnce({
      trackingId: TID, status: persistedStatus, createdAt: timestamp, updatedAt: timestamp,
      statusHistory: [{ id: 'status-1', status: persistedStatus, timestamp }],
    });
    const res = await request(makeApp()).patch(URL).set('x-internal-secret', SECRET).send({ status: 'investigating' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, data: { trackingId: TID, status: persistedStatus, activity: [
      { id: `${TID}-submit`, type: 'submit', description: 'Report submitted', timestamp },
      { id: 'status-1', type: 'status', description: `Status: ${persistedStatus}`, timestamp },
    ] }, source: 'mongodb' });
    expect(mockSetAdminStatus).toHaveBeenCalledWith(TID, 'investigating');
    expect(mockPatch).not.toHaveBeenCalled();
  });

  it('fails when the updated report cannot be reloaded', async () => {
    mockGet.mockResolvedValueOnce({ trackingId: TID, status: 'pending' }).mockResolvedValueOnce(null);
    const res = await request(makeApp()).patch(URL).set('x-internal-secret', SECRET).send({ status: 'resolved' });
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ success: false, error: 'Failed to update status' });
  });

});


it.each(['pending', 'reviewing', 'investigating', 'resolved', 'dismissed'])('preserves persisted %s in reporter and admin views', async status => {
  const stored = { trackingId: TID, status, processingStatus: 'completed', createdAt: new Date(), updatedAt: new Date() };
  mockGet.mockResolvedValue(stored);
  const response = await request(makeApp()).get(`/api/whistleblower/status/${TID}`);
  expect(response.status).toBe(200);
  expect(response.body.status).toBe(status);
  expect(mapReports([stored])[0].status).toBe(status);
});

it('exposes public contract binding for status verification without private proof inputs', async () => {
  mockGet.mockResolvedValue({ trackingId: TID, status: 'pending', createdAt: new Date(), updatedAt: new Date(),
    proofGeneration: { state: 'failed' },
    zkProof: { verified: true, proofType: 'compact_circuit', txHash: 'transaction', contractAddress: 'contract', proofHash: 'hash', nullifier: 'private-nullifier', publicSignals: ['private-input'] },
  });
  const res = await request(makeApp()).get(`/api/whistleblower/status/${TID}`);
  expect(res.status).toBe(200);
  expect(res.body.zkProof.contractAddress).toBe('contract');
  expect(res.body.proofStatus).toBe('attached'); // stored proof takes precedence over stale queue state
  expect(JSON.stringify(res.body)).not.toContain('private-nullifier');
  expect(JSON.stringify(res.body)).not.toContain('private-input');
});


it('manual reanalysis refuses corrupt narrative rather than sending empty text', async () => {
  mockGet.mockResolvedValue({ trackingId: TID, encryptedDescription: 'corrupt' });
  (verifyReport as jest.Mock).mockClear();
  (isShroudConfigured as jest.Mock).mockReturnValueOnce(true);
  const response = await request(makeApp()).post(`/api/whistleblower/admin/reports/${TID}/reanalyze`).set('x-internal-secret', SECRET);
  expect(response.status).toBe(503);
  expect(response.body.error).toBe('narrative_unavailable');
  expect(verifyReport).not.toHaveBeenCalled();
  expect(mockPatch).not.toHaveBeenCalled();
});


describe('admin report search', () => {
  const path = '/api/whistleblower/admin/reports/search';
  it('requires internal authentication and validates credentials', async () => {
    expect((await request(makeApp()).post(path).send({ query: 'ai-safety' })).status).toBe(401);
    for (const query of ['', { $ne: null }, 'VRC-short', 'a'.repeat(129)]) {
      expect((await request(makeApp()).post(path).set('x-internal-secret', SECRET).send({ query })).status).toBe(400);
    }
  });
  it('returns only dashboard fields, never the reporter access record', async () => {
    const { reportPersistenceService } = await import('../../../src/services/reportPersistence');
    (reportPersistenceService.searchAdmin as jest.Mock).mockResolvedValueOnce([{
      trackingId: TID, status: 'pending', createdAt: new Date(), updatedAt: new Date(),
      reporterAccess: { hash: 'private-hash', encryptedCode: 'private-code' },
    }]);
    const r = await request(makeApp()).post(path).set('x-internal-secret', SECRET).send({ query: `VRC-${'A'.repeat(64)}` });
    expect(r.status).toBe(200); expect(r.body.data.reports[0].reportId).toBe(TID);
    expect(JSON.stringify(r.body)).not.toMatch(/private-hash|private-code|reporterAccess/);
  });
});

it('limits search output and signals more results without exposing an extra report', async () => {
  const { reportPersistenceService } = await import('../../../src/services/reportPersistence');
  (reportPersistenceService.searchAdmin as jest.Mock).mockResolvedValueOnce(Array.from({ length: 101 }, () => ({
    trackingId: TID, status: 'pending', createdAt: new Date(), updatedAt: new Date(),
  })));
  const r = await request(makeApp()).post('/api/whistleblower/admin/reports/search').set('x-internal-secret', SECRET).send({ query: 'other' });
  expect(r.status).toBe(200); expect(r.body.data.reports).toHaveLength(100); expect(r.body.data.hasMore).toBe(true);
});
it('returns a retryable error rather than no matches when search storage fails', async () => {
  const { reportPersistenceService } = await import('../../../src/services/reportPersistence');
  (reportPersistenceService.searchAdmin as jest.Mock).mockRejectedValueOnce(new Error('private database failure'));
  const r = await request(makeApp()).post('/api/whistleblower/admin/reports/search').set('x-internal-secret', SECRET).send({ query: 'other' });
  expect(r.status).toBe(503); expect(JSON.stringify(r.body)).not.toContain('private database failure');
});


describe('internal report notes endpoints', () => {
  const notesUrl = `/api/whistleblower/admin/reports/${TID}/notes`;
  beforeEach(() => { mockAddNote.mockReset(); mockListNotes.mockReset(); });
  it('requires the internal secret for reads and writes', async () => {
    expect((await request(makeApp()).get(notesUrl)).status).toBe(401);
    expect((await request(makeApp()).post(notesUrl).send({ text: 'note', authorId: 'admin' })).status).toBe(401);
    expect(mockAddNote).not.toHaveBeenCalled();
    expect(mockListNotes).not.toHaveBeenCalled();
  });
  it.each(['', '   ', 'x'.repeat(5001), 123])('rejects invalid text', async text => {
    expect((await request(makeApp()).post(notesUrl).set('x-internal-secret', SECRET).send({ text, authorId: 'admin' })).status).toBe(400);
    expect(mockAddNote).not.toHaveBeenCalled();
  });
  it('persists a trimmed note and returns the stored timestamp', async () => {
    const note = { id: 'note-1', text: 'Review', authorId: 'admin', timestamp: '2026-09-22T10:15:30Z' };
    mockAddNote.mockResolvedValue(note);
    const res = await request(makeApp()).post(notesUrl).set('x-internal-secret', SECRET).send({ text: ' Review ', authorId: 'admin' });
    expect(res.status).toBe(201);
    expect(res.body.note).toEqual(note);
    expect(mockAddNote).toHaveBeenCalledWith(TID, 'Review', 'admin');
  });
  it('returns 404 for a missing report and 500 for a storage failure', async () => {
    mockAddNote.mockResolvedValueOnce(null).mockRejectedValueOnce(new Error('storage unavailable'));
    for (const expected of [404, 500]) {
      expect((await request(makeApp()).post(notesUrl).set('x-internal-secret', SECRET).send({ text: 'Note', authorId: 'admin' })).status).toBe(expected);
    }
  });
});

it('manual reanalysis reports scoring as unavailable when Shroud is not configured', async () => {
  mockGet.mockClear(); mockPatch.mockClear();
  (verifyReport as jest.Mock).mockClear();
  const response = await request(makeApp()).post(`/api/whistleblower/admin/reports/${TID}/reanalyze`).set('x-internal-secret', SECRET);
  expect(response.status).toBe(503);
  expect(response.body.error).toBe('scoring_unavailable');
  expect(verifyReport).not.toHaveBeenCalled();
  expect(mockPatch).not.toHaveBeenCalled();
});
