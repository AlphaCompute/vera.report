/**
 * Legacy whistleblower/admin routes refuse confidential-format identifiers
 * before any lookup, decrypt or log: a device-held VERA-OWNER-1 recovery code or
 * a 64-hex confidential case ID never reaches the legacy report store, and the
 * confidential store is never loaded by the legacy router.
 */
import express from 'express';
import request from 'supertest';

const SECRET = 'synthetic-confidential-isolation-secret';
process.env.INTERNAL_API_SECRET = SECRET;

const mockConfidentialStoreLoaded = jest.fn();
jest.mock('../../../src/services/confidentialCaseStore', () => {
  mockConfidentialStoreLoaded();
  return { MongoConfidentialCaseStore: { connect: jest.fn(), fromDatabase: jest.fn() } };
});
jest.mock('../../../src/services/evidenceEncryption', () => ({ evidenceEncryptionService: { decryptEvidence: jest.fn(), encryptEvidence: jest.fn() } }));
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: { upload: jest.fn(), readCiphertext: jest.fn() } }));
jest.mock('../../../src/services/veniceAI', () => ({ veniceAIService: { isConfigured: jest.fn(() => false) } }));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
jest.mock('../../../src/services/shroudClient', () => ({ shroudChat: jest.fn(), isShroudConfigured: jest.fn(() => false) }));
jest.mock('../../../src/services/metadataExtractor', () => ({ metadataExtractorService: { extract: jest.fn() } }));
jest.mock('../../../src/services/reportNarrative', () => ({ decryptReportNarrative: jest.fn(), encryptReportNarrative: jest.fn() }));
jest.mock('../../../src/services/rewardContact', () => ({ decryptRewardContact: jest.fn(), encryptRewardContact: jest.fn() }));

const mockStore: Record<string, jest.Mock> = {};
jest.mock('../../../src/services/reportPersistence', () => ({
  reportPersistenceService: new Proxy({}, { get: (_target, name: string) => (mockStore[name] ??= jest.fn(async () => null)) }),
}));
jest.mock('../../../src/services/dissemination/disseminationService', () => ({ disseminationService: { status: jest.fn(async () => []) } }));
jest.mock('../../../src/services/dissemination/relayService', () => ({ relayService: { getThread: jest.fn(async () => []), postFromReporter: jest.fn() } }));

import whistleblowerRouter from '../../../src/api/whistleblower';
import { isConfidentialCaseId, isConfidentialIdentifier, isConfidentialOwnerCode } from '../../../src/utils/confidentialIdentifiers';

const CASE_ID = 'ab'.repeat(32);
const SECRET_PART = 'Q0FTRS1TRUNSRVQtVEhBVC1NVVNULU5FVkVSLUxFQVZF';
const OWNER_CODE = `VERA-OWNER-1.${CASE_ID}.${'cd'.repeat(20)}.${SECRET_PART}`;
// Current short format: the bare secret in 14 groups of 4 (synthetic; the server never sees a real one).
const SHORT_CODE = '7K3M-9QXA-R2D8-WV4N-J6TC-P1HZ-5GBE-0SKY-M8FQ-3XAW-T7VN-2CJD-H9RB-4PZE';
const SHORT_SECRET = SHORT_CODE.replace(/-/g, '');

const app = express();
app.use(express.json());
app.use('/api/whistleblower', whistleblowerRouter);

let logs: jest.SpyInstance[] = [];
beforeEach(() => {
  for (const mock of Object.values(mockStore)) mock.mockClear();
  logs = (['log', 'info', 'warn', 'error', 'debug'] as const).map(level => jest.spyOn(console, level).mockImplementation(() => undefined));
});
afterEach(() => {
  // Never logged, in any form.
  const output = JSON.stringify(logs.flatMap(spy => spy.mock.calls));
  expect(output).not.toContain(SECRET_PART);
  for (const group of SHORT_CODE.split('-')) expect(output).not.toContain(group);
  expect(output).not.toContain(CASE_ID);
  for (const spy of logs) spy.mockRestore();
  // Nothing in the legacy report store was consulted.
  for (const [name, mock] of Object.entries(mockStore)) expect({ name, calls: mock.mock.calls.length }).toEqual({ name, calls: 0 });
  expect(mockConfidentialStoreLoaded).not.toHaveBeenCalled();
});

test('identifier classification', () => {
  expect(isConfidentialOwnerCode(OWNER_CODE)).toBe(true);
  expect(isConfidentialOwnerCode(` ${OWNER_CODE.toLowerCase()}`)).toBe(true);
  expect(isConfidentialCaseId(CASE_ID)).toBe(true);
  // Short codes are recognised by shape in any typed form, including mistyped ones.
  for (const typed of [SHORT_CODE, SHORT_CODE.toLowerCase(), SHORT_SECRET, SHORT_CODE.replace(/-/g, ' '),
    SHORT_CODE.slice(0, -5), `${SHORT_CODE}-ABCD`, 'A'.repeat(55) + 'U', 'A'.repeat(56), Array(14).fill('AAAA').join('·')]) {
    expect(isConfidentialOwnerCode(typed)).toBe(true);
  }
  for (const legacy of ['VRA-0123456789ABCDEF', `VRC-${'A'.repeat(64)}`, `VRC-${'0'.repeat(63)}`, 'fraud', undefined, 42,
    'short 1234']) {
    expect(isConfidentialIdentifier(legacy)).toBe(false);
  }
});

describe('reporter status lookup', () => {
  it.each([
    ['owner code in the path', `/api/whistleblower/status/${encodeURIComponent(OWNER_CODE)}`, {}],
    ['owner code in the credential header', '/api/whistleblower/status/lookup', { 'X-Reporter-Credential': OWNER_CODE }],
    ['short code in the path', `/api/whistleblower/status/${encodeURIComponent(SHORT_CODE)}`, {}],
    ['short code in the credential header', '/api/whistleblower/status/lookup', { 'X-Reporter-Credential': SHORT_CODE }],
    ['ungrouped short code in the credential header', '/api/whistleblower/status/lookup', { 'X-Reporter-Credential': SHORT_SECRET }],
    ['digit-free recovery shape', '/api/whistleblower/status/lookup', { 'X-Reporter-Credential': 'A'.repeat(56) }],
    ['letter-only code in the credential header', '/api/whistleblower/status/lookup', { 'X-Reporter-Credential': 'Z'.repeat(56) }],
    ['confidential case ID', `/api/whistleblower/status/${CASE_ID}`, {}],
  ])('rejects %s with the generic format error', async (_label, url, headers) => {
    const response = await request(app).get(url).set(headers).expect(400);
    expect(response.body).toEqual({ success: false, error: 'Invalid tracking ID format' });
    expect(JSON.stringify(response.body)).not.toContain(CASE_ID);
    expect(response.headers['cache-control']).toBe('private, no-store');
  });

  it('rejects owner codes on relay replies and access rotation', async () => {
    await request(app).post(`/api/whistleblower/status/${encodeURIComponent(OWNER_CODE)}/relay`).send({ message: 'hi' }).expect(400);
    await request(app).post('/api/whistleblower/status/lookup/relay').set('X-Reporter-Credential', OWNER_CODE).send({ message: 'hi' }).expect(400);
    await request(app).post('/api/whistleblower/status/access/rotate').set('X-Reporter-Credential', OWNER_CODE).expect(400);
  });
});

describe('admin private-read routes cannot be pointed at a confidential case', () => {
  const secret = { 'x-internal-secret': SECRET };
  it.each([
    ['get', `/api/whistleblower/narrative/${CASE_ID}`],
    ['get', `/api/whistleblower/reward-contact/${CASE_ID}`],
    ['get', `/api/whistleblower/evidence/${CASE_ID}/evidence.pdf`],
    ['get', `/api/whistleblower/narrative/${encodeURIComponent(OWNER_CODE)}`],
    ['get', `/api/whistleblower/admin/reports/${CASE_ID}/notes`],
    ['post', `/api/whistleblower/admin/reports/${CASE_ID}/notes`],
    ['patch', `/api/whistleblower/admin/reports/${CASE_ID}/status`],
    ['post', `/api/whistleblower/admin/reports/${CASE_ID}/reanalyze`],
    ['get', `/api/whistleblower/admin/reports?trackingId=${CASE_ID}`],
  ] as const)('%s %s', async (method, url) => {
    const response = await request(app)[method](url).set(secret).send({ text: 'note', authorId: 'a', status: 'reviewing' });
    expect(response.status).toBe(400);
  });

  it('rejects confidential identifiers as admin search terms', async () => {
    for (const query of [OWNER_CODE, CASE_ID, SHORT_CODE]) {
      await request(app).post('/api/whistleblower/admin/reports/search').set(secret).send({ query }).expect(400);
    }
  });
});

test.each(['submit', 'analyze'])('confidential mode refuses plaintext multipart at legacy %s', async endpoint => {
  const previous = process.env.CONFIDENTIAL_CASES_ENABLED;
  process.env.CONFIDENTIAL_CASES_ENABLED = 'true';
  try {
    const response = await request(app).post(`/api/whistleblower/${endpoint}`)
      .field('description', 'PRIVATE-MULTIPART-SENTINEL')
      .attach('files', Buffer.from('PRIVATE-FILE-SENTINEL'), 'private.txt').expect(409);
    expect(response.body.error).toBe('confidential_intake_required');
    expect(JSON.stringify(logs.flatMap(spy => spy.mock.calls))).not.toContain('PRIVATE-');
  } finally {
    if (previous === undefined) delete process.env.CONFIDENTIAL_CASES_ENABLED;
    else process.env.CONFIDENTIAL_CASES_ENABLED = previous;
  }
});

describe('reporter credential rotation', () => {
  it('refuses a legacy VRA- report ID before any lookup', async () => {
    const response = await request(app).post('/api/whistleblower/status/access/rotate')
      .set('X-Reporter-Credential', 'VRA-0123456789ABCDEF').expect(404);
    expect(response.body).toEqual({ success: false, error: 'Report not found' });
    // afterEach asserts the legacy report store was never consulted.
  });
});
