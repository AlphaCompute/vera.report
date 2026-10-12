import express from 'express';
import request from 'supertest';
jest.mock('express-rate-limit', () => {
    const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
    return { __esModule: true, ...actual, default: () => (_req: unknown, _res: unknown, next: () => void) => next() };
});
import router from '../../../src/api/dissemination';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { reportPersistenceService } from '../../../src/services/reportPersistence';

const app = express().use('/api/dissemination', router);
const trackingId = 'VRA-0000000000000001';
const secret = 'synthetic-sharing-status-secret';
const previousSecret = process.env.INTERNAL_API_SECRET;
const consent = { agency: true, psst: { granted: false }, press: false, capturedAt: new Date('2026-09-18T12:00:00Z'), textVersion: 'v3-legal-review-default' };

beforeEach(() => {
  process.env.INTERNAL_API_SECRET = secret;
  jest.spyOn(disseminationService, 'status').mockResolvedValue([]);
  jest.spyOn(disseminationService, 'plan');
  jest.spyOn(disseminationService, 'approve');
  jest.spyOn(disseminationPersistence, 'getDisposition').mockResolvedValue(null);
  jest.spyOn(disseminationPersistence, 'getAuditForReport').mockResolvedValue([]);
  jest.spyOn(reportPersistenceService, 'get').mockResolvedValue({ trackingId, consent, encryptedDescription: 'private-synthetic-data' } as any);
});
afterEach(() => jest.restoreAllMocks());
afterAll(() => {
  if (previousSecret === undefined) delete process.env.INTERNAL_API_SECRET;
  else process.env.INTERNAL_API_SECRET = previousSecret;
});

it('loads current consent before any channel is approved, without generating a routing plan', async () => {
  const response = await request(app).get(`/api/dissemination/${trackingId}/status`).set('x-internal-secret', secret);
  expect(response.status).toBe(200);
  // Legacy v3 `agency: true` is reported as legal review only, never agency dispatch (#926).
  expect(response.body).toEqual({ success: true, channels: [], disposition: null, audit: [],
    consent: { ...consent, agency: false, legalReview: true, capturedAt: consent.capturedAt.toISOString() } });
  expect(JSON.stringify(response.body)).not.toContain('private-synthetic-data');
  expect(disseminationService.plan).not.toHaveBeenCalled();
  expect(disseminationService.approve).not.toHaveBeenCalled();
});

it('does not substitute an old approval snapshot for current revoked consent', async () => {
  jest.mocked(reportPersistenceService.get).mockResolvedValue({ trackingId, consent: { ...consent, agency: false } } as any);
  jest.mocked(disseminationPersistence.getDisposition).mockResolvedValue({ consentSnapshot: consent } as any);
  const response = await request(app).get(`/api/dissemination/${trackingId}/status`).set('x-internal-secret', secret);
  expect(response.status).toBe(200);
  expect(response.body.consent.legalReview).toBe(false);
  expect(response.body.disposition.consentSnapshot.agency).toBe(true);
});

it.each([null, { trackingId }])('keeps missing report consent unknown (%j)', async report => {
  jest.mocked(reportPersistenceService.get).mockResolvedValue(report as any);
  const response = await request(app).get(`/api/dissemination/${trackingId}/status`).set('x-internal-secret', secret);
  expect(response.status).toBe(200);
  expect(response.body.consent).toBeNull();
});

it('denies unauthenticated status reads before loading report data', async () => {
  const response = await request(app).get(`/api/dissemination/${trackingId}/status`);
  expect(response.status).toBe(401);
  expect(reportPersistenceService.get).not.toHaveBeenCalled();
});
