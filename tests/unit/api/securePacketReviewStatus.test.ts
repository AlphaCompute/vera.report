import express from 'express';
import request from 'supertest';
jest.mock('express-rate-limit', () => {
    const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
    return { __esModule: true, ...actual, default: () => (_req: unknown, _res: unknown, next: () => void) => next() };
});
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { sendAlert: jest.fn() } }));
import router from '../../../src/api/dissemination';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { emailNotificationService } from '../../../src/services/emailNotification';

const app = express().use(express.json()).use('/api/dissemination', router);
const secret = 'synthetic-review-status-secret';
const previousSecret = process.env.INTERNAL_API_SECRET;

beforeEach(() => {
  process.env.INTERNAL_API_SECRET = secret;
  jest.spyOn(disseminationService, 'buildView').mockResolvedValue({
    narrativeReadable: true, report: { status: 'pending', consent: { legalReview: true, textVersion: 'v4-legal-review' } },
    view: { narrative: 'Synthetic narrative' },
  } as any);
  jest.spyOn(disseminationPersistence, 'getDisposition').mockResolvedValue(null);
  jest.spyOn(disseminationPersistence, 'issueRecipientGrant').mockResolvedValue(undefined as never);
  jest.spyOn(disseminationPersistence, 'appendAudit').mockResolvedValue(undefined as never);
  jest.mocked(emailNotificationService.sendAlert).mockClear();
});
afterEach(() => jest.restoreAllMocks());
afterAll(() => {
  if (previousSecret === undefined) delete process.env.INTERNAL_API_SECRET;
  else process.env.INTERNAL_API_SECRET = previousSecret;
});

it.each(['generate', 'email'])('returns 409 and does not issue or send an unreviewed %s packet', async action => {
  const response = await request(app)
    .post(`/api/dissemination/VRA-0000000000000001/secure-packet-${action}`)
    .set('x-internal-secret', secret)
    .send({ actor: 'synthetic-admin', recipientEmail: 'qa@example.invalid' });
  expect(response.status).toBe(409);
  expect(response.body).toEqual({ success: false, error: 'narrative_review_required' });
  expect(disseminationPersistence.issueRecipientGrant).not.toHaveBeenCalled();
  expect(disseminationPersistence.appendAudit).not.toHaveBeenCalled();
  expect(emailNotificationService.sendAlert).not.toHaveBeenCalled();
});
