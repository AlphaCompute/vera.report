import request from 'supertest';
// Heavy service deps mocked so the server module loads without real network.
jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: { middleware: () => (_req: any, _res: any, next: () => void) => next() },
}));
jest.mock('../../../src/services/reportScoring', () => ({
  verifyReport: jest.fn(),
}));
jest.mock('../../../src/services/shroudClient', () => ({
  shroudChat: jest.fn(),
  isShroudConfigured: jest.fn(() => false),
}));

import app from '../../../src/api/server';

describe('server identity headers', () => {
  it.each([
    { method: 'get' as const, path: '/health', status: 200 },
    { method: 'post' as const, path: '/api/monitoring/client', status: 400 },
    { method: 'get' as const, path: '/api/balance', status: 404 },
    { method: 'get' as const, path: '/missing-security-test-route', status: 404 },
  ])('omits X-Powered-By on $method $path', async ({ method, path, status }) => {
    const response = await request(app)[method](path);
    expect(response.status).toBe(status);
    expect(response.headers['x-powered-by']).toBeUndefined();
  });
});


it.each([
  ['post', '/api/connect'], ['get', '/api/balance'], ['get', '/api/messages'],
  ['post', '/api/send'], ['get', '/api/message/old'],
  ['post', '/api/inheritance/vault/create'], ['get', '/api/inheritance/user/vaults'],
] as const)('retired %s %s is unavailable', async (method, path) => {
  const response = await request(app)[method](path);
  expect(response.status).toBe(404);
  expect(response.headers['x-content-type-options']).toBe('nosniff');
});
it.each(['/api/analytics/global', '/api/analytics/activity'])('retires %s', async path => {
  expect((await request(app).get(path)).status).toBe(404);
});

it.each([
  ['get', '/api/midnight/health'], ['post', '/internal/relay/submission-proof'],
  ['post', '/internal/relay/audit-proof'], ['post', '/internal/relay/audit-proof/reconcile'],
] as const)('retired Midnight route %s %s is unavailable', async (method, path) => {
  expect((await request(app)[method](path)).status).toBe(404);
});
