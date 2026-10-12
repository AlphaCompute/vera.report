/**
 * API server after the Midnight integration was removed: it starts with no
 * wallet secrets, mounts no Midnight health or internal relay routes, and its
 * health endpoint carries no Midnight state.
 */
import request from 'supertest';
import type { Express } from 'express';

jest.mock('../../../src/utils/errorMonitor', () => ({
  errorMonitor: { middleware: () => (_req: unknown, _res: unknown, next: () => void) => next(), logError: jest.fn() },
}));
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: jest.fn() }));
jest.mock('../../../src/services/shroudClient', () => ({ shroudChat: jest.fn(), isShroudConfigured: jest.fn(() => false) }));

const WALLET_VARIABLES = ['MIDNIGHT_ENABLED', 'MIDNIGHT_MNEMONIC', 'MIDNIGHT_RELAY_MNEMONIC', 'MIDNIGHT_RELAY_SEED', 'WALLET_SEED', 'WALLET_ENCRYPTION_KEY', 'NULLIFIER_SEED', 'RELAY_ROLE', 'RELAY_WORKER_URL'];
const SECRET = 'synthetic-internal-secret-with-32-characters';
let savedEnv: NodeJS.ProcessEnv;
let server: typeof import('../../../src/api/server');
let app: Express;

beforeAll(() => {
  savedEnv = process.env;
  process.env = { ...savedEnv, API_PORT: '0', INTERNAL_API_SECRET: SECRET };
  for (const name of WALLET_VARIABLES) delete process.env[name];
  // Routes are mounted at import, so load the server under this environment.
  jest.isolateModules(() => { server = require('../../../src/api/server'); });
  app = server.default as unknown as Express;
});
afterAll(async () => {
  await server.stopApiServer();
  process.env = savedEnv;
});

it('starts without any wallet configuration', async () => {
  await expect(server.startApiServer()).resolves.toBeDefined();
});

it('reports health without Midnight state', async () => {
  const health = await request(app).get('/health');
  expect(health.status).toBe(200);
  expect(health.body).toMatchObject({ status: 'healthy' });
  expect(health.body).not.toHaveProperty('midnight');

  const res = await request(app).get('/api/midnight/health');
  expect(res.status).toBe(404);
});

it.each(['/internal/relay/submission-proof', '/internal/relay/audit-proof', '/internal/relay/audit-proof/reconcile'])(
  'mounts no wallet-backed internal route at %s', async path => {
    const res = await request(app).post(path).set('x-internal-secret', SECRET).send({ userId: 'u', evidenceHash: 'e' });
    expect(res.status).toBe(404);
  });

it('mounts no relay checkpoint route', async () => {
  const res = await request(app).get('/internal/relay/checkpoint').set('x-internal-secret', SECRET);
  expect(res.status).toBe(404);
});
