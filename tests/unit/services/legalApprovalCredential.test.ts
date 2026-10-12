import express from 'express';
import request from 'supertest';
import { createConfidentialService } from '../../../src/api/confidentialService';
import { requireHeaderSecret } from '../../../src/middleware/internalSecret';
import { privateRequest } from '../../../src/utils/requestPrivacy';

const id = 'a'.repeat(64), admin = 'frontend-'.repeat(8), worker = 'worker-'.repeat(8);
async function fixture(secret = worker) {
  const env = { CONFIDENTIAL_ADMIN_SECRET: admin, LEGAL_APPROVAL_BACKEND_SECRET: secret };
  const service = createConfidentialService({ env, adminGuard: requireHeaderSecret('CONFIDENTIAL_ADMIN_SECRET', env), onUnavailable: () => {} });
  await service.runtime.settled;
  const applications = { get: jest.fn(async () => ({ id })), list: jest.fn(async () => ({ applications: [], next: null })),
    saveCombinedApproval: jest.fn(async () => true) };
  jest.spyOn(service.runtime, 'get').mockResolvedValue({ store: { applications }, applicationProvisioningEnabled: true } as any);
  const app = express(); service.mount(app);
  return { app, applications, close: () => service.runtime.close() };
}
test('worker and frontend credentials cannot cross API authority boundaries', async () => {
  const f = await fixture();
  try {
    const workerPath = '/api/internal/legal-approval', frontend = '/api/admin/confidential/legal-applications';
    expect(privateRequest(workerPath + '/get')).toBe(true);
    for (const action of ['get', 'decide', 'combined-approval']) {
      await request(f.app).post(workerPath + '/' + action).set('x-internal-secret', admin).send({ id }).expect(401);
      await request(f.app).post(workerPath + '/' + action).set('x-internal-secret', worker).set('x-origin-verify', 'edge').send({ id }).expect(404);
    }
    await request(f.app).post(frontend + '/list').set('x-internal-secret', worker).send({}).expect(401);
    for (const action of ['get', 'combined-approval']) await request(f.app).post(frontend + '/' + action).set('x-internal-secret', admin).send({ id }).expect(404);
    for (const action of ['submit', 'list', 'status']) await request(f.app).post(workerPath + '/' + action).set('x-internal-secret', worker).send({ id }).expect(404);
    expect(f.applications.get).not.toHaveBeenCalled(); expect(f.applications.saveCombinedApproval).not.toHaveBeenCalled();
    await request(f.app).post(workerPath + '/get').set('x-internal-secret', worker).send({ id }).expect(200);
    await request(f.app).post(workerPath + '/combined-approval').set('x-internal-secret', worker).send({ id, digest: id, approval: 'signed' }).expect(200);
    await request(f.app).post(frontend + '/list').set('x-internal-secret', admin).send({}).expect(200);
  } finally { await f.close(); }
});
test.each(['', 'short', admin])('missing, weak or reused worker credentials fail closed (%#)', async secret => {
  const f = await fixture(secret);
  try {
    await request(f.app).post('/api/internal/legal-approval/get').set('x-internal-secret', secret || worker).send({ id }).expect(503);
    expect(f.applications.get).not.toHaveBeenCalled();
  } finally { await f.close(); }
});
