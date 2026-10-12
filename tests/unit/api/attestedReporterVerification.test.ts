import express from 'express';
import request from 'supertest';
import http from 'node:http';
import { createAttestedReporterVerificationRouter } from '../../../src/api/attestedReporterVerification';
const code = 'VRC-' + 'A'.repeat(64);
function app(read?: jest.Mock) { const app = express(); app.use(express.json()); app.use('/api/whistleblower', createAttestedReporterVerificationRouter(read ? { read } : undefined)); return app; }
const route = '/api/whistleblower/status/access/verification';
it('default-off route never receives a capability or data call', async () => {
  expect((await request(app()).post(route).set('X-Reporter-Credential', code).send({})).status).toBe(404);
});
it.each([{ body: { code } }, { body: { trackingId: 'VRA-0123456789ABCDEF' } }, { body: [] }, { body: {}, query: '?code=private' }, { body: {}, credential: 'VRA-0123456789ABCDEF' }])('rejects request-selected identifiers or extra payloads', async input => {
  const read = jest.fn(); const response = await request(app(read)).post(route + (input.query || '')).set('X-Reporter-Credential', input.credential || code).send(input.body);
  expect(response.status).toBe(400); expect(read).not.toHaveBeenCalled();
});
it('returns the projected value with no-store and generic errors', async () => {
  const read = jest.fn().mockResolvedValueOnce({ credibilityScore: 80, category: 'fraud' }).mockRejectedValueOnce(new Error('provider-secret'));
  const server = app(read);
  const result = await request(server).post(route).set('X-Reporter-Credential', code).send({});
  expect(result.body).toEqual({ success: true, verification: { credibilityScore: 80, category: 'fraud' } }); expect(result.headers['cache-control']).toBe('no-store');
  const failed = await request(server).post(route).set('X-Reporter-Credential', code).send({});
  expect(failed.status).toBe(503); expect(JSON.stringify(failed.body)).not.toContain('provider-secret');
});
it('rate limits the endpoint before starting additional readers', async () => {
  const read = jest.fn().mockResolvedValue(null); const server = app(read);
  for (let i = 0; i < 10; i++) expect((await request(server).post(route).set('X-Reporter-Credential', code).send({})).status).toBe(404);
  expect((await request(server).post(route).set('X-Reporter-Credential', code).send({})).status).toBe(429); expect(read).toHaveBeenCalledTimes(10);
});
it('aborts the reader when the HTTP peer disconnects', async () => {
  let started!: () => void; const began = new Promise<void>(resolve => { started = resolve; }); let aborted!: () => void; const done = new Promise<void>(resolve => { aborted = resolve; });
  const read = jest.fn((_code, signal: AbortSignal) => new Promise((_resolve, reject) => { signal.addEventListener('abort', () => { aborted(); reject(new Error('closed')); }); started(); }));
  const server = app(read).listen(0, '127.0.0.1'); await new Promise<void>(resolve => server.once('listening', resolve));
  try { const req = http.request({ host: '127.0.0.1', port: (server.address() as import('node:net').AddressInfo).port, path: route, method: 'POST', headers: { 'X-Reporter-Credential': code } }); req.on('error', () => {}); req.end(); await began; req.destroy(); await done; }
  finally { await new Promise<void>(resolve => server.close(() => resolve())); }
});
