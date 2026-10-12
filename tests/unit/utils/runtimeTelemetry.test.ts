import express from 'express';
import request from 'supertest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { clientTelemetry, parseClientTelemetry, operationName, parseClientMetric, runtimeTelemetry } from '../../../src/utils/runtimeTelemetry';
import { createRateLimiter, rateLimiters } from '../../../src/middleware/security';

describe('runtime telemetry privacy and coverage', () => {
  test('accepts only bounded metrics and drops all untrusted fields', () => {
    expect(parseClientMetric({ kind: 'exception', page: '/report', value: 1, message: 'secret', url: '?token=secret' }))
      .toEqual({ source: 'browser', operation: '/report', kind: 'exception', value: 1 });
    for (const value of [-1, Infinity, NaN, 300001, '1']) {
      expect(parseClientMetric({ kind: 'page_load', page: '/', value })).toBeNull();
    }
    expect(parseClientMetric({ kind: 'secret', page: '/', value: 1 })).toBeNull();
    expect(parseClientMetric({ kind: 'exception', page: '/status/private-id', value: 1 })).toBeNull();
  });
  test('unmatched operations never reflect a supplied path', () => {
    expect(operationName('/api/whistleblower/private-id?token=secret')).toBe('whistleblower:unmatched');
  });
  test('records route pattern, response failure and duration without identifiers', async () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const app = express();
      app.use(runtimeTelemetry);
      const router = express.Router();
      router.get('/evidence/:id', (_req, res) => res.status(503).end());
      app.use('/api/vault', router);
      await request(app).get('/api/vault/evidence/private-id?token=secret').set('Authorization', 'secret');
      const output = log.mock.calls.map(call => call[0]).find(line => String(line).includes('veraTelemetry'));
      const metric = JSON.parse(output);
      expect(metric).toMatchObject({ source: 'backend', operation: 'vault:/evidence/:id', statusClass: 5 });
      expect(metric.durationMs).toBeGreaterThanOrEqual(0);
      expect(output).not.toMatch(/private-id|secret|token/);
    } finally { log.mockRestore(); }
  });
  test('malformed or oversized bodies cannot reach global error logging', async () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    const globalError = jest.fn((_error, _req, res, _next) => res.status(500).end());
    try {
      const app = express();
      app.post('/api/monitoring/client', parseClientTelemetry, clientTelemetry);
      app.use(globalError);
      const malformed = await request(app).post('/api/monitoring/client').set('Content-Type', 'application/json')
        .send('{"narrative":"PRIVATE_REPORT_CONTENT"');
      expect(malformed.status).toBe(400);
      expect(malformed.body).toEqual({ error: 'Invalid metric payload' });
      const oversized = await request(app).post('/api/monitoring/client').send({ narrative: 'PRIVATE_REPORT_CONTENT'.repeat(100) });
      expect(oversized.status).toBe(413);
      expect(oversized.body).toEqual({ error: 'Invalid metric payload' });
      expect(globalError).not.toHaveBeenCalled();
      expect(log).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
  test('client endpoint validates before logging and returns no stored identifiers', async () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const app = express();
      app.post('/api/monitoring/client', parseClientTelemetry, clientTelemetry);
      await request(app).post('/api/monitoring/client').send({ kind: 'exception', page: '/report', value: 1, narrative: 'private' }).expect(204);
      expect(log.mock.calls).toHaveLength(1);
      expect(log.mock.calls[0][0]).not.toContain('private');
      await request(app).post('/api/monitoring/client').send({ kind: 'arbitrary' }).expect(400);
      expect(log.mock.calls).toHaveLength(1);
    } finally { log.mockRestore(); }
  });
  test('does not emit per-request timing events for reporter operations', async () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const app = express();
      app.use(runtimeTelemetry);
      app.get('/api/whistleblower/status/:id', (_req, res) => res.status(404).end());
      await request(app).get('/api/whistleblower/status/private-token').expect(404);
      expect(log).not.toHaveBeenCalled();
    } finally { log.mockRestore(); }
  });
  test('API registers the public collector behind the dedicated clientTelemetry limiter', () => {
    expect(typeof rateLimiters.clientTelemetry).toBe('function');
    expect(rateLimiters.clientTelemetry).not.toBe(rateLimiters.monitoring);
    const source = readFileSync(join(__dirname, '../../../src/api/server.ts'), 'utf8');
    expect(source).toMatch(/app\.post\('\/api\/monitoring\/client',\s*rateLimiters\.clientTelemetry,/);
  });
  test('client telemetry rate limit rejects a single source above 20 requests per minute', async () => {
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const app = express();
      // Fresh limiter matching production max so this test does not share quota state.
      app.post('/api/monitoring/client', createRateLimiter(60 * 1000, 20, 'Too many telemetry requests'), parseClientTelemetry, clientTelemetry);
      const payload = { kind: 'exception', page: '/', value: 1 };
      for (let i = 0; i < 20; i++) {
        await request(app).post('/api/monitoring/client').send(payload).expect(204);
      }
      const limited = await request(app).post('/api/monitoring/client').send(payload);
      expect(limited.status).toBe(429);
      expect(limited.body.error).toBe('Too many telemetry requests');
    } finally { log.mockRestore(); }
  });

});
