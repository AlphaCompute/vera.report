import express from 'express';
import request from 'supertest';
import { telemetryPath } from '../../../src/utils/requestPrivacy';
import { trackDataFlow, getDataFlowLogs, clearDataFlowLogs } from '../../../src/middleware/dataFlowTracking';
import { ErrorMonitor } from '../../../src/utils/errorMonitor';

it.each([
  '/api/whistleblower/status/VRA-1234567890ABCDEF?contact=source',
  '/api/dissemination/packets/private-token',
  '/api/%77histleblower/evidence/VRA-1234567890ABCDEF/alice.pdf',
  '/status?trackingId=VRA-1234567890ABCDEF',
])('omits private URL identifiers from telemetry: %s', url => {
  expect(telemetryPath(url)).not.toMatch(/VRA-|source|private-token|alice|trackingId/);
});

it('does not retain reporter identity, filename or payload sizes in flow/error monitoring', async () => {
  clearDataFlowLogs();
  const monitor = new ErrorMonitor();
  const log = jest.spyOn(monitor, 'logError').mockReturnValue('event');
  const app = express();
  app.use(monitor.middleware(), trackDataFlow);
  app.get('/api/whistleblower/status/:trackingId', (req, res) => {
    req.logError?.('source@example.com', 'error', { narrative: 'private story' });
    res.json({ success: true });
  });
  await request(app).get('/api/whistleblower/status/VRA-1234567890ABCDEF?email=source@example.com')
    .set('x-user-id', 'source-identity').set('Content-Length', '0');
  const output = JSON.stringify([getDataFlowLogs(), log.mock.calls]);
  expect(output).not.toMatch(/VRA-|source@example|source-identity|private story|dataSize|responseSize/);
  expect(log).toHaveBeenCalledTimes(1);
  expect(log).toHaveBeenCalledWith('Private request failed', 'error', {
    endpoint: 'GET /whistleblower/[redacted]'
  });
  expect(getDataFlowLogs()).toEqual([]);
  log.mockRestore();
  clearDataFlowLogs();
});

it('does not trust an attacker-chosen request identifier on reporter routes', () => {
  const { addRequestId } = require('../../../src/utils/errorResponse');
  const req = { headers: { 'x-request-id': 'source-account-identifier' }, originalUrl: '/api/whistleblower/submit', requestId: '' };
  addRequestId(req, { setHeader: jest.fn() }, jest.fn());
  expect(req.requestId).not.toBe('source-account-identifier');
  expect(req.requestId).toMatch(/^req_/);
});

it('preserves operational flow records for public routes', async () => {
  clearDataFlowLogs();
  const app = express();
  app.use(trackDataFlow);
  app.get('/health', (_req, res) => res.json({ ok: true }));
  await request(app).get('/health');
  expect(getDataFlowLogs().map(row => row.status).sort()).toEqual(['start', 'success']);
  expect(getDataFlowLogs()[0].endpoint).toBe('/health');
  clearDataFlowLogs();
});
