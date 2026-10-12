/**
 * Unit Tests — Privacy: IP/UA Stripping
 * Proves that IP addresses and User-Agent strings are absent from all
 * user-facing middleware (dataFlowTracking, securityErrorHandler, errorMonitor).
 */

import express from 'express';
import request from 'supertest';
import { trackDataFlow, getDataFlowLogs, clearDataFlowLogs } from '@/middleware/dataFlowTracking';
import { securityErrorHandler } from '@/middleware/security';
import { ErrorMonitor } from '@utils/errorMonitor';

describe('Privacy: IP/UA Stripping', () => {
  afterEach(() => {
    clearDataFlowLogs();
  });

  describe('dataFlowTracking middleware', () => {
    let app: express.Application;

    beforeEach(() => {
      clearDataFlowLogs();
      app = express();
      app.use(trackDataFlow);
      app.get('/api/test', (_req, res) => res.json({ ok: true }));
    });

    it('should not include ip or userAgent in start audit metadata', async () => {
      await request(app)
        .get('/api/test')
        .set('X-Forwarded-For', '1.2.3.4')
        .set('User-Agent', 'SecretAgent/1.0');

      const logs = getDataFlowLogs({ status: 'start' });
      expect(logs.length).toBeGreaterThanOrEqual(1);

      for (const log of logs) {
        expect(log.metadata).not.toHaveProperty('ip');
        expect(log.metadata).not.toHaveProperty('ipAddress');
        expect(log.metadata).not.toHaveProperty('userAgent');
        expect(log.metadata).not.toHaveProperty('user-agent');
        expect(JSON.stringify(log.metadata)).not.toContain('1.2.3.4');
        expect(JSON.stringify(log.metadata)).not.toContain('SecretAgent');
      }
    });

    it('should not include ip or userAgent in completion audit metadata', async () => {
      await request(app)
        .get('/api/test')
        .set('X-Forwarded-For', '10.0.0.1')
        .set('User-Agent', 'TestBrowser/2.0');

      const logs = getDataFlowLogs({ status: 'success' });
      expect(logs.length).toBeGreaterThanOrEqual(1);

      for (const log of logs) {
        expect(log.metadata).not.toHaveProperty('ip');
        expect(log.metadata).not.toHaveProperty('ipAddress');
        expect(log.metadata).not.toHaveProperty('userAgent');
        expect(JSON.stringify(log.metadata)).not.toContain('10.0.0.1');
        expect(JSON.stringify(log.metadata)).not.toContain('TestBrowser');
      }
    });

    it('should populate flowId, endpoint, method, dataType, destination', async () => {
      await request(app).get('/api/test');

      const logs = getDataFlowLogs();
      expect(logs.length).toBeGreaterThanOrEqual(1);
      expect(logs[0].flowId).toBeDefined();
      expect(logs[0].endpoint).toBe('/api/test');
      expect(logs[0].method).toBe('GET');
      expect(logs[0].dataType).toBe('system');
      expect(logs[0].destination).toBe('mongodb');
    });

    it('should determine dataType correctly for vault paths', async () => {
      app.get('/api/vault/123', (_req, res) => res.json({ ok: true }));
      await request(app).get('/api/vault/123');

      const logs = getDataFlowLogs({ status: 'start' });
      const vaultLog = logs.find(l => l.endpoint === '/api/vault/123');
      expect(vaultLog?.dataType).toBe('vault');
    });

    it('should determine destination correctly for upload paths', async () => {
      app.post('/api/upload', (_req, res) => res.json({ ok: true }));
      await request(app).post('/api/upload');

      const logs = getDataFlowLogs({ status: 'start' });
      const uploadLog = logs.find(l => l.endpoint === '/api/upload');
      expect(uploadLog?.destination).toBe('ipfs');
    });

    it('does not record a client-supplied x-user-id header as identity (#1113)', async () => {
      app.post('/api/user-test', (_req, res) => res.status(401).json({ ok: false }));

      await request(app).post('/api/user-test').set('x-user-id', 'forged-admin');

      const logs = getDataFlowLogs();
      expect(logs.map(l => l.status).sort()).toEqual(['error', 'start']);
      for (const log of logs) expect(log).not.toHaveProperty('userId');
      expect(JSON.stringify(logs)).not.toContain('forged-admin');
    });

    it('does not take identity from route params either', async () => {
      app.get('/api/users/:userId', (_req, res) => res.json({ ok: true }));

      await request(app).get('/api/users/param-user');

      for (const log of getDataFlowLogs()) expect(log).not.toHaveProperty('userId');
    });

    it('bounds retained string fields regardless of request size', async () => {
      // Short segments stay clear of the identifier redaction in telemetryPath;
      // path plus header stay under Node's 16 KB header ceiling.
      const longPath = `/api/${'x/'.repeat(2000)}end`;
      app.use((_req, res) => res.json({ ok: true }));

      await request(app).get(longPath).set('x-user-id', 'u'.repeat(10000)).expect(200);

      const logs = getDataFlowLogs();
      expect(logs).toHaveLength(2);
      for (const log of logs) {
        expect(log.endpoint.length).toBeLessThanOrEqual(200);
        expect(log.method.length).toBeLessThanOrEqual(16);
        expect(JSON.stringify(log).length).toBeLessThan(1000);
      }
    });
  });

  describe('securityErrorHandler', () => {
    let app: express.Application;

    beforeEach(() => {
      app = express();
      app.use((req: any, _res, next) => {
        req.requestId = 'req-123';
        next();
      });
      app.get('/api/error', () => {
        throw new Error('Something broke');
      });
      app.use(securityErrorHandler);
    });

    it('should log only requestId/method/path/error — no ip or userAgent', async () => {
      const consoleSpy = jest.spyOn(console, 'error');

      await request(app)
        .get('/api/error')
        .set('X-Forwarded-For', '192.168.1.1')
        .set('User-Agent', 'PrivacyTestAgent/1.0');

      const securityCalls = consoleSpy.mock.calls.filter(
        (args) => typeof args[0] === 'string' && args[0].includes('[SECURITY ERROR]'),
      );
      expect(securityCalls.length).toBeGreaterThanOrEqual(1);

      const loggedData = securityCalls[0][1];
      expect(loggedData).toHaveProperty('requestId');
      expect(loggedData).toHaveProperty('method');
      expect(loggedData).toHaveProperty('path');
      expect(loggedData).toHaveProperty('error');
      expect(loggedData).not.toHaveProperty('ip');
      expect(loggedData).not.toHaveProperty('ipAddress');
      expect(loggedData).not.toHaveProperty('userAgent');
      expect(JSON.stringify(loggedData)).not.toContain('192.168.1.1');
      expect(JSON.stringify(loggedData)).not.toContain('PrivacyTestAgent');

      consoleSpy.mockRestore();
    });

    it('should not include IP in error response body (production)', async () => {
      const prevEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const prodApp = express();
      prodApp.get('/api/error', () => {
        throw new Error('Prod error');
      });
      prodApp.use(securityErrorHandler);

      const response = await request(prodApp)
        .get('/api/error')
        .set('X-Forwarded-For', '172.16.0.1');

      expect(response.status).toBe(500);
      const body = JSON.stringify(response.body);
      expect(body).not.toContain('172.16.0.1');
      expect(response.body).not.toHaveProperty('ip');
      expect(response.body).not.toHaveProperty('userAgent');
      expect(response.body.error).toBe('Internal server error');

      process.env.NODE_ENV = prevEnv;
    });
  });

  describe('ErrorMonitor.middleware()', () => {
    it('retains only a fixed legacy error and route family without request metadata', () => {
      const monitor = new ErrorMonitor();
      // Prevent infinite recursion: triggerAlert → logError → triggerAlert
      jest.spyOn(monitor as any, 'checkAlertConditions').mockImplementation(() => {});
      const logSpy = jest.spyOn(monitor, 'logError');
      const mw = monitor.middleware();

      const mockReq: any = {
        userId: 'tg-12345',
        method: 'POST',
        originalUrl: '/api/whistleblower/submit',
        requestId: 'req-abc',
        ip: '10.10.10.10',
        headers: { 'user-agent': 'ShouldNotAppear/1.0' },
      };
      const mockRes: any = {};
      const mockNext = jest.fn();

      mw(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalled();

      // Now call the attached logError
      mockReq.logError('Test error', 'error', { extra: 'data' });

      expect(logSpy).toHaveBeenCalledTimes(1);
      expect(logSpy).toHaveBeenCalledWith('Private request failed', 'error', {
        endpoint: 'POST /whistleblower/[redacted]'
      });
      expect(JSON.stringify(monitor.getStats())).not.toMatch(
        /tg-12345|req-abc|10\.10\.10\.10|ShouldNotAppear|Test error|extra|data/
      );

      logSpy.mockRestore();
    });

    it('should include extra context passed by the caller', () => {
      const monitor = new ErrorMonitor();
      jest.spyOn(monitor as any, 'checkAlertConditions').mockImplementation(() => {});
      const logSpy = jest.spyOn(monitor, 'logError');
      const mw = monitor.middleware();

      const mockReq: any = {
        method: 'GET',
        originalUrl: '/api/test',
      };
      const mockRes: any = {};
      const mockNext = jest.fn();

      mw(mockReq, mockRes, mockNext);
      mockReq.logError('Err', 'warning', { customField: 42 });

      const context = logSpy.mock.calls[0][2];
      expect(context).toHaveProperty('customField', 42);

      logSpy.mockRestore();
    });
  });
});
