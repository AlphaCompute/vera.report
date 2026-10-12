/**
 * Unit Tests — Express Audit Router (src/api/audit.ts)
 * Tests the Express router that persists audit logs to MongoDB.
 */

jest.mock('@services/adminAuditLog', () => {
  const mockLog = jest.fn().mockResolvedValue(undefined);
  const mockQuery = jest.fn().mockResolvedValue({ entries: [], total: 0 });
  return {
    adminAuditLog: { log: mockLog, query: mockQuery },
    AdminAuditLogService: jest.fn(),
  };
});

jest.mock('@utils/errorMonitor', () => ({
  errorMonitor: { middleware: () => (_req: any, _res: any, next: () => void) => next() },
}));

import express from 'express';
import request from 'supertest';
import auditRouter from '@api/audit';
import { adminAuditLog } from '@services/adminAuditLog';
import { ADMIN_ACTIONS } from '@services/adminAuditActions';

const mockLog = adminAuditLog.log as jest.MockedFunction<typeof adminAuditLog.log>;
const mockQuery = adminAuditLog.query as jest.MockedFunction<typeof adminAuditLog.query>;

const SECRET = 'test-audit-secret';

function createApp(): express.Express {
  const app = express();
  app.use(express.json());
  app.use('/api/admin', auditRouter);
  return app;
}

describe('Express Audit Router', () => {
  let app: express.Express;

  beforeAll(() => {
    process.env.INTERNAL_API_SECRET = SECRET;
  });

  beforeEach(() => {
    app = createApp();
    mockLog.mockReset();
    mockLog.mockResolvedValue(undefined);
    mockQuery.mockReset();
    mockQuery.mockResolvedValue({ entries: [], total: 0 });
  });

  // Regression: the router kept its own hand-written allowlist that had drifted
  // from AdminAction, so user_invited, user_role_changed, user_deleted and
  // role_change_blocked were rejected with 400 and never persisted. The client
  // is fire-and-forget, so nothing surfaced. Assert the whole vocabulary round
  // trips rather than a sample, or the next omission goes unnoticed too.
  it.each(ADMIN_ACTIONS)('persists the %s action', async (action) => {
    const res = await request(app).post('/api/admin/audit-log')
      .set('x-internal-secret', SECRET).send({ action });
    expect(res.status).toBe(200);
    expect(mockLog).toHaveBeenCalledWith(expect.objectContaining({ action }), true);
  });

  it('accepts every user-management action the admin routes emit', () => {
    for (const action of ['user_invited', 'user_role_changed', 'user_deleted', 'role_change_blocked']) {
      expect(ADMIN_ACTIONS).toContain(action);
    }
  });

  it('does not acknowledge a failed durable audit write', async () => {
    mockLog.mockRejectedValueOnce(new Error('durable storage unavailable'));
    const res = await request(app).post('/api/admin/audit-log')
      .set('x-internal-secret', SECRET).send({ action: 'report_status_change' });
    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
    expect(mockLog).toHaveBeenCalledWith(expect.anything(), true);
  });

  describe('Authentication', () => {
    it('should return 401 when x-internal-secret header is missing', async () => {
      const res = await request(app)
        .post('/api/admin/audit-log')
        .send({ action: 'stats_view' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Unauthorized');
    });

    it('should return 401 when x-internal-secret header is wrong', async () => {
      const res = await request(app)
        .post('/api/admin/audit-log')
        .set('x-internal-secret', 'wrong-secret')
        .send({ action: 'stats_view' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Unauthorized');
    });

    it('should allow requests with correct secret', async () => {
      const res = await request(app)
        .post('/api/admin/audit-log')
        .set('x-internal-secret', SECRET)
        .send({
          action: 'stats_view',
          adminUserId: 'user-1',
          adminEmail: 'admin@example.com',
          endpoint: '/test',
          method: 'GET',
          responseStatus: 200,
          details: {},
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('POST /api/admin/audit-log', () => {
    it('should call adminAuditLog.log with the entry', async () => {
      await request(app)
        .post('/api/admin/audit-log')
        .set('x-internal-secret', SECRET)
        .send({
          adminUserId: 'user-1',
          adminEmail: 'admin@example.com',
          action: 'evidence_access',
          endpoint: '/api/evidence/VRA-123/file.pdf',
          method: 'GET',
          responseStatus: 200,
          details: { resourceId: 'VRA-123', filename: 'file.pdf' },
        });

      expect(mockLog).toHaveBeenCalledWith(
        expect.objectContaining({
          adminUserId: 'user-1',
          adminEmail: 'admin@example.com',
          action: 'evidence_access',
          details: expect.objectContaining({ resourceId: 'VRA-123' }),
        }),
        true,
      );
    });

    it('should return 400 for invalid action', async () => {
      const res = await request(app)
        .post('/api/admin/audit-log')
        .set('x-internal-secret', SECRET)
        .send({ action: 'hack_system' });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid action');
    });

    it('should return 400 when action is missing', async () => {
      const res = await request(app)
        .post('/api/admin/audit-log')
        .set('x-internal-secret', SECRET)
        .send({ adminEmail: 'admin@example.com' });

      expect(res.status).toBe(400);
    });
  });

  describe('GET /api/admin/audit-logs', () => {
    it('should return paginated results', async () => {
      mockQuery.mockResolvedValue({
        entries: [{ auditId: 'id-1', action: 'stats_view' }] as any,
        total: 1,
      });

      const res = await request(app)
        .get('/api/admin/audit-logs')
        .set('x-internal-secret', SECRET);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.entries).toHaveLength(1);
      expect(res.body.data.total).toBe(1);
      expect(res.body.data.page).toBe(1);
      expect(res.body.data.limit).toBe(50);
    });

    it('should pass filters to adminAuditLog.query', async () => {
      await request(app)
        .get('/api/admin/audit-logs?action=evidence_access&severity=critical&page=2&limit=10')
        .set('x-internal-secret', SECRET);

      expect(mockQuery).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'evidence_access',
          severity: 'critical',
          page: 2,
          limit: 10,
        }),
        true,
      );
    });

    it('should return 400 for invalid action filter', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs?action=bad_action')
        .set('x-internal-secret', SECRET);

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid action');
    });

    it('should return 400 for invalid severity filter', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs?severity=banana')
        .set('x-internal-secret', SECRET);

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Invalid severity');
    });
  });
});
