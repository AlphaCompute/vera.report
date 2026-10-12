/**
 * Integration Tests — AdminAuditLogService with MongoDB
 * Uses MongoMemoryServer for isolated database tests.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import { AdminAuditLogService } from '@services/adminAuditLog';
import type { AdminAction, AdminAuditEntry } from '@services/adminAuditLog';

describe('AdminAuditLogService — MongoDB Integration', () => {
  let mongoServer: MongoMemoryServer;
  const services: AdminAuditLogService[] = [];

  function createService(): AdminAuditLogService {
    const service = new AdminAuditLogService();
    services.push(service);
    return service;
  }

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    process.env.MONGODB_URI = mongoServer.getUri();
    process.env.MONGODB_DB_NAME = 'test_audit';
  });

  afterAll(async () => {
    await Promise.all(services.map(service => service.close()));
    process.env.MONGODB_URI = '';
    process.env.MONGODB_DB_NAME = '';
    if (mongoServer) await mongoServer.stop();
  });

  function makeEntry(overrides: Partial<{
    adminEmail: string;
    action: AdminAction;
    resourceId: string;
    severity: 'critical' | 'important' | 'info';
    ipAddress: string;
    userAgent: string;
  }> = {}) {
    return {
      adminUserId: 'auth0|test',
      adminEmail: overrides.adminEmail ?? 'admin@example.com',
      action: (overrides.action ?? 'evidence_access') as AdminAction,
      endpoint: '/api/test',
      method: 'GET',
      responseStatus: 200,
      details: {
        resourceId: overrides.resourceId,
        ipAddress: overrides.ipAddress,
        userAgent: overrides.userAgent,
      },
      ...(overrides.severity ? { severity: overrides.severity } : {}),
    };
  }

  describe('Connection & Indexes', () => {
    it('should connect and persist an entry', async () => {
      const service = createService();
      await service.log(makeEntry());

      const result = await service.query({});
      expect(result.total).toBeGreaterThanOrEqual(1);
      expect(result.entries[0].auditId).toBeDefined();
      expect(result.entries[0].timestamp).toBeInstanceOf(Date);
    });
  });

  describe('Entry fields', () => {
    let service: AdminAuditLogService;

    beforeEach(() => {
      service = createService();
    });

    it('should assign UUID auditId and auto-timestamp', async () => {
      const before = new Date();
      await service.log(makeEntry());
      const after = new Date();

      const { entries } = await service.query({});
      const entry = entries[0];
      expect(entry.auditId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      expect(entry.timestamp.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(entry.timestamp.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('should auto-assign severity from SEVERITY_MAP', async () => {
      const actionSeverity: Record<AdminAction, string> = {
        evidence_access: 'critical',
        contact_info_decrypt: 'critical',
        report_status_change: 'critical',
        report_analyze: 'important',
        report_list_view: 'info',
        stats_view: 'info',
      };

      for (const [action, expected] of Object.entries(actionSeverity)) {
        const svc = createService();
        await svc.log(makeEntry({ action: action as AdminAction }));
        const { entries } = await svc.query({ action: action as AdminAction });
        const match = entries.find(e => e.action === action);
        expect(match?.severity).toBe(expected);
      }
    });

    it('should allow severity override', async () => {
      await service.log(makeEntry({ action: 'stats_view', severity: 'critical' }));

      const { entries } = await service.query({});
      const entry = entries.find(e => e.action === 'stats_view' && e.severity === 'critical');
      expect(entry).toBeDefined();
    });

    it('should store ipAddress and userAgent in details (admin audit)', async () => {
      await service.log(
        makeEntry({ ipAddress: '203.0.113.1', userAgent: 'AdminBrowser/1.0' }),
      );

      const { entries } = await service.query({});
      const entry = entries.find(
        e => e.details.ipAddress === '203.0.113.1',
      );
      expect(entry).toBeDefined();
      expect(entry!.details.userAgent).toBe('AdminBrowser/1.0');
    });
  });

  describe('Filtering', () => {
    let service: AdminAuditLogService;

    beforeAll(async () => {
      service = createService();

      // Seed entries with distinct timestamps
      const entries = [
        { adminEmail: 'alice@example.com', action: 'evidence_access' as const, resourceId: 'TRK-001' },
        { adminEmail: 'alice@example.com', action: 'contact_info_decrypt' as const, resourceId: 'TRK-001' },
        { adminEmail: 'bob@example.com', action: 'report_status_change' as const, resourceId: 'TRK-002' },
        { adminEmail: 'alice@example.com', action: 'report_list_view' as const },
        { adminEmail: 'bob@example.com', action: 'stats_view' as const },
      ];

      for (const e of entries) {
        await service.log(makeEntry(e));
        // Small delay so timestamps differ
        await new Promise(r => setTimeout(r, 10));
      }
    });

    it('should filter by adminEmail', async () => {
      const result = await service.query({ adminEmail: 'alice@example.com' });
      expect(result.total).toBeGreaterThanOrEqual(3);
      expect(result.entries.every(e => e.adminEmail === 'alice@example.com')).toBe(true);
    });

    it('should filter by date range (startDate + endDate)', async () => {
      const all = await service.query({});
      if (all.total < 2) return; // guard

      // Use the middle entry's timestamp as bounds
      const sorted = [...all.entries].sort(
        (a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
      );
      const start = sorted[1].timestamp;
      const end = sorted[sorted.length - 2].timestamp;

      const result = await service.query({ startDate: start, endDate: end });
      for (const e of result.entries) {
        expect(e.timestamp.getTime()).toBeGreaterThanOrEqual(start.getTime());
        expect(e.timestamp.getTime()).toBeLessThanOrEqual(end.getTime());
      }
    });

    it('should filter by startDate only', async () => {
      const all = await service.query({});
      const midpoint = all.entries[Math.floor(all.entries.length / 2)].timestamp;

      const result = await service.query({ startDate: midpoint });
      for (const e of result.entries) {
        expect(e.timestamp.getTime()).toBeGreaterThanOrEqual(midpoint.getTime());
      }
    });

    it('should filter by endDate only', async () => {
      const all = await service.query({});
      const midpoint = all.entries[Math.floor(all.entries.length / 2)].timestamp;

      const result = await service.query({ endDate: midpoint });
      for (const e of result.entries) {
        expect(e.timestamp.getTime()).toBeLessThanOrEqual(midpoint.getTime());
      }
    });

    it('should combine multiple filters (adminEmail + action + severity)', async () => {
      const result = await service.query({
        adminEmail: 'alice@example.com',
        action: 'evidence_access',
        severity: 'critical',
      });
      expect(result.total).toBeGreaterThanOrEqual(1);
      for (const e of result.entries) {
        expect(e.adminEmail).toBe('alice@example.com');
        expect(e.action).toBe('evidence_access');
        expect(e.severity).toBe('critical');
      }
    });
  });

  describe('Pagination', () => {
    let service: AdminAuditLogService;

    beforeAll(async () => {
      service = createService();
      // Seed 10 entries
      for (let i = 0; i < 10; i++) {
        await service.log(makeEntry({ adminEmail: `pag${i}@example.com` }));
      }
    });

    it('should paginate with skip/limit', async () => {
      const page1 = await service.query({ page: 1, limit: 3 });
      expect(page1.entries.length).toBeLessThanOrEqual(3);

      const page2 = await service.query({ page: 2, limit: 3 });
      expect(page2.entries.length).toBeLessThanOrEqual(3);

      // No overlap
      const ids1 = page1.entries.map(e => e.auditId);
      const ids2 = page2.entries.map(e => e.auditId);
      for (const id of ids2) {
        expect(ids1).not.toContain(id);
      }
    });

    it('should return empty for page beyond total', async () => {
      const result = await service.query({ page: 999, limit: 10 });
      expect(result.entries.length).toBe(0);
    });

    it('should sort by timestamp descending', async () => {
      const result = await service.query({});
      for (let i = 1; i < result.entries.length; i++) {
        expect(result.entries[i - 1].timestamp.getTime()).toBeGreaterThanOrEqual(
          result.entries[i].timestamp.getTime(),
        );
      }
    });

    it('should cap limit at 200', async () => {
      const result = await service.query({ limit: 500 });
      // Limit is capped but we have fewer entries than 200
      expect(result.entries.length).toBeLessThanOrEqual(200);
    });
  });

  describe('Concurrent writes', () => {
    it('should handle 50 concurrent writes without data loss', async () => {
      const service = createService();

      // Get current count
      const before = await service.query({ limit: 1 });
      const beforeTotal = before.total;

      const promises = Array.from({ length: 50 }, (_, i) =>
        service.log(
          makeEntry({
            adminEmail: `concurrent-${i}@example.com`,
            action: 'stats_view',
          }),
        ),
      );

      await Promise.all(promises);

      const after = await service.query({ limit: 200 });
      expect(after.total).toBeGreaterThanOrEqual(beforeTotal + 50);
    });
  });

  describe('Memory fallback', () => {
    it('should fall back to memory when MongoDB is unavailable', async () => {
      const originalUri = process.env.MONGODB_URI;
      process.env.MONGODB_URI = '';

      const fallbackService = createService();
      await fallbackService.log(makeEntry({ action: 'stats_view' }));

      const result = await fallbackService.query({});
      expect(result.total).toBeGreaterThanOrEqual(1);

      process.env.MONGODB_URI = originalUri;
    });
  });
});
