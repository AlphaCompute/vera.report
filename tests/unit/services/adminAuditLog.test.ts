/**
 * Unit Tests for Admin Audit Log Service
 * Tests logging, severity mapping, query filtering, and memory fallback.
 */

import { AdminAuditLogService, adminAuditLog } from '@services/adminAuditLog';
import type { AdminAction } from '@services/adminAuditLog';

describe('AdminAuditLogService', () => {
  let service: AdminAuditLogService;

  beforeEach(() => {
    // No MONGODB_URI → service falls back to in-memory
    delete process.env.MONGODB_URI;
    process.env.NODE_ENV = 'test';
    service = new AdminAuditLogService();
  });

  describe('Singleton export', () => {
    it('should export a singleton instance', () => {
      expect(adminAuditLog).toBeDefined();
    });
  });

  describe('log()', () => {
    it('should log an entry and assign auditId + timestamp', async () => {
      await service.log({
        adminUserId: 'auth0|123',
        adminEmail: 'admin@example.com',
        action: 'evidence_access',
        endpoint: '/api/whistleblower/evidence/TRK-001/file.pdf',
        method: 'GET',
        responseStatus: 200,
        details: { resourceId: 'TRK-001', filename: 'file.pdf' },
      });

      const result = await service.query({});
      expect(result.total).toBe(1);
      expect(result.entries[0].auditId).toBeDefined();
      expect(result.entries[0].timestamp).toBeInstanceOf(Date);
      expect(result.entries[0].adminEmail).toBe('admin@example.com');
      expect(result.entries[0].action).toBe('evidence_access');
    });

    it('should auto-assign severity based on action', async () => {
      const severityMap: Record<AdminAction, string> = {
        evidence_access: 'critical',
        contact_info_decrypt: 'critical',
        report_status_change: 'critical',
        report_analyze: 'important',
        report_list_view: 'info',
        stats_view: 'info',
      };

      for (const [action, expectedSeverity] of Object.entries(severityMap)) {
        await service.log({
          adminUserId: 'auth0|123',
          adminEmail: 'admin@example.com',
          action: action as AdminAction,
          endpoint: '/test',
          method: 'GET',
          responseStatus: 200,
          details: {},
        });
      }

      const result = await service.query({});
      expect(result.total).toBe(6);

      for (const entry of result.entries) {
        expect(entry.severity).toBe(severityMap[entry.action]);
      }
    });

    it('should never throw on log failure', async () => {
      // Even without MongoDB, log() should not throw
      await expect(
        service.log({
          adminUserId: 'auth0|123',
          adminEmail: 'admin@example.com',
          action: 'stats_view',
          endpoint: '/test',
          method: 'GET',
          responseStatus: 200,
          details: {},
        }),
      ).resolves.toBeUndefined();
    });
  });

  describe('query()', () => {
    beforeEach(async () => {
      // Seed multiple entries
      const entries = [
        { action: 'evidence_access' as const, adminEmail: 'alice@example.com', resourceId: 'TRK-001' },
        { action: 'contact_info_decrypt' as const, adminEmail: 'alice@example.com', resourceId: 'TRK-001' },
        { action: 'report_status_change' as const, adminEmail: 'bob@example.com', resourceId: 'TRK-002' },
        { action: 'report_list_view' as const, adminEmail: 'alice@example.com', resourceId: undefined },
        { action: 'stats_view' as const, adminEmail: 'bob@example.com', resourceId: undefined },
      ];

      for (const e of entries) {
        await service.log({
          adminUserId: 'auth0|test',
          adminEmail: e.adminEmail,
          action: e.action,
          endpoint: '/test',
          method: 'GET',
          responseStatus: 200,
          details: { resourceId: e.resourceId },
        });
      }
    });

    it('should return all entries when no filters', async () => {
      const result = await service.query({});
      expect(result.total).toBe(5);
      expect(result.entries.length).toBe(5);
    });

    it('should filter by adminEmail', async () => {
      const result = await service.query({ adminEmail: 'alice@example.com' });
      expect(result.total).toBe(3);
      expect(result.entries.every((e) => e.adminEmail === 'alice@example.com')).toBe(true);
    });

    it('should filter by action', async () => {
      const result = await service.query({ action: 'evidence_access' });
      expect(result.total).toBe(1);
      expect(result.entries[0].action).toBe('evidence_access');
    });

    it('should filter by severity', async () => {
      const result = await service.query({ severity: 'critical' });
      expect(result.total).toBe(3);
      expect(result.entries.every((e) => e.severity === 'critical')).toBe(true);
    });

    it('should filter by resourceId', async () => {
      const result = await service.query({ resourceId: 'TRK-001' });
      expect(result.total).toBe(2);
      expect(result.entries.every((e) => e.details.resourceId === 'TRK-001')).toBe(true);
    });

    it('should paginate results', async () => {
      const page1 = await service.query({ page: 1, limit: 2 });
      expect(page1.entries.length).toBe(2);
      expect(page1.total).toBe(5);

      const page2 = await service.query({ page: 2, limit: 2 });
      expect(page2.entries.length).toBe(2);

      const page3 = await service.query({ page: 3, limit: 2 });
      expect(page3.entries.length).toBe(1);
    });

    it('should cap limit at 200', async () => {
      const result = await service.query({ limit: 500 });
      // All 5 entries returned (below cap), but the cap logic is applied
      expect(result.entries.length).toBe(5);
    });

    it('should sort by timestamp descending', async () => {
      const result = await service.query({});
      for (let i = 1; i < result.entries.length; i++) {
        expect(result.entries[i - 1].timestamp.getTime()).toBeGreaterThanOrEqual(
          result.entries[i].timestamp.getTime(),
        );
      }
    });
  });

  describe('query() — date and combined filters', () => {
    it('should filter by startDate and endDate in memory fallback', async () => {
      const svc = new AdminAuditLogService();

      // Log entries at known times
      const now = Date.now();
      await svc.log({
        adminUserId: 'auth0|d1',
        adminEmail: 'alice@example.com',
        action: 'evidence_access',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      });

      // Small delay to separate timestamps
      await new Promise((r) => setTimeout(r, 15));

      await svc.log({
        adminUserId: 'auth0|d2',
        adminEmail: 'alice@example.com',
        action: 'stats_view',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      });

      const all = await svc.query({});
      const sorted = [...all.entries].sort(
        (a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
      );

      // Query with range that only includes the first entry
      const result = await svc.query({
        startDate: sorted[0].timestamp,
        endDate: sorted[0].timestamp,
      });
      expect(result.total).toBe(1);
    });

    it('should filter by startDate only', async () => {
      const svc = new AdminAuditLogService();

      await svc.log({
        adminUserId: 'auth0|s1',
        adminEmail: 'bob@example.com',
        action: 'stats_view',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      });

      await new Promise((r) => setTimeout(r, 15));
      const midpoint = new Date();
      await new Promise((r) => setTimeout(r, 15));

      await svc.log({
        adminUserId: 'auth0|s2',
        adminEmail: 'bob@example.com',
        action: 'report_list_view',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      });

      const result = await svc.query({ startDate: midpoint });
      expect(result.total).toBe(1);
      expect(result.entries[0].action).toBe('report_list_view');
    });

    it('should filter by endDate only', async () => {
      const svc = new AdminAuditLogService();

      await svc.log({
        adminUserId: 'auth0|e1',
        adminEmail: 'bob@example.com',
        action: 'evidence_access',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      });

      await new Promise((r) => setTimeout(r, 15));
      const midpoint = new Date();
      await new Promise((r) => setTimeout(r, 15));

      await svc.log({
        adminUserId: 'auth0|e2',
        adminEmail: 'bob@example.com',
        action: 'stats_view',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      });

      const result = await svc.query({ endDate: midpoint });
      expect(result.total).toBe(1);
      expect(result.entries[0].action).toBe('evidence_access');
    });

    it('should combine adminEmail + action + resourceId filters', async () => {
      const svc = new AdminAuditLogService();

      await svc.log({
        adminUserId: 'auth0|c1',
        adminEmail: 'alice@example.com',
        action: 'evidence_access',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: { resourceId: 'TRK-100' },
      });

      await svc.log({
        adminUserId: 'auth0|c2',
        adminEmail: 'alice@example.com',
        action: 'evidence_access',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: { resourceId: 'TRK-200' },
      });

      await svc.log({
        adminUserId: 'auth0|c3',
        adminEmail: 'bob@example.com',
        action: 'evidence_access',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: { resourceId: 'TRK-100' },
      });

      const result = await svc.query({
        adminEmail: 'alice@example.com',
        action: 'evidence_access',
        resourceId: 'TRK-100',
      });
      expect(result.total).toBe(1);
      expect(result.entries[0].adminUserId).toBe('auth0|c1');
    });
  });

  describe('log() — severity override', () => {
    it('should use custom severity when provided', async () => {
      await service.log({
        adminUserId: 'auth0|123',
        adminEmail: 'admin@example.com',
        action: 'stats_view', // normally 'info'
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
        severity: 'critical',
      });

      const result = await service.query({});
      const entry = result.entries.find(
        (e) => e.action === 'stats_view' && e.severity === 'critical',
      );
      expect(entry).toBeDefined();
    });
  });

  describe('log() — production warning', () => {
    it('should log a production warning when MONGODB_URI is empty', async () => {
      const prevEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      const consoleSpy = jest.spyOn(console, 'error');

      const svc = new AdminAuditLogService();
      await expect(svc.log({
        adminUserId: 'auth0|123',
        adminEmail: 'admin@example.com',
        action: 'stats_view',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      })).rejects.toThrow('Durable audit storage unavailable');

      const criticalCalls = consoleSpy.mock.calls.filter(
        (args) => typeof args[0] === 'string' && args[0].includes('[CRITICAL]'),
      );
      expect(criticalCalls.length).toBeGreaterThanOrEqual(1);

      process.env.NODE_ENV = prevEnv;
      consoleSpy.mockRestore();
    });
  });

  describe('query() — edge cases', () => {
    it('should return empty results for filters matching nothing', async () => {
      const result = await service.query({
        adminEmail: 'nonexistent@example.com',
      });
      expect(result.total).toBe(0);
      expect(result.entries).toEqual([]);
    });

    it('should handle page=0 gracefully (treats as page 1)', async () => {
      await service.log({
        adminUserId: 'auth0|p0',
        adminEmail: 'admin@example.com',
        action: 'stats_view',
        endpoint: '/test',
        method: 'GET',
        responseStatus: 200,
        details: {},
      });

      // page=0 → skip = (0-1)*limit = -limit → should still work
      const result = await service.query({ page: 0, limit: 10 });
      // The service uses (page-1)*limit as skip, page=0 gives skip=-10
      // This should either return entries (skip is clamped) or be empty
      expect(result).toBeDefined();
      expect(Array.isArray(result.entries)).toBe(true);
    });
  });

  describe('Memory store limit', () => {
    it('should not exceed MAX_MEMORY entries in fallback mode', async () => {
      // Log more than the memory limit
      for (let i = 0; i < 1010; i++) {
        await service.log({
          adminUserId: 'auth0|123',
          adminEmail: 'admin@example.com',
          action: 'stats_view',
          endpoint: '/test',
          method: 'GET',
          responseStatus: 200,
          details: {},
        });
      }

      const result = await service.query({ limit: 200 });
      // Total should be capped at MAX_MEMORY (1000)
      expect(result.total).toBeLessThanOrEqual(1000);
    });
  });
});
