import { MongoMemoryServer } from 'mongodb-memory-server';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { AdminAuditLogService } from '../../../src/services/adminAuditLog';
const entry = { adminUserId: 'admin', adminEmail: 'admin@example.test', action: 'report_status_change' as const,
  endpoint: '/report/status', method: 'PATCH', responseStatus: 0,
  details: { resourceId: 'VRA-1', phase: 'attempted' as const, newStatus: 'reviewing' } };
const env = { ...process.env };
afterEach(() => { process.env = { ...env }; });
it('fails closed without a durable database and does not invent an empty audit history', async () => {
  delete process.env.MONGODB_URI;
  const service = new AdminAuditLogService();
  await expect(service.log(entry, true)).rejects.toThrow('Durable audit storage unavailable');
  await expect(service.query({}, true)).rejects.toThrow('Durable audit storage unavailable');
});
it('does not convert a rejected database insert into a memory-only success', async () => {
  const service = new AdminAuditLogService();
  (service as any).isConnected = true;
  (service as any).auditLogs = { insertOne: jest.fn().mockRejectedValue(new Error('write rejected')) };
  await expect(service.log(entry, true)).rejects.toThrow('Failed to persist audit entry');
  expect((service as any).memoryStore).toEqual([]);
});
it('keeps the attempted audit after both service and database restart', async () => {
  const dbPath = await mkdtemp(path.join(tmpdir(), 'vera-audit-'));
  const mongo = await MongoMemoryServer.create({ instance: { dbPath, storageEngine: 'wiredTiger' } });
  const writer = new AdminAuditLogService(); const reader = new AdminAuditLogService();
  try {
    process.env.MONGODB_URI = mongo.getUri(); process.env.MONGODB_DB_NAME = 'audit_restart';
    await writer.log(entry, true);
    await writer.close();
    await mongo.stop({ doCleanup: false });
    await mongo.start();
    process.env.MONGODB_URI = mongo.getUri();
    const result = await reader.query({ resourceId: 'VRA-1' }, true);
    expect(result.total).toBe(1);
    expect(result.entries[0].details).toMatchObject({ phase: 'attempted', newStatus: 'reviewing' });
    expect(result.entries[0].responseStatus).toBe(0);
  } finally {
    await writer.close(); await reader.close(); await mongo.stop(); await rm(dbPath, { recursive: true, force: true });
  }
}, 60000);

it('rejects an unacknowledged write and requests journaled majority persistence', async () => {
  const service = new AdminAuditLogService();
  const insertOne = jest.fn().mockResolvedValue({ acknowledged: false });
  (service as any).isConnected = true;
  (service as any).auditLogs = { insertOne };
  await expect(service.log(entry, true)).rejects.toThrow('Failed to persist audit entry');
  expect(insertOne).toHaveBeenCalledWith(expect.anything(), { writeConcern: { w: 'majority', j: true } });
  expect((service as any).memoryStore).toEqual([]);
});
