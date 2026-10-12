import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient, Collection } from 'mongodb';
import { CriticalAdminAlertWorker } from '../../../src/services/criticalAdminAlertWorker';
import { AdminAuditLogService } from '../../../src/services/adminAuditLog';
import { EmailNotificationService } from '../../../src/services/emailNotification';

jest.mock('@aws-sdk/client-sesv2', () => ({ SESv2Client: jest.fn(), SendEmailCommand: jest.fn() }));

describe('critical admin alert recovery', () => {
  let server: MongoMemoryServer;
  let client: MongoClient;
  let entries: Collection;
  let now: Date;
  const oldUri = process.env.MONGODB_URI;
  const oldDb = process.env.MONGODB_DB_NAME;
  const workers: CriticalAdminAlertWorker[] = [];
  const worker = (send: () => Promise<{ sent: boolean; error?: string }>) => {
    const result = new CriticalAdminAlertWorker(send, () => now); workers.push(result); return result;
  };
  const insert = (criticalNotification: unknown = { state: 'pending', attempts: 0, nextAttemptAt: now }) =>
    entries.insertOne({ auditId: 'test-audit', action: 'evidence_access', severity: 'critical', timestamp: now, criticalNotification });
  beforeAll(async () => {
    server = await MongoMemoryServer.create();
    process.env.MONGODB_URI = server.getUri(); process.env.MONGODB_DB_NAME = 'critical_alert_tests';
    client = await MongoClient.connect(server.getUri());
    entries = client.db('critical_alert_tests').collection('admin_audit_logs');
  });
  beforeEach(async () => { await entries.deleteMany({}); now = new Date('2026-09-15'); });
  afterEach(async () => { await Promise.all(workers.splice(0).map(w => w.close())); });
  afterAll(async () => {
    await client.close(); await server.stop();
    if (oldUri === undefined) delete process.env.MONGODB_URI; else process.env.MONGODB_URI = oldUri;
    if (oldDb === undefined) delete process.env.MONGODB_DB_NAME; else process.env.MONGODB_DB_NAME = oldDb;
  });
  it('persists critical intent with the actual audit write and leaves ordinary events alone', async () => {
    const audit = new AdminAuditLogService();
    try {
      for (const action of ['evidence_access', 'stats_view'] as const) {
        await audit.log({ action, adminUserId: 'synthetic', adminEmail: 'synthetic@example.test', endpoint: '/synthetic', method: 'GET', responseStatus: 200, details: {} }, true);
      }
      expect((await entries.findOne({ action: 'evidence_access' }))!.criticalNotification).toMatchObject({ state: 'pending', attempts: 0 });
      expect((await entries.findOne({ action: 'stats_view' }))!.criticalNotification).toBeUndefined();
    } finally { await audit.close(); }
  });
  it.each(['ses_unconfigured', 'no_admin_recipients'])('retries known pre-send failure %s after reconnect', async error => {
    await insert();
    const first = worker(async () => ({ sent: false, error })); await first.tick(); await first.close();
    expect((await entries.findOne({}))!.criticalNotification.state).toBe('pending');
    now = new Date(now.getTime() + 60_000);
    const send = jest.fn(async () => ({ sent: true }));
    const restarted = worker(send); await restarted.tick(); await restarted.tick();
    expect(send).toHaveBeenCalledTimes(1);
    expect((await entries.findOne({}))!.criticalNotification.state).toBe('sent');
  });
  it('quarantines an ambiguous provider result across reconnect', async () => {
    await insert();
    const first = worker(async () => ({ sent: false, error: 'provider_failed' })); await first.tick(); await first.close();
    now = new Date(now.getTime() + 600_000);
    const send = jest.fn(async () => ({ sent: true })); await worker(send).tick();
    expect(send).not.toHaveBeenCalled();
    expect((await entries.findOne({}))!.criticalNotification.state).toBe('uncertain');
  });
  it.each([
    { state: 'sent', attempts: 0, result: { sent: true } },
    { state: 'pending', attempts: 0, result: { sent: false, error: 'no_admin_recipients' } },
    { state: 'failed', attempts: 4, result: { sent: false, error: 'ses_unconfigured' } },
    { state: 'uncertain', attempts: 0, result: { sent: false, error: 'provider_failed' } },
  ])('uses literal audit ID equality when persisting $state', async ({ state, attempts, result }) => {
    await insert({ state: 'pending', attempts, nextAttemptAt: now });
    const send = jest.fn(async () => result);
    const update = jest.spyOn(Collection.prototype, 'updateOne');
    try {
      await worker(send).tick();
      expect(send).toHaveBeenCalledTimes(1);
      expect(update).toHaveBeenCalledTimes(1);
      expect(update.mock.calls[0][0]).toEqual({
        auditId: { $eq: 'test-audit' }, 'criticalNotification.leaseId': expect.any(String),
      });
      const saved = await entries.findOne({});
      expect(saved!.criticalNotification).toMatchObject({ state, attempts: attempts + 1 });
      expect(saved!.criticalNotification.leaseId).toBeUndefined();
    } finally { update.mockRestore(); }
  });
  it.each([{ $ne: null }, { $regex: '.*' }])('treats a stored operator-shaped audit ID as a literal (%j)', async auditId => {
    const { insertedId } = await insert();
    await entries.updateOne({ _id: insertedId }, { $set: { auditId } });
    await entries.insertOne({ auditId: 'unrelated-audit', severity: 'info' });
    const send = jest.fn(async () => ({ sent: true }));
    const update = jest.spyOn(Collection.prototype, 'updateOne');
    try {
      await worker(send).tick();
      expect(send).toHaveBeenCalledTimes(1);
      expect(update.mock.calls[0][0]).toEqual({
        auditId: { $eq: auditId }, 'criticalNotification.leaseId': expect.any(String),
      });
      expect((await entries.findOne({ _id: insertedId }))!.criticalNotification.state).toBe('sent');
      expect((await entries.findOne({ auditId: 'unrelated-audit' }))!.criticalNotification).toBeUndefined();
    } finally { update.mockRestore(); }
  });
  it('cannot persist a late result after the claimed lease changes', async () => {
    const { insertedId } = await insert();
    const send = jest.fn(async () => {
      await entries.updateOne({ _id: insertedId }, { $set: { 'criticalNotification.leaseId': 'replacement' } });
      return { sent: true };
    });
    await expect(worker(send).tick()).rejects.toThrow('Critical alert result was not persisted');
    expect(send).toHaveBeenCalledTimes(1);
    expect((await entries.findOne({ _id: insertedId }))!.criticalNotification)
      .toMatchObject({ state: 'sending', attempts: 1, leaseId: 'replacement' });
  });
  it('does not resend after acceptance when persisting the outcome fails', async () => {
    await insert();
    const send = jest.fn(async () => ({ sent: true }));
    const first = worker(send);
    const update = jest.spyOn(Collection.prototype, 'updateOne').mockRejectedValueOnce(new Error('write acknowledgement lost'));
    try { await expect(first.tick()).rejects.toThrow('acknowledgement lost'); }
    finally { update.mockRestore(); await first.close(); }
    now = new Date(now.getTime() + 600_000);
    await worker(send).tick();
    expect(send).toHaveBeenCalledTimes(1);
    expect((await entries.findOne({}))!.criticalNotification.state).toBe('uncertain');
  });

  it('quarantines an expired sending lease and does not backfill historical events', async () => {
    await insert({ state: 'sending', attempts: 1, nextAttemptAt: now, leaseId: 'interrupted' });
    await entries.insertOne({ auditId: 'legacy', severity: 'critical' });
    const send = jest.fn(async () => ({ sent: true })); await worker(send).tick();
    expect(send).not.toHaveBeenCalled();
    expect((await entries.findOne({ auditId: 'test-audit' }))!.criticalNotification.state).toBe('uncertain');
  });
  it('drains an active send and preserves exclusive delivery after lease expiry', async () => {
    await insert();
    let enter!: () => void; const entered = new Promise<void>(resolve => { enter = resolve; });
    let finish!: () => void; const pending = new Promise<void>(resolve => { finish = resolve; });
    const first = worker(async () => { enter(); await pending; return { sent: true }; });
    const run = first.tick(); await entered;
    let closed = false; const close = first.close().then(() => { closed = true; });
    try {
      await Promise.resolve(); expect(closed).toBe(false);
      now = new Date(now.getTime() + 600_000);
      const otherSend = jest.fn(async () => ({ sent: true })); await worker(otherSend).tick();
      expect(otherSend).not.toHaveBeenCalled();
    } finally { finish(); await run; await close; }
    expect((await entries.findOne({}))!.criticalNotification.state).toBe('sent');
  });
  it('recovers after an actual process kill at the external send boundary without resending', async () => {
    await insert();
    const child = spawn(process.execPath, ['-r', 'ts-node/register/transpile-only', '-e', `
      const { CriticalAdminAlertWorker } = require('./src/services/criticalAdminAlertWorker');
      const worker = new CriticalAdminAlertWorker(async () => {
        process.send('send-entered');
        return new Promise(() => {});
      }, () => new Date('2026-09-15'));
      worker.tick().catch(() => process.exit(1));
    `], { cwd: process.cwd(), env: { ...process.env, TS_NODE_COMPILER_OPTIONS: '{"module":"CommonJS"}' }, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => { cleanup(); reject(new Error('Child did not enter send')); }, 15000);
        const message = (value: unknown) => { if (value === 'send-entered') { cleanup(); resolve(); } };
        const exit = () => { cleanup(); reject(new Error('Child exited before send')); };
        const cleanup = () => { clearTimeout(timer); child.off('message', message); child.off('exit', exit); };
        child.on('message', message); child.on('exit', exit);
      });
      const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
      now = new Date(now.getTime() + 600_000);
      const send = jest.fn(async () => ({ sent: true })); await worker(send).tick();
      expect(send).not.toHaveBeenCalled();
      expect((await entries.findOne({}))!.criticalNotification).toMatchObject({ state: 'uncertain', lastError: 'send_interrupted' });
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
      }
    }
  });

  it('does not export audit fields in the email template', async () => {
    const service = new EmailNotificationService();
    const send = jest.spyOn(service, 'sendAlert').mockResolvedValue({ sent: true });
    expect(await service.notifyCriticalAdminAction()).toEqual({ sent: true });
    expect(send.mock.calls[0]).toEqual(['critical_admin_action', 'Critical Admin Action', expect.stringContaining('authenticated admin audit log')]);
  });
});
