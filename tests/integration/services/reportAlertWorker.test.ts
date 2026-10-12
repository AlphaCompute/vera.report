import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient, Collection } from 'mongodb';
import { ReportAlertWorker } from '../../../src/services/reportAlertWorker';
import { EmailNotificationService } from '../../../src/services/emailNotification';

jest.mock('@aws-sdk/client-sesv2', () => ({ SESv2Client: jest.fn(), SendEmailCommand: jest.fn() }));

describe('durable new report alerts', () => {
  let server: MongoMemoryServer;
  let client: MongoClient;
  let reports: Collection;
  let time: Date;
  const workers: ReportAlertWorker[] = [];
  const oldUri = process.env.MONGODB_URI;
  const oldDb = process.env.MONGODB_DB_NAME;
  const worker = (send: () => Promise<{ sent: boolean; error?: string }>, configured = () => true) => {
    const instance = new ReportAlertWorker(send, () => time, configured);
    workers.push(instance);
    return instance;
  };
  const insert = (extra = {}) => reports.insertOne({ trackingId: 'VRA-0123456789ABCDEF', status: 'pending',
    encryptedDescription: 'must-not-leave-database', createdAt: new Date('2026-01-01'), category: 'financial-fraud',
    adminNotification: { state: 'pending', attempts: 0, nextAttemptAt: time }, ...extra });
  beforeAll(async () => {
    server = await MongoMemoryServer.create();
    process.env.MONGODB_URI = server.getUri();
    process.env.MONGODB_DB_NAME = 'report_alert_tests';
    client = await MongoClient.connect(server.getUri());
    reports = client.db('report_alert_tests').collection('whistleblower_reports');
  });
  beforeEach(async () => { await reports.deleteMany({}); time = new Date('2026-01-01'); });
  afterEach(async () => { await Promise.all(workers.splice(0).map(w => w.close())); });
  afterAll(async () => {
    await client.close(); await server.stop();
    if (oldUri === undefined) delete process.env.MONGODB_URI; else process.env.MONGODB_URI = oldUri;
    if (oldDb === undefined) delete process.env.MONGODB_DB_NAME; else process.env.MONGODB_DB_NAME = oldDb;
  });

  it('uses the vera database when no database name is configured', async () => {
    await insert();
    const fallback = client.db('vera').collection('whistleblower_reports');
    await fallback.insertOne((await reports.findOne({}))!);
    delete process.env.MONGODB_DB_NAME;
    try {
      const send = jest.fn(async () => ({ sent: true }));
      await worker(send).tick();
      expect(send).toHaveBeenCalledTimes(1);
      expect((await fallback.findOne({}))?.adminNotification.state).toBe('sent');
      expect((await reports.findOne({}))?.adminNotification.state).toBe('pending');
    } finally { process.env.MONGODB_DB_NAME = 'report_alert_tests'; }
  });

  it.each(['provider_failed', 'no_admin_recipients', 'ses_unconfigured'])('retains %s and delivers after worker restart', async (error) => {
    await insert();
    const first = worker(async () => ({ sent: false, error }));
    await first.tick(); await first.close();
    const attempts = error === 'provider_failed' ? 1 : 0;
    expect((await reports.findOne({}))!.adminNotification).toMatchObject({ state: 'pending', attempts, lastError: error });
    const send = jest.fn(async () => ({ sent: true }));
    const restarted = worker(send);
    await restarted.tick(); expect(send).not.toHaveBeenCalled();
    time = new Date(time.getTime() + 60_000);
    await restarted.tick(); await restarted.tick();
    expect(send).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith({ acceptedAt: new Date('2026-01-01'), reportType: 'financial-fraud' });
    expect(JSON.stringify(send.mock.calls)).not.toMatch(/must-not-leave|VRA-/);
    expect((await reports.findOne({}))!.adminNotification).toMatchObject({ state: 'sent', attempts: attempts + 1 });
  });

  it('does not reclaim or exhaust due work while configuration is absent, then resumes existing intent', async () => {
    await insert({ adminNotification: { state: 'sending', attempts: 4, leaseId: 'expired', nextAttemptAt: time } });
    const before = await reports.findOne({});
    let configured = false;
    const send = jest.fn(async () => ({ sent: true }));
    const instance = worker(send, () => configured);
    for (let n = 0; n < 8; n++) { await instance.tick(); time = new Date(time.getTime() + 60_000); }
    expect(await reports.findOne({})).toEqual(before);
    expect(send).not.toHaveBeenCalled();
    configured = true;
    await instance.tick();
    expect(send).toHaveBeenCalledTimes(1);
    expect((await reports.findOne({}))!.adminNotification).toMatchObject({ state: 'sent', attempts: 5 });
  });

  it.each(['no_admin_recipients', 'ses_unconfigured'])('repeated %s preserves the final delivery attempt', async error => {
    await insert({ adminNotification: { state: 'pending', attempts: 4, nextAttemptAt: time } });
    let available = false;
    const send = jest.fn(async () => available ? { sent: true } : { sent: false, error });
    const instance = worker(send);
    for (let n = 0; n < 8; n++) { await instance.tick(); time = new Date(time.getTime() + 60_000); }
    expect(send).toHaveBeenCalledTimes(8);
    expect((await reports.findOne({}))!.adminNotification).toMatchObject({ state: 'pending', attempts: 4, lastError: error });
    expect((await reports.findOne({}))!.adminNotification.leaseId).toBeUndefined();
    available = true;
    await instance.tick();
    expect((await reports.findOne({}))!.adminNotification).toMatchObject({ state: 'sent', attempts: 5 });
  });

  it('cannot refund or reopen a newer lease after a paused sender returns late', async () => {
    await insert();
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    let release!: (result: { sent: boolean; error: string }) => void;
    const late = new Promise<{ sent: boolean; error: string }>(resolve => { release = resolve; });
    const first = worker(async () => { entered(); return late; });
    const pending = first.tick();
    await started;
    time = new Date(time.getTime() + 300_001);
    await worker(async () => ({ sent: true })).tick();
    const sent = await reports.findOne({});
    release({ sent: false, error: 'no_admin_recipients' });
    await pending;
    expect(await reports.findOne({})).toEqual(sent);
    expect(sent!.adminNotification).toMatchObject({ state: 'sent', attempts: 2 });
  });

  it('retains pending intent across a real Mongo process restart', async () => {
    await insert();
    await client.close();
    await server.stop({ doCleanup: false });
    await server.start(true);
    process.env.MONGODB_URI = server.getUri();
    client = await MongoClient.connect(server.getUri());
    reports = client.db('report_alert_tests').collection('whistleblower_reports');
    const send = jest.fn(async () => ({ sent: true }));
    await worker(send).tick();
    expect(send).toHaveBeenCalledTimes(1);
    expect((await reports.findOne({}))!.adminNotification.state).toBe('sent');
  });

  it('claims once across concurrent workers and never backfills old reports', async () => {
    await insert(); await insert({ trackingId: 'old-report', adminNotification: undefined });
    const send = jest.fn(async () => ({ sent: true }));
    await Promise.all([worker(send).tick(), worker(send).tick()]);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('uses literal ID equality when acknowledging the claimed report', async () => {
    await insert();
    const update = jest.spyOn(Collection.prototype, 'updateOne');
    try {
      await worker(async () => ({ sent: true })).tick();
      expect(update.mock.calls[0][0]).toEqual({
        trackingId: { $eq: 'VRA-0123456789ABCDEF' }, 'adminNotification.leaseId': expect.any(String),
      });
      expect((await reports.findOne({}))!.adminNotification.state).toBe('sent');
    } finally { update.mockRestore(); }
  });

  it('recovers an expired lease after process death', async () => {
    await insert({ adminNotification: { state: 'sending', attempts: 1, leaseId: 'dead-process', nextAttemptAt: new Date(time.getTime() + 300_000) } });
    const send = jest.fn(async () => ({ sent: true }));
    const restarted = worker(send);
    await restarted.tick(); expect(send).not.toHaveBeenCalled();
    time = new Date(time.getTime() + 300_000);
    await restarted.tick(); expect(send).toHaveBeenCalledTimes(1);
  });

  it('bounds retries, records exhaustion and sanitizes provider details', async () => {
    await insert();
    const send = jest.fn(async () => { throw new Error('secret-provider-response'); });
    const instance = worker(send);
    for (let i = 0; i < 6; i++) { await instance.tick(); time = new Date(time.getTime() + 3_600_000); }
    expect(send).toHaveBeenCalledTimes(5);
    expect((await reports.findOne({}))!.adminNotification).toMatchObject({ state: 'failed', attempts: 5, lastError: 'provider_failed' });
    expect(JSON.stringify((await reports.findOne({}))!.adminNotification)).not.toContain('secret');
  });

  it('marks a crashed final attempt visibly exhausted', async () => {
    await insert({ adminNotification: { state: 'sending', attempts: 5, leaseId: 'dead', nextAttemptAt: time } });
    const send = jest.fn(async () => ({ sent: true }));
    await worker(send).tick();
    expect(send).not.toHaveBeenCalled();
    expect((await reports.findOne({}))!.adminNotification.state).toBe('failed');
  });
});

describe('admin alert delivery acknowledgement', () => {
  it('returns failure for empty recipients rather than acknowledging delivery', async () => {
    const service = new EmailNotificationService();
    jest.spyOn(service as any, 'initialise').mockReturnValue(true);
    jest.spyOn(service as any, 'getAdminEmails').mockResolvedValue([]);
    expect(await service.notifyNewReport('secret-token', 'reporter-input')).toEqual({ sent: false, error: 'no_admin_recipients' });
  });
  it('contains no tracking token or reporter content in email', async () => {
    const service = new EmailNotificationService();
    const send = jest.spyOn(service, 'sendAlert').mockResolvedValue({ sent: true });
    await service.notifyNewReport('secret-token', '<script>reporter-input</script>');
    expect(JSON.stringify(send.mock.calls)).not.toMatch(/secret-token|reporter-input|script/);
  });
});

describe('safe new-report metadata', () => {
  it('includes the original acceptance timestamp, fixed report type and generic summary', async () => {
    const service = new EmailNotificationService();
    const send = jest.spyOn(service, 'sendAlert').mockResolvedValue({ sent: true });
    await service.notifyNewReport('secret-token', 'private-urgency', {
      acceptedAt: new Date('2026-01-02T03:04:05Z'), reportType: 'financial-fraud',
    });
    const text = JSON.stringify(send.mock.calls);
    expect(text).toContain('2026-01-02T03:04:05.000Z');
    expect(text).toContain('Financial Fraud');
    expect(text).toContain('A new report is awaiting review');
    expect(text).not.toMatch(/secret-token|private-urgency/);
  });
  it.each(['<script>private narrative</script>', '__proto__', 'constructor'])('never reflects unknown report type %s', async reportType => {
    const service = new EmailNotificationService();
    const send = jest.spyOn(service, 'sendAlert').mockResolvedValue({ sent: true });
    await service.notifyNewReport('', '', { acceptedAt: new Date(NaN), reportType });
    const text = JSON.stringify(send.mock.calls);
    expect(text).toContain('Confidential report');
    expect(text).toContain('Unavailable');
    expect(text).not.toContain(reportType);
  });
});

describe('admin alert deployment configuration gate', () => {
  it.each(['SES_SENDER_EMAIL', 'AUTH0_DOMAIN', 'AUTH0_MGMT_CLIENT_ID', 'AUTH0_MGMT_CLIENT_SECRET'])(
    'does not open storage or call a sender when %s is blank', async missing => {
      const keys = ['SES_SENDER_EMAIL', 'AUTH0_DOMAIN', 'AUTH0_MGMT_CLIENT_ID', 'AUTH0_MGMT_CLIENT_SECRET'];
      const previous = keys.map(key => process.env[key]);
      const send = jest.fn(async () => ({ sent: true }));
      const instance = new ReportAlertWorker(send);
      const collection = jest.spyOn(instance as any, 'collection');
      try {
        for (const key of keys) process.env[key] = key === missing ? '  ' : 'configured';
        await instance.tick();
        expect(collection).not.toHaveBeenCalled();
        expect(send).not.toHaveBeenCalled();
      } finally {
        keys.forEach((key, index) => {
          if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index];
        });
        await instance.close();
      }
    },
  );
});
