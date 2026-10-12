import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient, Collection } from 'mongodb';
import { SubmissionNotificationWorker } from '../../../src/services/submissionNotificationWorker';
import type { WebhookResult } from '../../../src/services/submissionWebhook';
let mongo: MongoMemoryServer; let client: MongoClient; let now: Date;
const workers: SubmissionNotificationWorker[] = [];
const keys = ['MONGODB_URI','MONGODB_DB_NAME','WEBHOOK_URL','WEBHOOK_SECRET','SLACK_WEBHOOK_URL','SLACK_ADMIN_URL'] as const;
const original = Object.fromEntries(keys.map(k => [k,process.env[k]]));
const records = () => client.db('queue-tests').collection('whistleblower_reports');
const create = (send?: jest.Mock) => { const w = new SubmissionNotificationWorker(send,()=>now);workers.push(w);return w; };
beforeAll(async()=>{mongo=await MongoMemoryServer.create();client=await MongoClient.connect(mongo.getUri());});
beforeEach(async()=>{
 process.env.MONGODB_URI=mongo.getUri();process.env.MONGODB_DB_NAME='queue-tests';process.env.WEBHOOK_URL='https://example.invalid';process.env.WEBHOOK_SECRET='synthetic';now=new Date('2026-01-01');await records().deleteMany({});
 delete process.env.SLACK_WEBHOOK_URL; delete process.env.SLACK_ADMIN_URL;
});
afterEach(async()=>{await Promise.all(workers.splice(0).map(w=>w.close()));});
afterAll(async()=>{await client.close();await mongo.stop();for(const k of keys){if(original[k]===undefined)delete process.env[k];else process.env[k]=original[k];}});
async function insert(extra={}){await records().insertOne({trackingId:'VRA-A1B2C3D4E5F60718',createdAt:now,encryptedDescription:'PRIVATE-NARRATIVE',adminNotification:{state:'sent'},submissionNotification:{state:'pending',source:'telegram',attempts:0,nextAttemptAt:now},...extra});}
test('two processes claim once, disclose only safe transport inputs, leave SES state untouched',async()=>{
 await insert();const send=jest.fn(async():Promise<WebhookResult>=>'delivered');await Promise.all([create(send).tick(),create(send).tick()]);
 expect(send).toHaveBeenCalledTimes(1);expect(send).toHaveBeenCalledWith('VRA-A1B2C3D4E5F60718',now,'telegram');expect(JSON.stringify(send.mock.calls)).not.toContain('PRIVATE-NARRATIVE');
 const record=await records().findOne({});expect(record?.submissionNotification.state).toBe('sent');expect(record?.adminNotification.state).toBe('sent');
});
test('retry survives worker restart and preserves original acceptance time',async()=>{
 await insert();const failed=create(jest.fn(async()=> 'failed' as const));await failed.tick();await failed.close();now=new Date(now.getTime()+60_000);const send=jest.fn(async()=> 'delivered' as const);await create(send).tick();
 expect(send).toHaveBeenCalledWith('VRA-A1B2C3D4E5F60718',new Date('2026-01-01'),'telegram');expect((await records().findOne({}))?.submissionNotification.attempts).toBe(2);
});
test('uses the vera database when no database name is configured', async () => {
 await insert();
 const fallback = client.db('vera').collection('whistleblower_reports');
 await fallback.insertOne((await records().findOne({}))!);
 delete process.env.MONGODB_DB_NAME;
 const send = jest.fn(async () => 'delivered' as const);
 await create(send).tick();
 expect(send).toHaveBeenCalledTimes(1);
 expect((await fallback.findOne({}))?.submissionNotification.state).toBe('sent');
 expect((await records().findOne({}))?.submissionNotification.state).toBe('pending');
});
test('recovers expired lease and terminates exhausted attempts',async()=>{
 await insert({submissionNotification:{state:'sending',source:'web',attempts:4,nextAttemptAt:now,leaseId:'dead-process'}});
 const send=jest.fn(async()=> 'failed' as const);await create(send).tick();expect((await records().findOne({}))?.submissionNotification.state).toBe('failed');now=new Date(now.getTime()+3600000);await create(send).tick();expect(send).toHaveBeenCalledTimes(1);
});
test('disabled or invalid configuration preserves intent and attempt count',async()=>{
 await insert();delete process.env.WEBHOOK_SECRET;const send=jest.fn();await create(send).tick();expect(send).not.toHaveBeenCalled();expect((await records().findOne({}))?.submissionNotification.attempts).toBe(0);
});
test('does not backfill or send historical reports without explicit intent',async()=>{
 await insert({submissionNotification:undefined});const send=jest.fn();await create(send).tick();expect(send).not.toHaveBeenCalled();
});
test('late sender cannot overwrite a lease taken by another worker',async()=>{
 await insert();const send=jest.fn(async()=>{await records().updateOne({},{$set:{'submissionNotification.leaseId':'replacement','submissionNotification.state':'sending'}});return 'delivered' as const;});await create(send).tick();expect((await records().findOne({}))?.submissionNotification.leaseId).toBe('replacement');
});

test.each([{ $ne: null }, { $regex: '^VRA-' }, /^VRA-/, ['VRA-1'], null, false, 0, '', '  '])(
 'rejects malformed targeted hints without consuming or delivering queued work (%p)', async trackingId => {
  await insert();
  const before = await records().findOne({});
  const send = jest.fn(async () => 'delivered' as const);
  await expect(create(send).tick(trackingId as unknown as string)).rejects.toThrow('invalid_tracking_id');
  expect(await records().findOne({})).toEqual(before);
  expect(send).not.toHaveBeenCalled();
 },
);

test('a valid targeted hint sends only that report and uses literal equality in its completion filter', async () => {
 await insert();
 await insert({ trackingId: 'VRA-OTHER' });
 const send = jest.fn(async () => 'delivered' as const);
 const update = jest.spyOn(Collection.prototype, 'updateOne');
 try {
  await create(send).tick('VRA-A1B2C3D4E5F60718');
  expect(send).toHaveBeenCalledTimes(1);
  expect(update.mock.calls[0][0]).toEqual({
   trackingId: { $eq: 'VRA-A1B2C3D4E5F60718' }, 'submissionNotification.leaseId': expect.any(String),
  });
  expect((await records().findOne({ trackingId: 'VRA-OTHER' }))?.submissionNotification.attempts).toBe(0);
 } finally { update.mockRestore(); }
});

function enableSlack() {
 delete process.env.WEBHOOK_URL; delete process.env.WEBHOOK_SECRET;
 process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/T/B/synthetic-test-only';
 process.env.SLACK_ADMIN_URL = 'https://staging.example.invalid/admin';
}

test('the real Slack sender retries a failure after restart without changing SES state', async () => {
 enableSlack(); await insert();
 const fetch = jest.spyOn(global, 'fetch')
  .mockResolvedValueOnce(new Response('temporary failure', { status: 503 }))
  .mockResolvedValueOnce(new Response('ok'));
 try {
  const first = create(); await first.tick(); await first.close();
  expect((await records().findOne({}))?.submissionNotification.state).toBe('pending');
  const restarted = create(); await restarted.tick(); expect(fetch).toHaveBeenCalledTimes(1);
  now = new Date(now.getTime() + 60_000); await restarted.tick();
  const saved = await records().findOne({});
  expect(saved?.submissionNotification).toMatchObject({ state: 'sent', attempts: 2 });
  expect(saved?.adminNotification.state).toBe('sent');
  const body = String(fetch.mock.calls[1][1]?.body);
  expect(body).toContain('2026-01-01T00:00:00.000Z');
  expect(body).not.toMatch(/VRA-|PRIVATE-NARRATIVE/);
 } finally { fetch.mockRestore(); }
});

test('invalid Slack configuration pauses the queue without consuming an attempt', async () => {
 enableSlack(); delete process.env.SLACK_ADMIN_URL; await insert();
 const send = jest.fn(); await create(send).tick();
 expect(send).not.toHaveBeenCalled();
 expect((await records().findOne({}))?.submissionNotification.attempts).toBe(0);
});

test('429 pauses the worker, refunds the still-owned attempt and persists Retry-After across restart', async () => {
 enableSlack(); await insert(); await insert({ trackingId: 'VRA-SECOND' });
 const send = jest.fn().mockResolvedValueOnce({ status: 'rate_limited', retryAfterMs: 120_000 }).mockResolvedValue('delivered');
 const first = create(send); await first.tick('VRA-A1B2C3D4E5F60718');
 const pending = await records().findOne({ trackingId: 'VRA-A1B2C3D4E5F60718' });
 expect(pending?.submissionNotification).toMatchObject({ state: 'pending', attempts: 0, nextAttemptAt: new Date(now.getTime() + 120_000) });
 expect(pending?.submissionNotification.leaseId).toBeUndefined();
 await first.tick('VRA-SECOND'); expect(send).toHaveBeenCalledTimes(1);
 expect((await records().findOne({ trackingId: 'VRA-SECOND' }))?.submissionNotification.attempts).toBe(0);
 await first.close(); const restarted = create(send);
 now = new Date(now.getTime() + 119_000); await restarted.tick('VRA-A1B2C3D4E5F60718');
 expect(send).toHaveBeenCalledTimes(1);
 now = new Date(now.getTime() + 1000); await restarted.tick('VRA-A1B2C3D4E5F60718');
 expect(send).toHaveBeenCalledTimes(2);
 expect((await records().findOne({ trackingId: 'VRA-A1B2C3D4E5F60718' }))?.submissionNotification.state).toBe('sent');
});

test('429 on the last allowed attempt does not exhaust delivery', async () => {
 enableSlack(); await insert({ submissionNotification: { state: 'pending', source: 'web', attempts: 4, nextAttemptAt: now } });
 await create(jest.fn(async () => ({ status: 'rate_limited', retryAfterMs: 120_000 }))).tick();
 expect((await records().findOne({}))?.submissionNotification).toMatchObject({ state: 'pending', attempts: 4 });
});

test('a late rate-limited sender cannot refund or replace a newer lease', async () => {
 enableSlack(); await insert();
 const send = jest.fn(async () => {
  await records().updateOne({}, { $set: { 'submissionNotification.leaseId': 'replacement', 'submissionNotification.attempts': 3 } });
  return { status: 'rate_limited', retryAfterMs: 120_000 };
 });
 await create(send).tick();
 expect((await records().findOne({}))?.submissionNotification).toMatchObject({ state: 'sending', attempts: 3, leaseId: 'replacement' });
});
