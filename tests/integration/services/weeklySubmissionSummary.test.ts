import { MongoClient, type Db } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { WeeklySubmissionSummaryWorker } from '../../../src/services/weeklySubmissionSummary';
import { WeeklySubmissionSummaryStore } from '../../../src/services/confidentialCaseStore';

const env = { DEPLOY_ENV: 'staging', WEEKLY_SUBMISSION_SUMMARY_ENABLED: 'true',
  SLACK_WEEKLY_SUMMARY_WEBHOOK_URL: 'https://hooks.slack.com/services/TEST/TEST/SYNTHETIC' };
const start = Date.parse('2026-09-28T00:00:00Z'), end = Date.parse('2026-10-05T00:00:00Z');
let server: MongoMemoryServer, client: MongoClient, db: Db, now: number;
const store = () => new WeeklySubmissionSummaryStore(db);
const worker = (send: ConstructorParameters<typeof WeeklySubmissionSummaryWorker>[2], source = store()) =>
  new WeeklySubmissionSummaryWorker(source, env, send, () => now);
const journal = () => db.collection('confidential_weekly_submission_summaries');
beforeAll(async () => {
  server = await MongoMemoryServer.create();
  client = await MongoClient.connect(server.getUri());
  db = client.db('weekly_summary_test');
}, 120_000);
beforeEach(async () => {
  now = end + 9 * 3_600_000;
  await db.collection('confidential_cases').deleteMany({});
  await journal().deleteMany({});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'info').mockImplementation(() => {});
});
afterEach(() => jest.restoreAllMocks());
afterAll(async () => { await client?.close(); await server?.stop(); });

test('counts accepted rows once at week boundaries, including hidden and unlisted reports', async () => {
  const cases = db.collection<{ _id: string; createdAt: number; directoryHidden?: boolean; listingDigest?: string | null }>('confidential_cases');
  await cases.insertMany([
    { _id: 'before', createdAt: start - 1 }, { _id: 'first', createdAt: start, listingDigest: null },
    { _id: 'hidden', createdAt: start + 86_400_000, directoryHidden: true },
    { _id: 'last', createdAt: end - 1 }, { _id: 'next-week', createdAt: end },
  ]);
  await expect(cases.insertOne({ _id: 'first', createdAt: start })).rejects.toMatchObject({ code: 11000 });
  await db.collection('confidential_staged_objects').insertOne({ createdAt: start });
  await db.collection('confidential_access_requests').insertOne({ createdAt: start });
  const send = jest.fn(async () => 'delivered' as const);
  await worker(send).tick();
  expect(send).toHaveBeenCalledWith(env.SLACK_WEEKLY_SUMMARY_WEBHOOK_URL, { start, end }, 3);
  expect(await journal().findOne({})).toMatchObject({ state: 'sent', total: 3, attempts: 1 });
});

test('concurrent replicas, repeated ticks and a restart send one weekly message, including zero', async () => {
  const send = jest.fn(async () => 'delivered' as const);
  const first = worker(send), second = worker(send);
  await Promise.all([first.tick(), first.tick(), second.tick()]);
  await worker(send).tick();
  expect(send).toHaveBeenCalledTimes(1);
  expect(send).toHaveBeenCalledWith(env.SLACK_WEEKLY_SUMMARY_WEBHOOK_URL, { start, end }, 0);
  expect(await journal().countDocuments()).toBe(1);
  now += 7 * 86_400_000;
  await first.tick();
  expect(send).toHaveBeenCalledTimes(2);
  expect(await journal().countDocuments()).toBe(2);
});

test('retries after restart with a frozen total and persisted backoff', async () => {
  await db.collection('confidential_cases').insertOne({ createdAt: start });
  const send = jest.fn().mockResolvedValueOnce('failed').mockResolvedValue('delivered');
  await worker(send).tick();
  await db.collection('confidential_cases').insertOne({ createdAt: start });
  now += 59_999;
  await worker(send).tick(); expect(send).toHaveBeenCalledTimes(1);
  now += 1;
  await worker(send).tick(); expect(send).toHaveBeenCalledTimes(2);
  expect(send.mock.calls.map(call => call[2])).toEqual([1, 1]);
  expect(await journal().findOne({})).toMatchObject({ state: 'sent', attempts: 2, total: 1 });
});

test('a rejected 429 persists its deadline across replicas without spending the retry budget', async () => {
  const send = jest.fn().mockResolvedValueOnce({ retryAfterMs: 3_600_000 }).mockResolvedValue('delivered');
  await worker(send).tick();
  expect(await journal().findOne({})).toMatchObject({ state: 'pending', attempts: 0 });
  now += 3_599_999;
  await worker(send).tick(); expect(send).toHaveBeenCalledTimes(1);
  now += 1;
  await worker(send).tick(); expect(send).toHaveBeenCalledTimes(2);
});

test('five delivery failures stop retries for that week', async () => {
  const send = jest.fn(async () => 'failed' as const);
  for (let i = 0; i < 7; i++) { await worker(send).tick(); now += 3_600_000; }
  expect(send).toHaveBeenCalledTimes(5);
  expect(await journal().findOne({})).toMatchObject({ state: 'failed', attempts: 5 });
});

test('a late failed sender cannot overwrite a newer lease that successfully sent', async () => {
  let release!: (result: 'failed') => void;
  let sending!: () => void;
  const started = new Promise<void>(resolve => { sending = resolve; });
  const first = worker(jest.fn(() => { sending(); return new Promise<'failed'>(resolve => { release = resolve; }); }));
  const pending = first.tick(); await started;
  now += 60_001;
  const send = jest.fn(async () => 'delivered' as const);
  await worker(send).tick();
  release('failed'); await pending;
  expect(send).toHaveBeenCalledTimes(1);
  expect(await journal().findOne({})).toMatchObject({ state: 'sent', attempts: 2 });
});

test('count failures do not send misleading zeros; the next attempt recovers', async () => {
  const source = store();
  jest.spyOn(source, 'count').mockRejectedValueOnce(new Error('PRIVATE_DATABASE_ERROR'));
  const send = jest.fn(async () => 'delivered' as const);
  const instance = worker(send, source);
  await instance.tick(); expect(send).not.toHaveBeenCalled();
  now += 60_000;
  await instance.tick(); expect(send).toHaveBeenCalledTimes(1);
  expect(JSON.stringify((console.warn as jest.Mock).mock.calls)).not.toContain('PRIVATE_DATABASE_ERROR');
});

test('shutdown waits for in-flight counting and prevents a subsequent Slack send', async () => {
  const source = store();
  let counted!: (total: number) => void, started!: () => void;
  const began = new Promise<void>(resolve => { started = resolve; });
  jest.spyOn(source, 'count').mockImplementation(() => { started(); return new Promise(resolve => { counted = resolve; }); });
  const send = jest.fn(async () => 'delivered' as const);
  const instance = worker(send, source);
  const running = instance.tick(); await began;
  const closing = instance.close(); counted(2); await Promise.all([running, closing]);
  await instance.tick(); expect(send).not.toHaveBeenCalled();
});
