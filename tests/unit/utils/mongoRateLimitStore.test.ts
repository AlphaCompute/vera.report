import express from 'express';
import request from 'supertest';
import rateLimit, { type Options } from 'express-rate-limit';
import { MongoClient, type Collection } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { closeRateLimitStore, MongoRateLimitStore, RATE_LIMIT_COLLECTION, sharedRateLimitStore, type RateLimitDoc } from '../../../src/utils/mongoRateLimitStore';
import { logger } from '../../../src/utils/logger';

// Two store instances over one collection stand in for two API tasks.
let mongo: MongoMemoryServer;
let client: MongoClient;
let collection: Collection<RateLimitDoc>;
const source = async () => collection;
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

function store(name: string, windowMs = 60_000, from: () => Promise<Collection<RateLimitDoc> | null> = source): MongoRateLimitStore {
  const instance = new MongoRateLimitStore(name, from);
  instance.init({ windowMs } as Options);
  return instance;
}

beforeAll(async () => {
  mongo = await MongoMemoryServer.create();
  client = await MongoClient.connect(mongo.getUri());
  collection = client.db('rate_limit_tests').collection<RateLimitDoc>(RATE_LIMIT_COLLECTION);
});
beforeEach(async () => { await collection.deleteMany({}); });
afterEach(() => jest.restoreAllMocks());
afterAll(async () => {
  await client?.close();
  await mongo?.stop();
});

it('counts hits from two instances against one shared budget', async () => {
  const taskA = store('submit');
  const taskB = store('submit');
  expect((await taskA.increment('ip:198.51.100.1')).totalHits).toBe(1);
  expect((await taskB.increment('ip:198.51.100.1')).totalHits).toBe(2);
  const third = await taskA.increment('ip:198.51.100.1');
  expect(third.totalHits).toBe(3);
  expect(await taskB.get('ip:198.51.100.1')).toEqual({ totalHits: 3, resetTime: third.resetTime });
  // Other clients and other limiters keep their own counters.
  expect((await taskB.increment('ip:198.51.100.2')).totalHits).toBe(1);
  expect((await store('status').increment('ip:198.51.100.1')).totalHits).toBe(1);
  taskA.shutdown(); taskB.shutdown();
});

it('starts exactly one window when instances race on a new key', async () => {
  const tasks = [store('race'), store('race')];
  const results = await Promise.all(Array.from({ length: 20 }, (_, i) => tasks[i % 2].increment('web:client')));
  expect(results.map(r => r.totalHits).sort((a, b) => a - b)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
  expect(new Set(results.map(r => r.resetTime!.getTime())).size).toBe(1);
  expect(await collection.countDocuments()).toBe(1);
});

it('resets the count once the window expires', async () => {
  const taskA = store('expiry', 300);
  const taskB = store('expiry', 300);
  await taskA.increment('ip:203.0.113.5');
  expect((await taskB.increment('ip:203.0.113.5')).totalHits).toBe(2);
  await sleep(350);
  expect(await taskA.get('ip:203.0.113.5')).toBeUndefined();
  const fresh = await taskB.increment('ip:203.0.113.5');
  expect(fresh.totalHits).toBe(1);
  expect(fresh.resetTime!.getTime()).toBeGreaterThan(Date.now());
  expect((await taskA.increment('ip:203.0.113.5')).totalHits).toBe(2);
});

it('applies decrement and resetKey across instances', async () => {
  const taskA = store('undo');
  const taskB = store('undo');
  await taskA.increment('k'); await taskA.increment('k');
  await taskB.decrement('k');
  expect((await taskA.get('k'))?.totalHits).toBe(1);
  await taskB.resetKey('k');
  expect(await taskA.get('k')).toBeUndefined();
  expect((await taskA.increment('k')).totalHits).toBe(1);
});

it('never stores the client key in the clear', async () => {
  await store('privacy').increment('ip:198.51.100.77');
  const [doc] = await collection.find().toArray();
  expect(JSON.stringify(doc)).not.toContain('198.51.100.77');
  expect(doc._id).toMatch(/^[a-f0-9]{64}$/);
});

it('connects through MONGODB_URI and expires windows with a TTL index', async () => {
  const original = { uri: process.env.MONGODB_URI, db: process.env.MONGODB_DB_NAME };
  process.env.MONGODB_URI = mongo.getUri();
  process.env.MONGODB_DB_NAME = 'rate_limit_shared';
  try {
    const shared = new MongoRateLimitStore('shared');
    shared.init({ windowMs: 60_000 } as Options);
    expect((await shared.increment('k')).totalHits).toBe(1);
    const indexes = await client.db('rate_limit_shared').collection(RATE_LIMIT_COLLECTION).indexes();
    expect(indexes).toEqual(expect.arrayContaining([expect.objectContaining({ key: { resetTime: 1 }, expireAfterSeconds: 0 })]));
    shared.shutdown();
  } finally {
    await closeRateLimitStore();
    if (original.uri === undefined) delete process.env.MONGODB_URI; else process.env.MONGODB_URI = original.uri;
    if (original.db === undefined) delete process.env.MONGODB_DB_NAME; else process.env.MONGODB_DB_NAME = original.db;
  }
});

it('fails open to per-instance counting with one warning when storage errors', async () => {
  const warn = jest.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const broken = store('degraded', 60_000, async () => { throw new Error('synthetic outage'); });
  expect((await broken.increment('k')).totalHits).toBe(1);
  expect((await broken.increment('k')).totalHits).toBe(2);
  await expect(broken.decrement('k')).resolves.toBeUndefined();
  await expect(broken.resetKey('k')).resolves.toBeUndefined();
  expect(warn).toHaveBeenCalledTimes(1);
  expect(String(warn.mock.calls[0][0])).toContain('synthetic outage');
  broken.shutdown();
});

it('counts locally when MongoDB is not configured', async () => {
  const unconfigured = store('local', 60_000, async () => null);
  expect((await unconfigured.increment('k')).totalHits).toBe(1);
  expect((await unconfigured.increment('k')).totalHits).toBe(2);
  expect(await collection.countDocuments()).toBe(0);
  unconfigured.shutdown();
});

it('enforces one limit across two express apps sharing the store', async () => {
  const app = () => {
    const server = express();
    server.use(rateLimit({ windowMs: 60_000, max: 3, keyGenerator: () => 'shared-client', store: store('http'), standardHeaders: true, legacyHeaders: false }));
    server.get('/', (_req, res) => res.sendStatus(204));
    return server;
  };
  const [taskA, taskB] = [app(), app()];
  expect((await request(taskA).get('/')).status).toBe(204);
  expect((await request(taskB).get('/')).status).toBe(204);
  expect((await request(taskA).get('/')).status).toBe(204);
  expect((await request(taskB).get('/')).status).toBe(429);
  expect((await request(taskA).get('/')).status).toBe(429);
});

it('keeps the library memory store under NODE_ENV=test', () => {
  expect(process.env.NODE_ENV).toBe('test');
  expect(sharedRateLimitStore('anything')).toBeUndefined();
});

it('writes counters to MongoDB only when RATE_LIMIT_SHARED_STORE=mongodb', () => {
  const env = { NODE_ENV: process.env.NODE_ENV, RATE_LIMIT_SHARED_STORE: process.env.RATE_LIMIT_SHARED_STORE };
  try {
    process.env.NODE_ENV = 'production';
    delete process.env.RATE_LIMIT_SHARED_STORE;
    expect(sharedRateLimitStore('default')).toBeUndefined();
    process.env.RATE_LIMIT_SHARED_STORE = 'memory';
    expect(sharedRateLimitStore('memory')).toBeUndefined();
    process.env.RATE_LIMIT_SHARED_STORE = 'mongodb';
    expect(sharedRateLimitStore('shared')).toBeInstanceOf(MongoRateLimitStore);
  } finally {
    process.env.NODE_ENV = env.NODE_ENV;
    if (env.RATE_LIMIT_SHARED_STORE === undefined) delete process.env.RATE_LIMIT_SHARED_STORE;
    else process.env.RATE_LIMIT_SHARED_STORE = env.RATE_LIMIT_SHARED_STORE;
  }
});
