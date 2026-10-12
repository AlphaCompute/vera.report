/**
 * Shared express-rate-limit store backed by MongoDB (issue #1043).
 *
 * The API runs as one task per enclave host behind an ALB without
 * stickiness. With the default in-memory store each task counts on its own,
 * so every limit is effectively multiplied by the task count. This store
 * keeps one fixed-window counter per (limiter, client key) document so all
 * tasks share the budget. Redis is not available to the API (#1010), and
 * MongoDB already is.
 *
 * Plain update operators only (no pipeline updates) so the same code runs on
 * DocumentDB. Document ids are an HMAC of the limiter name and client key:
 * the fallback client key is the caller's IP address, which must never be
 * written to storage in the clear.
 */

import { createHash, createHmac } from 'node:crypto';
import { MongoClient, type Collection } from 'mongodb';
import { MemoryStore, type ClientRateLimitInfo, type Options, type Store } from 'express-rate-limit';
import { logger } from './logger';

export type RateLimitDoc = { _id: string; hits: number; resetTime: Date };

export const RATE_LIMIT_COLLECTION = 'api_rate_limits';
/** After a storage error, count locally for this long before retrying MongoDB. */
const STORE_COOLDOWN_MS = 30_000;
const WARN_INTERVAL_MS = 60_000;
const MAX_UPSERT_ATTEMPTS = 3;

type CollectionSource = () => Promise<Collection<RateLimitDoc> | null>;

let shared: { client: MongoClient; collection: Promise<Collection<RateLimitDoc>> } | null = null;

/** One lazily connected client per process for every limiter. Null when MongoDB is not configured. */
async function sharedCollection(): Promise<Collection<RateLimitDoc> | null> {
  const uri = process.env.MONGODB_URI?.trim();
  if (!uri) return null;
  if (!shared) {
    const tlsCAFile = process.env.MONGODB_TLS_CA_FILE;
    // Short timeouts: a limiter must not hold a request for the driver's 30s default.
    const client = new MongoClient(uri, {
      readPreference: 'primary',
      ...(tlsCAFile ? { tlsCAFile } : {}),
      serverSelectionTimeoutMS: 2_000,
      connectTimeoutMS: 2_000,
      socketTimeoutMS: 5_000,
    });
    const collection = (async () => {
      await client.connect();
      const coll = client.db(process.env.MONGODB_DB_NAME || 'vera').collection<RateLimitDoc>(RATE_LIMIT_COLLECTION);
      // Expired windows are also ignored by the queries, so TTL lag is harmless.
      await coll.createIndex({ resetTime: 1 }, { expireAfterSeconds: 0 });
      return coll;
    })();
    shared = { client, collection };
    collection.catch(async () => {
      // Drop the failed client so the next attempt after the cooldown reconnects.
      if (shared?.client === client) shared = null;
      await client.close().catch(() => {});
    });
  }
  return shared.collection;
}

/** Close the shared client (graceful shutdown and tests). */
export async function closeRateLimitStore(): Promise<void> {
  const current = shared;
  shared = null;
  await current?.client.close().catch(() => {});
}

function isDuplicateKeyError(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: number }).code === 11000;
}

export class MongoRateLimitStore implements Store {
  readonly localKeys = false;
  readonly prefix: string;
  private windowMs = 60_000;
  private readonly fallback = new MemoryStore();
  private unavailableUntil = 0;
  private lastWarnAt = 0;

  constructor(private readonly name: string, private readonly source: CollectionSource = sharedCollection) {
    // The prefix keeps express-rate-limit's double-count check from treating
    // two limiters on one request (e.g. general plus submit) as the same counter.
    this.prefix = `${name}:`;
  }

  init(options: Options): void {
    this.windowMs = options.windowMs;
    this.fallback.init(options);
  }

  private id(key: string): string {
    const material = `vera:rate-limit:v1\0${this.name}\0${key}`;
    const secret = process.env.INTERNAL_API_SECRET;
    return secret
      ? createHmac('sha256', secret).update(material).digest('hex')
      : createHash('sha256').update(material).digest('hex');
  }

  /**
   * Run against MongoDB, or against the per-process memory store when MongoDB
   * is not configured or failed recently.
   *
   * Fail open to local counting rather than fail closed: these limiters guard
   * public intake, status and admin reads, and a MongoDB outage must not turn
   * into a refusal of every whistleblower submission. The worst case while
   * degraded is the pre-#1043 behaviour (each task enforces its own limit).
   */
  private async run<T>(op: string, mongo: (coll: Collection<RateLimitDoc>) => Promise<T>, local: () => Promise<T> | T): Promise<T> {
    if (Date.now() >= this.unavailableUntil) {
      try {
        const coll = await this.source();
        if (coll) return await mongo(coll);
      } catch (err: unknown) {
        this.unavailableUntil = Date.now() + STORE_COOLDOWN_MS;
        if (Date.now() - this.lastWarnAt >= WARN_INTERVAL_MS) {
          this.lastWarnAt = Date.now();
          const msg = err instanceof Error ? err.message : String(err);
          logger.warn(`[RATE_LIMIT] Shared store ${op} failed for ${this.name}; counting per task for ${STORE_COOLDOWN_MS / 1000}s: ${msg}`);
        }
      }
    }
    return local();
  }

  async get(key: string): Promise<ClientRateLimitInfo | undefined> {
    return this.run('get', async coll => {
      const doc = await coll.findOne({ _id: this.id(key), resetTime: { $gt: new Date() } });
      return doc ? { totalHits: doc.hits, resetTime: doc.resetTime } : undefined;
    }, () => this.fallback.get(key));
  }

  async increment(key: string): Promise<ClientRateLimitInfo> {
    return this.run('increment', async coll => {
      const _id = this.id(key);
      for (let attempt = 1; attempt <= MAX_UPSERT_ATTEMPTS; attempt++) {
        const now = new Date();
        // Inside the current window: count the hit.
        const current = await coll.findOneAndUpdate(
          { _id, resetTime: { $gt: now } },
          { $inc: { hits: 1 } },
          { returnDocument: 'after' },
        );
        if (current) return { totalHits: current.hits, resetTime: current.resetTime };
        try {
          // No window, or an expired one: start a new window. When another task
          // opened the window first, the upsert collides on _id and we retry
          // the increment above.
          const started = await coll.findOneAndUpdate(
            { _id, resetTime: { $lte: now } },
            { $set: { hits: 1, resetTime: new Date(now.getTime() + this.windowMs) } },
            { upsert: true, returnDocument: 'after' },
          );
          if (started) return { totalHits: started.hits, resetTime: started.resetTime };
        } catch (err: unknown) {
          if (!isDuplicateKeyError(err)) throw err;
        }
      }
      throw new Error('rate limit window kept changing during increment');
    }, () => this.fallback.increment(key));
  }

  async decrement(key: string): Promise<void> {
    await this.run('decrement', async coll => {
      await coll.updateOne({ _id: this.id(key), resetTime: { $gt: new Date() }, hits: { $gt: 0 } }, { $inc: { hits: -1 } });
    }, () => this.fallback.decrement(key));
  }

  async resetKey(key: string): Promise<void> {
    // Always clear the local counter too, in case it was used while degraded.
    this.fallback.resetKey(key);
    await this.run('resetKey', async coll => { await coll.deleteOne({ _id: this.id(key) }); }, () => undefined);
  }

  shutdown(): void {
    this.fallback.shutdown();
  }
}

/**
 * Store for a named limiter. Undefined (the library's per-process memory
 * store) unless RATE_LIMIT_SHARED_STORE=mongodb, so by default no counter
 * derived from a caller's IP address is ever written to the database or its
 * backups. Every environment runs one API task, so memory counting enforces
 * the same limits; opt in to the shared store before scaling the API out.
 * Also undefined under NODE_ENV=test. Each name must be unique: it scopes the
 * counters.
 */
export function sharedRateLimitStore(name: string): Store | undefined {
  if (process.env.NODE_ENV === 'test') return undefined;
  if (process.env.RATE_LIMIT_SHARED_STORE !== 'mongodb') return undefined;
  return new MongoRateLimitStore(name);
}
