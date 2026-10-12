/**
 * One-time secure-packet consumed-store — the single-use guard behind the
 * emailed link (VERA-PDR-001, reporter-reward flow). Uses MongoMemoryServer for
 * an isolated, real MongoDB (the unique index is what enforces the guarantee).
 *
 * The security properties: a jti is burned exactly once, a replay is rejected,
 * exactly one of many concurrent consumes wins, and if the store is unavailable
 * the consume FAILS CLOSED (throws) so the route refuses to serve an unguarded
 * packet — deliberately unlike the rest of this service's memory fallback.
 */
import { MongoMemoryServer } from 'mongodb-memory-server';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';

describe('secure-link consumed-store (single-use guard)', () => {
  let mongoServer: MongoMemoryServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    process.env.MONGODB_URI = mongoServer.getUri();
    process.env.MONGODB_DB_NAME = 'test_securelink';
    await disseminationPersistence.disconnect(); // force a fresh connect to the memory server
  });

  afterAll(async () => {
    await disseminationPersistence.disconnect();
    if (mongoServer) await mongoServer.stop();
  });

  it('consumes a jti exactly once and rejects replays', async () => {
    const jti = 'jti-once-0001';
    const first = await disseminationPersistence.consumeSecureLink({
      jti, trackingId: 'VRA-1', entityId: 'secure-link',
    });
    expect(first).toBe(true);
    const second = await disseminationPersistence.consumeSecureLink({
      jti, trackingId: 'VRA-1', entityId: 'secure-link',
    });
    expect(second).toBe(false);
  });

  it('reports consumption state without consuming', async () => {
    const jti = 'jti-state-0002';
    expect(await disseminationPersistence.isSecureLinkConsumed(jti)).toBe(false);
    await disseminationPersistence.consumeSecureLink({ jti, trackingId: 'VRA-2', entityId: 'secure-link' });
    expect(await disseminationPersistence.isSecureLinkConsumed(jti)).toBe(true);
  });

  it('lets exactly one of many concurrent consumes win (unique index)', async () => {
    const jti = 'jti-race-0003';
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        disseminationPersistence.consumeSecureLink({ jti, trackingId: 'VRA-3', entityId: 'secure-link' }),
      ),
    );
    expect(results.filter((r) => r === true)).toHaveLength(1);
    expect(results.filter((r) => r === false)).toHaveLength(7);
  });

  it('fails closed when the store is unavailable', async () => {
    await disseminationPersistence.disconnect();
    const savedUri = process.env.MONGODB_URI;
    delete process.env.MONGODB_URI; // connect() early-returns; no collection handle
    try {
      await expect(
        disseminationPersistence.consumeSecureLink({
          jti: 'jti-failclosed', trackingId: 'VRA-4', entityId: 'secure-link',
        }),
      ).rejects.toThrow(/unavailable|fail-closed/i);
      // The best-effort read degrades to "not consumed" so the landing still renders.
      expect(await disseminationPersistence.isSecureLinkConsumed('jti-failclosed')).toBe(false);
    } finally {
      process.env.MONGODB_URI = savedUri;
    }
  });
});
