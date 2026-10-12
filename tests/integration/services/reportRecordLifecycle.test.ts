/**
 * Report record lifecycle — persistence contract, end to end against a real MongoDB.
 *
 * Two guarantees the admin surface leans on, neither exercised outside mocks:
 *   1. the reporter's reward contact is stored AES-256-GCM encrypted and survives a
 *      Mongo round-trip — the ciphertext comes back byte-for-byte and still decrypts,
 *      and the plaintext is never what sits in the collection;
 *   2. a verification patch (what the #595 re-analyze endpoint writes) updates the
 *      AI fields and `processingStatus` WITHOUT touching the human triage `status`,
 *      and a triage `status` change likewise leaves the verification intact.
 *
 * Also pins the fail-loud contract: patching a tracking id that does not exist must
 * throw, never silently upsert a ghost report.
 *
 * Uses the real reportPersistenceService (upsert/get/patch/list) so the contract is
 * tested, not a re-implementation. tests/integration/services → runs in the CI gate;
 * Mongo only, no proof server.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import { encryptRewardContact, decryptRewardContact } from '../../../src/services/rewardContact';
import { encryptContactValue, decryptContactValue } from '../../../src/services/reportFieldCrypto';
import { reportPersistenceService } from '../../../src/services/reportPersistence';

let mongoServer: MongoMemoryServer;
const TOUCHED = ['MONGODB_URI', 'MONGODB_DB_NAME', 'REWARD_ENCRYPTION_KEY'] as const;
const savedEnv: Record<string, string | undefined> = {};

/** Persist a minimal-but-realistic report; overrides win. */
async function seed(trackingId: string, over: Record<string, unknown> = {}) {
  await reportPersistenceService.upsert({
    trackingId,
    category: 'fraud',
    status: 'reviewing',
    processingStatus: 'processing',
    consent: { agency: true, press: false, psst: { treatment: 'hold-encrypted' }, version: 'v1' },
    createdAt: new Date('2026-01-02T00:00:00.000Z'),
    updatedAt: new Date('2026-01-02T00:00:00.000Z'),
    ...over,
  } as any);
}

beforeAll(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.MONGODB_DB_NAME = 'integration_lifecycle';
  process.env.REWARD_ENCRYPTION_KEY = 'lifecycle-integration-test-key';
});

afterAll(async () => {
  await reportPersistenceService.close().catch(() => {});
  if (mongoServer) await mongoServer.stop();
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

describe('reward-contact confidentiality survives MongoDB', () => {
  it('persists a current wrapped contact and reads it after reconnecting the Mongo client', async () => {
    const trackingId = 'VRA-1111111111111111';
    const contact = 'current-reward@example.test';
    const encrypted = await encryptRewardContact(contact, trackingId);
    await seed(trackingId, { reward: { wantsReward: true, contactMethod: 'email',
      encryptedContactValue: encrypted.ciphertext, contactKeyWrapped: encrypted.wrappedKey } });
    await reportPersistenceService.close();
    const got = await reportPersistenceService.get(trackingId);
    expect(JSON.stringify(got)).not.toContain(contact);
    expect(got!.reward!.contactKeyWrapped).toBe(encrypted.wrappedKey);
    expect(await decryptRewardContact({ ciphertext: got!.reward!.encryptedContactValue!,
      wrappedKey: got!.reward!.contactKeyWrapped! }, trackingId)).toBe(contact);
  });

  it('stores the contact encrypted and round-trips it back decryptable', async () => {
    const contact = 'signal:+1-555-0100';
    const ciphertext = encryptContactValue(contact);
    await seed('VRA-LIFECYCLE0000CTC', {
      reward: { wantsReward: true, contactMethod: 'signal', encryptedContactValue: ciphertext },
    });

    const got = await reportPersistenceService.get('VRA-LIFECYCLE0000CTC');
    expect(got).not.toBeNull();
    expect(got!.reward?.encryptedContactValue).toBe(ciphertext); // came back byte-for-byte
    expect(got!.reward?.encryptedContactValue).not.toContain(contact); // never stored as plaintext
    expect(decryptContactValue(got!.reward!.encryptedContactValue!)).toBe(contact); // and still decrypts
  });
});

describe('patch semantics separate AI verification from human triage', () => {
  it('a verification patch leaves the triage status untouched (the #595 re-analyze invariant)', async () => {
    await seed('VRA-LIFECYCLE000VER1', { status: 'reviewing', processingStatus: 'processing' });

    // Exactly the shape the re-analyze endpoint writes.
    await reportPersistenceService.patch('VRA-LIFECYCLE000VER1', {
      processingStatus: 'completed',
      verification: { isLegitimate: true, credibilityScore: 77, category: 'financial-fraud' },
    } as any);

    const got = await reportPersistenceService.get('VRA-LIFECYCLE000VER1');
    expect(got!.processingStatus).toBe('completed');
    expect(got!.verification?.credibilityScore).toBe(77);
    expect(got!.status).toBe('reviewing'); // NOT reset by re-scoring — the whole point
  });

  it('a triage status change preserves the existing verification', async () => {
    await seed('VRA-LIFECYCLE000VER2', {
      status: 'reviewing',
      verification: { isLegitimate: true, credibilityScore: 91, category: 'safety' },
    });

    await reportPersistenceService.patch('VRA-LIFECYCLE000VER2', { status: 'investigating' } as any);

    const got = await reportPersistenceService.get('VRA-LIFECYCLE000VER2');
    expect(got!.status).toBe('investigating');
    expect(got!.verification?.credibilityScore).toBe(91); // triage move didn't drop the AI fields
  });
});

describe('fail-loud + listing', () => {
  it('refuses to patch a tracking id that does not exist (no ghost report)', async () => {
    await expect(
      reportPersistenceService.patch('VRA-LIFECYCLENOSUCH0', { status: 'resolved' } as any),
    ).rejects.toThrow(/not persisted/i);
    expect(await reportPersistenceService.get('VRA-LIFECYCLENOSUCH0')).toBeNull();
  });

  it('surfaces persisted reports through list()', async () => {
    await seed('VRA-LIFECYCLE000LIST');
    const rows = await reportPersistenceService.list(50);
    expect(rows.some((r) => r.trackingId === 'VRA-LIFECYCLE000LIST')).toBe(true);
  });
});
