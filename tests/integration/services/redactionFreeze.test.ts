/**
 * Admin redaction freeze — end to end against a real MongoDB.
 *
 * The redaction pass is the reporter's protection against self-identifying detail in
 * their own narrative. Once an admin freezes the redacted copy onto the disposition
 * (`narrativeOverride`), everything rendered from the dissemination view must use it —
 * the raw narrative never leaves the platform again.
 *
 * This seeds two reports with the same raw (encrypted) narrative into an in-memory
 * MongoDB and runs the real `disseminationService.buildView`:
 *   - with no override, the raw narrative decrypts through (the pre-review state);
 *   - with a frozen override, the view serves the redacted copy and the raw is gone.
 *
 * tests/integration/services → runs in the CI gate; Mongo only, no proof server.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import { encryptContactValue } from '../../../src/services/reportFieldCrypto';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';

const RAW = 'The plant manager Jane Doe falsified the Q3 emissions log on 14 March 2026.';
const REDACTED = 'A manager falsified an emissions log during Q3. [name and date redacted]';
const TID_RAW = 'VRA-REDACTFREEZE00RAW';
const TID_RED = 'VRA-REDACTFREEZEFROZE';

let mongoServer: MongoMemoryServer;
const TOUCHED = ['MONGODB_URI', 'MONGODB_DB_NAME', 'REWARD_ENCRYPTION_KEY'] as const;
const savedEnv: Record<string, string | undefined> = {};

const reportDoc = (trackingId: string) => ({
  trackingId,
  category: 'environmental',
  status: 'verified',
  processingStatus: 'completed',
  verification: { isLegitimate: true, credibilityScore: 84, category: 'environmental' },
  consent: { agency: true, press: false, psst: { treatment: 'hold-encrypted' }, version: 'v1' },
  encryptedDescription: encryptContactValue(RAW),
  createdAt: new Date('2026-03-15T00:00:00.000Z'),
  updatedAt: new Date('2026-03-15T00:00:00.000Z'),
});

beforeAll(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.MONGODB_DB_NAME = 'integration_redaction_freeze';
  process.env.REWARD_ENCRYPTION_KEY = 'redaction-freeze-integration-test-key';

  await reportPersistenceService.upsert(reportDoc(TID_RAW) as any);
  await reportPersistenceService.upsert(reportDoc(TID_RED) as any);

  // Freeze an admin-accepted redaction onto the second report's disposition.
  await disseminationPersistence.upsertDisposition({
    trackingId: TID_RED,
    channels: [],
    consentSnapshot: { agency: true, press: false, psst: { treatment: 'hold-encrypted' }, version: 'v1' } as any,
    approvedBy: 'synthetic-admin',
    narrativeOverride: { narrative: REDACTED, notes: ['scrubbed name + exact date'], setBy: 'synthetic-admin', setAt: new Date() },
  } as any);
});

afterAll(async () => {
  await reportPersistenceService.close().catch(() => {});
  await disseminationPersistence.disconnect().catch(() => {});
  if (mongoServer) await mongoServer.stop();
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

describe('dissemination view narrative source', () => {
  it('decrypts the raw narrative when no redaction has been frozen (pre-review)', async () => {
    const loaded = await disseminationService.buildView(TID_RAW);
    expect(loaded).not.toBeNull();
    expect(loaded!.narrativeReadable).toBe(true);
    expect(loaded!.view.narrative).toBe(RAW);
  });

  it('serves the frozen redaction and never the raw narrative once an admin accepts it', async () => {
    const loaded = await disseminationService.buildView(TID_RED);
    expect(loaded).not.toBeNull();
    const { view, narrativeReadable } = loaded!;

    expect(narrativeReadable).toBe(true);
    expect(view.narrative).toBe(REDACTED);
    // The raw narrative — and its self-identifying specifics — must not survive anywhere in the view.
    expect(JSON.stringify(view)).not.toContain(RAW);
    expect(view.narrative).not.toContain('Jane Doe');
    expect(view.narrative).not.toContain('14 March');
  });
});
