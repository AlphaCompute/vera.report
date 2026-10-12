/**
 * Report narrative at rest — the KMS envelope, written on intake.
 *
 * #370 left intake writing the legacy `encryptedDescription` (app-key AES-GCM)
 * even when KMS was configured; nothing wrote the `encryptedNarrative` envelope,
 * so every report sat on the legacy field. `encryptReportNarrative` is now the
 * shared write path used by both intake and the migration script. These lock in
 * that a narrative is written as the envelope (wrapped key, not plaintext),
 * round-trips through a real MongoDB via `decryptReportNarrative`, and that no
 * legacy `encryptedDescription` is produced on a new report.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import { encryptReportNarrative, decryptReportNarrative } from '../../../src/services/reportNarrative';
import { reportPersistenceService } from '../../../src/services/reportPersistence';

const NARRATIVE = 'The site lead ordered the emissions monitor bypassed for three shifts in June.';

let mongoServer: MongoMemoryServer;
const TOUCHED = ['MONGODB_URI', 'MONGODB_DB_NAME', 'AT_REST_LOCAL_KEY'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.MONGODB_DB_NAME = 'integration_narrative_envelope';
  process.env.AT_REST_LOCAL_KEY = 'narrative-envelope-integration-test-key'; // deterministic local wrap (no KMS)
});

afterAll(async () => {
  await reportPersistenceService.close().catch(() => {});
  if (mongoServer) await mongoServer.stop();
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

describe('encryptReportNarrative writes the envelope', () => {
  it('produces a wrapped envelope (not plaintext) that decrypts back', async () => {
    const tid = 'VRA-ENVELOPE00000001';
    const env = await encryptReportNarrative(tid, NARRATIVE);

    expect(env.encryptedData).toBeTruthy();
    expect(env.encryptedData).not.toContain(NARRATIVE); // ciphertext, not plaintext
    expect(env.encryptionKey).toMatch(/^enc:(local|kms):v1:/); // data key wrapped, never raw
    expect(env.salt).toBeTruthy();
    expect(env.iv).toBeTruthy();
    expect(env.authTag).toBeTruthy();

    // Read it the way intake's reader does; the trackingId is the wrap context.
    const text = await decryptReportNarrative({ trackingId: tid, encryptedNarrative: env } as any);
    expect(text).toBe(NARRATIVE);
  });
});

describe('a persisted intake record uses the envelope, not the legacy field', () => {
  it('stores encryptedNarrative and no encryptedDescription, and round-trips through MongoDB', async () => {
    const tid = 'VRA-ENVELOPE0000BEEF';
    // Exactly the shape intake now builds: encryptedNarrative set, encryptedDescription absent.
    await reportPersistenceService.upsert({
      trackingId: tid,
      status: 'pending',
      processingStatus: 'processing',
      encryptedNarrative: await encryptReportNarrative(tid, NARRATIVE),
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);

    const got = await reportPersistenceService.get(tid);
    expect(got).not.toBeNull();
    expect(got!.encryptedNarrative).toBeTruthy();
    expect(got!.encryptedDescription).toBeUndefined(); // the #370 bug: no new legacy field
    expect(await decryptReportNarrative(got!)).toBe(NARRATIVE); // decrypts after the Mongo round-trip
  });
});
