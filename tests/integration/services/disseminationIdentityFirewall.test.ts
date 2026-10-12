/**
 * Dissemination identity firewall — end to end, against a real MongoDB.
 *
 * The whole safety promise of dissemination is that a packet bound for an outside
 * party (agency, counsel, press) carries the report's substance but NONE of the
 * reporter's identity surface: the encrypted reward-contact blob, the at-rest keys,
 * the raw encrypted narratives, and the zk nullifier (which correlates repeat
 * submissions). `DisseminationView` enforces this structurally — it copies only an
 * allowlist of fields — but that guarantee had no test that seeds a report full of
 * sensitive material and proves none of it survives into the view.
 *
 * This seeds two reports directly into an in-memory MongoDB and runs the real
 * `disseminationService.buildView` (load → decrypt → project), asserting the
 * firewall holds on both the readable-narrative path and the decrypt-failure path.
 * Lives under tests/integration/services so it runs in the CI gate — Mongo only,
 * no live proof server.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { encryptContactValue } from '../../../src/services/reportFieldCrypto';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';

// Distinctive sentinels, one per sensitive field. If any reaches the view, a plain
// substring scan of the serialized view catches it — even a field added later.
const CONTACT_CIPHER = 'ZZ-reward-contact-ciphertext-ZZ';
const CONTACT_WRAPPED = 'ZZ-contact-key-wrapped-ZZ';
const TOP_KEY = 'ZZ-top-encryption-key-ZZ';
const DISS_NARR = 'ZZ-encrypted-dissemination-narrative-ZZ';
const NULLIFIER = 'ZZ-zk-nullifier-ZZ';
const SECRETS = [CONTACT_CIPHER, CONTACT_WRAPPED, TOP_KEY, DISS_NARR, NULLIFIER];

const READABLE_NARRATIVE = 'The CFO booked fictitious Q3 revenue to clear the bonus threshold.';
const TID_READABLE = 'VRA-FIREWALLREADABLE';
const TID_UNREADABLE = 'VRA-FIREWALLUNREAD00';

let mongoServer: MongoMemoryServer;
let seedClient: MongoClient;
const TOUCHED = ['MONGODB_URI', 'MONGODB_DB_NAME', 'REWARD_ENCRYPTION_KEY'] as const;
const savedEnv: Record<string, string | undefined> = {};

/** A persisted report carrying identity material in every sensitive slot. */
function sensitiveReport(trackingId: string, encryptedDescription: string) {
  return {
    trackingId,
    category: 'financial-fraud',
    categories: ['fraud'],
    status: 'verified',
    processingStatus: 'completed',
    createdAt: new Date('2026-01-02T00:00:00.000Z'),
    urgency: 'high',
    location: 'Springfield',
    dateOfIncident: '2026-01-01',
    verification: {
      isLegitimate: true,
      credibilityScore: 88,
      category: 'financial-fraud',
      organizationType: 'public-company',
      namedOrganization: 'Acme Corp',
    },
    evidenceHash: 'ev-hash',
    ipfsHash: 'QmSafeCid',
    zkProof: { proofHash: 'ph', proofType: 'compact_circuit', contractAddress: '0xc', txHash: '0xt', verified: true, nullifier: NULLIFIER },
    consent: { agency: true, press: false, securedrop: false, psst: { treatment: 'hold-encrypted' }, version: 'v1' },
    encryptedDescription,
    // ↓ identity surface — none of this may cross the firewall
    encryptionKey: TOP_KEY,
    reward: { wantsReward: true, contactMethod: 'email', encryptedContactValue: CONTACT_CIPHER, contactKeyWrapped: CONTACT_WRAPPED },
    encryptedDisseminationNarrative: DISS_NARR,
    disseminationRecipients: ['whistleblower-org'],
  };
}

/** No sensitive value, and no forbidden key, survived into the outbound view. */
function assertNoLeak(view: Record<string, any>) {
  const serialized = JSON.stringify(view);
  for (const secret of SECRETS) expect(serialized).not.toContain(secret);
  for (const key of ['reward', 'encryptionKey', 'consent', 'encryptedDescription', 'encryptedNarrative', 'encryptedDisseminationNarrative', 'disseminationRecipients']) {
    expect(view).not.toHaveProperty(key);
  }
  if (view.zkProof) expect(view.zkProof).not.toHaveProperty('nullifier');
}

beforeAll(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.MONGODB_DB_NAME = 'integration_firewall';
  process.env.REWARD_ENCRYPTION_KEY = 'firewall-integration-test-key';

  seedClient = new MongoClient(mongoServer.getUri());
  await seedClient.connect();
  const reports = seedClient.db('integration_firewall').collection('whistleblower_reports');

  // Readable path: a valid encrypted narrative that decrypts cleanly.
  await reports.insertOne(sensitiveReport(TID_READABLE, encryptContactValue(READABLE_NARRATIVE)));
  // Decrypt-failure path: a malformed ciphertext — buildView treats this as non-fatal.
  await reports.insertOne(sensitiveReport(TID_UNREADABLE, 'ZZ-not-a-valid-ciphertext-ZZ'));
});

afterAll(async () => {
  await reportPersistenceService.close().catch(() => {});
  await disseminationPersistence.disconnect().catch(() => {});
  await seedClient?.close().catch(() => {});
  if (mongoServer) await mongoServer.stop();
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

describe('buildView serves the report substance', () => {
  it('decrypts the narrative and passes through non-identifying fields', async () => {
    const loaded = await disseminationService.buildView(TID_READABLE);
    expect(loaded).not.toBeNull();
    const { view, narrativeReadable } = loaded!;

    expect(narrativeReadable).toBe(true);
    expect(view.trackingId).toBe(TID_READABLE);
    expect(view.narrative).toBe(READABLE_NARRATIVE);
    expect(view.rawCategories).toContain('fraud');
    expect(view.verification).toEqual({ credibilityScore: 88, category: 'financial-fraud' });
    expect(view.psstTreatment).toBe('hold-encrypted'); // handling election is metadata, not identity
    expect(view.zkProof?.verified).toBe(true);
  });
});

describe('identity firewall — nothing identifying crosses into the view', () => {
  it('strips reward contact, at-rest keys, raw narratives and the nullifier (readable report)', async () => {
    const { view } = (await disseminationService.buildView(TID_READABLE))!;
    assertNoLeak(view);
  });

  it('still fails closed on the identity surface when the narrative cannot be decrypted', async () => {
    const loaded = await disseminationService.buildView(TID_UNREADABLE);
    expect(loaded).not.toBeNull();
    const { view, narrativeReadable } = loaded!;

    // Decrypt failure is non-fatal: the narrative is blank + flagged, never raw ciphertext.
    expect(narrativeReadable).toBe(false);
    expect(view.narrative).toBe('');
    assertNoLeak(view);
  });

  it('returns null for an unknown tracking id rather than a partial view', async () => {
    expect(await disseminationService.buildView('VRA-DOESNOTEXIST0000')).toBeNull();
  });
});
