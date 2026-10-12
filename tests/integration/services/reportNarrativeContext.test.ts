/**
 * Integration tests for the report narrative + evidence manifest context path.
 * Uses MongoMemoryServer for isolated database tests.
 * Follows the pattern in tests/integration/services/adminAuditLogMongo.test.ts.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import { encryptContactValue } from '@services/reportFieldCrypto';
import { randomBytes } from 'node:crypto';
import { reportPersistenceService } from '@services/reportPersistence';
import { evidenceEncryptionService } from '@services/evidenceEncryption';
import { disseminationService } from '@services/dissemination/disseminationService';
import type { EvidenceDecryptionParams } from '@services/reportPersistence';

describe('Report narrative context — MongoDB integration', () => {
  let mongoServer: MongoMemoryServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    process.env.MONGODB_URI = mongoServer.getUri();
    process.env.MONGODB_DB_NAME = 'test_report_context';
  });

  afterAll(async () => {
    await reportPersistenceService.close();
    const { disseminationPersistence } = await import('@services/dissemination/disseminationPersistence');
    await disseminationPersistence.disconnect();
    process.env.MONGODB_URI = '';
    process.env.MONGODB_DB_NAME = '';
    if (mongoServer) await mongoServer.stop();
  });

  function makeTrackingId(): string {
    return `VRA-${randomBytes(8).toString('hex').toUpperCase()}`;
  }

  function makeEvidenceParams(overrides: Partial<EvidenceDecryptionParams> = {}): EvidenceDecryptionParams {
    return {
      encryptionKey: randomBytes(32).toString('hex'),
      originalCID: 'bafy-test-cid',
      pinataIv: 'test-iv',
      pinataAuthTag: 'test-auth-tag',
      evidenceSalt: 'test-salt',
      evidenceIv: 'test-evidence-iv',
      evidenceAuthTag: 'test-evidence-auth-tag',
      mimetype: 'application/pdf',
      ...overrides,
    };
  }

  async function seedReport(trackingId: string): Promise<void> {
    await reportPersistenceService.upsert({
      trackingId,
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  }

  it('round-trips the encrypted narrative and rebuilds a CID-only evidence manifest', async () => {
    const trackingId = makeTrackingId();
    await seedReport(trackingId);

    const plaintext = 'The finance team backdated three vendor invoices in March.';
    const encryptionKey = randomBytes(32).toString('hex');
    const encrypted = await evidenceEncryptionService.encryptEvidence(
      plaintext,
      'text/plain',
      encryptionKey,
      { fileName: 'report.txt' },
    );

    await reportPersistenceService.patch(trackingId, {
      encryptedNarrative: {
        encryptedData: encrypted.encryptedData,
        encryptionKey,
        salt: encrypted.encryptionMetadata.salt,
        iv: encrypted.encryptionMetadata.iv,
        authTag: encrypted.encryptionMetadata.authTag,
      },
    });

    await reportPersistenceService.saveEvidenceParams(
      `${trackingId}/a.pdf`,
      makeEvidenceParams({ originalCID: 'cid-for-a-pdf' }),
    );
    await reportPersistenceService.saveEvidenceParams(
      `${trackingId}/b.png`,
      makeEvidenceParams({ originalCID: 'cid-for-b-png', mimetype: 'image/png' }),
    );

    const context = await reportPersistenceService.getReportContext(trackingId);

    expect(context).not.toBeNull();
    expect(context?.description).toBe(plaintext);
    expect(context?.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'a.pdf', ipfsHash: 'cid-for-a-pdf' }),
        expect.objectContaining({ name: 'b.png', ipfsHash: 'cid-for-b-png' }),
      ]),
    );
    expect(context?.evidence).toHaveLength(2);
  });

  it('excludes evidence files without a CID from the manifest', async () => {
    const trackingId = makeTrackingId();
    await seedReport(trackingId);

    await reportPersistenceService.saveEvidenceParams(
      `${trackingId}/no-cid.txt`,
      makeEvidenceParams({ originalCID: '' }),
    );

    const context = await reportPersistenceService.getReportContext(trackingId);

    expect(context).not.toBeNull();
    expect(context?.evidence.find((e) => e.name === 'no-cid.txt')).toBeUndefined();
  });

  it('resolves with an empty narrative instead of throwing when no narrative was persisted', async () => {
    const trackingId = makeTrackingId();
    await seedReport(trackingId);

    const context = await reportPersistenceService.getReportContext(trackingId);

    expect(context).not.toBeNull();
    expect(context?.description ?? '').toBe('');
  });

  it('resolves with an empty narrative instead of throwing when the ciphertext fails authentication', async () => {
    const trackingId = makeTrackingId();
    await seedReport(trackingId);

    const plaintext = 'Narrative that will be corrupted before decryption.';
    const encryptionKey = randomBytes(32).toString('hex');
    const encrypted = await evidenceEncryptionService.encryptEvidence(
      plaintext,
      'text/plain',
      encryptionKey,
      { fileName: 'report.txt' },
    );

    const corruptedAuthTag = Buffer.from(encrypted.encryptionMetadata.authTag, 'base64');
    corruptedAuthTag[0] ^= 0xff;

    await reportPersistenceService.patch(trackingId, {
      encryptedNarrative: {
        encryptedData: encrypted.encryptedData,
        encryptionKey,
        salt: encrypted.encryptionMetadata.salt,
        iv: encrypted.encryptionMetadata.iv,
        authTag: corruptedAuthTag.toString('base64'),
      },
    });

    const context = await reportPersistenceService.getReportContext(trackingId);

    expect(context).not.toBeNull();
    expect(context?.description ?? '').toBe('');
  });

  it('sources the dissemination view narrative from the persisted Mongo narrative', async () => {
    const trackingId = makeTrackingId();
    await seedReport(trackingId);

    const plaintext = 'A dissemination-view narrative persisted only in Mongo.';
    const encryptionKey = randomBytes(32).toString('hex');
    const encrypted = await evidenceEncryptionService.encryptEvidence(
      plaintext,
      'text/plain',
      encryptionKey,
      { fileName: 'report.txt' },
    );

    await reportPersistenceService.patch(trackingId, {
      encryptedNarrative: {
        encryptedData: encrypted.encryptedData,
        encryptionKey,
        salt: encrypted.encryptionMetadata.salt,
        iv: encrypted.encryptionMetadata.iv,
        authTag: encrypted.encryptionMetadata.authTag,
      },
    });

    const loaded = await disseminationService.buildView(trackingId);

    expect(loaded).not.toBeNull();
    expect(loaded?.view.narrative).toBe(plaintext);
  });
  it('retains legacy narratives across restart during the migration window', async () => {
    const trackingId = makeTrackingId();
    await reportPersistenceService.upsert({ trackingId, status: 'pending',
      encryptedDescription: encryptContactValue('Legacy narrative remains readable'),
      createdAt: new Date(), updatedAt: new Date(),
    });
    await reportPersistenceService.close();
    expect((await reportPersistenceService.getReportContext(trackingId))?.description).toBe('Legacy narrative remains readable');
  });

});
