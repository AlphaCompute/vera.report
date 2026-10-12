/**
 * Evidence decryption keys at rest — end to end against a real MongoDB.
 *
 * Each evidence file's data-encryption key is stored WRAPPED (a key-envelope), never
 * beside its ciphertext in plaintext, and the wrap is bound to the record it belongs
 * to by an encryption context. So the guarantees are:
 *   - a save→get round-trip returns the original key (and the rest of the params);
 *   - what actually sits in the collection is the wrapped form, not the plaintext DEK;
 *   - a wrapped key stolen from one record cannot be unwrapped under another record's
 *     context (the context is the AES-GCM AAD / KMS EncryptionContext).
 *
 * Runs on the local key-envelope fallback (`enc:local:v1:…`) — no AWS/KMS call — so it
 * belongs in the CI gate. tests/integration/services; Mongo only, no proof server.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient } from 'mongodb';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import type { EvidenceDecryptionParams } from '../../../src/services/reportPersistence';
import { keyEnvelope } from '../../../src/services/keyEnvelope';

let mongoServer: MongoMemoryServer;
let rawClient: MongoClient;
const TOUCHED = ['MONGODB_URI', 'MONGODB_DB_NAME', 'AT_REST_LOCAL_KEY'] as const;
const savedEnv: Record<string, string | undefined> = {};

const DEK = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90'; // 32-byte hex data key
const FILE_KEY = 'VRA-EVIDENCE00000001/badge.jpg';

const params = (): EvidenceDecryptionParams => ({
  encryptionKey: DEK,
  originalCID: 'QmEvidenceCid',
  pinataIv: 'p-iv',
  pinataAuthTag: 'p-tag',
  pinataSalt: 'p-salt',
  evidenceSalt: 'e-salt',
  evidenceIv: 'e-iv',
  evidenceAuthTag: 'e-tag',
  mimetype: 'image/jpeg',
  contentHash: 'b'.repeat(64),
  contentSize: 1234,
});

beforeAll(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.MONGODB_DB_NAME = 'integration_evidence_envelope';
  process.env.AT_REST_LOCAL_KEY = 'evidence-envelope-integration-test-master-key'; // deterministic local wrap

  rawClient = new MongoClient(mongoServer.getUri());
  await rawClient.connect();
});

afterAll(async () => {
  await reportPersistenceService.close().catch(() => {});
  await rawClient?.close().catch(() => {});
  if (mongoServer) await mongoServer.stop();
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

const rawEvidenceDoc = (fileKey: string) =>
  rawClient.db('integration_evidence_envelope').collection('evidence_decryption_params').findOne({ fileKey });

describe('evidence key envelope', () => {
  it('round-trips the data key and the rest of the params through save → get', async () => {
    await reportPersistenceService.saveEvidenceParams(FILE_KEY, params());
    await reportPersistenceService.close();
    const got = await reportPersistenceService.getEvidenceParams(FILE_KEY);

    expect(got).not.toBeNull();
    expect(got!.encryptionKey).toBe(DEK); // unwrapped back to the original
    expect(got!.originalCID).toBe('QmEvidenceCid');
    expect(got!.evidenceIv).toBe('e-iv');
    expect(got!.evidenceAuthTag).toBe('e-tag');
    expect(got!.mimetype).toBe('image/jpeg');
  });

  it('stores the key wrapped at rest, never the plaintext DEK', async () => {
    await reportPersistenceService.saveEvidenceParams(FILE_KEY, params());
    const stored = await rawEvidenceDoc(FILE_KEY);

    expect(stored).not.toBeNull();
    expect(stored!.encryptionKey).toMatch(/^enc:(local|kms):v1:/); // enveloped
    expect(stored!.encryptionKey).not.toBe(DEK);
    expect(stored!.encryptionKey).not.toContain(DEK);
    // the non-secret params are stored as-is
    expect(stored!.mimetype).toBe('image/jpeg');
  });

  it('binds the wrapped key to its record — a foreign context cannot unwrap it', async () => {
    await reportPersistenceService.saveEvidenceParams(FILE_KEY, params());
    const stored = await rawEvidenceDoc(FILE_KEY);
    const wrapped = stored!.encryptionKey as string;

    // Correct context unwraps.
    await expect(keyEnvelope.unwrap(wrapped, { fileKey: FILE_KEY, purpose: 'evidence' })).resolves.toBe(DEK);
    // A different record's fileKey must not — a blob lifted from the DB can't be reused.
    await expect(keyEnvelope.unwrap(wrapped, { fileKey: 'VRA-OTHER0000/x.jpg', purpose: 'evidence' })).rejects.toThrow();
    // Nor a different purpose.
    await expect(keyEnvelope.unwrap(wrapped, { fileKey: FILE_KEY, purpose: 'narrative' })).rejects.toThrow();
  });
});
