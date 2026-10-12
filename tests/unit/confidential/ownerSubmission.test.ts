import { createHash, randomBytes, webcrypto } from 'node:crypto';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { BSON } from 'mongodb';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import {
  CONFIDENTIAL_FILE_LIMIT, CONFIDENTIAL_UPLOAD_LIMIT, prepareConfidentialSubmission,
} from '../../../enclave/src/confidential/ownerSubmission';
import {
  CHUNK_PLAINTEXT_BYTES, EvidenceTooLargeError, MAX_CHUNKED_INDEX_BYTES, MAX_CHUNK_CIPHERTEXT_BYTES,
  openOwnerChunkedObject, parseChunkedIndex,
} from '../../../enclave/src/confidential/caseChunks';
import type { EvidenceSource } from '../../../enclave/src/confidential/caseChunks';
import type { ConfidentialDraft } from '../../../enclave/src/confidential/ownerSubmission';
import { verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseManifest } from '../../../enclave/src/confidential/authorization';
import { restoreOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import { createCaseService } from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import type { CaseRecord, CaseStore } from '../../../enclave/src/cases/service';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const CHANNEL = { nonce: hex(0xc01), serverKeyId: hex(0xc02), challenges: createSessionChallenges() };
const RELEASE_MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const draft: ConfidentialDraft = {
  summary: 'Possible procurement fraud at a regional agency; seeking legal review.',
  narrative: { description: 'PRIVATE-SENTINEL-NARRATIVE full account', category: 'fraud', wantsReward: false, location: null },
  contact: { contactMethod: 'signal', contactValue: 'PRIVATE-SENTINEL-CONTACT' },
  identity: null,
  files: [{ name: 'PRIVATE-SENTINEL-FILENAME.pdf', type: 'application/pdf',
    bytes: new TextEncoder().encode('%PDF PRIVATE-SENTINEL-EVIDENCE') }],
};

beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
});

/** Streams a large deterministic file without allocating it. */
function patternSource(name: string, size: number, seed: Uint8Array): EvidenceSource {
  return { name, type: 'video/mp4', size, async read(start, end) {
    const out = new Uint8Array(end - start);
    for (let at = 0; at < out.length;) {
      const offset = (start + at) % seed.length, take = Math.min(seed.length - offset, out.length - at);
      out.set(seed.subarray(offset, offset + take), at); at += take;
    }
    return out;
  } };
}

/** TEST-ONLY minimal store for the publish/directory path. */
function publishStore(staged: Map<string, string>, chunks = new Map<string, Uint8Array>()): CaseStore {
  const cases = new Map<string, CaseRecord>();
  return {
    async getStagedObject(digest: string) { return staged.get(digest) ?? null; },
    async promoteChunks(_caseId: string, _digest: string, digests: string[], finalBytes: number) {
      return digests.every((digest, position) => chunks.get(digest)?.length ===
        (position === digests.length - 1 ? finalBytes : CHUNK_PLAINTEXT_BYTES) + 16);
    },
    async putObjects() { /* content-addressed; not needed for this check */ },
    async createCase(record: CaseRecord) { if (cases.has(record.caseId)) return false; cases.set(record.caseId, record); return true; },
    async getCase(caseId: string) { return cases.get(caseId) ?? null; },
    async listListedCases() { return [...cases.values()]; },
  } as unknown as CaseStore;
}

describe('owner-browser confidential submission', () => {
  test('encrypts every private field and file before the publish body exists', async () => {
    const prepared = await prepareConfidentialSubmission(draft, RELEASE_MANIFEST, now);
    const wire = new TextDecoder().decode(prepared.publishBody);
    for (const sentinel of ['PRIVATE-SENTINEL', prepared.recoveryCode, prepared.recoveryCode.replace(/-/g, '')]) {
      expect(wire).not.toContain(sentinel);
    }
    expect(wire).toContain('Possible procurement fraud'); // The approved summary is the only plaintext.
    const body = JSON.parse(wire);
    expect((await verifyOwnerStatement(body.statements[0], prepared.owner.trust)).statement)
      .toMatchObject({ publishedAt: now, hasAttachments: true });
    const manifest = (await verifyOwnerStatement(body.statements[2], prepared.owner.trust)).statement as CaseManifest;
    expect(manifest.objects.map(entry => entry.scope).sort()).toEqual(['contact', 'evidence', 'narrative']);
    const evidence = manifest.objects.find(entry => entry.scope === 'evidence')!;
    const reference = body.objects.find((item: { objectId: string }) => item.objectId === evidence.objectId);
    // Evidence is a chunked object: the body carries only its index (digests and a sealed header).
    expect(Object.keys(reference).sort()).toEqual(['chunkedIndex', 'objectId', 'ownerEnvelope']);
    expect(parseChunkedIndex(reference.chunkedIndex).chunkCount).toBe(1);
    for (const item of prepared.stagedObjects) expect(item.ciphertext).not.toContain('PRIVATE-SENTINEL');
    const [object] = prepared.chunkedObjects;
    expect(object.digest).toBe(evidence.ciphertextDigest);
    const chunk = await object.chunk(0);
    expect(Buffer.from(chunk).toString('latin1')).not.toContain('PRIVATE-SENTINEL');
    const reader = await openOwnerChunkedObject(reference.chunkedIndex, reference.ownerEnvelope, { caseId: prepared.caseId,
      objectId: evidence.objectId, scope: 'evidence', keyEpoch: 1, objectRevision: 1 }, evidence.ciphertextDigest, prepared.owner.privateKey);
    expect(reader.name).toBe('PRIVATE-SENTINEL-FILENAME.pdf');
    expect(new TextDecoder().decode(await reader.openChunk(0, chunk))).toBe('%PDF PRIVATE-SENTINEL-EVIDENCE');
  });

  test('the recovery code alone restores the owner on a fresh device', async () => {
    const prepared = await prepareConfidentialSubmission({ ...draft, contact: null, files: [] }, RELEASE_MANIFEST, now);
    const restored = await restoreOwnerRecovery(prepared.recoveryCode, prepared.recoveryPackage);
    expect(restored.trust.ownerFingerprint).toBe(prepared.owner.trust.ownerFingerprint);
    expect(restored.pin).toEqual(prepared.pin);
  });

  test('the case service accepts the prepared body and lists only the summary', async () => {
    const { digest } = await readReleaseManifest(RELEASE_MANIFEST);
    const staged = new Map<string, string>(), chunks = new Map<string, Uint8Array>();
    const keyring = createCaseKeyring({ clock: () => now });
    const inner = publishStore(staged, chunks);
    const service = createCaseService({ channel: CHANNEL, store: createSealedCaseStore(inner, keyring), keyring,
      clock: () => now, audience: 'vera-confidential-cases', releaseDigest: digest });
    const prepared = await prepareConfidentialSubmission(draft, RELEASE_MANIFEST, now);
    const { challenge } = await service.issueChallenge();
    const proof = await signParticipantRequest({ ...CHANNEL, audience: 'vera-confidential-cases', role: 'owner',
      caseId: prepared.caseId, organizationId: null, operation: 'publish-case', body: prepared.publishBody, challenge,
      issuedAt: now }, prepared.owner.privateKey);
    // Without the staged ciphertext the publish fails closed.
    await expect(service.publishCase(prepared.publishBody, proof)).rejects.toThrow('not-found');
    for (const item of prepared.stagedObjects) staged.set(item.digest, item.ciphertext);
    // A substituted staged object with the right key but different bytes is rejected.
    const [first] = prepared.stagedObjects;
    staged.set(first.digest, prepared.stagedObjects[1].ciphertext);
    const retry = async () => {
      const { challenge: next } = await service.issueChallenge();
      return signParticipantRequest({ ...CHANNEL, audience: 'vera-confidential-cases', role: 'owner',
        caseId: prepared.caseId, organizationId: null, operation: 'publish-case', body: prepared.publishBody,
        challenge: next, issuedAt: now }, prepared.owner.privateKey);
    };
    await expect(service.publishCase(prepared.publishBody, await retry())).rejects.toThrow('invalid');
    staged.set(first.digest, first.ciphertext);
    // Evidence chunks that were never staged (or expired) fail closed too.
    await expect(service.publishCase(prepared.publishBody, await retry())).rejects.toThrow('not-found');
    for (const object of prepared.chunkedObjects) {
      for (let position = 0; position < object.chunkDigests.length; position++) {
        chunks.set(object.chunkDigests[position], await object.chunk(position));
      }
    }
    await expect(service.publishCase(prepared.publishBody, await retry())).resolves.toMatchObject({ caseId: prepared.caseId });
    expect((await service.listListings({ kind: 'admin' }, null)).listings).toEqual([
      { caseId: prepared.caseId, summary: draft.summary, publishedAt: now, hasAttachments: true }]);
    // Storage holds the public listing but no manifest, release or checkpoint in readable form.
    const record = (await inner.getCase(prepared.caseId))!;
    expect(Object.values(record.statements).map(wire => JSON.parse(wire).statement.kind).sort()).toEqual(['listing', 'release']);
    expect(record.checkpoints.map(wire => JSON.parse(wire).format)).toEqual(['vera-sealed-case-delta/v1']);
    const stored = JSON.stringify(record);
    for (const hidden of ['manifest', 'checkpoint\\"', 'grant', 'stateKey']) expect(stored).not.toContain(hidden);
  });

  test('the case service enforces the evidence budget itself, whatever the client sends', async () => {
    const { digest } = await readReleaseManifest(RELEASE_MANIFEST);
    const staged = new Map<string, string>(), chunks = new Map<string, Uint8Array>();
    const keyring = createCaseKeyring({ clock: () => now });
    const promoted: string[][] = [];
    const inner = publishStore(staged, chunks);
    const store = { ...inner, async promoteChunks(caseId: string, objectDigest: string, digests: string[], finalBytes: number) {
      promoted.push(digests);
      return inner.promoteChunks!(caseId, objectDigest, digests, finalBytes);
    } } as CaseStore;
    // A deliberately small budget: two chunks per commit.
    const service = createCaseService({ channel: CHANNEL, store: createSealedCaseStore(store, keyring), keyring,
      clock: () => now, audience: 'vera-confidential-cases', releaseDigest: digest, limits: { maxChunksPerCommit: 2 } });
    const prepared = await prepareConfidentialSubmission({ ...draft, files: [
      { name: 'a.bin', type: 'application/octet-stream', bytes: new Uint8Array(CHUNK_PLAINTEXT_BYTES + 1) },
      { name: 'b.bin', type: 'application/octet-stream', bytes: new Uint8Array(10) }] }, RELEASE_MANIFEST, now);
    expect(prepared.chunkedObjects.reduce((sum, item) => sum + item.chunkDigests.length, 0)).toBe(3);
    for (const item of prepared.stagedObjects) staged.set(item.digest, item.ciphertext);
    for (const object of prepared.chunkedObjects) {
      for (let position = 0; position < object.chunkDigests.length; position++) chunks.set(object.chunkDigests[position], await object.chunk(position));
    }
    const { challenge } = await service.issueChallenge();
    const proof = await signParticipantRequest({ ...CHANNEL, audience: 'vera-confidential-cases', role: 'owner',
      caseId: prepared.caseId, organizationId: null, operation: 'publish-case', body: prepared.publishBody, challenge,
      issuedAt: now }, prepared.owner.privateKey);
    await expect(service.publishCase(prepared.publishBody, proof)).rejects.toThrow('invalid');
    // Refused before any staged chunk was made permanent.
    expect(promoted).toEqual([]);
    for (const item of prepared.chunkedObjects) item.dispose();
  });

  test('a stored chunk of the wrong size for its position is never promoted', async () => {
    const { digest } = await readReleaseManifest(RELEASE_MANIFEST);
    const staged = new Map<string, string>(), chunks = new Map<string, Uint8Array>();
    const keyring = createCaseKeyring({ clock: () => now });
    const service = createCaseService({ channel: CHANNEL, store: createSealedCaseStore(publishStore(staged, chunks), keyring), keyring,
      clock: () => now, audience: 'vera-confidential-cases', releaseDigest: digest });
    const prepared = await prepareConfidentialSubmission({ ...draft, files: [
      { name: 'a.bin', type: 'application/octet-stream', bytes: new Uint8Array(CHUNK_PLAINTEXT_BYTES + 1) }] }, RELEASE_MANIFEST, now);
    for (const item of prepared.stagedObjects) staged.set(item.digest, item.ciphertext);
    const [object] = prepared.chunkedObjects;
    // Truncated storage: the final chunk is present but the first one is cut short.
    chunks.set(object.chunkDigests[0], (await object.chunk(0)).subarray(0, 4096 + 16));
    chunks.set(object.chunkDigests[1], await object.chunk(1));
    const { challenge } = await service.issueChallenge();
    const proof = await signParticipantRequest({ ...CHANNEL, audience: 'vera-confidential-cases', role: 'owner',
      caseId: prepared.caseId, organizationId: null, operation: 'publish-case', body: prepared.publishBody, challenge,
      issuedAt: now }, prepared.owner.privateKey);
    await expect(service.publishCase(prepared.publishBody, proof)).rejects.toThrow('not-found');
    object.dispose();
  });

  test('refuses an unapproved backend, missing summary and oversized evidence', async () => {
    await expect(prepareConfidentialSubmission(draft, RELEASE_MANIFEST.replace('"', ' "'), now)).rejects.toThrow();
    await expect(prepareConfidentialSubmission({ ...draft, summary: ' ' }, RELEASE_MANIFEST, now)).rejects.toThrow('summary');
    await expect(prepareConfidentialSubmission({ ...draft, summary: 'x'.repeat(601) }, RELEASE_MANIFEST, now)).rejects.toThrow();
    const read = jest.fn();
    await expect(prepareConfidentialSubmission({ ...draft, files: [{ name: 'big.mp4', type: 'video/mp4',
      size: CONFIDENTIAL_FILE_LIMIT + 1, read }] }, RELEASE_MANIFEST, now)).rejects.toThrow(EvidenceTooLargeError);
    await expect(prepareConfidentialSubmission({ ...draft, files: [{ name: 'a.mp4', type: 'video/mp4', size: 200 * 1024 * 1024, read },
      { name: 'b.mp4', type: 'video/mp4', size: 57 * 1024 * 1024, read }] }, RELEASE_MANIFEST, now)).rejects.toThrow('total 256 MB');
    await expect(prepareConfidentialSubmission({ ...draft, files: Array.from({ length: 17 }, (_, n) =>
      ({ name: `${n}.txt`, type: 'text/plain', size: 1, read })) }, RELEASE_MANIFEST, now)).rejects.toThrow('at most 16');
    expect(read).not.toHaveBeenCalled();
    await expect(prepareConfidentialSubmission({ ...draft, narrative: { nested: { a: 1 } } as never }, RELEASE_MANIFEST, now))
      .rejects.toThrow();
  });
});

test('a maximum 256 MB evidence upload fits transport and BSON budgets and round-trips', async () => {
  const seed = new Uint8Array(randomBytes(1024 * 1024 + 7));
  const big = CONFIDENTIAL_UPLOAD_LIMIT - 15 * 1000;
  const expected = createHash('sha256');
  const source = patternSource('maximum.mp4', big, seed);
  for (let at = 0; at < big; at += 8 * 1024 * 1024) expected.update(await source.read(at, Math.min(big, at + 8 * 1024 * 1024)));
  let progressCalls = 0;
  const prepared = await prepareConfidentialSubmission({ ...draft, files: [source,
    ...Array.from({ length: 15 }, (_, i) => patternSource(`small-${i}.txt`, 1000, seed))] }, RELEASE_MANIFEST, Date.now(),
  { onProgress: ({ bytesDone, bytesTotal }) => { progressCalls++; expect(bytesDone).toBeLessThanOrEqual(bytesTotal); } });
  expect(progressCalls).toBe(16);
  expect(prepared.publishBody.length).toBeLessThanOrEqual(128 * 1024);
  expect(prepared.chunkedObjects).toHaveLength(16);
  expect(prepared.chunkedObjects.reduce((sum, item) => sum + item.chunkDigests.length, 0)).toBe(512 + 15);
  for (const object of prepared.chunkedObjects) expect(object.index.length).toBeLessThanOrEqual(MAX_CHUNKED_INDEX_BYTES);
  // Stored chunk documents stay far below the 16 MiB BSON limit.
  expect(BSON.calculateObjectSize({ _id: hex(1), data: Buffer.alloc(MAX_CHUNK_CIPHERTEXT_BYTES), size: MAX_CHUNK_CIPHERTEXT_BYTES,
    expiresAt: new Date() })).toBeLessThan(1024 * 1024);
  const body = JSON.parse(new TextDecoder().decode(prepared.publishBody));
  const manifest = await verifyOwnerStatement(body.statements[2], prepared.owner.trust);
  const evidence = (manifest.statement as CaseManifest).objects.filter(item => item.scope === 'evidence');
  expect(evidence).toHaveLength(16);
  const [object] = prepared.chunkedObjects;
  const reference = body.objects.find((item: { objectId: string }) => item.objectId === object.context.objectId);
  const reader = await openOwnerChunkedObject(reference.chunkedIndex, reference.ownerEnvelope, object.context, object.digest,
    prepared.owner.privateKey);
  const actual = createHash('sha256');
  for (let position = 0; position < reader.index.chunkCount; position++) {
    const plain = await reader.openChunk(position, await object.chunk(position));
    actual.update(plain); plain.fill(0);
  }
  expect(reader.size).toBe(big);
  expect(actual.digest('hex')).toBe(expected.digest('hex'));
  for (const item of prepared.chunkedObjects) item.dispose();
}, 300_000);
