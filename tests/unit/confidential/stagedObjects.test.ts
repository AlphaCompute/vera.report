import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { webcrypto } from 'node:crypto';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { caseObjectDigest, sealCaseObject } from '../../../enclave/src/confidential/caseObject';
import type { ObjectContext } from '../../../enclave/src/confidential/caseObject';
import { createCaseOwner, createOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import { createCaseService } from '../../../enclave/src/cases/service';
import type { CaseRecord, CaseStore, StoredObject } from '../../../enclave/src/cases/service';

/** Review item 5: publish/commit staged-object handling must not let one
 * request make the enclave hold many staged ciphertexts at once. */
const hex = (n: number) => n.toString(16).padStart(64, '0');
const AUDIENCE = 'vera-confidential-cases';
const CHANNEL = { nonce: hex(0xc01), serverKeyId: hex(0xc02) };
const RELEASE = hex(0xabc);
const clock = Date.now();

type Probe = { fetches: number; inFlight: number; maxInFlight: number; events: string[]; objects: Map<string, StoredObject> };
function stagedStore(staged: Map<string, string>, probe: Probe): CaseStore {
  const cases = new Map<string, CaseRecord>();
  return {
    async getStagedObject(digest: string) {
      probe.fetches++; probe.inFlight++; probe.maxInFlight = Math.max(probe.maxInFlight, probe.inFlight);
      probe.events.push(`fetch:${digest.slice(0, 6)}`);
      await new Promise(resolve => setTimeout(resolve, 5));
      probe.inFlight--;
      return staged.get(digest) ?? null;
    },
    async putObjects(caseId: string, objects: StoredObject[]) {
      for (const item of objects) {
        probe.events.push(`put:${item.ciphertextDigest.slice(0, 6)}`);
        probe.objects.set(`${caseId}:${item.objectId}:${item.ciphertextDigest}`, item);
      }
    },
    async getObjects(caseId: string, refs: { objectId: string; ciphertextDigest: string }[]) {
      return refs.flatMap(ref => { const found = probe.objects.get(`${caseId}:${ref.objectId}:${ref.ciphertextDigest}`); return found ? [found] : []; });
    },
    async createCase(record: CaseRecord) { if (cases.has(record.caseId)) return false; cases.set(record.caseId, record); return true; },
    async getCase(caseId: string) { return cases.get(caseId) ?? null; },
  } as unknown as CaseStore;
}

async function publication(files: number) {
  const owner = await createCaseOwner(), trust = owner.trust;
  const signed = async (statement: OwnerStatement) => {
    const wire = await signOwnerStatement(statement, owner.privateKey);
    return { wire, ...await verifyOwnerStatement(wire, trust) };
  };
  const sealed = await Promise.all(Array.from({ length: files }, async (_, index) => {
    const context: ObjectContext = { caseId: trust.caseId, objectId: hex(0x200 + index), scope: 'evidence', keyEpoch: 1, objectRevision: 1 };
    const object = await sealCaseObject(context, new TextEncoder().encode(`synthetic evidence ${index} `.repeat(200)), owner.privateKey);
    return { context, object, digest: await caseObjectDigest(object.ciphertext) };
  }));
  const release = await signed({ kind: 'release', caseId: trust.caseId, revision: 1, releaseDigest: RELEASE, issuedAt: clock });
  const manifest = await signed({ kind: 'manifest', caseId: trust.caseId, revision: 1, objects: sealed.map(item => ({
    objectId: item.context.objectId, scope: 'evidence' as const, objectRevision: 1, keyEpoch: 1, ciphertextDigest: item.digest })) });
  const first = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 1, keyEpoch: 1, previousDigest: null,
    listingDigest: null, manifestDigest: manifest.digest, grantDigests: [], releaseDigests: [release.digest], issuedAt: clock });
  const recovery = await createOwnerRecovery(owner, first.wire);
  const staged = new Map(sealed.map(item => [item.digest, item.object.ciphertext]));
  const body = (objects: unknown[]) => new TextEncoder().encode(JSON.stringify({ caseId: trust.caseId,
    ownerPublicKey: trust.ownerPublicKey.armor(), statements: [release.wire, manifest.wire], checkpoint: first.wire,
    objects, recoveryPackage: recovery.encryptedPackage }));
  const references = sealed.map(item => ({ objectId: item.context.objectId, stagedDigest: item.digest, ownerEnvelope: item.object.ownerEnvelope }));
  return { owner, trust, staged, body, references, sealed };
}

async function publish(fixture: Awaited<ReturnType<typeof publication>>, objects: unknown[], probe: Probe,
  limits: Record<string, number> = {}) {
  const service = createCaseService({ channel: { ...CHANNEL, challenges: createSessionChallenges() }, store: stagedStore(fixture.staged, probe), clock: () => clock,
    audience: AUDIENCE, releaseDigest: RELEASE, limits });
  const raw = fixture.body(objects);
  const { challenge } = await service.issueChallenge();
  const proof = await signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role: 'owner', caseId: fixture.trust.caseId,
    organizationId: null, operation: 'publish-case', body: raw, challenge, issuedAt: clock }, fixture.owner.privateKey);
  return service.publishCase(raw, proof);
}
const probe = (): Probe => ({ fetches: 0, inFlight: 0, maxInFlight: 0, events: [], objects: new Map() });

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

test('staged objects are fetched and written one at a time', async () => {
  const fixture = await publication(3), seen = probe();
  await expect(publish(fixture, fixture.references, seen)).resolves.toMatchObject({ caseId: fixture.trust.caseId });
  expect(seen.maxInFlight).toBe(1);
  // Each object is written before the next is fetched, so only one is held.
  expect(seen.events.map(event => event.split(':')[0])).toEqual(['fetch', 'put', 'fetch', 'put', 'fetch', 'put']);
  expect(seen.objects.size).toBe(3);
});

test('a staged digest referenced twice is refused before any staged object is fetched', async () => {
  const fixture = await publication(2), seen = probe();
  const repeated = [fixture.references[0], { ...fixture.references[1], stagedDigest: fixture.references[0].stagedDigest }];
  await expect(publish(fixture, repeated, seen)).rejects.toThrow('invalid');
  // The 64-copies-of-one-12-MiB-object request is now rejected up front.
  const many = Array.from({ length: 64 }, (_, index) => ({ ...fixture.references[0], objectId: hex(0x900 + index) }));
  await expect(publish(fixture, many, seen)).rejects.toThrow('invalid');
  expect(seen.fetches).toBe(0);
});

test('duplicate object IDs are refused before any fetch', async () => {
  const fixture = await publication(2), seen = probe();
  await expect(publish(fixture, [fixture.references[0], { ...fixture.references[1], objectId: fixture.references[0].objectId }], seen))
    .rejects.toThrow('invalid');
  expect(seen.fetches).toBe(0);
});

test('total staged bytes per request are capped', async () => {
  const fixture = await publication(3), seen = probe();
  // Armored ciphertext sizes can differ even for equal-sized plaintexts.
  // Set the exact boundary from both actual objects, so the third crosses it.
  const firstTwo = fixture.sealed.slice(0, 2).reduce((total, item) => total + item.object.ciphertext.length, 0);
  await expect(publish(fixture, fixture.references, seen, { maxStagedBytesPerCommit: firstTwo })).rejects.toThrow('invalid');
  expect(seen.fetches).toBe(3);
  expect(seen.objects.size).toBe(2); // Stops at the object that crosses the cap.
});
