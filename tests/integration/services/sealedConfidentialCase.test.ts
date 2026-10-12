import { createHash, webcrypto } from 'node:crypto';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { BSON, MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { createConfidentialStorageServer } from '../../../src/services/confidentialStorageRpc';
import { createRemoteCaseStore } from '../../../enclave/src/cases/storageRpc';
import type { AddressInfo, Server } from 'node:net';
import { createCaseService } from '../../../enclave/src/cases/service';
import type { CaseStore } from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint, CaseManifest, OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { caseRecipientKeyId, grantCaseObject, openGrantedCaseObject } from '../../../enclave/src/confidential/caseObject';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { encodeBase64, findCaseStateKey, generateCaseStateKey, wrapCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import { createLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import { sealReportOpenReceipt } from '../../../enclave/src/confidential/reportOpenReceipt';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import type { ParticipantOperation } from '../../../enclave/src/confidential/participantRequest';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const CHANNEL = { nonce: hex(0xc01), serverKeyId: hex(0xc02), challenges: createSessionChallenges() };
const AUDIENCE = 'vera-confidential-cases';
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const HOUR = 3_600_000, DAY = 86_400_000;
/** Every stored number or Date that looks like an epoch time, and no driver ObjectId. */
function storedTimes(value: unknown, times: number[] = []): number[] {
  if (value instanceof BSON.ObjectId) throw new Error('A driver ObjectId embeds its insertion second');
  if (value instanceof Date) times.push(value.getTime());
  else if (typeof value === 'number' && value > 1e12) times.push(value);
  else if (Array.isArray(value)) value.forEach(item => storedTimes(item, times));
  else if (value && typeof value === 'object') Object.values(value).forEach(item => storedTimes(item, times));
  return times;
}

describe.each([['direct store'], ['host storage RPC']])('sealed confidential case lifecycle (participant-held state key) via %s', mode => {
  let server: MongoMemoryReplSet, client: MongoClient, inner: MongoConfidentialCaseStore, rpc: Server | undefined;
  let enclaveStore: CaseStore;
  const now = Date.now();
  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    server = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(server.getUri());
    inner = await MongoConfidentialCaseStore.fromDatabase(client.db('test_sealed'), client);
    enclaveStore = inner as unknown as CaseStore;
    if (mode === 'host storage RPC') {
      rpc = createConfidentialStorageServer(inner as unknown as Record<string, unknown>);
      await new Promise<void>(resolve => rpc!.listen(0, '127.0.0.1', resolve));
      enclaveStore = createRemoteCaseStore({ port: (rpc.address() as AddressInfo).port });
    }
  }, 180_000);
  afterAll(async () => { rpc?.close(); await client?.close(); await server?.stop(); });

  /** A fresh enclave process: new empty keyring over the same persistent store. */
  async function boot() {
    const keyring = createCaseKeyring({ clock: () => now });
    const store = createSealedCaseStore(enclaveStore, keyring);
    const service = createCaseService({ channel: CHANNEL, store,
      keyring, clock: () => now, audience: AUDIENCE, releaseDigest: (await readReleaseManifest(MANIFEST)).digest });
    const call = async (operation: ParticipantOperation, body: Uint8Array, key: PrivateKey, organizationId: string | null) => {
      const { challenge } = await service.issueChallenge();
      return signParticipantRequest({ ...CHANNEL, audience: AUDIENCE, role: organizationId ? 'organization' : 'owner',
        caseId: JSON.parse(new TextDecoder().decode(body)).caseId, organizationId, operation, body, challenge, issuedAt: now }, key);
    };
    return { service, call, store };
  }

  test('storage never holds readable private metadata; unlock is owner- or grantee-only and revocation rotates', async () => {
    const firm = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic firm' }], format: 'object' })).privateKey;
    const org = { organizationId: hex(0xf1), recipientKeyId: await caseRecipientKeyId(firm.toPublic()), publicKey: firm.toPublic().armor() };

    // 1. Owner device prepares and publishes. Evidence goes through staging.
    let enclave = await boot();
    const prepared = await prepareConfidentialSubmission({ summary: 'Public summary', narrative: { description: 'PRIVATE-SENTINEL' },
      contact: { contactValue: 'PRIVATE-SENTINEL-CONTACT' }, identity: null, files: [] }, MANIFEST, now);
    for (const item of prepared.stagedObjects) await inner.stageObject(item.digest, item.ciphertext, now);
    const owner = prepared.owner.privateKey, trust = prepared.owner.trust, caseId = prepared.caseId;
    await enclave.service.publishCase(prepared.publishBody, await enclave.call('publish-case', prepared.publishBody, owner, null));

    const raw = JSON.stringify(await client.db('test_sealed').collection('confidential_cases').findOne({ _id: caseId as never }));
    // Release approvals are public by design (checked by owner devices before unlock).
    for (const hidden of ['PRIVATE-SENTINEL', 'manifest', 'grant', '\\"checkpoint\\"']) expect(raw).not.toContain(hidden);
    // Plaintext times at rest: the case's creation day and staged ciphertext
    // expiring at the end of an hour. Submission alerts are no longer queued.
    const db = client.db('test_sealed');
    const caseRow = await db.collection('confidential_cases').findOne({ _id: caseId as never });
    expect(caseRow!.createdAt).toBe(now - (now % DAY));
    expect(caseRow).not.toHaveProperty('adminAlert');
    const stagedRows = await db.collection('confidential_staged_objects')
      .find({ _id: { $in: prepared.stagedObjects.map(item => item.digest) } } as never).toArray();
    expect(stagedRows.length).toBeGreaterThan(0);
    for (const row of [caseRow, ...stagedRows]) for (const time of storedTimes(row)) expect(time % HOUR).toBe(0);
    for (const row of stagedRows) expect(row.expiresAt.getTime()).toBeGreaterThanOrEqual(now + DAY);

    // 2. Enclave restart: the case is locked. Listing and access requests still work.
    enclave = await boot();
    expect((await enclave.service.listListings({ kind: 'admin' }, null)).listings).toEqual([{ caseId, summary: 'Public summary', publishedAt: now, hasAttachments: false }]);
    const inboxBody = encode({ caseId, afterCheckpoint: null });
    await expect(enclave.service.readInbox(inboxBody, await enclave.call('read-inbox', inboxBody, owner, null))).rejects.toThrow('locked');
    const requestCiphertext = await createLegalAccessRequest({ requestId: hex(0x201), scopes: ['narrative'], objectRevisionLimit: null,
      purpose: 'Counsel review', issuedAt: now, expiresAt: now + 86_400_000 }, org.organizationId, firm, trust);
    const requestBody = encode({ caseId, requestId: hex(0x201), ciphertext: requestCiphertext, expiresAt: now + 86_400_000 });
    await expect(enclave.service.submitAccessRequest(requestBody, await enclave.call('request-access', requestBody, firm, org.organizationId), org))
      .resolves.toEqual({ state: 'requested' });

    // 3. A firm without a grant cannot unlock, even with a guessed key; the owner can.
    const keysBody = encode({ caseId });
    const { stateEnvelopes } = await enclave.service.getStateEnvelopes(keysBody, await enclave.call('read-state-keys', keysBody, owner, null), null);
    await expect(findCaseStateKey(stateEnvelopes, caseId, firm, trust.ownerPublicKey)).rejects.toThrow();
    const ownerState = await findCaseStateKey(stateEnvelopes, caseId, owner, trust.ownerPublicKey);
    const guess = encode({ caseId, stateKey: encodeBase64(new Uint8Array(32).fill(7)), stateEpoch: 1 });
    await expect(enclave.service.unlockCase(guess, await enclave.call('unlock-case', guess, firm, org.organizationId), org)).rejects.toThrow('unauthorized');
    const unlock = encode({ caseId, stateKey: encodeBase64(ownerState.key), stateEpoch: ownerState.stateEpoch });
    await enclave.service.unlockCase(unlock, await enclave.call('unlock-case', unlock, owner, null), null);
    const inbox = await enclave.service.readInbox(inboxBody, await enclave.call('read-inbox', inboxBody, owner, null));
    expect(inbox.requests).toHaveLength(1);

    // 4. Owner grants narrative; the state key is re-wrapped to owner + firm.
    const signed = async (statement: OwnerStatement) => {
      const wire = await signOwnerStatement(statement, owner);
      return { wire, ...await verifyOwnerStatement(wire, trust) };
    };
    const tip = (await verifyOwnerStatement(inbox.checkpoints[inbox.checkpoints.length - 1], trust));
    const current = tip.statement as CaseCheckpoint;
    const manifestWire = inbox.statements[current.manifestDigest!];
    const manifest = (await verifyOwnerStatement(manifestWire, trust)).statement as CaseManifest;
    const releaseWire = inbox.statements[current.releaseDigests[0]];
    const narrative = manifest.objects.find(entry => entry.scope === 'narrative')!;
    const publish = JSON.parse(new TextDecoder().decode(prepared.publishBody));
    const owned = { ciphertext: prepared.stagedObjects.find(item => item.digest === narrative.ciphertextDigest)!.ciphertext,
      ownerEnvelope: publish.objects.find((item: { objectId: string }) => item.objectId === narrative.objectId).ownerEnvelope };
    const grant = await signed({ kind: 'grant', caseId, revision: current.revision + 1, grantId: hex(0x301),
      organizationId: org.organizationId, recipientKeyId: org.recipientKeyId, scopes: ['narrative'], keyEpoch: 1,
      objectRevisionLimit: null, issuedAt: now, expiresAt: now + 30 * 86_400_000 });
    const granted = await signed({ ...current, revision: current.revision + 1, previousDigest: tip.digest,
      grantDigests: [grant.digest], issuedAt: now });
    const context = { caseId, objectId: narrative.objectId, scope: 'narrative' as const, keyEpoch: 1, objectRevision: 1 };
    const auth = { trust, grant: grant.wire, release: releaseWire, manifest: manifestWire, checkpoint: granted.wire,
      checkpointDigest: granted.digest, request: { organizationId: org.organizationId, recipientKeyId: org.recipientKeyId,
        objectId: narrative.objectId, ciphertextDigest: narrative.ciphertextDigest, scope: 'narrative' as const,
        releaseDigest: (await readReleaseManifest(MANIFEST)).digest, keyEpoch: 1, objectRevision: 1, now } };
    const shared = await grantCaseObject(owned, context, owner, firm.toPublic(), auth);
    const envelopesFor = async (state: { stateEpoch: number; key: Uint8Array }, recipients: PrivateKey[]) =>
      Promise.all([owner, ...recipients].map(key => wrapCaseStateKey(caseId, state, key.toPublic(), owner)));
    const grantBody = encode({ caseId, statements: [grant.wire], checkpoint: granted.wire, objects: [],
      envelopes: [{ objectId: narrative.objectId, recipientKeyId: org.recipientKeyId, envelope: shared.recipientEnvelope }],
      recoveryPackage: null, stateEnvelopes: await envelopesFor(ownerState, [firm]), stateKeyRotation: null });
    // Adding a grantee without redistributing the state key is refused.
    const missing = encode({ ...JSON.parse(new TextDecoder().decode(grantBody)), stateEnvelopes: null });
    await expect(enclave.service.commitTransition(missing, await enclave.call('commit-transition', missing, owner, null))).rejects.toThrow('invalid');
    await enclave.service.commitTransition(grantBody, await enclave.call('commit-transition', grantBody, owner, null));
    const envelopeRows = JSON.stringify(await client.db('test_sealed').collection('confidential_cases').findOne({ _id: caseId as never }));
    expect(envelopeRows).not.toContain(org.recipientKeyId); // Routing uses an HMAC tag the host cannot compute.

    // 5. Restart again: the firm unlocks with its own envelope and opens the narrative.
    enclave = await boot();
    const openBody = encode({ caseId });
    await expect(enclave.service.openCase(openBody, await enclave.call('open-case', openBody, firm, org.organizationId), org)).rejects.toThrow('locked');
    const firmKeys = await enclave.service.getStateEnvelopes(keysBody, await enclave.call('read-state-keys', keysBody, firm, org.organizationId), org);
    const firmState = await findCaseStateKey(firmKeys.stateEnvelopes, caseId, firm, trust.ownerPublicKey);
    const firmUnlock = encode({ caseId, stateKey: encodeBase64(firmState.key), stateEpoch: firmState.stateEpoch });
    await enclave.service.unlockCase(firmUnlock, await enclave.call('unlock-case', firmUnlock, firm, org.organizationId), org);
    const opened = await enclave.service.openCase(openBody, await enclave.call('open-case', openBody, firm, org.organizationId), org);
    const plaintext = await openGrantedCaseObject({ ciphertext: opened.objects[0].ciphertext, recipientEnvelope: opened.objects[0].recipientEnvelope },
      context, firm, { ...auth, checkpoint: opened.checkpoint, checkpointDigest: opened.checkpointDigest });
    expect(JSON.parse(new TextDecoder().decode(plaintext)).description).toBe('PRIVATE-SENTINEL');

    // 5a. A first-open receipt is stored once and in exactly the shape of any
    // other sealed message: its kind and firm stay inside the ciphertext.
    const receipt = await sealReportOpenReceipt({ checkpointDigest: opened.checkpointDigest, openedAt: now },
      { owner: trust, organization: { organizationId: org.organizationId, publicKey: firm.toPublic() } }, firm);
    const ackBody = encode({ caseId, checkpointDigest: opened.checkpointDigest, ciphertext: receipt });
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(enclave.service.acknowledgeReportOpen(ackBody,
        await enclave.call('acknowledge-report-open', ackBody, firm, org.organizationId), org)).resolves.toEqual({ recorded: true });
    }
    expect(await enclave.store.appendMessage({ caseId, organizationId: org.organizationId, sender: 'organization',
      ciphertext: 'synthetic conversation ciphertext', createdAt: now },
    { checkpointDigest: opened.checkpointDigest, since: now - 3_600_000, limit: 60 })).toBe('stored');
    const messageRows = await client.db('test_sealed').collection('confidential_messages').find({ caseId }).toArray();
    expect(messageRows).toHaveLength(2);
    for (const row of messageRows) {
      expect(Object.keys(row).sort()).toEqual(['_id', 'caseId', 'ciphertext', 'createdAt', 'dedupeTag', 'organizationId', 'sender', 'sequence']);
      expect(row.sender).toBe('owner');
      // The exact time is sealed; the row keeps the UTC hour and a random id.
      expect(row.createdAt).toBe(now - (now % HOUR));
      for (const time of storedTimes(row)) expect(time % HOUR).toBe(0);
      expect(row.dedupeTag).toMatch(/^[a-f0-9]{64}$/);
    }
    expect(JSON.stringify(messageRows)).not.toContain('report-open');
    expect(JSON.stringify(messageRows)).not.toContain(org.organizationId);
    const withReceipt = await enclave.service.readInbox(inboxBody, await enclave.call('read-inbox', inboxBody, owner, null));
    expect(withReceipt.messages.filter(item => item.kind === 'report-open')).toEqual([expect.objectContaining({
      organizationId: org.organizationId, sender: 'organization', ciphertext: receipt })]);

    // 5b. The same organization under a substituted key (for example one VERA
    // registered in its place) holds no grant: the enclave releases neither the
    // state-key list nor the case, and the stored envelopes do not open with it.
    const substitute = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Substituted key' }], format: 'object' })).privateKey;
    const swapped = { organizationId: org.organizationId, recipientKeyId: await caseRecipientKeyId(substitute.toPublic()), publicKey: substitute.toPublic().armor() };
    await expect(enclave.service.getStateEnvelopes(keysBody, await enclave.call('read-state-keys', keysBody, substitute, org.organizationId), swapped))
      .rejects.toThrow('not-found');
    await expect(enclave.service.openCase(openBody, await enclave.call('open-case', openBody, substitute, org.organizationId), swapped)).rejects.toThrow();
    await expect(findCaseStateKey(firmKeys.stateEnvelopes, caseId, substitute, trust.ownerPublicKey)).rejects.toThrow();

    // 6. Revocation must rotate the key; the revoked firm's copy no longer unlocks after restart.
    const revoked = await signed({ ...(granted.statement as CaseCheckpoint), revision: granted.statement.revision + 1,
      previousDigest: granted.digest, grantDigests: [], issuedAt: now });
    const noRotation = encode({ caseId, statements: [], checkpoint: revoked.wire, objects: [], envelopes: [], recoveryPackage: null,
      stateEnvelopes: await envelopesFor(ownerState, []), stateKeyRotation: null });
    await expect(enclave.service.commitTransition(noRotation, await enclave.call('commit-transition', noRotation, owner, null))).rejects.toThrow('invalid');
    const next = generateCaseStateKey(2);
    const rotate = encode({ caseId, statements: [], checkpoint: revoked.wire, objects: [], envelopes: [], recoveryPackage: null,
      stateEnvelopes: await envelopesFor(next, []), stateKeyRotation: { stateKey: encodeBase64(next.key), stateEpoch: 2 } });
    await enclave.service.commitTransition(rotate, await enclave.call('commit-transition', rotate, owner, null));
    enclave = await boot();
    await expect(enclave.service.unlockCase(firmUnlock, await enclave.call('unlock-case', firmUnlock, firm, org.organizationId), org)).rejects.toThrow();
    const afterKeys = await enclave.service.getStateEnvelopes(keysBody, await enclave.call('read-state-keys', keysBody, owner, null), null);
    await expect(findCaseStateKey(afterKeys.stateEnvelopes, caseId, firm, trust.ownerPublicKey)).rejects.toThrow();
    const ownerNext = await findCaseStateKey(afterKeys.stateEnvelopes, caseId, owner, trust.ownerPublicKey);
    const ownerUnlock = encode({ caseId, stateKey: encodeBase64(ownerNext.key), stateEpoch: 2 });
    await enclave.service.unlockCase(ownerUnlock, await enclave.call('unlock-case', ownerUnlock, owner, null), null);
    // The newest key opens the whole history, including epoch-1 deltas.
    const full = await enclave.service.readInbox(inboxBody, await enclave.call('read-inbox', inboxBody, owner, null));
    expect(full.checkpoints).toHaveLength(3);
    expect(createHash('sha256').update(JSON.stringify(full.statements)).digest('hex')).toMatch(/^[a-f0-9]{64}$/);
  }, 240_000);

  test('many listing edits and release approvals keep the case document a constant size, readable only as public rows', async () => {
    let enclave = await boot();
    const prepared = await prepareConfidentialSubmission({ summary: 'Summary 1', narrative: { description: 'PRIVATE-SENTINEL' },
      contact: { contactValue: 'PRIVATE-SENTINEL-CONTACT' }, identity: null, files: [] }, MANIFEST, now);
    for (const item of prepared.stagedObjects) await inner.stageObject(item.digest, item.ciphertext, now);
    const owner = prepared.owner.privateKey, trust = prepared.owner.trust, caseId = prepared.caseId;
    await enclave.service.publishCase(prepared.publishBody, await enclave.call('publish-case', prepared.publishBody, owner, null));
    const db = client.db('test_sealed');
    const size = async () => BSON.calculateObjectSize((await db.collection('confidential_cases').findOne({ _id: caseId as never }))!);
    const published = await size();
    const signed = async (statement: OwnerStatement) => {
      const wire = await signOwnerStatement(statement, owner);
      return { wire, ...await verifyOwnerStatement(wire, trust) };
    };
    const stateBody = encode({ caseId, afterCheckpoint: null });
    const state = await enclave.service.readState(stateBody, await enclave.call('read-state', stateBody, owner, null));
    let tip = await verifyOwnerStatement(state.checkpoints[state.checkpoints.length - 1], trust);
    const releaseDigest = (await readReleaseManifest(MANIFEST)).digest;
    let latestApproval = '';
    const EDITS = 40;
    for (let edit = 2; edit <= EDITS + 1; edit++) {
      const current = tip.statement as CaseCheckpoint, revision = current.revision + 1;
      const listing = await signed({ kind: 'listing', caseId, revision, summary: `Summary ${edit}` });
      const statements = [listing.wire];
      let releaseDigests = current.releaseDigests;
      if (edit % 2 === 0) {
        // The owner re-approves the running backend release (newest approval per release).
        const release = await signed({ kind: 'release', caseId, revision, releaseDigest, issuedAt: now });
        statements.push(release.wire); releaseDigests = [release.digest]; latestApproval = release.wire;
      }
      const checkpoint = await signed({ ...current, revision, previousDigest: tip.digest, listingDigest: listing.digest,
        releaseDigests, issuedAt: now });
      const body = encode({ caseId, statements, checkpoint: checkpoint.wire, objects: [], envelopes: [], recoveryPackage: null,
        stateEnvelopes: null, stateKeyRotation: null });
      await enclave.service.commitTransition(body, await enclave.call('commit-transition', body, owner, null));
      tip = checkpoint;
    }
    // Every public statement went to its own row; the head did not grow at all.
    expect(await size()).toBe(published);
    const rows = await db.collection('confidential_case_statements').find({ caseId } as never).toArray();
    expect(rows).toHaveLength(EDITS + EDITS / 2);
    expect(rows.map(row => row.index).sort((a, b) => a - b)).toEqual(Array.from({ length: rows.length }, (_, index) => index));
    // Only public listings and release approvals reach the segment rows: private
    // statements and checkpoints stay inside the sealed history.
    expect(new Set(rows.map(row => row.kind))).toEqual(new Set(['listing', 'release']));
    const raw = JSON.stringify(rows);
    for (const hidden of ['PRIVATE-SENTINEL', 'manifest', 'grant', '\\"checkpoint\\"']) expect(raw).not.toContain(hidden);
    for (const row of rows) expect((await verifyOwnerStatement(row.wire, trust)).digest).toBe(row.digest);
    // Exact full read on the host: genesis public statements plus every row.
    expect(Object.keys((await inner.getCase(caseId))!.statements)).toHaveLength(2 + rows.length);

    // Restart: the case is locked. The directory serves the newest listing and the
    // public release read is bounded yet still includes the current approval first.
    enclave = await boot();
    expect((await enclave.service.listListings({ kind: 'admin' }, null)).listings.find(item => item.caseId === caseId)?.summary)
      .toBe(`Summary ${EDITS + 1}`);
    const { releases } = await enclave.service.releaseApprovals(caseId);
    expect(releases[0]).toBe(latestApproval);
    expect(releases).toHaveLength(1 + EDITS / 2);
    // After unlock, the owner's view comes from the sealed history, complete.
    const keysBody = encode({ caseId });
    const { stateEnvelopes } = await enclave.service.getStateEnvelopes(keysBody, await enclave.call('read-state-keys', keysBody, owner, null), null);
    const ownerState = await findCaseStateKey(stateEnvelopes, caseId, owner, trust.ownerPublicKey);
    const unlock = encode({ caseId, stateKey: encodeBase64(ownerState.key), stateEpoch: ownerState.stateEpoch });
    await enclave.service.unlockCase(unlock, await enclave.call('unlock-case', unlock, owner, null), null);
    const checkpoints: string[] = [], statements: Record<string, string> = {};
    let cursor: unknown = null;
    do {
      const body = encode({ caseId, afterCheckpoint: null, ...(cursor ? { stateCursor: cursor } : {}) });
      const page = await enclave.service.readState(body, await enclave.call('read-state', body, owner, null));
      checkpoints.push(...page.checkpoints); Object.assign(statements, page.statements); cursor = page.stateNext;
    } while (cursor);
    expect(checkpoints).toHaveLength(EDITS + 1);
    // Genesis listing, release and manifest plus every edit's statements.
    expect(Object.keys(statements)).toHaveLength(3 + rows.length);
  }, 240_000);
});
