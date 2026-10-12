import { authenticatedRoster } from '../../../enclave/src/cases/authenticatedRoster';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { signOrganizationRegistration } from '../../../enclave/src/confidential/organizationRegistration';
import { issueLegalInvitation } from '../../../lib/confidential/onboarding';
import { redeemInvitation } from '../../../lib/confidential/firmCase';
import { collectGrantedCaseRanges } from '../../../enclave/src/confidential/caseRanges';
import { isChunkedIndexText, openGrantedChunkedObject } from '../../../enclave/src/confidential/caseChunks';
import { createHash, randomBytes, webcrypto } from 'node:crypto';
import type { AddressInfo, Server } from 'node:net';

// AWS quote verification is mocked (no Nitro hardware here). The relay limiter
// uses a short window to model participant actions across visits without minutes
// of wall-clock delay; production keeps its 120 requests/minute limit. Everything
// else is the production composition: browser client -> host HTTP relay -> enclave
// frame server -> attested session core -> owner dispatcher -> sealed store ->
// host storage RPC -> MongoDB, plus ciphertext staging.
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));

jest.mock('express-rate-limit', () => {
  const actual = jest.requireActual('express-rate-limit');
  const limited = (options: Record<string, unknown>) => actual.rateLimit({ ...options, windowMs: 100 });
  return { ...actual, __esModule: true, default: limited, rateLimit: limited };
});

import * as jose from 'jose';
import express from 'express';
import { MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { createConfidentialStorageServer } from '../../../src/services/confidentialStorageRpc';
import { createConfidentialChannelRouter, tcpEnclaveTransport } from '../../../src/api/confidentialChannel';
import { createConfidentialObjectRouter } from '../../../src/api/confidentialObjects';
import {
  createRemoteCaseStore, createRemoteEnrollmentStore, createRemoteLegalFirmStore, createRemoteLegalMembershipStore, fetchLegalIdentityPolicy,
} from '../../../enclave/src/cases/storageRpc';
import { FIRM_ONBOARDING_TERMS_VERSION, firmOnboardingTermsDigest, signFirmSetupStatement } from '../../../enclave/src/confidential/firmSetup';
import { createLegalCaseDispatcher } from '../../../enclave/src/cases/legalChannel';
import { LEGAL_ASSURANCE_CLAIM } from '../../../enclave/src/legal/identity';
import { sealChannelRequest } from '../../../enclave/src/confidential/channelMessage';
import { readKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signEnrollmentChallenge } from '../../../enclave/src/confidential/enrollmentProof';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { createCaseChannelDispatch, createConfidentialFrameServer } from '../../../enclave/src/confidential-server';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { encodeBase64, findCaseStateKey } from '../../../enclave/src/confidential/caseStateKey';
import { restoreOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { fetchRelay, ownerOperation, publishPreparedCase } from '../../../lib/confidential/client';
import {
  RevokeBlockedError, addEvidence, allowAccess, approveCurrentRelease, changeAccess, currentGrantees, currentManifest, readOwnerInbox,
  readOwnerThreads, releaseApprovalStatus, renewAccess, restoreOwnerSession, revokeAccess, sendOwnerMessage, updateSummary, verifiedRequests,
  verifiedRoster,
} from '../../../lib/confidential/ownerCase';
import { changeChoice, changeDecisionFromChoice, evidenceEntries } from '../../../lib/confidential/accessChoices';
import type { OwnerSession } from '../../../lib/confidential/ownerCase';
import { buildOwnerTimeline, ownerJourney } from '../../../lib/confidential/ownerTimeline';
import { openCaseMessage, sealCaseMessage } from '../../../enclave/src/confidential/caseMessage';
import { unpackCaseFile } from '../../../enclave/src/confidential/ownerSubmission';
import type { CaseScope } from '../../../enclave/src/confidential/authorization';
import { createCaseService } from '../../../enclave/src/cases/service';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import { createLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import { caseRecipientKeyId, openGrantedCaseObject } from '../../../enclave/src/confidential/caseObject';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseManifest } from '../../../enclave/src/confidential/authorization';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const listen = (server: Server) => new Promise<number>(resolve =>
  server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));

describe('mounted confidential stack (local, synthetic attestation)', () => {
  let mongo: MongoMemoryReplSet, client: MongoClient, store: MongoConfidentialCaseStore;
  let storage: Server, enclave: Server, host: Server, storagePort: number, relayBase: string;
  let onboarding: Awaited<ReturnType<typeof generateKey>>;
  let channelKey: Awaited<ReturnType<typeof generateKey>>;
  let issuer: jose.GenerateKeyPairResult;
  const servers: Server[] = [];

  /** Boot (or reboot) the enclave process: fresh keyring and sessions, same storage. */
  async function bootEnclave(port?: number, manifest = MANIFEST, withFirm = false) {
    // Same composition as startConfidentialServer, minus NSM self-verification.
    const keyring = createCaseKeyring({ clock: Date.now });
    const options = { store: authenticatedRoster(createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), keyring), onboarding.publicKey.armor(), Date.now),
      keyring, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest: (await readReleaseManifest(manifest)).digest };
    const policy = await fetchLegalIdentityPolicy({ port: storagePort });
    const dispatch = createCaseChannelDispatch(createOwnerCaseControlDispatcher(options),
      createLegalCaseDispatcher({ ...options, identity: policy!, members: createRemoteLegalMembershipStore({ port: storagePort }),
        enrollment: createRemoteEnrollmentStore({ port: storagePort }), administration: { identity: { ...policy!, audience: 'admin-api', clientId: 'admin-client' }, organizationId: 'org_admin', onboardingPublicKey: onboarding.publicKey.armor() },
        // The production server always mounts the firm store (and with it the enforced organization setup).
        ...(withFirm ? { firm: createRemoteLegalFirmStore({ port: storagePort }) } : {}) }));
    const sessions = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(channelKey.privateKey,
      { nonce, publicKey: Buffer.from(channelKey.publicKey.write()).toString('base64'), document: Buffer.from('synthetic-not-attestation').toString('base64') }), () => Date.now());
    const server = createConfidentialFrameServer(sessions);
    await new Promise<void>(resolve => server.listen(port ?? 0, '127.0.0.1', resolve));
    servers.push(server);
    return server;
  }

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(mongo.getUri());
    store = await MongoConfidentialCaseStore.fromDatabase(client.db('test_mounted'), client);
    issuer = await jose.generateKeyPair('RS256');
    const legalIdentityPolicy = { issuer: 'https://identity.example/', audience: 'https://api.example/legal', clientId: 'legal-client',
      jwks: { keys: [{ ...await jose.exportJWK(issuer.publicKey), alg: 'RS256', use: 'sig', kid: 'issuer-key' }] } };
    storage = createConfidentialStorageServer(store as unknown as Record<string, unknown>, { releaseManifest: MANIFEST, legalIdentityPolicy });
    storagePort = await listen(storage);
    channelKey = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic enclave' }], format: 'object' });
    onboarding = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic onboarding' }], format: 'object' });
    enclave = await bootEnclave();
    const enclavePort = (enclave.address() as AddressInfo).port;
    const app = express();
    app.use(express.json({ limit: '10mb' }));
    app.use('/api/confidential', createConfidentialObjectRouter(store));
    app.use('/api/confidential', createConfidentialChannelRouter(tcpEnclaveTransport(enclavePort), { maxPerMinute: 10_000 }));
    host = app.listen(0, '127.0.0.1');
    await new Promise(resolve => host.once('listening', resolve));
    relayBase = `http://127.0.0.1:${(host.address() as AddressInfo).port}/api/confidential`;
  }, 180_000);
  afterAll(async () => {
    for (const server of [host, storage, ...servers]) server?.close();
    await client?.close(); await mongo?.stop();
  });

  test('publish with staged evidence, restart, locked, owner unlocks from recovery, reads inbox', async () => {
    const relay = fetchRelay(`${relayBase}/channel`, `${relayBase}/objects`);
    const now = Date.now();
    const prepared = await prepareConfidentialSubmission({ summary: 'Public summary', narrative: { description: 'PRIVATE-SENTINEL-NARRATIVE' },
      contact: { contactValue: 'PRIVATE-SENTINEL-CONTACT' }, identity: null,
      files: [{ name: 'PRIVATE-SENTINEL.pdf', type: 'application/pdf', bytes: new Uint8Array(400 * 1024).fill(0x42) }] }, MANIFEST, now);
    await expect(publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared })).resolves.toEqual({ caseId: prepared.caseId });

    const everything = JSON.stringify(await Promise.all((await client.db('test_mounted').collections())
      .map(collection => collection.find().toArray())));
    for (const secret of ['PRIVATE-SENTINEL', prepared.recoveryCode.replace(/-/g, ''), '"grant', 'manifest']) expect(everything).not.toContain(secret);

    // Enclave restart on the same port: keys are gone, the case is locked.
    const port = (enclave.address() as AddressInfo).port;
    await new Promise(resolve => enclave.close(resolve));
    enclave = await bootEnclave(port);
    const inboxBody = new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId, afterCheckpoint: null }));
    const operate = (owner: typeof prepared.owner.privateKey, operation: Parameters<typeof ownerOperation>[0]['operation'], body: Uint8Array) =>
      ownerOperation({ relay, releaseManifest: MANIFEST, now: Date.now(), caseId: prepared.caseId, owner, operation, body });
    await expect(operate(prepared.owner.privateKey, 'read-inbox', inboxBody)).resolves.toEqual({ error: 'locked' });

    // A new device restores from the recovery code, unwraps its state key and unlocks.
    const restored = await restoreOwnerRecovery(prepared.recoveryCode, prepared.recoveryPackage);
    const keysBody = new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId }));
    const { stateEnvelopes } = await operate(restored.privateKey, 'read-state-keys', keysBody) as { stateEnvelopes: string[] };
    const state = await findCaseStateKey(stateEnvelopes, prepared.caseId, restored.privateKey, restored.trust.ownerPublicKey);
    const unlockBody = new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch }));
    await expect(operate(restored.privateKey, 'unlock-case', unlockBody)).resolves.toEqual({ unlocked: true });
    const inbox = await operate(restored.privateKey, 'read-inbox', inboxBody) as { checkpoints: string[]; requests: unknown[] };
    expect(inbox.checkpoints).toHaveLength(1);
    expect(inbox.requests).toEqual([]);
    // The host relay saw only nonces, NSM evidence and ciphertext.
  }, 240_000);

  test('a firm enrolled after publication discovers the case and decrypts only after owner approval', async () => {
    const relay = fetchRelay(`${relayBase}/channel`, `${relayBase}/objects`);
    const now = Date.now();
    const largeEvidence = new Uint8Array(randomBytes(400 * 1024));
    const prepared = await prepareConfidentialSubmission({ summary: 'Second public summary', narrative: { description: 'PRIVATE-SENTINEL-2' },
      contact: { contactValue: 'PRIVATE-SENTINEL-CONTACT-2' }, identity: null, files: [{ name: 'large.bin', type: 'application/octet-stream', bytes: largeEvidence }] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared });

    // This firm did not exist when the case was published. No submit-time
    // recipient snapshot may exclude it from the directory or owner grants.
    // Onboarded firm with a domain-confirmed key and one enrolled member. Firm
    // operations go browser -> host relay -> frame server -> legal dispatcher, with
    // the organization derived in the enclave from the legal token + membership.
    const firm = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic firm' }], format: 'object' })).privateKey;
    const org = { organizationId: hex(0xf1), recipientKeyId: await caseRecipientKeyId(firm.toPublic()), publicKey: firm.toPublic().armor() };
    await store.upsertLegalOrganization({ organizationId: org.organizationId, displayName: 'Synthetic Counsel LLP',
      domain: 'counsel.example', publicKey: org.publicKey, approved: true, providerOrganizationId: 'org_firm',
      recipientKeyId: org.recipientKeyId }, now);
    const bindingDocument = await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org.organizationId, issuedAt: now }, firm);
    const accessToken = async (scope = 'legal:directory legal:case', admin = false) => {
      const iat = Math.floor(Date.now() / 1000);
      return new jose.SignJWT({ iss: 'https://identity.example/', aud: admin ? 'admin-api' : 'https://api.example/legal', azp: admin ? 'admin-client' : 'legal-client',
        sub: admin ? 'auth0|operator' : 'auth0|lawyer', org_id: admin ? 'org_admin' : 'org_firm', scope, iat, exp: iat + 300,
        [LEGAL_ASSURANCE_CLAIM]: admin ? 'mfa-verified-email' : 'approved-member-verified-email' }).setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer-key' }).sign(issuer.privateKey);
    };
    const firmSession = async () => {
      const nonce = randomBytes(32).toString('hex');
      const serverKey = await readKey({ binaryKey: (await relay.open(nonce)).publicKey });
      return { nonce, serverKey, serverKeyId: await caseRecipientKeyId(serverKey) };
    };
    const exchange = async (channel: Awaited<ReturnType<typeof firmSession>>, request: unknown, last = true): Promise<any> => {
      const pending = await sealChannelRequest(channel.serverKey, channel.nonce, new TextEncoder().encode(JSON.stringify(request)));
      return JSON.parse(new TextDecoder().decode(await pending.openResponse(await relay.call(channel.nonce, pending.ciphertext, last))));
    };
    const firmCall = async (operation: ParticipantOperation, body: Uint8Array, key: PrivateKey = firm): Promise<any> => {
      // Challenge and operation share one attested session (challenges are session-bound).
      const channel = await firmSession();
      const { challenge } = await exchange(channel, { operation: 'legal.challenge' }, false);
      const proof = await signParticipantRequest({ audience: 'vera-confidential-cases', role: 'organization', caseId: prepared.caseId,
        organizationId: org.organizationId, operation, body, challenge, issuedAt: Date.now(), nonce: channel.nonce,
        serverKeyId: channel.serverKeyId }, key);
      return exchange(channel, { operation: `legal.${operation}`, accessToken: await accessToken(), proof,
        body: Buffer.from(body).toString('base64') });
    };
    // Real browser issuer through the mounted encrypted channel and Mongo RPC.
    const invitationInput = { relay, releaseManifest: MANIFEST, authority: onboarding.privateKey,
      organizationId: org.organizationId, recipientKeyId: org.recipientKeyId, providerOrganizationId: 'org_firm',
      subject: 'auth0|lawyer', now: Date.now(), lifetimeMs: 3_600_000, registration: { domain: 'counsel.example', displayName: 'Synthetic Counsel LLP', bindingDocument } };
    await expect(issueLegalInvitation({ ...invitationInput, accessToken: await accessToken('legal:invite') })).rejects.toThrow();
    await expect(issueLegalInvitation({ ...invitationInput, authority: firm, accessToken: await accessToken('legal:invite', true) })).rejects.toThrow();
    const { token: invitationToken } = await issueLegalInvitation({ ...invitationInput, accessToken: await accessToken('legal:invite', true) });
    const enroll = async (operation: string, body: unknown) => exchange(await firmSession(), { operation,
      accessToken: await accessToken('legal:enroll'), body: Buffer.from(JSON.stringify(body)).toString('base64') });
    const enrollmentChallenge = await enroll('legal.enrollment-challenge', { token: invitationToken });
    await expect(redeemInvitation({ relay, releaseManifest: MANIFEST, now: Date.now(), invitation: invitationToken,
      accessToken: await accessToken('legal:enroll'), firm: { organizationId: org.organizationId, domain: 'counsel.example',
        privateKey: firm, recipientKeyId: org.recipientKeyId } })).resolves.toEqual({ organizationId: org.organizationId });
    await expect(enroll('legal.enroll', { token: invitationToken, proof: await signEnrollmentChallenge(enrollmentChallenge, firm) }))
      .rejects.toThrow();
    const directory = await exchange(await firmSession(), { operation: 'legal.directory', accessToken: await accessToken(), after: null, limit: 20 });
    expect(directory.listings).toContainEqual({ caseId: prepared.caseId, summary: 'Second public summary', publishedAt: expect.any(Number), hasAttachments: true,
      ownerPublicKey: prepared.owner.trust.ownerPublicKey.armor(), listing: expect.any(String) });
    const requestCiphertext = await createLegalAccessRequest({ requestId: hex(0x301), scopes: ['narrative', 'evidence'], objectRevisionLimit: null,
      purpose: 'Counsel review', issuedAt: now, expiresAt: now + 86_400_000 }, org.organizationId, firm, prepared.owner.trust);
    const requestBody = new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId, requestId: hex(0x301),
      ciphertext: requestCiphertext, expiresAt: now + 86_400_000 }));
    await expect(firmCall('request-access', requestBody)).resolves.toEqual({ state: 'requested' });
    await expect(firmCall('open-case', new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId }))))
      .resolves.toEqual({ error: 'not-granted' });

    // Owner on a new device: recovery code only.
    const session = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    expect(await releaseApprovalStatus(session, Date.now())).toBe('approved');
    const inbox = await readOwnerInbox(session, Date.now());
    expect(inbox.summary).toBe('Second public summary');
    // Approval and sharing use the attested roster; no firm-domain connection is required.
    const roster = await verifiedRoster(session, Date.now());
    expect(roster.map(item => item.displayName)).toEqual(['Synthetic Counsel LLP']);
    const requests = await verifiedRequests(session, inbox, roster, Date.now());
    expect(requests.map(item => item.request.purpose)).toEqual(['Counsel review']);
    const decision = { grantId: hex(0x401), scopes: ['narrative', 'evidence'] as CaseScope[], objectRevisionLimit: null,
      expiresAt: Date.now() + 86_400_000 };
    await allowAccess(session, inbox, roster, requests[0], decision, Date.now());
    // The commit refreshed the stored recovery package: a fresh device restores the
    // grant checkpoint, but cannot confirm freshness without a prior device pin.
    expect(session.freshness).toBe('unconfirmed');
    const fresh = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    expect(fresh.pin).toEqual(session.pin);
    expect(fresh.freshness).toBe('unconfirmed');
    const pinned = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now(),
      rememberedPin: session.pin });
    await readOwnerInbox(pinned, Date.now());
    expect(pinned.freshness).toBe('device-pinned');

    // Enclave restart: the case is locked; the firm unlocks with its own envelope
    // and decrypts the narrative, all through the relay.
    const keysBody = new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId }));
    const restartPort = (enclave.address() as AddressInfo).port;
    await new Promise(resolve => enclave.close(resolve));
    enclave = await bootEnclave(restartPort);
    await expect(firmCall('open-case', keysBody)).resolves.toEqual({ error: 'locked' });
    const { stateEnvelopes } = await firmCall('read-state-keys', keysBody);
    const state = await findCaseStateKey(stateEnvelopes, prepared.caseId, firm, prepared.owner.trust.ownerPublicKey);
    const unlockBody = new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch }));
    await expect(firmCall('unlock-case', unlockBody)).resolves.toEqual({ unlocked: true });
    const opened = await firmCall('open-case', new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId, minimumCheckpoint: null, mode: 'index' })));
    const manifest = (await verifyOwnerStatement(opened.manifest, prepared.owner.trust)).statement as CaseManifest;
    const narrative = manifest.objects.find(entry => entry.scope === 'narrative')!;
    const context = { caseId: prepared.caseId, objectId: narrative.objectId, scope: 'narrative' as const, keyEpoch: 1, objectRevision: 1 };
    const fetchObject = async (entry: CaseManifest['objects'][number]) => {
      const indexed = opened.objects.find((item: { objectId: string }) => item.objectId === entry.objectId);
      expect(indexed).not.toHaveProperty('ciphertext');
      return collectGrantedCaseRanges({ caseId: prepared.caseId, objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest,
        scope: entry.scope, keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision, totalBytes: indexed.totalBytes },
        (offset, length) => firmCall('open-case', new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId,
          minimumCheckpoint: opened.checkpointDigest, checkpointDigest: opened.checkpointDigest,
          mode: 'range', objectId: entry.objectId, offset, length }))));
    };
    const narrativeObject = await fetchObject(narrative);
    const evidence = manifest.objects.find(entry => entry.scope === 'evidence')!;
    const encryptedEvidence = await fetchObject(evidence);
    const evidenceGrant = opened.grants.find((wire: string) => JSON.parse(wire).statement.scopes.includes('evidence'));
    // Evidence is a chunked object: the stored text is its index; chunks are
    // separate authenticated reads through the same relay and storage RPC.
    expect(isChunkedIndexText(encryptedEvidence.ciphertext)).toBe(true);
    const reader = await openGrantedChunkedObject(encryptedEvidence.ciphertext, encryptedEvidence.recipientEnvelope,
      { caseId: prepared.caseId, objectId: evidence.objectId, scope: evidence.scope, keyEpoch: evidence.keyEpoch, objectRevision: evidence.objectRevision },
      firm, { trust: prepared.owner.trust, grant: evidenceGrant, release: opened.release, manifest: opened.manifest,
        checkpoint: opened.checkpoint, checkpointDigest: opened.checkpointDigest, request: { organizationId: org.organizationId,
          recipientKeyId: org.recipientKeyId, objectId: evidence.objectId, ciphertextDigest: evidence.ciphertextDigest,
          scope: evidence.scope, releaseDigest: (await readReleaseManifest(MANIFEST)).digest,
          keyEpoch: evidence.keyEpoch, objectRevision: evidence.objectRevision, now: Date.now() } });
    expect(reader.name).toBe('large.bin');
    const readChunk = (chunkIndex: number) => firmCall('open-case', new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId,
      minimumCheckpoint: opened.checkpointDigest, checkpointDigest: opened.checkpointDigest, mode: 'chunk', objectId: evidence.objectId,
      chunkIndex })));
    const fileHash = createHash('sha256');
    for (let position = 0; position < reader.index.chunkCount; position++) {
      const reply = await readChunk(position);
      expect(Object.keys(reply).sort()).toEqual(['caseId', 'chunk', 'chunkIndex', 'ciphertextDigest', 'keyEpoch', 'objectId', 'objectRevision', 'scope']);
      fileHash.update(await reader.openChunk(position, new Uint8Array(Buffer.from(reply.chunk, 'base64'))));
    }
    expect(fileHash.digest('hex')).toBe(createHash('sha256').update(largeEvidence).digest('hex'));
    await expect(readChunk(reader.index.chunkCount)).rejects.toThrow();
    // Chunks live in their own collection; nothing there names the case or the file.
    const chunkRows = await client.db('test_mounted').collection('confidential_object_chunks').find({ _id: { $in: reader.index.chunks } } as never).toArray();
    expect(chunkRows).toHaveLength(reader.index.chunkCount);
    for (const row of chunkRows) expect(Object.keys(row).sort()).toEqual(['_id', 'data', 'size']);
    reader.dispose();
    await expect(firmCall('open-case', new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId,
      minimumCheckpoint: opened.checkpointDigest, checkpointDigest: hex(0xdead), mode: 'range', objectId: evidence.objectId,
      offset: 0, length: 1 })))).rejects.toThrow();
    // Removing the member stops the firm at the enclave, whatever the token says.
    await store.upsertLegalMember({ subject: 'auth0|lawyer', providerOrganizationId: 'org_firm', organizationId: org.organizationId,
      recipientKeyId: org.recipientKeyId, active: false }, Date.now());
    await expect(firmCall('open-case', keysBody)).rejects.toThrow();
    await expect(fetchObject(evidence)).rejects.toThrow();
    await expect(readChunk(0)).rejects.toThrow();
    const plaintext = await openGrantedCaseObject(narrativeObject,
      context, firm, { trust: prepared.owner.trust, grant: opened.grants[0], release: opened.release, manifest: opened.manifest,
        checkpoint: opened.checkpoint, checkpointDigest: opened.checkpointDigest, request: { organizationId: org.organizationId,
          recipientKeyId: org.recipientKeyId, objectId: narrative.objectId, ciphertextDigest: narrative.ciphertextDigest, scope: 'narrative',
          releaseDigest: (await readReleaseManifest(MANIFEST)).digest, keyEpoch: 1, objectRevision: 1, now: Date.now() } });
    expect(JSON.parse(new TextDecoder().decode(plaintext)).description).toBe('PRIVATE-SENTINEL-2');

    // A new backend release is deployed: the owner device sees it needs approval,
    // approves it explicitly, and only then can read through it.
    const UPGRADE = canonicalReleaseManifest({ ...JSON.parse(MANIFEST), sourceCommit: '2'.repeat(40),
      measurements: { pcr0: '44'.repeat(48), pcr1: '55'.repeat(48), pcr2: '66'.repeat(48) } });
    const port = (enclave.address() as AddressInfo).port;
    await new Promise(resolve => enclave.close(resolve));
    enclave = await bootEnclave(port, UPGRADE);
    const upgraded = { ...session, releaseManifest: UPGRADE, releaseDigest: (await readReleaseManifest(UPGRADE)).digest };
    expect(await releaseApprovalStatus(upgraded, Date.now())).toBe('needs-approval');
    await expect(readOwnerInbox(upgraded, Date.now())).rejects.toThrow();
    await approveCurrentRelease(upgraded, Date.now());
    const afterApproval = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: UPGRADE, now: Date.now() });
    expect(afterApproval.pin).toEqual(upgraded.pin);
    expect(await releaseApprovalStatus(upgraded, Date.now())).toBe('approved');
    await expect(readOwnerInbox(upgraded, Date.now())).resolves.toMatchObject({ summary: 'Second public summary' });
  }, 300_000);

  test('owner extras: add evidence, legacy message storage, summary edit/withdraw, revoke with key rotation across restart', async () => {
    // The previous test left the enclave on its upgraded release; boot the original one.
    const enclavePort = (enclave.address() as AddressInfo).port;
    await new Promise(resolve => enclave.close(resolve));
    enclave = await bootEnclave(enclavePort);
    const relay = fetchRelay(`${relayBase}/channel`, `${relayBase}/objects`);
    const now = Date.now();
    const releaseDigest = (await readReleaseManifest(MANIFEST)).digest;
    const prepared = await prepareConfidentialSubmission({ summary: 'Third public summary', narrative: { description: 'PRIVATE-SENTINEL-3' },
      contact: null, identity: null, files: [{ name: 'first.txt', type: 'text/plain', bytes: new TextEncoder().encode('FIRST-FILE') }] },
    MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared });
    const trust = prepared.owner.trust;

    // Two onboarded firms with domain-confirmed keys.
    const firms = await Promise.all([0xa, 0xb].map(async (n, index) => {
      const key = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Firm ${n}` }], format: 'object' })).privateKey;
      const org = { organizationId: hex(0xf100 + n), recipientKeyId: await caseRecipientKeyId(key.toPublic()), publicKey: key.toPublic().armor() };
      const domain = `firm${index}.example`;
      await store.upsertLegalOrganization({ organizationId: org.organizationId, displayName: `Firm ${index === 0 ? 'Alpha' : 'Bravo'} LLP`,
        domain, publicKey: org.publicKey, approved: true, registration: await signOrganizationRegistration({
          format: 'vera-organization-registration/v1', ...org, providerOrganizationId: `org_firm${index}`,
          displayName: `Firm ${index === 0 ? 'Alpha' : 'Bravo'} LLP`, domain, approved: true, issuedAt: now }, onboarding.privateKey) }, now);
      const binding = await createFirmKeyBinding({ domain, organizationId: org.organizationId, issuedAt: now }, key);
      return { key, org, domain, binding };
    }));
    const [alpha, bravo] = firms;
    const channel = { nonce: hex(0xb1), serverKeyId: hex(0xb2), challenges: createSessionChallenges() };
    // The firm side runs on its own service instance (its channel mount is separate work).
    const firmService = () => {
      const keyring = createCaseKeyring({ clock: Date.now });
      return createCaseService({ channel, store: createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), keyring),
        keyring, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest });
    };
    let firmSide = firmService();
    const firmCall = async (firm: typeof alpha, operation: ParticipantOperation, value: unknown) => {
      const body = new TextEncoder().encode(JSON.stringify(value));
      const { challenge } = await firmSide.issueChallenge();
      const proof = await signParticipantRequest({ ...channel, audience: 'vera-confidential-cases', role: 'organization', caseId: prepared.caseId,
        organizationId: firm.org.organizationId, operation, body, challenge, issuedAt: Date.now() }, firm.key);
      return { body, proof };
    };
    const scopes: CaseScope[] = ['narrative', 'evidence', 'messages'];
    for (const [index, firm] of firms.entries()) {
      const requestId = hex(0x500 + index);
      const ciphertext = await createLegalAccessRequest({ requestId, scopes, objectRevisionLimit: null,
        purpose: `Review ${index}`, issuedAt: now, expiresAt: now + 86_400_000 }, firm.org.organizationId, firm.key, trust);
      const call = await firmCall(firm, 'request-access', { caseId: prepared.caseId, requestId, ciphertext, expiresAt: now + 86_400_000 });
      await firmSide.submitAccessRequest(call.body, call.proof, firm.org);
    }

    const session: OwnerSession = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const pins: number[] = [];
    session.onPinAdvance = pin => pins.push(pin.revision);
    const refresh = async () => {
      const inbox = await readOwnerInbox(session, Date.now());
      const roster = await verifiedRoster(session, Date.now());
      const requests = await verifiedRequests(session, inbox, roster, Date.now());
      const grantees = await currentGrantees(session, inbox, roster);
      return { inbox, roster, requests, grantees, threads: await readOwnerThreads(session, inbox, roster, requests, grantees) };
    };
    let view = await refresh();
    expect(view.requests).toHaveLength(2);
    const rawRequests = await client.db('test_mounted').collection('confidential_access_requests').find({ caseId: prepared.caseId }).toArray();
    for (const firm of [alpha, bravo]) {
      expect(JSON.stringify(rawRequests)).not.toContain(firm.org.organizationId);
      expect(JSON.stringify(rawRequests)).not.toContain(firm.org.recipientKeyId);
    }
    for (const item of view.requests) expect(JSON.stringify(rawRequests)).not.toContain(item.request.requestId);
    // Same-day requests have no stored arrival order (rows keep only the day), so
    // allow them in a fixed order: Alpha, then Bravo.
    const byName = [...view.requests].sort((a, b) => a.organization.displayName.localeCompare(b.organization.displayName));
    for (const request of byName) {
      await allowAccess(session, view.inbox, view.roster, request, { grantId: request.delivery.requestId, scopes,
        objectRevisionLimit: null, expiresAt: Date.now() + 86_400_000 }, Date.now());
      view = await refresh();
    }
    expect(view.grantees.map(item => item.organization?.displayName).sort()).toEqual(['Firm Alpha LLP', 'Firm Bravo LLP']);

    // Firm helpers: unlock with its own state-key envelope, then open and decrypt.
    const stateOf = async (firm: typeof alpha) => {
      const keys = await firmCall(firm, 'read-state-keys', { caseId: prepared.caseId });
      const { stateEnvelopes } = await firmSide.getStateEnvelopes(keys.body, keys.proof, firm.org);
      return findCaseStateKey(stateEnvelopes, prepared.caseId, firm.key, trust.ownerPublicKey);
    };
    const unlockAs = async (firm: typeof alpha, retained?: Awaited<ReturnType<typeof stateOf>>) => {
      const state = retained ?? await stateOf(firm);
      const unlock = await firmCall(firm, 'unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch });
      return firmSide.unlockCase(unlock.body, unlock.proof, firm.org);
    };
    const openAs = async (firm: typeof alpha) => {
      const call = await firmCall(firm, 'open-case', { caseId: prepared.caseId });
      const opened = await firmSide.openCase(call.body, call.proof, firm.org);
      const manifest = (await verifyOwnerStatement(opened.manifest, trust)).statement as CaseManifest;
      const files: string[] = [];
      for (const object of opened.objects) {
        const entry = manifest.objects.find(item => item.objectId === object.objectId)!;
        let grant = '';
        for (const wire of opened.grants) if ((await verifyOwnerStatement(wire, trust)).digest === object.grantDigest) grant = wire;
        const objectContext = { caseId: prepared.caseId, objectId: entry.objectId, scope: entry.scope, keyEpoch: entry.keyEpoch,
          objectRevision: entry.objectRevision };
        const authorization = { trust, grant, release: opened.release, manifest: opened.manifest, checkpoint: opened.checkpoint,
          checkpointDigest: opened.checkpointDigest, request: { organizationId: firm.org.organizationId, recipientKeyId: firm.org.recipientKeyId,
            objectId: entry.objectId, ciphertextDigest: entry.ciphertextDigest, scope: entry.scope, releaseDigest,
            keyEpoch: entry.keyEpoch, objectRevision: entry.objectRevision, now: Date.now() } };
        if (entry.scope === 'evidence' && isChunkedIndexText(object.ciphertext)) {
          // Chunked evidence: the index, then each chunk as its own authorized read.
          const reader = await openGrantedChunkedObject(object.ciphertext, object.recipientEnvelope, objectContext, firm.key, authorization);
          const parts: Uint8Array[] = [];
          for (let position = 0; position < reader.index.chunkCount; position++) {
            const read = await firmCall(firm, 'open-case', { caseId: prepared.caseId, minimumCheckpoint: opened.checkpointDigest,
              mode: 'chunk', objectId: entry.objectId, chunkIndex: position, checkpointDigest: opened.checkpointDigest });
            const { chunk } = await firmSide.openCase(read.body, read.proof, firm.org) as { chunk: string };
            parts.push(await reader.openChunk(position, new Uint8Array(Buffer.from(chunk, 'base64'))));
          }
          files.push(`${reader.name}:${new TextDecoder().decode(Buffer.concat(parts))}`);
          reader.dispose();
          continue;
        }
        const plaintext = await openGrantedCaseObject({ ciphertext: object.ciphertext, recipientEnvelope: object.recipientEnvelope },
          objectContext, firm.key, authorization);
        if (entry.scope === 'evidence') {
          const file = unpackCaseFile(plaintext);
          files.push(`${file.name}:${new TextDecoder().decode(file.bytes)}`);
        }
      }
      return files.sort();
    };
    await unlockAs(alpha);
    expect(await openAs(alpha)).toEqual(['first.txt:FIRST-FILE']);

    // 1. Add evidence after submission: sealed, staged, manifest + checkpoint signed,
    // content key wrapped for both future-inclusive grantees.
    const added = await addEvidence(session, view.inbox, view.roster,
      [{ name: 'later.pdf', type: 'application/pdf', bytes: new TextEncoder().encode('LATER-EVIDENCE') }], Date.now());
    expect(added.sharedWith.map(item => item.displayName).sort()).toEqual(['Firm Alpha LLP', 'Firm Bravo LLP']);
    expect(await openAs(alpha)).toEqual(['first.txt:FIRST-FILE', 'later.pdf:LATER-EVIDENCE']);
    expect(await openAs(bravo)).toEqual(['first.txt:FIRST-FILE', 'later.pdf:LATER-EVIDENCE']);
    const everything = JSON.stringify(await Promise.all((await client.db('test_mounted').collections())
      .map(collection => collection.find().toArray())));
    for (const secret of ['LATER-EVIDENCE', 'later.pdf', 'PRIVATE-SENTINEL-3']) expect(everything).not.toContain(secret);

    // 2. Legacy encrypted message storage remains readable; the mounted owner route refuses new replies.
    const participants = (firm: typeof alpha) => ({ owner: trust, organization: { organizationId: firm.org.organizationId, publicKey: firm.key.toPublic() } });
    const firmMessage = await sealCaseMessage({ sender: 'organization', sequence: 1, sentAt: Date.now(), body: 'Question from Alpha' },
      participants(alpha), alpha.key);
    const send = await firmCall(alpha, 'send-message', { caseId: prepared.caseId, organizationId: alpha.org.organizationId, ciphertext: firmMessage });
    await firmSide.sendMessage(send.body, send.proof, alpha.org);
    view = await refresh();
    const alphaThread = view.threads.find(thread => thread.organization.organizationId === alpha.org.organizationId)!;
    expect(alphaThread.messages.map(item => [item.sender, item.body])).toEqual([['organization', 'Question from Alpha']]);
    await expect(sendOwnerMessage(session, alphaThread, 'Owner answer', Date.now())).rejects.toThrow();
    view = await refresh();
    const thread = view.threads.find(item => item.organization.organizationId === alpha.org.organizationId)!;
    expect(thread.messages.map(item => [item.sender, item.sequence, item.body]))
      .toEqual([['organization', 1, 'Question from Alpha']]);
    const read = await firmCall(alpha, 'read-messages', { caseId: prepared.caseId });
    const { messages } = await firmSide.readMessages(read.body, read.proof, alpha.org);
    const floors = { owner: 0, organization: 0 };
    const opened = [];
    for (const stored of messages) {
      const message = await openCaseMessage(stored.ciphertext, participants(alpha), alpha.key, floors);
      floors[message.sender] = message.sequence;
      opened.push(message.body);
    }
    expect(opened).toEqual(['Question from Alpha']);
    const messageCollection = client.db('test_mounted').collection('confidential_messages');
    const rawMessages = await messageCollection.find({ caseId: prepared.caseId }).toArray();
    for (const firm of [alpha, bravo]) {
      expect(JSON.stringify(rawMessages)).not.toContain(firm.org.organizationId);
      expect(JSON.stringify(rawMessages)).not.toContain(firm.org.recipientKeyId);
    }
    // The host's own index refuses a verbatim copy of a stored row's idempotency tag.
    const { _id: ignoredId, ...rawReplay } = rawMessages[rawMessages.length - 1];
    await expect(messageCollection.insertOne({ ...rawReplay })).rejects.toMatchObject({ code: 11000 });
    // A hostile host can still mint a fresh tag (it is unauthenticated host metadata),
    // so the remaining replay checks run with one. Substituting visible
    // routing/timestamp fails authenticated opening.
    const freshTag = () => randomBytes(32).toString('hex');
    const inserted = await messageCollection.insertOne({ ...rawReplay, createdAt: rawReplay.createdAt + 1, dedupeTag: freshTag() });
    await expect(refresh()).rejects.toThrow();
    await messageCollection.deleteOne({ _id: inserted.insertedId });
    // An otherwise exact sealed replay is still discarded by participant sequence floors.
    const replayed = await messageCollection.insertOne({ ...rawReplay, dedupeTag: freshTag() });
    view = await refresh();
    expect(view.threads.find(item => item.organization.organizationId === alpha.org.organizationId)!.messages).toHaveLength(1);
    await messageCollection.deleteOne({ _id: replayed.insertedId });

    // 3. Summary edit and withdrawal.
    await updateSummary(session, view.inbox, 'Edited public summary', Date.now());
    view = await refresh();
    expect(view.inbox.summary).toBe('Edited public summary');
    // Withdraw from a device whose clock lags the last checkpoint: the successor keeps
    // signed time monotonic, so the enclave's no-regression check accepts it.
    const editedAt = view.inbox.current.issuedAt;
    await updateSummary(session, view.inbox, null, Date.now() - 60_000);
    view = await refresh();
    expect(view.inbox.current.issuedAt).toBe(editedAt);
    expect(view.inbox.summary).toBeNull();
    expect(view.inbox.current.listingDigest).toBeNull();
    expect((await firmSide.listListings({ kind: 'admin' }, null)).listings.map(item => item.caseId)).not.toContain(prepared.caseId);

    // 4. Revoke Bravo: new checkpoint without its grant, state key rotated to epoch 2
    // and wrapped only to the owner and Alpha.
    const bravoOldKey = await stateOf(bravo);
    expect(bravoOldKey.stateEpoch).toBe(1);
    const bravoGrant = view.grantees.find(item => item.organizationId === bravo.org.organizationId)!;
    await revokeAccess(session, view.inbox, view.roster, bravoGrant.grantDigests[0], Date.now());
    view = await refresh();
    expect(view.grantees.map(item => item.organizationId)).toEqual([alpha.org.organizationId]);
    expect(view.threads.find(item => item.organization.organizationId === bravo.org.organizationId)).toBeUndefined();

    // Restart both the enclave and the firm-side process: every cached key is gone.
    const port = (enclave.address() as AddressInfo).port;
    await new Promise(resolve => enclave.close(resolve));
    enclave = await bootEnclave(port);
    firmSide = firmService();
    // No current envelope opens for Bravo, and the epoch-1 key it retained no longer unlocks.
    await expect(stateOf(bravo)).rejects.toThrow();
    await expect(unlockAs(bravo, bravoOldKey)).rejects.toMatchObject({ code: 'unauthorized' });
    expect((await stateOf(alpha)).stateEpoch).toBe(2);
    const bravoOpen = await firmCall(bravo, 'open-case', { caseId: prepared.caseId });
    await expect(firmSide.openCase(bravoOpen.body, bravoOpen.proof, bravo.org)).rejects.toMatchObject({ code: 'locked' });
    // Alpha still unlocks with the rotated key and reads everything, including the older evidence.
    await expect(unlockAs(alpha)).resolves.toEqual({ unlocked: true });
    expect(await openAs(alpha)).toEqual(['first.txt:FIRST-FILE', 'later.pdf:LATER-EVIDENCE']);
    // Even with the case unlocked by someone else, Bravo has no current grant.
    const bravoOpenAgain = await firmCall(bravo, 'open-case', { caseId: prepared.caseId });
    await expect(firmSide.openCase(bravoOpenAgain.body, bravoOpenAgain.proof, bravo.org)).rejects.toMatchObject({ code: 'not-found' });
    const bravoMessage = await sealCaseMessage({ sender: 'organization', sequence: 1, sentAt: Date.now(), body: 'After revoke' }, participants(bravo), bravo.key);
    const bravoSend = await firmCall(bravo, 'send-message', { caseId: prepared.caseId, organizationId: bravo.org.organizationId, ciphertext: bravoMessage });
    await expect(firmSide.sendMessage(bravoSend.body, bravoSend.proof, bravo.org)).rejects.toMatchObject({ code: 'unauthorized' });
    // The owner device still works after the restart (it unlocks with its rotated key).
    await expect(readOwnerInbox(session, Date.now())).resolves.toMatchObject({ summary: null });

    // 5. Evidence added after revocation reaches only the remaining grantee.
    view = await refresh();
    const after = await addEvidence(session, view.inbox, view.roster,
      [{ name: 'after.txt', type: 'text/plain', bytes: new TextEncoder().encode('AFTER-REVOKE') }], Date.now());
    expect(after.sharedWith.map(item => item.displayName)).toEqual(['Firm Alpha LLP']);
    expect(await openAs(alpha)).toEqual(['after.txt:AFTER-REVOKE', 'first.txt:FIRST-FILE', 'later.pdf:LATER-EVIDENCE']);

    // 5b. Files added after an Allow that did not include later files can be
    // shared with that organization by the reporter, without a new request.
    view = await refresh();
    let alphaRow = view.grantees.find(item => item.organizationId === alpha.org.organizationId)!;
    let entries = evidenceEntries(await currentManifest(session, view.inbox));
    const currentOnly = { ...changeChoice(alphaRow.grants, entries), future: false };
    await changeAccess(session, view.inbox, alphaRow, changeDecisionFromChoice(currentOnly, alphaRow.grants, entries,
      view.inbox.current.revision, Date.now()), Date.now());
    view = await refresh();
    alphaRow = view.grantees.find(item => item.organizationId === alpha.org.organizationId)!;
    expect(alphaRow.grants.map(grant => grant.objectRevisionLimit)).toEqual([view.inbox.current.revision - 1]);
    const late = await addEvidence(session, view.inbox, view.roster,
      [{ name: 'late.txt', type: 'text/plain', bytes: new TextEncoder().encode('LATE-FILE') }], Date.now());
    expect(late.sharedWith).toEqual([]);
    expect(await openAs(alpha)).toEqual(['after.txt:AFTER-REVOKE', 'first.txt:FIRST-FILE', 'later.pdf:LATER-EVIDENCE']);
    view = await refresh();
    alphaRow = view.grantees.find(item => item.organizationId === alpha.org.organizationId)!;
    entries = evidenceEntries(await currentManifest(session, view.inbox));
    const everyFile = changeChoice(alphaRow.grants, entries);
    expect(everyFile).toMatchObject({ report: true, evidence: 'some', future: false });
    const shareAll = changeDecisionFromChoice({ ...everyFile, evidence: 'all' }, alphaRow.grants, entries, view.inbox.current.revision, Date.now());
    // The end date is kept; only what they can read changes.
    expect(shareAll.expiresAt).toBe(alphaRow.grants[0].expiresAt);
    await changeAccess(session, view.inbox, alphaRow, shareAll, Date.now());
    expect(await openAs(alpha)).toEqual(['after.txt:AFTER-REVOKE', 'first.txt:FIRST-FILE', 'late.txt:LATE-FILE', 'later.pdf:LATER-EVIDENCE']);
    view = await refresh();

    // 6. A device that remembered its pin refuses a rolled-back (older) chain.
    const remembered = session.pin;
    expect(pins.length).toBeGreaterThan(5);
    const fresh = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now(), rememberedPin: remembered });
    await expect(readOwnerInbox(fresh, Date.now())).resolves.toMatchObject({ checkpointDigest: remembered.digest });
    const forged = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now(),
      rememberedPin: { ...remembered, revision: remembered.revision + 1, digest: hex(0xdead) } });
    await expect(readOwnerInbox(forged, Date.now())).rejects.toThrow('does not match');

    // 7. Every change left a record: a new device restored from the recovery code
    // verifies the whole signed chain from genesis and rebuilds the same timeline.
    const reopened = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const reopenedInbox = await readOwnerInbox(reopened, Date.now());
    expect(reopened.history!.map(entry => entry.checkpoint.revision))
      .toEqual(Array.from({ length: reopened.pin.revision }, (_, index) => index + 1));
    expect(reopened.history!.map(entry => entry.digest)).toEqual(session.history!.map(entry => entry.digest));
    const reopenedRoster = await verifiedRoster(reopened, Date.now());
    const reopenedRequests = await verifiedRequests(reopened, reopenedInbox, reopenedRoster, Date.now());
    const reopenedGrantees = await currentGrantees(reopened, reopenedInbox, reopenedRoster);
    const timeline = await buildOwnerTimeline({ trust: reopened.trust, history: reopened.history!, statements: reopenedInbox.statements,
      roster: reopenedRoster, requests: reopenedRequests, threads: await readOwnerThreads(reopened, reopenedInbox, reopenedRoster,
        reopenedRequests, reopenedGrantees), now: Date.now() });
    expect(timeline.incomplete).toBe(false);
    expect([...timeline.events].reverse().map(event => event.title)).toEqual([
      'You submitted your report', 'Your summary was published for legal organizations',
      'You allowed access for Firm Alpha LLP', 'You allowed access for Firm Bravo LLP', 'You added 1 file',
      'Message from Firm Alpha LLP',
      'You edited your summary', 'You withdrew your summary from the directory',
      'You revoked access for Firm Bravo LLP', 'You added 1 file',
      'You changed access for Firm Alpha LLP', 'You added 1 file', 'You changed access for Firm Alpha LLP',
    ]);
    const files = timeline.events.filter(event => event.kind === 'files-added').map(event => event.detail);
    expect(files).toEqual(['Only you can open them.', 'Covered by access for Firm Alpha LLP.',
      'Covered by access for Firm Alpha LLP, Firm Bravo LLP.']);
    const timelineText = JSON.stringify(timeline);
    for (const secret of ['Question from Alpha', 'Owner answer', 'LATER-EVIDENCE', 'later.pdf', 'Edited public summary']) {
      expect(timelineText).not.toContain(secret);
    }
    expect(ownerJourney(reopenedInbox.current, reopenedRequests, reopenedGrantees, Date.now()))
      .toEqual({ submitted: true, visible: false, requests: 0, sharedWith: 1 });
  }, 600_000);
  test('revoking one organization never re-keys or checks an organization whose access has ended', async () => {
    const relay = fetchRelay(`${relayBase}/channel`, `${relayBase}/objects`);
    const now = Date.now();
    const releaseDigest = (await readReleaseManifest(MANIFEST)).digest;
    const prepared = await prepareConfidentialSubmission({ summary: 'Expiry public summary', narrative: { description: 'PRIVATE-SENTINEL-4' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared });
    const trust = prepared.owner.trust;
    const names = ['Charlie', 'Delta', 'Echo'];
    const firms = await Promise.all([0xc, 0xd, 0xe].map(async (n, index) => {
      const key = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Firm ${n}` }], format: 'object' })).privateKey;
      const org = { organizationId: hex(0xf200 + n), recipientKeyId: await caseRecipientKeyId(key.toPublic()), publicKey: key.toPublic().armor() };
      const domain = `expiry${index}.example`, displayName = `Firm ${names[index]} LLP`;
      await store.upsertLegalOrganization({ organizationId: org.organizationId, displayName, domain, publicKey: org.publicKey, approved: true,
        registration: await signOrganizationRegistration({ format: 'vera-organization-registration/v1', ...org,
          providerOrganizationId: `org_expiry${index}`, displayName, domain, approved: true, issuedAt: now }, onboarding.privateKey) }, now);
      const binding = await createFirmKeyBinding({ domain, organizationId: org.organizationId, issuedAt: now }, key);
      return { key, org, domain, binding };
    }));
    const [charlie, delta, echo] = firms;
    const channel = { nonce: hex(0xc1), serverKeyId: hex(0xc2), challenges: createSessionChallenges() };
    const keyring = createCaseKeyring({ clock: Date.now });
    const firmSide = createCaseService({ channel, store: createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), keyring),
      keyring, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest });
    const firmCall = async (firm: typeof charlie, operation: ParticipantOperation, value: unknown) => {
      const body = new TextEncoder().encode(JSON.stringify(value));
      const { challenge } = await firmSide.issueChallenge();
      const proof = await signParticipantRequest({ ...channel, audience: 'vera-confidential-cases', role: 'organization', caseId: prepared.caseId,
        organizationId: firm.org.organizationId, operation, body, challenge, issuedAt: Date.now() }, firm.key);
      return { body, proof };
    };
    const stateOf = async (firm: typeof charlie) => {
      const keys = await firmCall(firm, 'read-state-keys', { caseId: prepared.caseId });
      const { stateEnvelopes } = await firmSide.getStateEnvelopes(keys.body, keys.proof, firm.org);
      return findCaseStateKey(stateEnvelopes, prepared.caseId, firm.key, trust.ownerPublicKey);
    };
    const scopes: CaseScope[] = ['narrative', 'messages'];
    for (const [index, firm] of firms.entries()) {
      const requestId = hex(0x600 + index);
      const ciphertext = await createLegalAccessRequest({ requestId, scopes, objectRevisionLimit: null,
        purpose: `Expiry review ${index}`, issuedAt: now, expiresAt: now + 86_400_000 }, firm.org.organizationId, firm.key, trust);
      const call = await firmCall(firm, 'request-access', { caseId: prepared.caseId, requestId, ciphertext, expiresAt: now + 86_400_000 });
      await firmSide.submitAccessRequest(call.body, call.proof, firm.org);
    }
    const session: OwnerSession = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const refresh = async () => {
      const inbox = await readOwnerInbox(session, Date.now());
      const roster = await verifiedRoster(session, Date.now());
      const requests = await verifiedRequests(session, inbox, roster, Date.now());
      return { inbox, roster, requests, grantees: await currentGrantees(session, inbox, roster) };
    };
    const allow = async (firm: typeof charlie, expiresAt: number | null, now = Date.now()) => {
      const view = await refresh();
      const request = view.requests.find(item => item.request.organizationId === firm.org.organizationId)!;
      await allowAccess(session, view.inbox, view.roster, request, { grantId: request.delivery.requestId, scopes,
        objectRevisionLimit: null, expiresAt }, now);
    };
    // Delta's access ends a few seconds after it is allowed; Charlie's is until revoked.
    const deltaEnds = Date.now() + 6_000;
    await allow(delta, deltaEnds);
    await allow(charlie, null);
    expect((await stateOf(delta)).stateEpoch).toBe(1);
    await new Promise(resolve => setTimeout(resolve, Math.max(0, deltaEnds - Date.now()) + 500));

    // Revoke Charlie while Delta's access has ended: Delta does not block the
    // revoke and gets no rotated key.
    let view = await refresh();
    expect(view.grantees.map(item => item.organizationId).sort())
      .toEqual([charlie.org.organizationId, delta.org.organizationId].sort());
    const charlieRow = view.grantees.find(item => item.organizationId === charlie.org.organizationId)!;
    await revokeAccess(session, view.inbox, view.roster, charlieRow.grantDigests[0], Date.now());
    view = await refresh();
    // The ended access stays listed (renew or revoke it), but holds no current key.
    expect(view.grantees.map(item => item.organizationId)).toEqual([delta.org.organizationId]);
    await expect(stateOf(delta)).rejects.toThrow();
    await expect(stateOf(charlie)).rejects.toThrow();

    // A later Allow re-wraps the (rotated) state key: again never to Delta. It runs
    // from a device whose clock lags the last checkpoint (the revoke above): the
    // grant commit keeps signed time monotonic, so the enclave accepts it.
    // The lag stays after Delta's end (the revoke ran 500 ms past it), so Delta
    // still reads as ended on this device.
    const revokedAt = view.inbox.current.issuedAt;
    await allow(echo, null, revokedAt - 200);
    view = await refresh();
    expect(view.inbox.current.issuedAt).toBe(revokedAt);
    expect((await stateOf(echo)).stateEpoch).toBe(2);
    await expect(stateOf(delta)).rejects.toThrow();

    // Renewing Delta is the explicit way back: only then does it receive the key.
    view = await refresh();
    const deltaRow = view.grantees.find(item => item.organizationId === delta.org.organizationId)!;
    // Also from the lagging device: Renew must not be refused either.
    const allowedAt = view.inbox.current.issuedAt;
    await renewAccess(session, view.inbox, view.roster, deltaRow, null, allowedAt - 200);
    view = await refresh();
    expect(view.inbox.current.issuedAt).toBe(allowedAt);
    expect((await stateOf(delta)).stateEpoch).toBe(2);
    expect((await stateOf(echo)).stateEpoch).toBe(2);
    await expect(stateOf(charlie)).rejects.toThrow();
  }, 300_000);
  test('an organization whose access has ended is refused on expiry alone, before any revoke or re-key', async () => {
    const relay = fetchRelay(`${relayBase}/channel`, `${relayBase}/objects`);
    const now = Date.now();
    const releaseDigest = (await readReleaseManifest(MANIFEST)).digest;
    const prepared = await prepareConfidentialSubmission({ summary: 'Ended access public summary', narrative: { description: 'PRIVATE-SENTINEL-5' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared });
    const trust = prepared.owner.trust;
    const names = ['Foxtrot', 'Golf'];
    const firms = await Promise.all([0xf, 0x10].map(async (n, index) => {
      const key = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Firm ${n}` }], format: 'object' })).privateKey;
      const org = { organizationId: hex(0xf300 + n), recipientKeyId: await caseRecipientKeyId(key.toPublic()), publicKey: key.toPublic().armor() };
      const domain = `ended${index}.example`, displayName = `Firm ${names[index]} LLP`;
      await store.upsertLegalOrganization({ organizationId: org.organizationId, displayName, domain, publicKey: org.publicKey, approved: true,
        registration: await signOrganizationRegistration({ format: 'vera-organization-registration/v1', ...org,
          providerOrganizationId: `org_ended${index}`, displayName, domain, approved: true, issuedAt: now }, onboarding.privateKey) }, now);
      return { key, org, domain, requestId: hex(0x700 + index) };
    }));
    const [foxtrot, golf] = firms;
    const channel = { nonce: hex(0xd1), serverKeyId: hex(0xd2), challenges: createSessionChallenges() };
    const keyring = createCaseKeyring({ clock: Date.now });
    const firmSide = createCaseService({ channel, store: createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), keyring),
      keyring, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest });
    const firmCall = async (firm: typeof golf, operation: ParticipantOperation, value: unknown) => {
      const body = new TextEncoder().encode(JSON.stringify(value));
      const { challenge } = await firmSide.issueChallenge();
      const proof = await signParticipantRequest({ ...channel, audience: 'vera-confidential-cases', role: 'organization', caseId: prepared.caseId,
        organizationId: firm.org.organizationId, operation, body, challenge, issuedAt: Date.now() }, firm.key);
      return { body, proof };
    };
    const stateOf = async (firm: typeof golf) => {
      const keys = await firmCall(firm, 'read-state-keys', { caseId: prepared.caseId });
      const { stateEnvelopes } = await firmSide.getStateEnvelopes(keys.body, keys.proof, firm.org);
      return findCaseStateKey(stateEnvelopes, prepared.caseId, firm.key, trust.ownerPublicKey);
    };
    const unlockWith = async (firm: typeof golf, state: Awaited<ReturnType<typeof stateOf>>) => {
      const call = await firmCall(firm, 'unlock-case', { caseId: prepared.caseId, stateKey: encodeBase64(state.key), stateEpoch: state.stateEpoch });
      return firmSide.unlockCase(call.body, call.proof, firm.org);
    };
    const open = async (firm: typeof golf) => {
      const call = await firmCall(firm, 'open-case', { caseId: prepared.caseId });
      return await firmSide.openCase(call.body, call.proof, firm.org) as { grants: string[] };
    };
    const status = async (firm: typeof golf) => {
      const call = await firmCall(firm, 'request-status', { caseId: prepared.caseId, requestIds: [firm.requestId] });
      return (await firmSide.requestStatus(call.body, call.proof, firm.org)).access;
    };
    const scopes: CaseScope[] = ['narrative', 'messages'];
    for (const firm of firms) {
      const ciphertext = await createLegalAccessRequest({ requestId: firm.requestId, scopes, objectRevisionLimit: null,
        purpose: 'Ended access review', issuedAt: now, expiresAt: now + 86_400_000 }, firm.org.organizationId, firm.key, trust);
      const call = await firmCall(firm, 'request-access', { caseId: prepared.caseId, requestId: firm.requestId, ciphertext, expiresAt: now + 86_400_000 });
      await firmSide.submitAccessRequest(call.body, call.proof, firm.org);
    }
    const session: OwnerSession = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    const refresh = async () => {
      const inbox = await readOwnerInbox(session, Date.now());
      const roster = await verifiedRoster(session, Date.now());
      return { inbox, roster, requests: await verifiedRequests(session, inbox, roster, Date.now()) };
    };
    const allow = async (firm: typeof golf, expiresAt: number | null) => {
      const view = await refresh();
      const request = view.requests.find(item => item.request.organizationId === firm.org.organizationId)!;
      await allowAccess(session, view.inbox, view.roster, request, { grantId: request.delivery.requestId, scopes,
        objectRevisionLimit: null, expiresAt }, Date.now());
    };
    // Foxtrot's access is until revoked. It unlocks this firm-side instance, so the
    // case reads as open (not `locked`) here and only Golf's own grant decides.
    await allow(foxtrot, null);
    await expect(unlockWith(foxtrot, await stateOf(foxtrot))).resolves.toEqual({ unlocked: true });
    // Golf's access ends shortly after it is allowed (with room for a loaded
    // machine). While it lasts, Golf reads its state key and opens the case.
    const golfEnds = Date.now() + 30_000;
    await allow(golf, golfEnds);
    const golfState = await stateOf(golf);
    expect(golfState.stateEpoch).toBe(1);
    expect((await open(golf)).grants).toHaveLength(1);
    await expect(status(golf)).resolves.toMatchObject({ state: 'active', expiresAt: golfEnds });
    expect(Date.now()).toBeLessThan(golfEnds);
    const allowed = (await refresh()).inbox;
    await new Promise(resolve => setTimeout(resolve, Math.max(0, golfEnds - Date.now()) + 500));

    // Past the end date on the same checkpoint and state-key epoch: no revoke, no
    // re-key, no new owner statement. Expiry alone refuses every read path.
    const after = (await refresh()).inbox;
    expect(after.checkpointDigest).toBe(allowed.checkpointDigest);
    await expect(status(golf)).resolves.toMatchObject({ state: 'expired', expiresAt: golfEnds, scopes: [] });
    await expect(open(golf)).rejects.toMatchObject({ code: 'not-found' });
    await expect(stateOf(golf)).rejects.toMatchObject({ code: 'not-found' });
    // The state key Golf kept from while its access lasted is still current, and
    // still refused: a key alone never stands in for a grant. The key opens the
    // sealed state (a wrong key stays `unauthorized`), so the refusal is the grant
    // check itself: `not-found`, the same as open-case and read-state-keys, which
    // the legal channel answers to the firm as `not-granted`.
    await expect(unlockWith(golf, { ...golfState, key: randomBytes(golfState.key.length) }))
      .rejects.toMatchObject({ code: 'unauthorized' });
    await expect(unlockWith(golf, golfState)).rejects.toMatchObject({ code: 'not-found' });
    await expect(open(golf)).rejects.toMatchObject({ code: 'not-found' });
    // Foxtrot, on that same checkpoint and epoch, still reads.
    await expect(status(foxtrot)).resolves.toMatchObject({ state: 'active', expiresAt: null });
    expect((await open(foxtrot)).grants).toHaveLength(1);
    expect((await stateOf(foxtrot)).stateEpoch).toBe(1);
  }, 300_000);

  test('organization setup is enforced through the mounted stack: refused until custody and signed terms are stored with the organization', async () => {
    // Restart the enclave with the firm store, exactly as confidential-server.ts composes it.
    const port = (enclave.address() as AddressInfo).port;
    await new Promise(resolve => enclave.close(resolve));
    enclave = await bootEnclave(port, MANIFEST, true);
    const relay = fetchRelay(`${relayBase}/channel`, `${relayBase}/objects`);
    const now = Date.now();
    const prepared = await prepareConfidentialSubmission({ summary: 'Setup gate summary', narrative: { description: 'PRIVATE-SENTINEL-SETUP' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared });
    const firm = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic setup firm' }], format: 'object' })).privateKey;
    const org = { organizationId: hex(0xf5), recipientKeyId: await caseRecipientKeyId(firm.toPublic()), publicKey: firm.toPublic().armor() };
    await store.upsertLegalOrganization({ organizationId: org.organizationId, displayName: 'Synthetic Setup LLP', domain: 'setup.example',
      publicKey: org.publicKey, approved: true, providerOrganizationId: 'org_setup', recipientKeyId: org.recipientKeyId }, now);
    const bindingDocument = await createFirmKeyBinding({ domain: 'setup.example', organizationId: org.organizationId, issuedAt: now }, firm);
    const accessToken = async (subject: string, scope = 'legal:directory legal:case', admin = false) => {
      const iat = Math.floor(Date.now() / 1000);
      return new jose.SignJWT({ iss: 'https://identity.example/', aud: admin ? 'admin-api' : 'https://api.example/legal', azp: admin ? 'admin-client' : 'legal-client',
        sub: admin ? 'auth0|operator' : subject, org_id: admin ? 'org_admin' : 'org_setup', scope, iat, exp: iat + 300,
        [LEGAL_ASSURANCE_CLAIM]: admin ? 'mfa-verified-email' : 'approved-member-verified-email' }).setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer-key' }).sign(issuer.privateKey);
    };
    const channel = async () => {
      const nonce = randomBytes(32).toString('hex');
      const serverKey = await readKey({ binaryKey: (await relay.open(nonce)).publicKey });
      return { nonce, serverKey, serverKeyId: await caseRecipientKeyId(serverKey) };
    };
    const exchange = async (session: Awaited<ReturnType<typeof channel>>, request: unknown, last = true): Promise<any> => {
      const pending = await sealChannelRequest(session.serverKey, session.nonce, new TextEncoder().encode(JSON.stringify(request)));
      return JSON.parse(new TextDecoder().decode(await pending.openResponse(await relay.call(session.nonce, pending.ciphertext, last))));
    };
    const enrollMember = async (subject: string, register: boolean) => {
      const { token } = await issueLegalInvitation({ relay, releaseManifest: MANIFEST, authority: onboarding.privateKey,
        organizationId: org.organizationId, recipientKeyId: org.recipientKeyId, providerOrganizationId: 'org_setup', subject,
        now: Date.now(), lifetimeMs: 3_600_000,
        ...(register ? { registration: { domain: 'setup.example', displayName: 'Synthetic Setup LLP', bindingDocument } } : {}), accessToken: await accessToken(subject, 'legal:invite', true) });
      await redeemInvitation({ relay, releaseManifest: MANIFEST, now: Date.now(), invitation: token,
        accessToken: await accessToken(subject, 'legal:enroll'), firm: { organizationId: org.organizationId, domain: 'setup.example',
          privateKey: firm, recipientKeyId: org.recipientKeyId } });
    };
    const firmCall = async (operation: ParticipantOperation, value: unknown): Promise<any> => {
      const body = new TextEncoder().encode(JSON.stringify(value));
      const session = await channel();
      const { challenge } = await exchange(session, { operation: 'legal.challenge' }, false);
      const proof = await signParticipantRequest({ audience: 'vera-confidential-cases', role: 'organization', caseId: prepared.caseId,
        organizationId: org.organizationId, operation, body, challenge, issuedAt: Date.now(), nonce: session.nonce,
        serverKeyId: session.serverKeyId }, firm);
      return exchange(session, { operation: `legal.${operation}`, accessToken: await accessToken('auth0|setup-steward'), proof,
        body: Buffer.from(body).toString('base64') });
    };
    const setupCall = async (operation: 'legal.setup-status' | 'legal.setup-record', value: unknown, subject = 'auth0|setup-steward') =>
      exchange(await channel(), { operation, accessToken: await accessToken(subject),
        body: Buffer.from(JSON.stringify({ organizationId: org.organizationId, ...value as object })).toString('base64') });
    await enrollMember('auth0|setup-steward', true);

    const requestCiphertext = await createLegalAccessRequest({ requestId: hex(0x3f1), scopes: ['narrative'], objectRevisionLimit: null,
      purpose: 'Counsel review', issuedAt: now, expiresAt: now + 86_400_000 }, org.organizationId, firm, prepared.owner.trust);
    const request = { caseId: prepared.caseId, requestId: hex(0x3f1), ciphertext: requestCiphertext, expiresAt: now + 86_400_000 };
    await expect(setupCall('legal.setup-status', {})).resolves.toMatchObject({ complete: false, missing: ['terms'], holders: 1 });
    await expect(firmCall('request-access', request)).resolves.toEqual({ error: 'setup-incomplete', missing: ['terms'] });
    await expect(firmCall('open-case', { caseId: prepared.caseId })).resolves.toEqual({ error: 'setup-incomplete', missing: ['terms'] });
    expect(await client.db('test_mounted').collection('confidential_access_requests').countDocuments({ caseId: prepared.caseId })).toBe(0);

    // The organization key signs the terms acknowledgement; it is stored with the organization row.
    const terms = await signFirmSetupStatement({ format: 'vera-legal-onboarding-terms/v1', organizationId: org.organizationId,
      recipientKeyId: org.recipientKeyId, termsVersion: FIRM_ONBOARDING_TERMS_VERSION, termsDigest: await firmOnboardingTermsDigest(),
      acknowledgedAt: Date.now() }, firm);
    await expect(setupCall('legal.setup-record', { kind: 'terms', statement: terms })).resolves.toMatchObject({ complete: true, missing: [], custody: null, holders: 1 });
    const row = await client.db('test_mounted').collection('confidential_legal_organizations').findOne({ _id: org.organizationId as never });
    expect(row?.setup).toEqual({ terms });
    await expect(firmCall('request-access', request)).resolves.toEqual({ state: 'requested' });
    await expect(firmCall('open-case', { caseId: prepared.caseId })).resolves.toEqual({ error: 'not-granted' });

    // Optional second-person custody is still counted accurately
    // (Mongo lists the enrolled members; the enclave verifies each enrollment).
    await enrollMember('auth0|setup-lawyer', false);
    await expect(setupCall('legal.setup-status', {}, 'auth0|setup-lawyer')).resolves.toMatchObject({ complete: true, custody: 'members', holders: 2 });
    await expect(firmCall('request-access', request)).resolves.toEqual({ state: 'requested' });
    await expect(firmCall('open-case', { caseId: prepared.caseId })).resolves.toEqual({ error: 'not-granted' });
  }, 240_000);
});
