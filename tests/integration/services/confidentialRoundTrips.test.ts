import { webcrypto } from 'node:crypto';
import type { AddressInfo, Server } from 'node:net';

// Round-trip benchmark for the owner status page and one owner action. Only the
// AWS quote check is mocked; the channel, owner proofs, sealed store, storage RPC
// and MongoDB are the production composition. Every relay request pays a
// simulated network round trip, so wall time reflects what a participant waits.
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));

import { MongoClient } from 'mongodb';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { createConfidentialStorageServer } from '../../../src/services/confidentialStorageRpc';
import { createRemoteCaseStore } from '../../../enclave/src/cases/storageRpc';
import { authenticatedRoster } from '../../../enclave/src/cases/authenticatedRoster';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createCaseService } from '../../../enclave/src/cases/service';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { createCaseChannelDispatch } from '../../../enclave/src/confidential-server';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { signOrganizationRegistration } from '../../../enclave/src/confidential/organizationRegistration';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { createLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { signParticipantRequest } from '../../../enclave/src/confidential/participantRequest';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';
import { publishPreparedCase } from '../../../lib/confidential/client';
import type { ChannelRelay } from '../../../lib/confidential/client';
import {
  allowAccess, currentGrantees, readOwnerInbox, readOwnerThreads, releaseApprovalStatus, restoreOwnerSession,
  reviewOwnerRequests, verifiedRoster,
} from '../../../lib/confidential/ownerCase';

const hex = (n: number) => n.toString(16).padStart(64, '0');
/** Simulated network round trip per relay request (override to model mobile links). */
const RTT_MS = Number(process.env.CONFIDENTIAL_BENCH_RTT_MS ?? 25);
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const listen = (server: Server) => new Promise<number>(resolve =>
  server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));
const delay = () => new Promise(resolve => setTimeout(resolve, RTT_MS));
/** Measured with this same benchmark on the protocol before session reuse
 * (claude/confidential-case-completion at 5add9254, RTT 25 ms): a challenge
 * session plus an operation session per owner operation, one session per
 * public read. Wall times there were 15.1 s, 23.0 s and 11.5 s. */
const BEFORE: Record<string, { opens: number; calls: number }> = {
  'status page load (unlocked)': { opens: 6, calls: 6 },
  'status page load after enclave restart (locked)': { opens: 12, calls: 12 },
  'allow access (one owner action)': { opens: 6, calls: 6 },
};

describe('owner round trips (local stack, synthetic attestation, simulated network)', () => {
  let mongo: MongoMemoryReplSet, client: MongoClient, storage: Server, storagePort: number;
  let sessions: ReturnType<typeof createSessionCore>;
  let onboarding: Awaited<ReturnType<typeof generateKey>>, channelKey: Awaited<ReturnType<typeof generateKey>>;
  let releaseDigest: string;
  const counts = { opens: 0, calls: 0, storage: 0 };
  const storageCalls = new Map<string, number>();
  const results: Record<string, { opens: number; calls: number; storage: number; ms: number }> = {};

  /** Fresh enclave process (new keyring and sessions) over the same storage. */
  async function bootEnclave() {
    sessions?.close();
    const keyring = createCaseKeyring({ clock: Date.now });
    const options = { store: authenticatedRoster(createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), keyring),
      onboarding.publicKey.armor(), Date.now), keyring, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest };
    sessions = createSessionCore(createCaseChannelDispatch(createOwnerCaseControlDispatcher(options), null),
      async nonce => new ApplicationChannelIdentity(channelKey.privateKey, { nonce,
        publicKey: Buffer.from(channelKey.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }),
      () => Date.now());
  }
  const relay: ChannelRelay = {
    async stage(ciphertext) {
      await delay();
      const digest = require('node:crypto').createHash('sha256').update(ciphertext, 'utf8').digest('hex');
      await storeRef.stageObject(digest, ciphertext, Date.now());
      return digest;
    },
    async open(nonce) {
      counts.opens++; await delay();
      const identity = await sessions.open(nonce);
      return { document: new Uint8Array([1]), publicKey: new Uint8Array(Buffer.from(identity.publicKey, 'base64')) };
    },
    async call(nonce, ciphertext) {
      counts.calls++; await delay();
      return sessions.execute(nonce, ciphertext);
    },
  };
  let storeRef: MongoConfidentialCaseStore;
  async function measure<T>(name: string, work: () => Promise<T>): Promise<T> {
    counts.opens = 0; counts.calls = 0; counts.storage = 0; storageCalls.clear();
    const started = performance.now();
    const value = await work();
    results[name] = { opens: counts.opens, calls: counts.calls, storage: counts.storage, ms: Math.round(performance.now() - started) };
    if (process.env.CONFIDENTIAL_BENCH_VERBOSE) process.stdout.write(`${name}: ${JSON.stringify(Object.fromEntries(storageCalls))}\n`);
    return value;
  }

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    client = await MongoClient.connect(mongo.getUri());
    storeRef = await MongoConfidentialCaseStore.fromDatabase(client.db('test_round_trips'), client);
    // Host storage RPC, counting enclave -> host storage calls per measurement.
    const counted = new Proxy(storeRef as unknown as Record<string, unknown>, { get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== 'function' || typeof property !== 'string') return value;
      return (...args: unknown[]) => {
        counts.storage++; storageCalls.set(property, (storageCalls.get(property) ?? 0) + 1);
        return (value as (...values: unknown[]) => unknown).apply(target, args);
      };
    } });
    storage = createConfidentialStorageServer(counted, { releaseManifest: MANIFEST, legalIdentityPolicy: null });
    storagePort = await listen(storage);
    channelKey = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic enclave' }], format: 'object' });
    onboarding = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic onboarding' }], format: 'object' });
    releaseDigest = (await readReleaseManifest(MANIFEST)).digest;
    await bootEnclave();
  }, 180_000);
  afterAll(async () => {
    sessions?.close(); storage?.close();
    await client?.close(); await mongo?.stop();
    // Printed so a run records the numbers next to the assertions below.
    process.stdout.write(`\nconfidential owner round trips (RTT ${RTT_MS} ms):\n${Object.entries(results)
      .map(([name, value]) => `  ${name}: ${value.opens} sessions, ${value.opens + value.calls} round trips, ` +
        `${value.storage} storage calls, ${value.ms} ms`).join('\n')}\n`);
  });

  test('status page load and one owner action', async () => {
    const now = Date.now();
    const prepared = await prepareConfidentialSubmission({ summary: 'Round-trip summary', narrative: { description: 'SYNTHETIC' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared });

    // One onboarded firm with a domain-confirmed key and a pending request.
    const firmKey = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Firm' }], format: 'object' })).privateKey;
    const org = { organizationId: hex(0xf1), recipientKeyId: await caseRecipientKeyId(firmKey.toPublic()), publicKey: firmKey.toPublic().armor() };
    await storeRef.upsertLegalOrganization({ organizationId: org.organizationId, displayName: 'Synthetic Counsel LLP', domain: 'counsel.example',
      publicKey: org.publicKey, approved: true, registration: await signOrganizationRegistration({
        format: 'vera-organization-registration/v1', ...org, providerOrganizationId: 'org_firm', displayName: 'Synthetic Counsel LLP',
        domain: 'counsel.example', approved: true, issuedAt: now }, onboarding.privateKey) }, now);
    const binding = await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org.organizationId, issuedAt: now }, firmKey);
    const channel = { nonce: hex(0xb1), serverKeyId: hex(0xb2), challenges: createSessionChallenges() };
    const firmKeyring = createCaseKeyring({ clock: Date.now });
    const firmSide = createCaseService({ channel, store: createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), firmKeyring),
      keyring: firmKeyring, clock: Date.now, audience: 'vera-confidential-cases', releaseDigest });
    const requestId = hex(0x501);
    const ciphertext = await createLegalAccessRequest({ requestId, scopes: ['narrative'], objectRevisionLimit: null, purpose: 'Review',
      issuedAt: now, expiresAt: now + 86_400_000 }, org.organizationId, firmKey, prepared.owner.trust);
    const body = new TextEncoder().encode(JSON.stringify({ caseId: prepared.caseId, requestId, ciphertext, expiresAt: now + 86_400_000 }));
    const { challenge } = await firmSide.issueChallenge();
    await firmSide.submitAccessRequest(body, await signParticipantRequest({ nonce: channel.nonce, serverKeyId: channel.serverKeyId,
      audience: 'vera-confidential-cases', role: 'organization', caseId: prepared.caseId, organizationId: org.organizationId,
      operation: 'request-access', body, challenge, issuedAt: Date.now() }, firmKey), org);

    // Same sequence as ConfidentialCaseStatus.load().
    const progress: string[] = [];
    const statusLoad = async () => {
      const session = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
      session.onProgress = stage => progress.push(stage);
      expect(await releaseApprovalStatus(session, Date.now())).toBe('approved');
      const inbox = await readOwnerInbox(session, Date.now());
      const roster = await verifiedRoster(session, Date.now());
      const { requests } = await reviewOwnerRequests(session, inbox, roster, Date.now());
      const grantees = await currentGrantees(session, inbox, roster);
      await readOwnerThreads(session, inbox, roster, requests, grantees);
      return { session, inbox, roster, requests };
    };
    await measure('status page load (unlocked)', statusLoad);
    await bootEnclave();
    const loaded = await measure('status page load after enclave restart (locked)', statusLoad);
    expect(loaded.requests).toHaveLength(1);
    expect(progress).toEqual(['unlocking', 'unlocked']); // Only the load after the restart had to unlock.
    await measure('allow access (one owner action)', () => allowAccess(loaded.session, loaded.inbox, loaded.roster, loaded.requests[0],
      { grantId: requestId, scopes: ['narrative'], objectRevisionLimit: null, expiresAt: Date.now() + 86_400_000 }, Date.now()));

    // Budgets: one attested session per page load (an action reuses the page's
    // session), and at most half the round trips of one session per call.
    const trips = (name: string) => results[name].opens + results[name].calls;
    for (const [name, before] of Object.entries(BEFORE)) {
      expect(results[name].opens).toBeLessThanOrEqual(1);
      expect(trips(name) * 2).toBeLessThanOrEqual(before.opens + before.calls);
    }
    expect(trips('status page load (unlocked)')).toBeLessThanOrEqual(6);
    expect(trips('status page load after enclave restart (locked)')).toBeLessThanOrEqual(10);
    // A change always fetches its own challenge first (liveness before the signed
    // change, which is never re-sent), and re-reads the attested approved roster
    // before wrapping any key (confirmOrganizationKeys), so a key replaced since
    // the page loaded is never shared. That roster read replaced the former
    // firm-website check, so an action costs two more calls than a read.
    expect(storageCalls.get('listLegalOrganizations')).toBe(1);
    expect(trips('allow access (one owner action)')).toBeLessThanOrEqual(5);
  }, 300_000);
});
