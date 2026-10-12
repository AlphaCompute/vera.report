/**
 * Log sentinel sweep over a complete confidential flow.
 *
 * Every private value a participant handles (recovery code and package, case
 * ID, organization ID and domain, member identity, tokens, request IDs, report
 * text, file names and contents, messages, the public summary) and every
 * firm-to-case relationship must stay out of everything the host and enclave
 * processes emit: console output, stdout/stderr (including the MongoDB driver,
 * with MONGODB_LOG_ALL=debug set as an operator might), request-flow records,
 * error-monitor records and runtime telemetry.
 *
 * Composition: browser clients (lib/confidential) -> host HTTP stack with the
 * production logging/telemetry middleware -> enclave frame server -> attested
 * session core -> owner and legal dispatchers -> sealed store -> host storage
 * RPC -> MongoDB through the production confidential driver options. Only the
 * AWS quote check is synthetic (no Nitro hardware here).
 */
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));
jest.mock('express-rate-limit', () => {
  const actual = jest.requireActual('express-rate-limit');
  const limited = (options: Record<string, unknown>) => actual.rateLimit({ ...options, windowMs: 100 });
  return { ...actual, __esModule: true, default: limited, rateLimit: limited };
});

import { randomBytes, webcrypto } from 'node:crypto';
import type { AddressInfo, Server } from 'node:net';
import * as jose from 'jose';
import express from 'express';
import bodyParser from 'body-parser';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { addRequestId } from '../../../src/utils/errorResponse';
import { ErrorMonitor } from '../../../src/utils/errorMonitor';
import { runtimeTelemetry } from '../../../src/utils/runtimeTelemetry';
import { clearDataFlowLogs, getDataFlowLogs, trackDataFlow } from '../../../src/middleware/dataFlowTracking';
import { securityErrorHandler, validateRequestBody } from '../../../src/middleware/security';
import { logger } from '../../../src/utils/logger';
import { MongoConfidentialCaseStore } from '../../../src/services/confidentialCaseStore';
import { createConfidentialStorageServer } from '../../../src/services/confidentialStorageRpc';
import { createConfidentialChannelRouter, tcpEnclaveTransport } from '../../../src/api/confidentialChannel';
import { createConfidentialObjectRouter } from '../../../src/api/confidentialObjects';
import { createConfidentialAdminListingRouter } from '../../../src/api/confidentialAdminListings';
import { authenticatedRoster } from '../../../enclave/src/cases/authenticatedRoster';
import {
  createRemoteCaseStore, createRemoteEnrollmentStore, createRemoteLegalMembershipStore, fetchLegalIdentityPolicy,
} from '../../../enclave/src/cases/storageRpc';
import { createLegalCaseDispatcher } from '../../../enclave/src/cases/legalChannel';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { createCaseChannelDispatch, createConfidentialFrameServer } from '../../../enclave/src/confidential-server';
import { LEGAL_ASSURANCE_CLAIM } from '../../../enclave/src/legal/identity';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { fetchRelay, publishPreparedCase } from '../../../lib/confidential/client';
import { issueLegalInvitation } from '../../../lib/confidential/onboarding';
import { generateFirmIdentity } from '../../../lib/confidential/firmKey';
import {
  createFirmSession, openFirmCase, readFirmMessages, readLegalDirectory, redeemInvitation, requestCaseAccess, sendFirmMessage,
} from '../../../lib/confidential/firmCase';
import {
  allowAccess, currentGrantees, readOwnerInbox, readOwnerThreads, restoreOwnerSession, revokeAccess, reviewOwnerRequests,
  sendOwnerMessage, verifiedRoster,
} from '../../../lib/confidential/ownerCase';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const listen = (server: Server) => new Promise<number>(resolve =>
  server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)));

/** Everything emitted by this process while the flow runs. */
const emitted: string[] = [];
const text = (value: unknown): string => {
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  try { return JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item); }
  catch { return String(value); }
};

describe('confidential flows leave no secrets or firm-case linkage in logs', () => {
  const saved = { ...process.env };
  const restore: (() => void)[] = [];
  const servers: Server[] = [];
  let mongo: MongoMemoryReplSet, store: MongoConfidentialCaseStore;
  const monitor = new ErrorMonitor();

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    // Maximum verbosity: every logger level, development flow logging, JSON
    // format and MongoDB driver command logging requested through environment.
    Object.assign(process.env, { LOG_LEVEL: 'debug', LOG_FORMAT: 'json', NODE_ENV: 'development',
      INTERNAL_API_SECRET: 'synthetic-log-secret' });
    for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      const spy = jest.spyOn(console, level).mockImplementation((...args: unknown[]) => { emitted.push(args.map(text).join(' ')); });
      restore.push(() => spy.mockRestore());
    }
    for (const stream of [process.stdout, process.stderr]) {
      const original = stream.write.bind(stream);
      stream.write = ((chunk: unknown, ...rest: unknown[]) => { emitted.push(text(chunk)); return original(chunk as string, ...(rest as [])); }) as typeof stream.write;
      restore.push(() => { stream.write = original; });
    }
    const logError = jest.spyOn(monitor, 'logError');
    restore.push(() => { emitted.push(text(logError.mock.calls)); logError.mockRestore(); });
    clearDataFlowLogs();
  });

  afterAll(async () => {
    for (const server of servers) server.close();
    await store?.close?.();
    await mongo?.stop();
    for (const undo of restore.reverse()) undo();
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
    clearDataFlowLogs();
  });

  test('publish, onboard, request, allow, open, message and revoke', async () => {
    mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    // The test database server's own setup client is not under test; from here
    // on, an operator-style environment asks every MongoDB driver to log
    // commands. The production confidential connection must ignore it.
    const sweepStart = emitted.length;
    Object.assign(process.env, { MONGODB_LOG_ALL: 'debug', MONGODB_LOG_COMMAND: 'debug', MONGODB_LOG_PATH: 'stdout' });
    store = await MongoConfidentialCaseStore.connect(mongo.getUri(), 'vera_confidential_log_sentinel');
    const issuer = await jose.generateKeyPair('RS256');
    const legalIdentityPolicy = { issuer: 'https://identity.example/', audience: 'https://api.example/legal', clientId: 'legal-client',
      jwks: { keys: [{ ...await jose.exportJWK(issuer.publicKey), alg: 'RS256', use: 'sig', kid: 'issuer-key' }] } };
    const storage = createConfidentialStorageServer(store as unknown as Record<string, unknown>, { releaseManifest: MANIFEST, legalIdentityPolicy });
    servers.push(storage);
    const storagePort = await listen(storage);
    const channelKey = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic enclave' }], format: 'object' });
    const onboarding = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic onboarding' }], format: 'object' });

    // Enclave process composition (as startConfidentialServer, minus NSM).
    const keyring = createCaseKeyring({ clock: Date.now });
    const options = { store: authenticatedRoster(createSealedCaseStore(createRemoteCaseStore({ port: storagePort }), keyring),
      onboarding.publicKey.armor(), Date.now), keyring, clock: Date.now, audience: 'vera-confidential-cases',
    releaseDigest: (await readReleaseManifest(MANIFEST)).digest };
    const policy = await fetchLegalIdentityPolicy({ port: storagePort });
    const dispatch = createCaseChannelDispatch(createOwnerCaseControlDispatcher(options),
      createLegalCaseDispatcher({ ...options, identity: policy!, members: createRemoteLegalMembershipStore({ port: storagePort }),
        enrollment: createRemoteEnrollmentStore({ port: storagePort }), administration: { identity: { ...policy!, audience: 'admin-api',
          clientId: 'admin-client' }, organizationId: 'org_admin', onboardingPublicKey: onboarding.publicKey.armor() } }));
    const sessions = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(channelKey.privateKey,
      { nonce, publicKey: Buffer.from(channelKey.publicKey.write()).toString('base64'),
        document: Buffer.from('synthetic-not-attestation').toString('base64') }), () => Date.now());
    const enclave = createConfidentialFrameServer(sessions);
    servers.push(enclave);
    const enclavePort = await listen(enclave);

    // Host: the production middleware order around the confidential routers.
    const app = express();
    app.use(addRequestId);
    app.use(monitor.middleware());
    app.use(runtimeTelemetry);
    app.use(bodyParser.json({ limit: '10mb' }));
    app.use(validateRequestBody);
    app.use(trackDataFlow);
    app.use('/api/confidential', createConfidentialObjectRouter(store));
    app.use('/api/admin/confidential', createConfidentialAdminListingRouter(async () => store));
    app.use('/api/confidential', createConfidentialChannelRouter(tcpEnclaveTransport(enclavePort), { maxPerMinute: 10_000 }));
    app.use(securityErrorHandler);
    const host = app.listen(0, '127.0.0.1');
    servers.push(host);
    await new Promise(resolve => host.once('listening', resolve));
    const origin = `http://127.0.0.1:${(host.address() as AddressInfo).port}`;
    const relay = fetchRelay(`${origin}/api/confidential/channel`, `${origin}/api/confidential/objects`);

    // 1. Whistleblower submits.
    const secrets = new Set<string>();
    const summary = `Summary sentinel ${randomBytes(6).toString('hex')}`;
    const narrativeText = `NARRATIVE-SENTINEL-${randomBytes(6).toString('hex')}`;
    const contactText = `CONTACT-SENTINEL-${randomBytes(6).toString('hex')}`;
    const fileName = `FILENAME-SENTINEL-${randomBytes(4).toString('hex')}.txt`;
    const fileText = `FILE-SENTINEL-${randomBytes(6).toString('hex')}`;
    const prepared = await prepareConfidentialSubmission({ summary, narrative: { description: narrativeText },
      contact: { contactValue: contactText }, identity: null,
      files: [{ name: fileName, type: 'text/plain', bytes: new TextEncoder().encode(fileText) }] }, MANIFEST, Date.now());
    await publishPreparedCase({ relay, releaseManifest: MANIFEST, now: Date.now(), prepared });
    const caseId = prepared.caseId;
    for (const value of [summary, narrativeText, contactText, fileName, fileText, caseId, prepared.recoveryCode,
      ...prepared.recoveryCode.split('.').slice(1), prepared.recoveryPackage.slice(0, 80), prepared.owner.trust.ownerFingerprint]) secrets.add(value);

    // 2. VERA onboarding admin approves the firm's submitted key and invites it.
    const organizationId = randomBytes(32).toString('hex');
    const domain = `sentinel-${randomBytes(4).toString('hex')}.example`;
    const displayName = `Sentinel Counsel ${randomBytes(3).toString('hex')} LLP`;
    const subject = `auth0|member-sentinel-${randomBytes(4).toString('hex')}`;
    const providerOrganizationId = `org_${randomBytes(6).toString('hex')}`;
    const firm = await generateFirmIdentity({ organizationId, domain });
    const binding = await createFirmKeyBinding({ domain, organizationId, issuedAt: Date.now() }, firm.privateKey);
    const tokens: string[] = [];
    const accessToken = async (scope: string, admin = false) => {
      const iat = Math.floor(Date.now() / 1000);
      const token = await new jose.SignJWT({ iss: 'https://identity.example/', aud: admin ? 'admin-api' : 'https://api.example/legal',
        azp: admin ? 'admin-client' : 'legal-client', sub: admin ? 'auth0|operator' : subject, org_id: admin ? 'org_admin' : providerOrganizationId,
        scope, iat, exp: iat + 300, [LEGAL_ASSURANCE_CLAIM]: admin ? 'mfa-verified-email' : 'approved-member-verified-email' })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'issuer-key' }).sign(issuer.privateKey);
      tokens.push(token);
      return token;
    };
    await store.upsertLegalOrganization({ organizationId, displayName, domain, publicKey: firm.privateKey.toPublic().armor(),
      approved: true, providerOrganizationId, recipientKeyId: firm.recipientKeyId }, Date.now());
    const { token: invitation } = await issueLegalInvitation({ relay, releaseManifest: MANIFEST, authority: onboarding.privateKey,
      organizationId, recipientKeyId: firm.recipientKeyId, providerOrganizationId, subject, now: Date.now(), lifetimeMs: 3_600_000,
      registration: { domain, displayName, bindingDocument: binding }, accessToken: await accessToken('legal:invite', true) });
    await redeemInvitation({ relay, releaseManifest: MANIFEST, now: Date.now(), invitation,
      accessToken: await accessToken('legal:enroll'), firm });
    for (const value of [organizationId, domain, displayName, subject, providerOrganizationId, invitation, firm.recipientKeyId]) secrets.add(value);

    // 3. The firm browses and requests access.
    const firmSession = await createFirmSession({ relay, releaseManifest: MANIFEST, firm,
      accessToken: () => accessToken('legal:directory legal:case') });
    const directory = await readLegalDirectory(firmSession, null, Date.now());
    const listing = directory.listings.find(item => item.caseId === caseId)!;
    expect(listing.summary).toBe(summary);
    const purpose = `PURPOSE-SENTINEL-${randomBytes(4).toString('hex')}`;
    const { requestId } = await requestCaseAccess(firmSession, listing, { purpose, scopes: ['narrative', 'evidence', 'messages'],
      details: { kind: 'new', conflictsChecked: true, feeBasis: 'no-fee', responseTime: 'one-week', practiceAreas: ['Employment'],
        jurisdiction: 'England and Wales', website: null } }, Date.now());
    secrets.add(requestId); secrets.add(purpose);

    // 4. The whistleblower reviews on a fresh device and allows.
    const owner = await restoreOwnerSession({ code: prepared.recoveryCode, relay, releaseManifest: MANIFEST, now: Date.now() });
    let inbox = await readOwnerInbox(owner, Date.now());
    const roster = await verifiedRoster(owner, Date.now());
    const { requests } = await reviewOwnerRequests(owner, inbox, roster, Date.now());
    expect(requests.map(item => item.request.purpose)).toEqual([purpose]);
    await allowAccess(owner, inbox, roster, requests[0], { grantId: requests[0].delivery.requestId,
      scopes: ['narrative', 'evidence', 'messages'], objectRevisionLimit: null, expiresAt: Date.now() + 86_400_000 }, Date.now());

    // 5. The report still opens, but retired messaging routes reject both participants without leaking payloads.
    const opened = await openFirmCase(firmSession, caseId, Date.now());
    expect(opened.narrative?.description).toBe(narrativeText);
    const firmMessage = `FIRM-MESSAGE-SENTINEL-${randomBytes(4).toString('hex')}`;
    const ownerMessage = `OWNER-MESSAGE-SENTINEL-${randomBytes(4).toString('hex')}`;
    secrets.add(firmMessage); secrets.add(ownerMessage);
    await expect(sendFirmMessage(firmSession, caseId, firmMessage, Date.now())).rejects.toThrow();
    inbox = await readOwnerInbox(owner, Date.now());
    const grantees = await currentGrantees(owner, inbox, roster);
    const threads = await readOwnerThreads(owner, inbox, roster, [], grantees);
    expect(threads[0].messages).toEqual([]);
    await expect(sendOwnerMessage(owner, threads[0], ownerMessage, Date.now())).rejects.toThrow();
    await expect(readFirmMessages(firmSession, caseId, Date.now())).rejects.toThrow();

    // 6. Admin listing (with a case-ID cursor) and failure paths.
    const listings = await fetch(`${origin}/api/admin/confidential/listings`, { method: 'POST',
      headers: { 'x-internal-secret': 'synthetic-log-secret', 'Content-Type': 'application/json' }, body: JSON.stringify({ after: caseId }) });
    expect(listings.status).toBe(200);
    await fetch(`${origin}/api/confidential/channel/call`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: caseId, ciphertext: `-----BEGIN PGP MESSAGE-----\n${organizationId}\n-----END PGP MESSAGE-----` }) });
    await fetch(`${origin}/api/confidential/channel/call`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: `{"nonce":"${caseId}","ciphertext":"${prepared.recoveryCode}` });
    // Even a careless server-side log call cannot print a recovery code, armored
    // ciphertext or a bearer token verbatim.
    logger.error(`careless ${prepared.recoveryCode} ${tokens[0]} -----BEGIN PGP MESSAGE-----\n${fileText}\n-----END PGP MESSAGE-----`,
      { recoveryCode: prepared.recoveryCode, accessToken: tokens[0], ciphertext: fileText });

    // 7. The whistleblower revokes.
    inbox = await readOwnerInbox(owner, Date.now());
    const current = await currentGrantees(owner, inbox, roster);
    await revokeAccess(owner, inbox, roster, current[0].grantDigests[0], Date.now());
    for (const token of tokens) secrets.add(token);

    // Sweep.
    const records = [emitted.slice(sweepStart).join('\n'), text(getDataFlowLogs())].join('\n');
    expect(records.length).toBeGreaterThan(0);
    for (const secret of secrets) expect({ secret, found: records.includes(secret) }).toEqual({ secret, found: false });
    expect(records).not.toMatch(/VERA-OWNER-1\./);
    expect(records).not.toMatch(/-----BEGIN PGP/);
    expect(records).not.toMatch(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./);
    // No 64-hex identifier (case, organization, request, digest, nonce) at all.
    expect(records).not.toMatch(/(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])/i);
    // Private routes produce no per-request flow records at all.
    const flows = getDataFlowLogs();
    expect(flows.filter(entry => /confidential|legal|onboarding/i.test(String(entry.endpoint)))).toEqual([]);
    // The MongoDB driver produced no command log despite the environment.
    expect(records).not.toMatch(/"commandName"|CommandStarted|command started/i);
  }, 300_000);
});
