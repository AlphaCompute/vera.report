import { createHash, webcrypto } from 'node:crypto';

// Only the AWS quote check is mocked; channel encryption, owner proofs, service
// authorization and publish validation are real. This is not Nitro acceptance.
const attestationCalls: { expectedPcrs: Map<number, Uint8Array>; nonce: Uint8Array }[] = [];
let attestationFails = false;
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array,
    policy: { expectedPcrs: Map<number, Uint8Array>; nonce: Uint8Array }) => {
    attestationCalls.push(policy);
    if (attestationFails) throw new Error('Application channel attestation verification failed');
    return { publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() };
  },
}));

import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { prepareConfidentialSubmission } from '../../../enclave/src/confidential/ownerSubmission';
import { createOwnerCaseControlDispatcher } from '../../../enclave/src/cases/ownerChannel';
import { SESSION_LIMITS, createSessionCore } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import type { CaseRecord, CaseStore } from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import {
  ChannelSessions, ConfidentialUnavailableError, ConfidentialUploadInterruptedError, verifiedSession, RelayHttpError, RelayNetworkError,
  channelFailure, createChunkUploadState, fetchRelay, publishPreparedCase,
} from '../../../lib/confidential/client';
import { ConfidentialRateLimitError } from '../../../lib/confidential/readRetry';
import type { ChannelRelay, UploadProgress } from '../../../lib/confidential/client';
import { EvidenceChangedError } from '../../../enclave/src/confidential/caseChunks';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
let serviceTime = now;
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });

const staged = new Map<string, string>(), stagedChunks = new Map<string, Uint8Array>();
function store(): CaseStore & { dump(): string } {
  const cases = new Map<string, CaseRecord>();
  return {
    async getStagedObject(digest: string) { return staged.get(digest) ?? null; },
    async promoteChunks(_caseId: string, _digest: string, digests: string[]) { return digests.every(digest => stagedChunks.has(digest)); },
    async putObjects() { /* not needed */ },
    async createCase(record: CaseRecord) { if (cases.has(record.caseId)) return false; cases.set(record.caseId, record); return true; },
    async getCase(caseId: string) { return cases.get(caseId) ?? null; },
    dump() { return JSON.stringify([...cases.values()]); },
  } as unknown as CaseStore & { dump(): string };
}

describe('browser confidential client over encrypted sessions', () => {
  let relay: ChannelRelay, backing: ReturnType<typeof store>, relayed: string[] = [];
  const outstanding = new Set<string>();
  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    const keys = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic channel' }], format: 'object' });
    backing = store();
    const keyring = createCaseKeyring({ clock: () => serviceTime });
    const dispatch = createOwnerCaseControlDispatcher({ store: createSealedCaseStore(backing, keyring), keyring, clock: () => serviceTime,
      audience: 'vera-confidential-cases', releaseDigest: (await readReleaseManifest(MANIFEST)).digest });
    const sessions = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(keys.privateKey,
      { nonce, publicKey: Buffer.from(keys.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }), () => 1);
    // Host relay: sees only these strings.
    relay = {
      async stage(ciphertext) {
        relayed.push(ciphertext);
        const digest = require('node:crypto').createHash('sha256').update(ciphertext, 'utf8').digest('hex');
        staged.set(digest, ciphertext);
        return digest;
      },
      async stageChunk(chunk) {
        relayed.push(Buffer.from(chunk).toString('latin1'));
        const digest = createHash('sha256').update(chunk).digest('hex');
        stagedChunks.set(digest, new Uint8Array(chunk));
        return digest;
      },
      async open(nonce) {
        const identity = await sessions.open(nonce);
        outstanding.add(nonce);
        return { document: new Uint8Array([1]), publicKey: new Uint8Array(Buffer.from(identity.publicKey, 'base64')) };
      },
      async call(nonce, ciphertext, last) {
        relayed.push(ciphertext);
        const reply = await sessions.execute(nonce, ciphertext, { last });
        outstanding.delete(nonce);
        relayed.push(reply);
        return reply;
      },
    };
  });

  test('publishes a locally encrypted case; the relay and store never see private text', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Public summary for legal review',
      narrative: { description: 'PRIVATE-SENTINEL-NARRATIVE' }, contact: { contactValue: 'PRIVATE-SENTINEL-CONTACT' },
      identity: null, files: [{ name: 'PRIVATE-SENTINEL.pdf', type: 'application/pdf',
        bytes: new Uint8Array(600 * 1024).fill(0x41) }] }, MANIFEST, now);
    // Evidence travels as staged encrypted chunks outside the channel.
    expect(prepared.chunkedObjects.map(item => item.chunkDigests.length)).toEqual([2]);
    const progress: UploadProgress[] = [];
    await expect(publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared,
      upload: { onProgress: value => progress.push(value) } })).resolves.toEqual({ caseId: prepared.caseId });
    // A two-chunk file is stored as two full chunks (vera-case-object/v3 size padding).
    expect(progress.at(-1)).toEqual({ bytesDone: 2 * (512 * 1024 + 16), bytesTotal: 2 * (512 * 1024 + 16) });
    for (const digest of prepared.chunkedObjects[0].chunkDigests) expect(stagedChunks.has(digest)).toBe(true);
    expect(outstanding.size).toBe(0); // Preflight must consume its lease too.
    expect(backing.dump()).not.toContain('"kind":"manifest"');
    for (const wire of [...relayed, backing.dump()]) {
      expect(wire).not.toContain('PRIVATE-SENTINEL');
      expect(wire).not.toContain(prepared.recoveryCode.replace(/-/g, ''));
    }
    // Expected PCRs came from the bundled manifest, never from the relay.
    expect(attestationCalls.at(-1)!.expectedPcrs.get(1)).toEqual(new Uint8Array(48).fill(0x22));
  });

  test('attestation failure sends nothing and never falls back', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Another summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    const before = relayed.length;
    attestationFails = true;
    try {
      await expect(publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared })).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    } finally { attestationFails = false; }
    expect(relayed.length).toBe(before);
  });

  test('attestation failure is reported as a verification failure, never as busy or offline', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Fourth summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    attestationFails = true;
    try {
      const error = await publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared }).catch(caught => caught);
      expect(error).toBeInstanceOf(ConfidentialUnavailableError);
      expect(error.reason).toBe('verification');
      expect(error.message).toMatch(/^The secure connection could not be verified\./);
    } finally { attestationFails = false; }
  });

  test.each([
    ['offline', new RelayNetworkError(), /could not be reached/],
    ['busy', new ConfidentialRateLimitError('5'), /is busy/],
    ['unavailable', new RelayHttpError(503), /temporarily unavailable/],
  ] as const)('a relay failure is reported as %s', async (reason, failure, message) => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Fifth summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    const failing: ChannelRelay = { ...relay, open: async () => { throw failure; } };
    const error = await publishPreparedCase({ relay: failing, releaseManifest: MANIFEST, now, prepared }).catch(caught => caught);
    expect(error).toBeInstanceOf(ConfidentialUnavailableError);
    expect(error.reason).toBe(reason);
    expect(error.message).toMatch(/^The secure connection /);
    expect(error.message).toMatch(message);
    expect(error.message).toContain("may have completed");
    expect(error.message).not.toContain("Nothing was sent");
  });

  test('an interrupted evidence upload resumes with only the missing chunks, then publishes once', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Resumable summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [{ name: 'video.mp4', type: 'video/mp4', bytes: new Uint8Array(3 * 512 * 1024 + 5).fill(7) }] },
    MANIFEST, now);
    const sent: string[] = [];
    let failFrom = 2;
    const flaky: ChannelRelay = { ...relay, async stageChunk(chunk) {
      const digest = createHash('sha256').update(chunk).digest('hex');
      if (sent.length >= failFrom) throw new TypeError('Failed to fetch');
      sent.push(digest);
      return relay.stageChunk(chunk);
    } };
    const state = createChunkUploadState(), waits: number[] = [];
    const wait = async (ms: number) => { waits.push(ms); };
    await expect(publishPreparedCase({ relay: flaky, releaseManifest: MANIFEST, now, prepared, upload: { state, wait } }))
      .rejects.toBeInstanceOf(ConfidentialUploadInterruptedError);
    expect(state.staged.size).toBe(2);
    expect(waits.length).toBeGreaterThan(0);
    // Nothing was published: the case does not exist yet.
    expect(backing.dump()).not.toContain(prepared.caseId);
    failFrom = Infinity;
    const before = sent.length;
    await expect(publishPreparedCase({ relay: flaky, releaseManifest: MANIFEST, now, prepared, upload: { state, wait } }))
      .resolves.toEqual({ caseId: prepared.caseId });
    expect(sent.slice(before).sort()).toEqual(prepared.chunkedObjects[0].chunkDigests.slice().filter(digest => !sent.slice(0, before).includes(digest)).sort());
    expect(sent.length).toBe(4);
  });

  test('a busy relay is waited out; a lying relay or a changed file stops the upload', async () => {
    const bytes = new Uint8Array(700 * 1024).fill(3);
    const prepared = await prepareConfidentialSubmission({ summary: 'Busy summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [{ name: 'a.bin', type: '', bytes }] }, MANIFEST, now);
    let busy = 2;
    const waits: number[] = [];
    const throttled: ChannelRelay = { ...relay, async stageChunk(chunk) {
      if (busy-- > 0) throw new ConfidentialRateLimitError('5');
      return relay.stageChunk(chunk);
    } };
    await expect(publishPreparedCase({ relay: throttled, releaseManifest: MANIFEST, now, prepared,
      upload: { wait: async ms => { waits.push(ms); } } })).resolves.toEqual({ caseId: prepared.caseId });
    expect(waits).toEqual([5250, 5250]);
    const second = await prepareConfidentialSubmission({ summary: 'Lying summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [{ name: 'b.bin', type: '', bytes }] }, MANIFEST, now);
    await expect(publishPreparedCase({ relay: { ...relay, stageChunk: async () => 'e'.repeat(64) }, releaseManifest: MANIFEST, now,
      prepared: second })).rejects.toBeInstanceOf(ConfidentialUnavailableError);
    bytes[0] ^= 1;
    await expect(publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared: second }))
      .rejects.toBeInstanceOf(EvidenceChangedError);
  });

  test('a lost publish reply is flagged as maybe published, and retrying the same prepared report finishes it once', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Lost reply summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [{ name: 'c.bin', type: '', bytes: new Uint8Array(1024).fill(9) }] }, MANIFEST, now);
    let sending = false, dropped = 0;
    // The enclave applies the publish, then its reply is lost on the way back.
    const lossy: ChannelRelay = { ...relay, async call(nonce, ciphertext, last) {
      const existed = backing.dump().includes(prepared.caseId);
      const reply = await relay.call(nonce, ciphertext, last);
      if (!existed && backing.dump().includes(prepared.caseId) && dropped++ === 0) throw new RelayNetworkError();
      return reply;
    } };
    const state = createChunkUploadState();
    const error = await publishPreparedCase({ relay: lossy, releaseManifest: MANIFEST, now, prepared, upload: { state },
      onPublishSending: () => { sending = true; } }).catch(caught => caught);
    expect(error).toBeInstanceOf(ConfidentialUnavailableError);
    expect(error.reason).toBe('offline');
    expect(sending).toBe(true);
    // The report already exists even though the reporter saw a failure.
    expect(backing.dump()).toContain(prepared.caseId);
    // Retrying the exact same prepared report is accepted and creates nothing new.
    const before = backing.dump();
    await expect(publishPreparedCase({ relay: lossy, releaseManifest: MANIFEST, now, prepared, upload: { state } }))
      .resolves.toEqual({ caseId: prepared.caseId });
    expect(backing.dump()).toBe(before);
  });

  test('a failure before the publish request is sent never flags it as maybe published', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Unsent summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    const onPublishSending = jest.fn();
    attestationFails = true;
    try {
      await expect(publishPreparedCase({ relay, releaseManifest: MANIFEST, now, prepared, onPublishSending }))
        .rejects.toBeInstanceOf(ConfidentialUnavailableError);
    } finally { attestationFails = false; }
    await expect(publishPreparedCase({ relay: { ...relay, stage: async () => 'e'.repeat(64) }, releaseManifest: MANIFEST, now,
      prepared: { ...prepared, stagedObjects: [{ digest: 'f'.repeat(64), ciphertext: 'x' }] }, onPublishSending }))
      .rejects.toBeInstanceOf(ConfidentialUnavailableError);
    expect(onPublishSending).not.toHaveBeenCalled();
  });

  test('a relay that stages different bytes than it was given is refused', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Third summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    const lying = { ...relay, stage: async () => 'f'.repeat(64) };
    await expect(publishPreparedCase({ relay: lying, releaseManifest: MANIFEST, now, prepared })).rejects.toBeInstanceOf(ConfidentialUnavailableError);
  });
  test('pausing an evidence upload sends nothing more; a long upload still publishes with a current proof time', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Paused summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [{ name: 'long.mp4', type: 'video/mp4', bytes: new Uint8Array(2 * 512 * 1024).fill(9) }] },
    MANIFEST, now);
    const state = createChunkUploadState();
    const paused = new AbortController();
    paused.abort();
    let calls = 0;
    const counting: ChannelRelay = { ...relay, async stageChunk(chunk) { calls++; return relay.stageChunk(chunk); } };
    await expect(publishPreparedCase({ relay: counting, releaseManifest: MANIFEST, now, prepared, upload: { state, signal: paused.signal } }))
      .rejects.toBeInstanceOf(ConfidentialUploadInterruptedError);
    expect(calls).toBe(0);
    // A maximum upload on a slow connection can take hours; the proof uses caller time plus elapsed time.
    let elapsed = 0;
    const clock = jest.spyOn(globalThis.performance, 'now').mockImplementation(() => elapsed);
    const slow: ChannelRelay = { ...counting, async stageChunk(chunk) {
      elapsed += 60 * 60_000; serviceTime = now + elapsed;
      return counting.stageChunk(chunk);
    } };
    try {
      await expect(publishPreparedCase({ relay: slow, releaseManifest: MANIFEST, now, prepared, upload: { state } }))
        .resolves.toEqual({ caseId: prepared.caseId });
    } finally { clock.mockRestore(); serviceTime = now; }
    expect(calls).toBe(2);
  });

  test('slow staging advances proof time from the caller clock using elapsed monotonic time', async () => {
    const prepared = await prepareConfidentialSubmission({ summary: 'Slow upload summary', narrative: { description: 'x' },
      contact: null, identity: null, files: [] }, MANIFEST, now);
    let elapsed = 0;
    const clock = jest.spyOn(globalThis.performance, 'now').mockImplementation(() => elapsed);
    const slow = { ...relay, stage: async (ciphertext: string) => {
      elapsed = 5 * 60_000; serviceTime = now + elapsed;
      return relay.stage(ciphertext);
    } };
    try {
      await expect(publishPreparedCase({ relay: slow, releaseManifest: MANIFEST, now, prepared })).resolves.toEqual({ caseId: prepared.caseId });
    } finally { clock.mockRestore(); serviceTime = now; }
  });


  test('attestation is checked at the time the quote arrives, not when the flow started', async () => {
    let elapsed = 0;
    const clock = jest.spyOn(globalThis.performance, 'now').mockImplementation(() => elapsed);
    try {
      const slow: ChannelRelay = { ...relay, async open(nonce) { elapsed = 10 * 60_000; return relay.open(nonce); } };
      const started = 1_800_000_000_000;
      await verifiedSession(slow, MANIFEST, started);
      expect((attestationCalls.at(-1) as unknown as { now: number }).now).toBe(started + 10 * 60_000);
    } finally { clock.mockRestore(); }
  });

  test('sequential operations reuse one verified session and replace one the enclave expired', async () => {
    const keys = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic reuse' }], format: 'object' });
    let enclaveTime = 1, clientTime = 1, opens = 0;
    const dispatch = createOwnerCaseControlDispatcher({ store: store(), clock: () => serviceTime,
      audience: 'vera-confidential-cases', releaseDigest: (await readReleaseManifest(MANIFEST)).digest });
    const core = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(keys.privateKey,
      { nonce, publicKey: Buffer.from(keys.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }), () => enclaveTime);
    const counting: ChannelRelay = { ...relay,
      async open(nonce) { opens++; const identity = await core.open(nonce);
        return { document: new Uint8Array([1]), publicKey: new Uint8Array(Buffer.from(identity.publicKey, 'base64')) }; },
      async call(nonce, ciphertext, last) { return core.execute(nonce, ciphertext, { last }); } };
    const sessions = new ChannelSessions(counting, MANIFEST, () => clientTime);
    const challenge = () => sessions.run(send => send({ operation: 'case.challenge' })) as Promise<{ challenge: string }>;
    for (let index = 0; index < 3; index++) {
      expect((await challenge()).challenge).toMatch(/^[a-f0-9]{64}$/);
      enclaveTime += 1_000; clientTime += 1_000;
    }
    expect(opens).toBe(1);
    // The enclave reclaimed the session although this client still thinks it idle-valid.
    enclaveTime += SESSION_LIMITS.anonymousIdle;
    expect((await challenge()).challenge).toMatch(/^[a-f0-9]{64}$/);
    expect(opens).toBe(2);
    // Only the first request of a run is retried, and only once.
    enclaveTime += SESSION_LIMITS.anonymousIdle;
    await expect(sessions.run(async send => { await send({ operation: 'case.challenge' }); enclaveTime += SESSION_LIMITS.anonymousIdle;
      return send({ operation: 'case.challenge' }); })).rejects.toThrow();
    expect(opens).toBe(3);
    core.close();
  });
});

describe('fetch relay failure classes', () => {
  const original = global.fetch;
  afterEach(() => { global.fetch = original; });
  const respond = (status: number, headers: Record<string, string> = {}) => {
    global.fetch = jest.fn(async () => new Response(JSON.stringify({ error: 'x' }), { status, headers })) as typeof fetch;
  };

  test('network failure, throttle, load shedding and HTTP errors are distinguished', async () => {
    const relay = fetchRelay('https://vera.test/api/confidential/channel', 'https://vera.test/api/confidential/objects');
    global.fetch = jest.fn(async () => { throw new TypeError('Failed to fetch'); }) as typeof fetch;
    await expect(relay.open('a'.repeat(64))).rejects.toBeInstanceOf(RelayNetworkError);
    respond(429, { 'Retry-After': '30' });
    await expect(relay.call('a'.repeat(64), 'x')).rejects.toBeInstanceOf(ConfidentialRateLimitError);
    respond(503, { 'Retry-After': '2' });
    await expect(relay.stage('x')).rejects.toBeInstanceOf(ConfidentialRateLimitError);
    respond(503);
    await expect(relay.open('a'.repeat(64))).rejects.toBeInstanceOf(RelayHttpError);
    respond(403);
    await expect(relay.open('a'.repeat(64))).rejects.toBeInstanceOf(RelayHttpError);
  });

  test('cancelling a relay call aborts fetch and settles even if the transport never responds', async () => {
    let transportSignal: AbortSignal | undefined;
    global.fetch = jest.fn((_url, init) => {
      transportSignal = init?.signal as AbortSignal;
      return new Promise<Response>(() => {});
    }) as typeof fetch;
    const controller = new AbortController();
    const pending = fetchRelay().call('a'.repeat(64), 'synthetic', false, controller.signal);
    expect(transportSignal?.aborted).toBe(false);
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(transportSignal?.aborted).toBe(true);
    await expect(fetchRelay().call('a'.repeat(64), 'synthetic', false, controller.signal))
      .rejects.toMatchObject({ name: 'AbortError' });
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('every class maps to one user-facing message that names the secure connection', () => {
    for (const [failure, reason] of [[new RelayNetworkError(), 'offline'], [new ConfidentialRateLimitError(null), 'busy'],
      [new RelayHttpError(500), 'unavailable'], [new Error('bad attestation'), 'verification'],
      [new TypeError('x is undefined'), 'verification']] as const) {
      const mapped = channelFailure(failure);
      expect(mapped.reason).toBe(reason);
      expect(mapped.message.startsWith('The secure connection')).toBe(true);
    }
    const existing = new ConfidentialUnavailableError('offline');
    expect(channelFailure(existing)).toBe(existing);
    expect(new ConfidentialRateLimitError('1').message.startsWith('The secure connection')).toBe(true);
  });
});
