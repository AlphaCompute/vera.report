import { generateKey } from '../../../enclave/src/confidential/pgp';
import { openChannelRequest, sealChannelResponse } from '../../../enclave/src/confidential/channelMessage';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { createCaseService } from '../../../enclave/src/cases/service';
import type { CaseRecord, CaseStore } from '../../../enclave/src/cases/service';
import { createCaseKeyring, createSealedCaseStore } from '../../../enclave/src/cases/sealedStore';
import { createSessionChallenges } from '../../../enclave/src/session-challenges';

// Only AWS attestation is substituted. All PGP keys, signatures, encryption,
// owner proofs and case publication below use the real implementations.
let enclaveTime = 0;
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey, timestamp: enclaveTime, verifiedAt: enclaveTime }),
}));
const hex = (n: number) => n.toString(16).padStart(64, '0');
const manifest = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

afterEach(() => jest.useRealTimers());

it.each([-5_000, 5_000])('submits a report with a browser clock offset of %i ms', async skew => {
  enclaveTime = Math.floor(Date.now() / 1000) * 1000;
  jest.useFakeTimers({ now: enclaveTime, doNotFake: ['nextTick', 'setImmediate', 'setTimeout', 'clearTimeout', 'performance'] });
  const channelKey = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Synthetic enclave' }], format: 'object' });
  const staged = new Map<string, string>(), records = new Map<string, CaseRecord>();
  const store = {
    async getStagedObject(digest: string) { return staged.get(digest) ?? null; },
    async putObjects() {},
    async createCase(record: CaseRecord) { records.set(record.caseId, record); return true; },
    async getCase(id: string) { return records.get(id) ?? null; },
  } as unknown as CaseStore;
  const channel = { nonce: hex(1), serverKeyId: hex(2), challenges: createSessionChallenges() };
  const keyring = createCaseKeyring({ clock: () => enclaveTime });
  const service = createCaseService({ channel, store: createSealedCaseStore(store, keyring), keyring,
    clock: () => enclaveTime, audience: 'vera-confidential-cases', releaseDigest: (await readReleaseManifest(manifest)).digest });

  // Separate module instances model the two processes: a browser's attested
  // clock must not alter the enclave's independent OpenPGP clock.
  await jest.isolateModulesAsync(async () => {
    const client = await import('../../../lib/confidential/client');
    const { prepareConfidentialSubmission } = await import('../../../enclave/src/confidential/ownerSubmission');
    const { signParticipantRequest } = await import('../../../enclave/src/confidential/participantRequest');
    jest.setSystemTime(enclaveTime + skew);
    await client.synchronizeTrustedTime({
      stage: async () => { throw new Error('unused'); },
      open: async () => ({ document: new Uint8Array([1]), publicKey: channelKey.publicKey.write() }),
      call: async (nonce, ciphertext) => {
        jest.setSystemTime(enclaveTime);
        try {
          const request = await openChannelRequest(ciphertext, nonce, channelKey.privateKey);
          return await sealChannelResponse(request, encode({ challenge: hex(3) }), channelKey.privateKey);
        } finally { jest.setSystemTime(enclaveTime + skew); }
      },
    }, manifest, Date.now());
    const prepared = await prepareConfidentialSubmission({ summary: 'Synthetic report',
      narrative: { description: 'Synthetic account' }, contact: { email: 'owner@example.com' }, identity: null, files: [] },
    manifest, client.trustedTime(Date.now()));
    for (const item of prepared.stagedObjects) staged.set(item.digest, item.ciphertext);
    const { challenge } = await service.issueChallenge();
    const proof = await signParticipantRequest({ ...channel, audience: 'vera-confidential-cases', role: 'owner',
      caseId: prepared.caseId, organizationId: null, operation: 'publish-case', body: prepared.publishBody,
      challenge, issuedAt: client.trustedTime(Date.now()) }, prepared.owner.privateKey);
    jest.setSystemTime(enclaveTime);
    await expect(service.publishCase(prepared.publishBody, proof)).resolves.toMatchObject({ caseId: prepared.caseId });
    expect(records.size).toBe(1);
    await expect(service.publishCase(prepared.publishBody, proof)).rejects.toThrow(); // Challenge cannot be replayed.
    client.resetTrustedTime();
  });
});
