import { generateKey } from '../../../enclave/src/confidential/pgp';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { OwnerTrust, ReleaseApproval, CaseCheckpoint } from '../../../enclave/src/confidential/authorization';
import { canonicalReleaseManifest, readReleaseManifest, approvedReleasePolicy } from '../../../enclave/src/confidential/releaseManifest';
import type { ConfidentialReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';

const h = (n: number, length = 64) => n.toString(16).padStart(length, '0');
const now = Date.now();
const manifest: ConfidentialReleaseManifest = {
  format: 'vera-confidential-release/v1', sourceRepository: 'https://github.com/example/vera', sourceCommit: h(1, 40),
  eifSha256: h(2), imageSha256: h(3), configurationSha256: h(4), provenanceSha256: h(5),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: h(6, 96), pcr1: h(7, 96), pcr2: h(8, 96) },
};
let owner: PrivateKey, other: PrivateKey, trust: OwnerTrust;
beforeAll(async () => {
  [owner, other] = await Promise.all(['owner', 'admin'].map(async name => (await generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object',
  })).privateKey));
  trust = { caseId: h(10), ownerFingerprint: owner.getFingerprint(), ownerPublicKey: owner.toPublic() };
});
async function fixture(releaseChange: Partial<ReleaseApproval> = {}, checkpointChange: Partial<CaseCheckpoint> = {}) {
  const wire = canonicalReleaseManifest(manifest), parsed = await readReleaseManifest(wire);
  const release = await signOwnerStatement({ kind: 'release', caseId: trust.caseId, revision: 1,
    releaseDigest: parsed.digest, issuedAt: now - 1000, ...releaseChange }, owner);
  const releaseDigest = (await verifyOwnerStatement(release, trust)).digest;
  const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: trust.caseId, revision: 2,
    keyEpoch: 1, previousDigest: null, listingDigest: null, manifestDigest: null,
    grantDigests: [], releaseDigests: [releaseDigest], issuedAt: now - 500, ...checkpointChange }, owner);
  return { manifest: wire, release, checkpoint, checkpointDigest: (await verifyOwnerStatement(checkpoint, trust)).digest,
    trust, now, nonce: new Uint8Array(32).fill(1) };
}

test('binds current owner consent to exact manifest bytes and PCR0/1/2', async () => {
  const input = await fixture(), result = await approvedReleasePolicy(input);
  expect(result.releaseDigest).toBe((await readReleaseManifest(input.manifest)).digest);
  expect([...result.policy.expectedPcrs.keys()]).toEqual([0, 1, 2]);
  expect(Buffer.from(result.policy.expectedPcrs.get(1)!).toString('hex')).toBe(manifest.measurements.pcr1);
  expect(result.policy.nonce).toEqual(input.nonce);
});
test.each(['sourceCommit', 'eifSha256', 'imageSha256', 'configurationSha256', 'provenanceSha256'] as const)(
  'rejects substitution of approved %s', async field => {
    const input = await fixture();
    input.manifest = canonicalReleaseManifest({ ...manifest, [field]: h(99, field === 'sourceCommit' ? 40 : 64) });
    await expect(approvedReleasePolicy(input)).rejects.toThrow();
  });
test('rejects changed PCRs and repository even if schema remains valid', async () => {
  const input = await fixture();
  for (const changed of [ { ...manifest, measurements: { ...manifest.measurements, pcr0: h(99, 96) } },
    { ...manifest, sourceRepository: 'https://github.com/other/vera' } ]) {
    await expect(approvedReleasePolicy({ ...input, manifest: canonicalReleaseManifest(changed) })).rejects.toThrow();
  }
});
test('rejects removed approvals, stale checkpoints, wrong cases and future consent', async () => {
  await expect(approvedReleasePolicy(await fixture({}, { releaseDigests: [] }))).rejects.toThrow();
  await expect(approvedReleasePolicy(await fixture({ revision: 3 }))).rejects.toThrow();
  await expect(approvedReleasePolicy(await fixture({ issuedAt: now + CLOCK_SKEW_MS + 1 }))).rejects.toThrow();
  await expect(approvedReleasePolicy(await fixture({}, { issuedAt: now + CLOCK_SKEW_MS + 1 }))).rejects.toThrow();
  const input = await fixture();
  await expect(approvedReleasePolicy({ ...input, checkpointDigest: h(99) })).rejects.toThrow();
  await expect(approvedReleasePolicy({ ...input, trust: { ...trust, caseId: h(99) } })).rejects.toThrow();
});
test('admin signatures cannot stand in for the owner', async () => {
  const input = await fixture();
  input.release = await signOwnerStatement({ kind: 'release', caseId: trust.caseId, revision: 1,
    releaseDigest: (await readReleaseManifest(input.manifest)).digest, issuedAt: now }, other);
  await expect(approvedReleasePolicy(input)).rejects.toThrow();
});
test('rejects noncanonical and ambiguous JSON', async () => {
  const wire = canonicalReleaseManifest(manifest);
  for (const value of [wire + '\n', JSON.stringify(manifest, null, 2),
    wire.replace('"format":', '"format":"vera-confidential-release/v1","format":'),
    JSON.stringify({ ...manifest, extra: 'ignored?' }),
    JSON.stringify(Object.fromEntries(Object.entries(manifest).reverse())), '{}']) {
    await expect(readReleaseManifest(value)).rejects.toThrow();
  }
});
test('rejects unsupported formats, debug measurements and unsafe source URLs', () => {
  for (const value of [ { ...manifest, format: 'legacy' }, { ...manifest, protocolVersion: 'unknown' },
    { ...manifest, dataFormatVersion: 'unknown' }, { ...manifest, measurements: { ...manifest.measurements, pcr0: '0'.repeat(96) } },
    { ...manifest, sourceRepository: 'https://github.com/user/repo?token=secret' },
    { ...manifest, sourceRepository: 'https://evil.example/repo' },
  ]) expect(() => canonicalReleaseManifest(value as ConfidentialReleaseManifest)).toThrow();
});
test('snapshots inputs before verification awaits', async () => {
  const input = await fixture(), pending = approvedReleasePolicy(input);
  input.nonce.fill(0); input.manifest = '{}'; input.checkpointDigest = h(99); input.now = 0;
  const result = await pending;
  expect(result.policy.nonce).toEqual(new Uint8Array(32).fill(1));
  expect(result.policy.now).toBe(now);
});
