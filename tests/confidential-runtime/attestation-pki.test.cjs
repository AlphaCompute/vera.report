const { test } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const { createHash, X509Certificate } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { createPkiFixture } = require('./attestation-fixture.cjs');
const { verifyAttestationPki } = require('../../enclave/dist/confidential/attestationPki.js');
const { prepareApplicationAttestation } = require('../../enclave/dist/confidential/attestationEvidence.js');
const { verifyApplicationAttestation, verifyApprovedCaseChannel } = require('../../enclave/dist/confidential/attestation.js');
const fixture = createPkiFixture(), other = createPkiFixture();

test('validates an independent OpenSSL chain and real COSE ES384 signature', async () => {
  const evidence = await prepareApplicationAttestation(fixture.document, fixture.publicKey, fixture);
  await verifyAttestationPki(evidence, fixture.root, fixture.now);
});
test('production verifier rejects the valid synthetic root even when supplied in the document', async () => {
  await assert.rejects(verifyApplicationAttestation(fixture.document, fixture.publicKey, fixture), /verification failed/);
});
test('embedded production root exactly matches pinned AWS certificate', () => {
  const source = readFileSync(require.resolve('../../enclave/dist/confidential/attestation.js'), 'utf8');
  const encoded = /const ROOT = '([^']+)'/.exec(source)[1];
  const root = new X509Certificate(readFileSync('enclave/verification/aws-nitro-root.pem')).raw;
  assert.deepEqual(Buffer.from(encoded, 'base64'), root);
  assert.equal(createHash('sha256').update(root).digest('hex'), '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b');
});
test('rejects changed signature, payload, certificate, chain and trust root', async () => {
  const signature = Buffer.from(fixture.evidence.signature); signature[0] ^= 1;
  const signedBytes = Buffer.from(fixture.evidence.signedBytes); signedBytes[20] ^= 1;
  for (const change of [{ signature }, { signedBytes }, { certificate: other.evidence.certificate },
    { certificate: Buffer.concat([fixture.evidence.certificate, Buffer.from([0])]) },
    { cabundle: [other.root] }, { cabundle: [] }]) {
    await assert.rejects(verifyAttestationPki({ ...fixture.evidence, ...change }, fixture.root, fixture.now));
  }
  await assert.rejects(verifyAttestationPki(fixture.evidence, other.root, fixture.now));
});
test('rejects expired and not-yet-valid certificates', async () => {
  await assert.rejects(verifyAttestationPki(fixture.evidence, fixture.root, fixture.now + 3 * 86400000));
  await assert.rejects(verifyAttestationPki(fixture.evidence, fixture.root, fixture.now - 86400000));
});
test('rejects a CA leaf, missing signing usage and unknown critical extensions', async () => {
  for (const extensions of [
    'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign',
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment',
    'basicConstraints=critical,CA:FALSE\n1.2.3.4=critical,DER:05:00',
  ]) {
    const f = createPkiFixture(extensions);
    await assert.rejects(verifyAttestationPki(f.evidence, f.root, f.now));
  }
});
test('verifies intermediate chains and rejects omitted, reordered and non-CA issuers', async () => {
  const f = createPkiFixture(undefined, true);
  await verifyAttestationPki(f.evidence, f.root, f.now);
  await assert.rejects(verifyAttestationPki({ ...f.evidence, cabundle: [f.root] }, f.root, f.now));
  await assert.rejects(verifyAttestationPki({ ...f.evidence, cabundle: [...f.evidence.cabundle].reverse() }, f.root, f.now));
  const bad = createPkiFixture(undefined, false);
  await assert.rejects(verifyAttestationPki(bad.evidence, bad.root, bad.now));
});
test('owner approval cannot override the pinned AWS root in the integrated case verifier', async () => {
  const { generateKey } = require('../../enclave/dist/confidential/pgp.js');
  const { signOwnerStatement, verifyOwnerStatement } = require('../../enclave/dist/confidential/authorization.js');
  const { canonicalReleaseManifest, readReleaseManifest, approvedReleasePolicy } = require('../../enclave/dist/confidential/releaseManifest.js');
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Synthetic owner' }], format: 'object' });
  const trust = { caseId: '1'.repeat(64), ownerFingerprint: publicKey.getFingerprint(), ownerPublicKey: publicKey };
  const manifest = canonicalReleaseManifest({ format: 'vera-confidential-release/v1', sourceRepository: 'https://github.com/example/vera',
    sourceCommit: '1'.repeat(40), eifSha256: '2'.repeat(64), imageSha256: '3'.repeat(64),
    configurationSha256: '4'.repeat(64), provenanceSha256: '5'.repeat(64),
    protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
    measurements: { pcr0: fixture.expectedPcrs.get(0).toString('hex'), pcr1: fixture.expectedPcrs.get(1).toString('hex'),
      pcr2: fixture.expectedPcrs.get(2).toString('hex') } });
  const release = await signOwnerStatement({ kind: 'release', caseId: trust.caseId, revision: 1,
    releaseDigest: (await readReleaseManifest(manifest)).digest, issuedAt: fixture.now }, privateKey);
  const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: trust.caseId, revision: 2, keyEpoch: 1,
    previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [(await verifyOwnerStatement(release, trust)).digest], issuedAt: fixture.now }, privateKey);
  const approval = { manifest, release, checkpoint, checkpointDigest: (await verifyOwnerStatement(checkpoint, trust)).digest,
    trust, now: fixture.now, nonce: fixture.nonce };
  const { policy } = await approvedReleasePolicy(approval);
  const prepared = await prepareApplicationAttestation(fixture.document, fixture.publicKey, policy);
  await verifyAttestationPki(prepared, fixture.root, fixture.now); // Same bytes are valid under the synthetic issuer.
  await assert.rejects(verifyApprovedCaseChannel(fixture.document, fixture.publicKey, approval), /Owner-approved channel verification failed/);
  const { createApprovedChannelRequest } = require('../../enclave/dist/confidential/channelMessage.js');
  await assert.rejects(createApprovedChannelRequest(fixture.document, fixture.publicKey, approval,
    new TextEncoder().encode('SYNTHETIC PRIVATE INPUT')), /Invalid confidential channel message/);
});
test('certificate size cap leaves headroom over real Nitro certificates and fails distinctly', async () => {
  const { MAX_ATTESTATION_CERTIFICATE_BYTES, AttestationCertificateSizeError } = require('../../enclave/dist/confidential/attestationPki.js');
  const { decodeAttestationCbor } = require('../../enclave/dist/confidential/attestationCbor.js');
  const real = JSON.parse(readFileSync('enclave/verification/fixtures/nsm-channel-indefinite-20260915.json', 'utf8'));
  const cose = decodeAttestationCbor(new Uint8Array(Buffer.from(real.documentBase64, 'base64')), true);
  const body = decodeAttestationCbor(cose[2]);
  const sizes = [body.get('certificate'), ...body.get('cabundle')].map(value => value.length);
  // A tightened cap must fail here, not against AWS's next certificate profile.
  assert.ok(Math.max(...sizes) * 4 < MAX_ATTESTATION_CERTIFICATE_BYTES, `largest real certificate ${Math.max(...sizes)} bytes`);
  const oversized = new Uint8Array(MAX_ATTESTATION_CERTIFICATE_BYTES + 1);
  await assert.rejects(verifyAttestationPki({ ...fixture.evidence, certificate: oversized }, fixture.root, fixture.now),
    error => error instanceof AttestationCertificateSizeError && !/[0-9a-f]{16}/i.test(error.message));
  // Every other malformed certificate keeps the generic failure.
  await assert.rejects(verifyAttestationPki({ ...fixture.evidence, certificate: new Uint8Array(32) }, fixture.root, fixture.now),
    error => !(error instanceof AttestationCertificateSizeError));
});
