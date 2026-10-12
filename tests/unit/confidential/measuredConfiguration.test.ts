import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { measuredLegalAdministration, legalIdentityPolicyDigest, measuredReleaseWithdrawalKey, measuredRoughtimePolicy,
  verifyMeasuredConfiguration, verifyMeasuredLegalPolicy } from '../../../enclave/src/cases/measuredConfiguration';

const policy = { issuer: 'https://legal.example/', audience: 'legal-api', clientId: 'legal-client',
  jwks: { keys: [{ kty: 'RSA', kid: 'test', alg: 'RS256', use: 'sig', n: 'test', e: 'AQAB' }] } };
function fixture(pin: unknown = legalIdentityPolicyDigest(policy), legalAdministration: unknown = null) {
  const bytes = Buffer.from(JSON.stringify({ format: 'vera-confidential-configuration/v1',
    protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
    channelAudience: 'vera-confidential-cases', legalIdentityPolicySha256: pin, legalAdministration }));
  return { bytes, wire: manifestFor(bytes) };
}
function manifestFor(bytes: Buffer) {
  return canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
    sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
    eifSha256: '1'.repeat(64), imageSha256: '2'.repeat(64), provenanceSha256: '3'.repeat(64),
    configurationSha256: createHash('sha256').update(bytes).digest('hex'),
    protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
    measurements: { pcr0: '1'.repeat(96), pcr1: '2'.repeat(96), pcr2: '3'.repeat(96) } });
}
test('measured bytes and exact pinned policy are both required', async () => {
  const { wire, bytes } = fixture();
  const pin = await verifyMeasuredConfiguration(wire, bytes);
  expect(verifyMeasuredLegalPolicy(pin, policy)).toEqual(policy);
  await expect(verifyMeasuredConfiguration(wire, Buffer.concat([bytes, Buffer.from(' ')]))).rejects.toThrow();
  expect(() => verifyMeasuredLegalPolicy(pin, { ...policy, issuer: 'https://attacker.example/' })).toThrow();
  expect(() => verifyMeasuredLegalPolicy(pin, { ...policy, jwks: { keys: [] } })).toThrow();
  expect(() => verifyMeasuredLegalPolicy(pin, null)).toThrow();
});
test('host input cannot enable firm operations disabled in the measured image', async () => {
  const { wire, bytes } = fixture(null);
  expect(verifyMeasuredLegalPolicy(await verifyMeasuredConfiguration(wire, bytes), policy)).toBeNull();
});
test.each([undefined, '', '0'.repeat(64), 'A'.repeat(64)])('missing or invalid pin fails closed (%s)', async pin => {
  const { wire, bytes } = fixture(pin === undefined ? false : pin);
  await expect(verifyMeasuredConfiguration(wire, bytes)).rejects.toThrow();
});

test('onboarding authority and admin identity must come from exact measured bytes', async () => {
  const administration = { identity: { ...policy, audience: 'admin-api', clientId: 'admin-client' },
    organizationId: 'org_admin', onboardingPublicKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----\npublicfixture' };
  const { wire, bytes } = fixture(legalIdentityPolicyDigest(policy), administration);
  await expect(measuredLegalAdministration(wire, bytes)).resolves.toEqual(administration);
  await expect(measuredLegalAdministration(wire, Buffer.from(bytes.toString().replace('admin-api', 'attacker-api')))).rejects.toThrow();
  const disabled = fixture(null);
  await expect(measuredLegalAdministration(disabled.wire, disabled.bytes)).resolves.toBeUndefined();
  const privateKey = fixture(null, { ...administration, onboardingPublicKey: '-----BEGIN PGP PRIVATE KEY BLOCK-----' });
  await expect(measuredLegalAdministration(privateKey.wire, privateKey.bytes)).rejects.toThrow();
});

test('initial approvals require a distinct measured public key, never the administrator key', async () => {
  const [admin, worker] = await Promise.all(['admin', 'worker'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
  const administration = { identity: { ...policy, audience: 'admin-api', clientId: 'admin-client' }, organizationId: 'org_admin',
    onboardingPublicKey: admin.toPublic().armor(), initialApprovalPublicKey: worker.toPublic().armor() };
  const valid = fixture(null, administration);
  await expect(measuredLegalAdministration(valid.wire, valid.bytes)).resolves.toEqual(administration);
  for (const initialApprovalPublicKey of [admin.toPublic().armor(), worker.armor(), '', 'invalid']) {
    const invalid = fixture(null, { ...administration, initialApprovalPublicKey });
    await expect(measuredLegalAdministration(invalid.wire, invalid.bytes)).rejects.toThrow();
  }
  const changed = fixture(null, { ...administration, initialApprovalPublicKey: admin.toPublic().armor() });
  await expect(measuredLegalAdministration(valid.wire, changed.bytes)).rejects.toThrow();
});

// The source template grants no live authority and still passes the measured configuration checks.
test.each(['enclave/confidential-config.json'])('%s passes the enclave measured configuration checks', async file => {
  const bytes = readFileSync(resolve(__dirname, '../../..', file));
  expect(JSON.parse(bytes.toString('utf8'))).toMatchObject({ enabled: false, legalIdentityPolicySha256: null, legalAdministration: null });
  const wire = manifestFor(bytes);
  const pin = await verifyMeasuredConfiguration(wire, bytes);
  expect(pin === null || /^[a-f0-9]{64}$/.test(pin)).toBe(true);
  await measuredLegalAdministration(wire, bytes);
  await measuredReleaseWithdrawalKey(wire, bytes);
  await measuredRoughtimePolicy(wire, bytes);
  await expect(verifyMeasuredConfiguration(manifestFor(Buffer.concat([bytes, Buffer.from(' ')])), bytes)).rejects.toThrow();
});
