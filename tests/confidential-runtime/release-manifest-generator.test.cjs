// Release manifest generator against a fixed vector and the compiled enclave
// reader. Requires `npm --prefix enclave run build` (or the browser harness,
// which compiles enclave/dist first). Synthetic data only; no network.
const { test } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { generate, parseArgs } = require('../../scripts/security/confidential-release-manifest.cjs');
const { readReleaseManifest } = require('../../enclave/dist/confidential/releaseManifest.js');
const { CASE_STORE_RPC_METHODS } = require('../../enclave/dist/cases/storageRpc.js');

const ROOT = path.resolve(__dirname, '../..');
const DIST = path.join(ROOT, 'enclave/dist');
const VECTOR = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/fixtures/confidential-release-manifest-vector.json'), 'utf8'));

function workspace(t, overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vera-release-manifest-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const files = {
    measurements: JSON.stringify(overrides.measurements ?? VECTOR.measurements),
    eif: overrides.eif ?? VECTOR.eif,
    configuration: overrides.configuration ?? VECTOR.configuration,
    provenance: overrides.provenance ?? VECTOR.provenance,
  };
  const paths = {};
  for (const [name, content] of Object.entries(files)) {
    paths[name] = path.join(dir, name);
    fs.writeFileSync(paths[name], content);
  }
  return { dir, options: { dist: DIST, measurements: paths.measurements, eif: paths.eif,
    configuration: paths.configuration, provenance: paths.provenance,
    repository: overrides.repository ?? VECTOR.repository, commit: overrides.commit ?? VECTOR.commit,
    out: path.join(dir, 'confidential-release-manifest.json') } };
}

test('fixed vector: generator bytes equal the enclave canonical form and digest', async t => {
  const { options } = workspace(t);
  const result = await generate(options);
  const written = fs.readFileSync(options.out, 'utf8');
  assert.equal(written, VECTOR.expected.canonical);
  assert.equal(result.digest, VECTOR.expected.sha256);
  assert.equal(createHash('sha256').update(written).digest('hex'), VECTOR.expected.sha256);
  assert.equal(fs.readFileSync(`${options.out}.sha256`, 'utf8'),
    `${VECTOR.expected.sha256}  confidential-release-manifest.json\n`);
  // The enclave's strict reader accepts the exact file and yields the same digest.
  const parsed = await readReleaseManifest(written);
  assert.equal(parsed.digest, VECTOR.expected.sha256);
  assert.equal(parsed.manifest.measurements.pcr0, VECTOR.measurements.PCR0);
  // A trailing newline is not canonical; the file must not carry one.
  await assert.rejects(readReleaseManifest(`${written}\n`));
  // One line, so it passes through the one-argument-per-line frontend build-args.
  assert.doesNotMatch(written, /[\r\n]/);
});

test('Nitro CLI 1.5 SHA-384 debug alias preserves canonical manifest identity', async t => {
  const { options } = workspace(t, { measurements: { ...VECTOR.measurements, HashAlgorithm: 'Sha512_48 { .. }' } });
  assert.equal((await generate(options)).digest, VECTOR.expected.sha256);
});

test('rejects unknown or wrong-sized hash debug aliases', async t => {
  for (const HashAlgorithm of ['Sha512', 'Sha512_64 { .. }', 'Sha512_48', 'Sha512_48 { .. }extra']) {
    const { options } = workspace(t, { measurements: { ...VECTOR.measurements, HashAlgorithm } });
    await assert.rejects(generate(options), /unexpected measurement algorithm/);
    assert.equal(fs.existsSync(options.out), false);
  }
});

test('never overwrites an existing manifest', async t => {
  const { options } = workspace(t);
  await generate(options);
  await assert.rejects(generate(options), /EEXIST/);
});

test('rejects inputs that do not describe the measured release', async t => {
  const cases = {
    'other commit': { commit: 'f'.repeat(40) },
    'EIF bytes differ': { eif: 'tampered' },
    'zero PCR': { measurements: { ...VECTOR.measurements, PCR1: '0'.repeat(96) } },
    'malformed image id': { measurements: { ...VECTOR.measurements, docker_image_id: 'ab'.repeat(32) } },
    'wrong algorithm': { measurements: { ...VECTOR.measurements, HashAlgorithm: 'Sha256' } },
    'non-GitHub repository': { repository: 'https://example.com/AlphaCompute/vera' },
    'provenance not a bundle': { provenance: '{"predicateType":"https://slsa.dev/provenance/v1"}' },
    'empty provenance': { provenance: '' },
    'config for another protocol': { configuration: VECTOR.configuration.replace('channel/v1', 'channel/v2') },
    'config with key material': { configuration: JSON.stringify({ ...JSON.parse(VECTOR.configuration),
      leaked: '-----BEGIN PRIVATE KEY-----' }) },
    'config with hex secret': { configuration: JSON.stringify({ ...JSON.parse(VECTOR.configuration), key: 'ab'.repeat(32) }) },
  };
  for (const [name, override] of Object.entries(cases)) {
    await t.test(name, async t2 => {
      const { options } = workspace(t2, override);
      await assert.rejects(generate(options));
      assert.equal(fs.existsSync(options.out), false);
    });
  }
});

test('argument parsing is strict', () => {
  assert.throws(() => parseArgs(['--dist']));
  assert.throws(() => parseArgs(['--unknown', 'x']));
  assert.throws(() => parseArgs(['--dist', 'a', '--dist', 'b']));
  assert.throws(() => parseArgs(['--dist', 'a']), /missing/);
});

test('checked-in confidential configuration is accepted and matches the compiled service set', async t => {
  const configurationPath = path.join(ROOT, 'enclave/confidential-config.json');
  const configuration = JSON.parse(fs.readFileSync(configurationPath, 'utf8'));
  assert.deepEqual(configuration.vsock.storage.methods, [...CASE_STORE_RPC_METHODS]);
  const ownerChannel = fs.readFileSync(path.join(DIST, 'cases/ownerChannel.js'), 'utf8');
  const ownerServed = new Set(ownerChannel.match(/'case\.[a-z-]+'/g).map(item => item.slice(1, -1)));
  assert.deepEqual([...ownerServed].sort(), [...configuration.ownerOperations].sort());
  const legalChannel = fs.readFileSync(path.join(DIST, 'cases/legalChannel.js'), 'utf8') +
    fs.readFileSync(path.join(DIST, 'cases/legalFirm.js'), 'utf8');
  for (const operation of configuration.firmOperations) assert.ok(legalChannel.includes(`'${operation}'`), operation);
  const served = new Set(legalChannel.match(/'legal\.[a-z-]+'/g).map(item => item.slice(1, -1)));
  assert.deepEqual([...served].sort(), [...configuration.firmOperations].sort());
  const entrypoint = fs.readFileSync(path.join(ROOT, 'enclave/entrypoint.sh'), 'utf8');
  assert.match(entrypoint, new RegExp(`VSOCK-LISTEN:${configuration.vsock.session.port},`));
  assert.match(entrypoint, new RegExp(`VSOCK-CONNECT:${configuration.vsock.storage.parentCid}:${configuration.vsock.storage.port}`));
  assert.equal(configuration.custody.caseSecretsOnHost, false);
  assert.equal(configuration.custody.kmsKeysForConfidentialCases, false);
  const { options } = workspace(t, { configuration: fs.readFileSync(configurationPath, 'utf8') });
  const { canonical } = await generate(options);
  assert.equal(JSON.parse(canonical).configurationSha256,
    createHash('sha256').update(fs.readFileSync(configurationPath)).digest('hex'));
});

test('accepts a public identity-policy digest while still rejecting malformed pins', async t => {
  const config = JSON.parse(VECTOR.configuration);
  config.legalIdentityPolicySha256 = 'a'.repeat(64);
  const { options } = workspace(t, { configuration: JSON.stringify(config) });
  const result = await generate(options);
  assert.equal(JSON.parse(result.canonical).configurationSha256,
    createHash('sha256').update(JSON.stringify(config)).digest('hex'));
  for (const pin of ['', '0'.repeat(64), 'A'.repeat(64)]) {
    const invalid = workspace(t, { configuration: JSON.stringify({ ...config, legalIdentityPolicySha256: pin }) });
    await assert.rejects(generate(invalid.options));
  }
});

for (const HashAlgorithm of ['Sha384', 'Sha384 { ... }', 'Sha512_48 { .. }']) {
  test(`accepts Nitro SHA384 debug spelling ${HashAlgorithm}`, async t => {
    const { options } = workspace(t, { measurements: { ...VECTOR.measurements, HashAlgorithm } });
    assert.equal((await generate(options)).canonical, VECTOR.expected.canonical);
  });
}
test('accepts only a public release-withdrawal verification key', async t => {
  const config = JSON.parse(VECTOR.configuration);
  const publicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----';
  const accepted = workspace(t, { configuration: JSON.stringify({ ...config, releaseWithdrawal: { publicKey } }) });
  await generate(accepted.options);
  for (const releaseWithdrawal of [{ publicKey: '-----BEGIN PGP PRIVATE KEY BLOCK-----\nx' }, { publicKey, unsigned: true }, 'key']) {
    const invalid = workspace(t, { configuration: JSON.stringify({ ...config, releaseWithdrawal }) });
    await assert.rejects(generate(invalid.options), /releaseWithdrawal/);
  }
});
test('accepts only public Ed25519 Roughtime server keys with a bounded quorum', async t => {
  const config = JSON.parse(VECTOR.configuration);
  const server = { name: 'synthetic', address: 'roughtime.example:2002', publicKey: Buffer.alloc(32, 7).toString('base64') };
  // Nonzero unused trailing bits decode to the same key, but are not canonical.
  const alias = server.publicKey.slice(0, -2) + 'd=';
  assert.notEqual(alias, server.publicKey);
  assert.deepEqual(Buffer.from(alias, 'base64'), Buffer.from(server.publicKey, 'base64'));
  const roughtime = { servers: [server], quorum: 1, toleranceMs: 10000 };
  const accepted = workspace(t, { configuration: JSON.stringify({ ...config, roughtime }) });
  await generate(accepted.options);
  for (const invalid of [{ ...roughtime, quorum: 2 }, { ...roughtime, toleranceMs: 0 }, { ...roughtime, extra: 1 },
    { ...roughtime, servers: [{ ...server, publicKey: Buffer.alloc(64, 7).toString('base64') }] },
    { ...roughtime, servers: [{ ...server, publicKey: alias }] },
    { ...roughtime, servers: [server, { ...server, name: 'other', publicKey: alias }], quorum: 2 },
    { ...roughtime, servers: [server, { ...server, name: 'other' }], quorum: 2 },
    { ...roughtime, servers: [{ ...server, address: 'https://roughtime.example' }] }, 'roughtime']) {
    const rejected = workspace(t, { configuration: JSON.stringify({ ...config, roughtime: invalid }) });
    await assert.rejects(generate(rejected.options), /roughtime/);
  }
});
