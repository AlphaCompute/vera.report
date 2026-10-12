// Release step for the measured legal identity policy: the script's canonical
// bytes and pinned digest must be exactly what the compiled enclave accepts from
// the host file. Requires `npm --prefix enclave run build`. Synthetic keys only.
const { test } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { main, sha256 } = require('../../scripts/security/confidential-legal-identity.cjs');
const { legalIdentityPolicyDigest, verifyMeasuredLegalPolicy } = require('../../enclave/dist/cases/measuredConfiguration.js');

const ROOT = path.resolve(__dirname, '../..');

function rsaJwk(kid) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { public: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256', x5t: 'ignored' },
    private: { ...privateKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' } };
}

function workspace(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vera-legal-identity-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const write = (name, value) => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
    return file;
  };
  // Start from the committed configuration with its pin cleared, so these runs
  // pin fresh test keys whether or not production is already pinned.
  const committed = JSON.parse(fs.readFileSync(path.join(ROOT, 'enclave/confidential-config.json'), 'utf8'));
  const config = write('confidential-config.json', `${JSON.stringify({ ...committed, legalIdentityPolicySha256: null }, null, 2)}\n`);
  return { dir, write, config };
}

// A permitted key ID containing the metadata name must survive canonicalization.
const current = rsaJwk('current-x5t'), next = rsaJwk('next');
const JWKS = { keys: [current.public, next.public, { kty: 'EC', use: 'sig', kid: 'ignored-ec', crv: 'P-256', x: 'a', y: 'b' }] };
const AUTH0_OUTPUT = { issuer: 'https://legal.example/', audience: 'https://api.example/legal', clientId: 'legal-client',
  jwks_url: 'https://legal.example/.well-known/jwks.json' };

test('pin writes canonical policy bytes whose digest the compiled enclave verifies', async t => {
  const w = workspace(t);
  const out = path.join(w.dir, 'legal-identity-policy.json');
  const result = main(['pin', '--auth0-output', w.write('auth0.json', AUTH0_OUTPUT), '--jwks', w.write('a.json', JWKS),
    '--jwks-witness', w.write('b.json', JWKS), '--config', w.config, '--out', out]);
  const bytes = fs.readFileSync(out);
  const config = JSON.parse(fs.readFileSync(w.config, 'utf8'));
  assert.equal(result.legalIdentityPolicySha256, sha256(bytes));
  assert.equal(config.legalIdentityPolicySha256, sha256(bytes));
  assert.deepEqual(result.keys, ['current-x5t', 'next']);
  // Config keeps its committed formatting (2-space JSON, trailing newline).
  assert.equal(fs.readFileSync(w.config, 'utf8'), `${JSON.stringify(config, null, 2)}\n`);

  // The host serves JSON.parse(file); the enclave recomputes the digest from it.
  const policy = JSON.parse(bytes.toString('utf8'));
  assert.equal(legalIdentityPolicyDigest(policy), config.legalIdentityPolicySha256);
  assert.deepEqual(verifyMeasuredLegalPolicy(config.legalIdentityPolicySha256, policy), policy);
  assert.ok(policy.jwks.keys.every(key => Object.keys(key).join(',') === 'kty,use,alg,kid,n,e'));
  assert.ok(policy.jwks.keys.every(key => !Object.hasOwn(key, 'x5t')));

  assert.deepEqual(main(['verify', '--config', w.config, '--policy', out]),
    { legalIdentityPolicySha256: config.legalIdentityPolicySha256, firmOperations: 'enabled' });
  // One changed byte: verify and the enclave both refuse.
  const tampered = w.write('tampered.json', bytes.toString('utf8').replace('legal-client', 'legal-clienT'));
  assert.throws(() => main(['verify', '--config', w.config, '--policy', tampered]), /does not match the pinned digest/);
  assert.throws(() => verifyMeasuredLegalPolicy(config.legalIdentityPolicySha256, JSON.parse(fs.readFileSync(tampered, 'utf8'))));
});

test('pin refuses disagreeing witnesses, private key material and non-https issuers', t => {
  const w = workspace(t);
  const base = ['--auth0-output', w.write('auth0.json', AUTH0_OUTPUT), '--config', w.config, '--out', path.join(w.dir, 'p.json')];
  assert.throws(() => main(['pin', ...base, '--jwks', w.write('a.json', JWKS), '--jwks-witness', w.write('b.json', { keys: [current.public] })]),
    /differ; do not pin/);
  assert.throws(() => main(['pin', ...base, '--jwks', w.write('c.json', { keys: [current.private] }), '--jwks-witness', w.write('d.json', { keys: [current.private] })]),
    /private key material/);
  const insecure = w.write('insecure.json', { ...AUTH0_OUTPUT, issuer: 'http://legal.example/' });
  assert.throws(() => main(['pin', '--auth0-output', insecure, '--jwks', w.write('e.json', JWKS), '--jwks-witness', w.write('f.json', JWKS),
    '--config', w.config, '--out', path.join(w.dir, 'q.json')]), /https origin/);
  // Nothing was pinned by the refused runs.
  assert.equal(JSON.parse(fs.readFileSync(w.config, 'utf8')).legalIdentityPolicySha256, null);
});

test('admin inputs pin the measured onboarding administration policy', t => {
  const w = workspace(t);
  const key = w.write('onboarding.asc', '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n');
  main(['pin', '--auth0-output', w.write('auth0.json', AUTH0_OUTPUT), '--jwks', w.write('a.json', JWKS), '--jwks-witness', w.write('b.json', JWKS),
    '--admin-output', w.write('admin.json', { issuer: 'https://legal.example/', audience: 'https://api.example/admin', clientId: 'admin-client', organizationId: 'org_internal1' }),
    '--onboarding-key', key, '--config', w.config, '--out', path.join(w.dir, 'p.json')]);
  const config = JSON.parse(fs.readFileSync(w.config, 'utf8'));
  assert.equal(config.legalAdministration.organizationId, 'org_internal1');
  assert.equal(config.legalAdministration.identity.clientId, 'admin-client');
  assert.equal(legalIdentityPolicyDigest(config.legalAdministration.identity).length, 64);
});

test('the committed configuration verifies: null pin means firm operations stay disabled', () => {
  const config = path.join(ROOT, 'enclave/confidential-config.json');
  const pinned = JSON.parse(fs.readFileSync(config, 'utf8')).legalIdentityPolicySha256;
  const policy = path.join(ROOT, 'enclave/legal-identity-policy.json');
  const result = main(['verify', '--config', config, '--policy', policy]);
  assert.equal(result.legalIdentityPolicySha256, pinned);
  if (pinned === null) assert.equal(result.firmOperations, 'disabled');
});

test('pin accepts a separate initial-approval public key and refuses administrator key reuse', t => {
  const w = workspace(t);
  const root = w.write('admin.asc', '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nadmin\n-----END PGP PUBLIC KEY BLOCK-----\n');
  const worker = w.write('worker.asc', '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nworker\n-----END PGP PUBLIC KEY BLOCK-----\n');
  const args = ['pin', '--auth0-output', w.write('auth0.json', AUTH0_OUTPUT), '--jwks', w.write('a.json', JWKS), '--jwks-witness', w.write('b.json', JWKS),
    '--admin-output', w.write('admin.json', { issuer: 'https://legal.example/', audience: 'https://api.example/admin', clientId: 'admin-client', organizationId: 'org_internal1' }),
    '--onboarding-key', root, '--config', w.config, '--out', path.join(w.dir, 'p.json')];
  assert.throws(() => main([...args, '--initial-approval-key', root]), /separate public key/);
  main([...args, '--initial-approval-key', worker]);
  assert.equal(JSON.parse(fs.readFileSync(w.config, 'utf8')).legalAdministration.initialApprovalPublicKey, fs.readFileSync(worker, 'utf8').trim());
});
