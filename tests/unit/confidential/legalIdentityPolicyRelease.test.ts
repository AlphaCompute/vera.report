import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { legalIdentityPolicyDigest, verifyMeasuredLegalPolicy } from '../../../enclave/src/cases/measuredConfiguration';
import { createLegalIdentityVerifier } from '../../../enclave/src/legal/identity';

const root = resolve(__dirname, '../../..');
const script = resolve(root, 'scripts/security/confidential-legal-identity-policy.cjs');
const run = (...args: string[]) => execFileSync(process.execPath, [script, ...args], { encoding: 'utf8', stdio: 'pipe' });
const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const unpinnedConfig = () => ({ ...JSON.parse(readFileSync(resolve(root, 'enclave/confidential-config.json'), 'utf8')), legalIdentityPolicySha256: null });

function release() {
  const dir = mkdtempSync(join(tmpdir(), 'vera-legal-policy-'));
  const config = join(dir, 'confidential-config.json'), policy = join(dir, 'legal-identity-policy.json');
  // Start from the committed configuration with its pin cleared, so the test
  // pins fresh test keys whether or not production is already pinned.
  writeFileSync(config, `${JSON.stringify(unpinnedConfig(), null, 2)}\n`);
  const jwk = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
  // Published order and extra public members (x5t) are preserved as-is.
  const jwks = { keys: [{ kid: 'k1', x5t: 'thumb', kty: 'RSA', alg: 'RS256', use: 'sig', n: jwk.n, e: jwk.e }] };
  const auth0 = { issuer: 'https://identity.example/', audience: 'https://legal.example/api', clientId: 'legal-portal-client',
    jwks_url: 'https://identity.example/.well-known/jwks.json' };
  writeFileSync(join(dir, 'auth0.json'), JSON.stringify(auth0));
  writeFileSync(join(dir, 'jwks.json'), JSON.stringify(jwks));
  return { dir, config, policy, auth0, jwks };
}
const pin = (r: ReturnType<typeof release>, auth0 = join(r.dir, 'auth0.json')) =>
  run('pin', '--auth0-output', auth0, '--jwks', join(r.dir, 'jwks.json'), '--config', r.config, '--policy', r.policy).trim();

test('pinning writes canonical policy bytes whose sha256 is the enclave digest and the measured pin', () => {
  const r = release();
  const digest = pin(r);
  const bytes = readFileSync(r.policy);
  const parsed = JSON.parse(bytes.toString('utf8'));
  expect(sha256(bytes)).toBe(digest);
  expect(legalIdentityPolicyDigest(parsed)).toBe(digest);
  expect(JSON.parse(readFileSync(r.config, 'utf8')).legalIdentityPolicySha256).toBe(digest);
  expect(verifyMeasuredLegalPolicy(digest, parsed)).toEqual(parsed);
  expect(() => createLegalIdentityVerifier(parsed)).not.toThrow();
  expect(Object.keys(parsed.jwks.keys[0])).toEqual(Object.keys(r.jwks.keys[0]));
  // Only the pin changed in the measured configuration, and the format is kept.
  const original = unpinnedConfig();
  expect({ ...JSON.parse(readFileSync(r.config, 'utf8')), legalIdentityPolicySha256: null }).toEqual(original);
  expect(readFileSync(r.config, 'utf8')).toMatch(/^\{\n {2}"format"/);
  expect(run('check', '--config', r.config, '--policy', r.policy, '--stage', join(r.dir, 'out')).trim()).toBe(digest);
  expect(readFileSync(join(r.dir, 'out/legal-identity-policy.json')).equals(bytes)).toBe(true);
});

test('check refuses a policy that differs from the measured pin or is not canonical', () => {
  const r = release();
  pin(r);
  const parsed = JSON.parse(readFileSync(r.policy, 'utf8'));
  writeFileSync(r.policy, JSON.stringify({ ...parsed, audience: 'https://other.example/api' }));
  expect(() => run('check', '--config', r.config, '--policy', r.policy)).toThrow(/does not match/);
  writeFileSync(r.policy, JSON.stringify(parsed, null, 2));
  expect(() => run('check', '--config', r.config, '--policy', r.policy)).toThrow(/canonical/);
  run('unpin', '--config', r.config, '--policy', r.policy);
  expect(existsSync(r.policy)).toBe(false);
  expect(run('check', '--config', r.config, '--policy', r.policy)).toMatch(/disabled/);
  writeFileSync(r.policy, '{}');
  expect(() => run('check', '--config', r.config, '--policy', r.policy)).toThrow(/is null/);
});

test('pinning refuses private keys, weak algorithms and a foreign JWKS endpoint', () => {
  const r = release();
  writeFileSync(join(r.dir, 'jwks.json'), JSON.stringify({ keys: [{ ...r.jwks.keys[0], d: 'secret' }] }));
  expect(() => pin(r)).toThrow(/private key/);
  writeFileSync(join(r.dir, 'jwks.json'), JSON.stringify({ keys: [{ ...r.jwks.keys[0], alg: 'HS256' }] }));
  expect(() => pin(r)).toThrow(/RS256/);
  writeFileSync(join(r.dir, 'jwks.json'), JSON.stringify(r.jwks));
  writeFileSync(join(r.dir, 'evil.json'), JSON.stringify({ ...r.auth0, jwks_url: 'https://evil.example/.well-known/jwks.json' }));
  expect(() => pin(r, join(r.dir, 'evil.json'))).toThrow(/jwks_url/);
  expect(existsSync(r.policy)).toBe(false);
  expect(JSON.parse(readFileSync(r.config, 'utf8')).legalIdentityPolicySha256).toBeNull();
});

test('the committed release inputs agree', () => {
  expect(() => run('check')).not.toThrow();
});
