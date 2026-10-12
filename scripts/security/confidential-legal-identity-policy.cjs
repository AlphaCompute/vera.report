#!/usr/bin/env node
'use strict';

// Release step for the firm (legal-member) identity policy the enclave pins.
//
//   auth0 output ──► canonical policy file ──► sha256 ──► confidential-config.json ──► EIF
//
// 1. `terraform -chdir=auth0 output -json legal_identity_policy > auth0-legal.json`
// 2. `curl -fsS "$(jq -r .jwks_url auth0-legal.json)" > jwks.json` over authenticated TLS,
//    then compare the key IDs with the Auth0 dashboard (Settings > Signing Keys).
// 3. `node scripts/security/confidential-legal-identity-policy.cjs pin --auth0-output auth0-legal.json --jwks jwks.json`
//    writes enclave/legal-identity-policy.json (canonical bytes) and sets
//    enclave/confidential-config.json `legalIdentityPolicySha256` to its sha256.
// 4. Commit both files. The next Enclave EIF build measures the configuration,
//    `check --stage out` verifies the pin, and publish uploads the policy next to
//    the release manifest (s3://…/eif/<commit>/legal-identity-policy.json).
// 5. Set terraform-prod `confidential_legal_identity_policy_sha256` to the same
//    digest. Hosts download, verify and mount the file into the API task as
//    CONFIDENTIAL_LEGAL_IDENTITY_FILE; the enclave re-verifies it against the pin.
//
// The canonical bytes are exactly what `legalIdentityPolicyDigest`
// (enclave/src/cases/measuredConfiguration.ts) hashes, so the file's sha256 is
// the pin. JWKS keys keep their published order and members. No network access.
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const ROOT = path.resolve(__dirname, '../..');
const DEFAULT_CONFIG = path.join(ROOT, 'enclave/confidential-config.json');
const DEFAULT_POLICY = path.join(ROOT, 'enclave/legal-identity-policy.json');
const STAGED_NAME = 'legal-identity-policy.json';
const MAX_BYTES = 64 * 1024;
const PRIVATE_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

function fail(message) { throw new Error(`legal identity policy: ${message}`); }
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function readJson(file, label) {
  const bytes = fs.readFileSync(file);
  if (!bytes.length || bytes.length > MAX_BYTES) fail(`${label} is empty or too large`);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fail(`${label} is not JSON`); }
}

/** Same acceptance rules as `createLegalIdentityVerifier` (enclave/src/legal/identity.ts). */
function validatePolicy(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy) ||
      Object.keys(policy).sort().join(',') !== 'audience,clientId,issuer,jwks') fail('policy must have exactly issuer, audience, clientId and jwks');
  const { issuer, audience, clientId, jwks } = policy;
  let origin;
  try { origin = new URL(issuer); } catch { fail('issuer is not a URL'); }
  if (origin.protocol !== 'https:' || issuer !== `${origin.origin}/`) fail('issuer must be an https origin with a trailing slash');
  if (typeof audience !== 'string' || !audience || audience.length > 512) fail('invalid audience');
  if (typeof clientId !== 'string' || !clientId || clientId.length > 128 || audience === clientId) fail('invalid clientId');
  if (!jwks || typeof jwks !== 'object' || !Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.length > 8) fail('jwks must hold 1-8 keys');
  const kids = new Set();
  for (const key of jwks.keys) {
    if (!key || key.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig' || typeof key.kid !== 'string' || !key.kid ||
        kids.has(key.kid) || typeof key.n !== 'string' || typeof key.e !== 'string') fail('every key must be a distinct RS256 signing key');
    if (PRIVATE_FIELDS.some(field => key[field] !== undefined)) fail('jwks contains private key material');
    kids.add(key.kid);
  }
  return policy;
}

/** Canonical bytes: fixed field order, JWKS as published. */
function canonicalPolicy(policy) {
  validatePolicy(policy);
  return Buffer.from(JSON.stringify({ issuer: policy.issuer, audience: policy.audience, clientId: policy.clientId, jwks: policy.jwks }), 'utf8');
}

function policyFromAuth0(output, jwks) {
  if (!output || typeof output !== 'object') fail('invalid auth0 output');
  // Accept both `output -json legal_identity_policy` and the full `output -json` map.
  const value = output.legal_identity_policy ? output.legal_identity_policy.value ?? output.legal_identity_policy : output;
  const { issuer, audience, clientId, jwks_url: jwksUrl } = value;
  if (typeof jwksUrl !== 'string' || jwksUrl !== `${issuer}.well-known/jwks.json`) fail('jwks_url must be the issuer JWKS endpoint');
  return { issuer, audience, clientId, jwks };
}

function writeConfigPin(configFile, pin) {
  const config = readJson(configFile, 'configuration');
  if (config.format !== 'vera-confidential-configuration/v1') fail('unexpected configuration format');
  config.legalIdentityPolicySha256 = pin;
  fs.writeFileSync(configFile, `${JSON.stringify(config, null, 2)}\n`);
}

/** The measured pin and the policy file must agree. A null pin means firm
 * operations are disabled, and then no policy file may be shipped. */
function check(configFile, policyFile) {
  const pin = readJson(configFile, 'configuration').legalIdentityPolicySha256;
  const exists = fs.existsSync(policyFile);
  if (pin === null) {
    if (exists) fail(`${path.basename(policyFile)} exists but legalIdentityPolicySha256 is null`);
    return null;
  }
  if (typeof pin !== 'string' || !/^[0-9a-f]{64}$/.test(pin) || /^0+$/.test(pin)) fail('invalid legalIdentityPolicySha256');
  if (!exists) fail(`legalIdentityPolicySha256 is set but ${path.basename(policyFile)} is missing`);
  const bytes = fs.readFileSync(policyFile);
  if (!canonicalPolicy(readJson(policyFile, 'policy')).equals(bytes)) fail('policy file is not in canonical form');
  if (sha256(bytes) !== pin) fail('policy file does not match legalIdentityPolicySha256');
  return pin;
}

function parse(argv, allowed) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index], value = argv[index + 1];
    if (typeof flag !== 'string' || !flag.startsWith('--') || !allowed.includes(flag.slice(2)) ||
        typeof value !== 'string' || !value || Object.hasOwn(options, flag.slice(2))) fail(`invalid argument ${flag}`);
    options[flag.slice(2)] = value;
  }
  return options;
}

function main(argv) {
  const [command, ...rest] = argv;
  if (command === 'pin') {
    const options = parse(rest, ['auth0-output', 'jwks', 'config', 'policy']);
    if (!options['auth0-output'] || !options.jwks) fail('pin requires --auth0-output and --jwks');
    const bytes = canonicalPolicy(policyFromAuth0(readJson(options['auth0-output'], 'auth0 output'), readJson(options.jwks, 'jwks')));
    const policyFile = options.policy ?? DEFAULT_POLICY, configFile = options.config ?? DEFAULT_CONFIG;
    fs.writeFileSync(policyFile, bytes);
    writeConfigPin(configFile, sha256(bytes));
    process.stdout.write(`${sha256(bytes)}\n`);
  } else if (command === 'unpin') {
    const options = parse(rest, ['config', 'policy']);
    fs.rmSync(options.policy ?? DEFAULT_POLICY, { force: true });
    writeConfigPin(options.config ?? DEFAULT_CONFIG, null);
  } else if (command === 'check') {
    const options = parse(rest, ['config', 'policy', 'stage']);
    const policyFile = options.policy ?? DEFAULT_POLICY;
    const pin = check(options.config ?? DEFAULT_CONFIG, policyFile);
    if (pin && options.stage) {
      fs.mkdirSync(options.stage, { recursive: true });
      fs.copyFileSync(policyFile, path.join(options.stage, STAGED_NAME));
    }
    process.stdout.write(pin ? `${pin}\n` : 'firm operations disabled (legalIdentityPolicySha256 is null)\n');
  } else {
    fail('usage: pin --auth0-output FILE --jwks FILE | unpin | check [--stage DIR]  (optional --config FILE --policy FILE)');
  }
}

module.exports = { canonicalPolicy, check, policyFromAuth0, validatePolicy };

if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`${error.message}\n`); process.exit(1); }
}
