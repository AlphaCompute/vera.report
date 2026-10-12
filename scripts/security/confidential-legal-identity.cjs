#!/usr/bin/env node
'use strict';

// Release step for the measured legal identity policy (runbook "Measured legal
// identity policy"): canonical policy -> sha256 -> enclave/confidential-config.json
// -> EIF build -> published beside the release manifest -> host file
// (CONFIDENTIAL_LEGAL_IDENTITY_FILE, pinned by confidential_legal_identity_policy_sha256).
//
//   pin     --auth0-output <terraform output -json legal_identity_policy>
//           --jwks <jwks.json fetched from network A> --jwks-witness <jwks.json fetched from network B>
//           [--admin-output <terraform output -json admin_identity_policy> --onboarding-key <armored public key>]
//           [--initial-approval-key <separate worker public key; requires admin inputs>]
//           --config enclave/confidential-config.json --out enclave/legal-identity-policy.json
//           Writes the canonical policy bytes and pins their digest (and, with the
//           admin inputs, the measured onboarding administration policy) in the config.
//   verify  --config enclave/confidential-config.json --policy enclave/legal-identity-policy.json
//           Exits 0 when the pin is null (firm operations disabled) or the policy
//           file's sha256 equals the pin. CI runs this before publishing.
//   onboarding-keygen --out-key <encrypted key file> --out-public <onboarding-public.asc>
//           Creates the onboarding authority key that signs legal-organization
//           registrations and invitations at /legal/administration. Writes the
//           encrypted key file (the same vera-firm-key-export/v1 format the page
//           imports) and the armored public key that `pin --onboarding-key` embeds
//           in the measured configuration. Prints the recovery code once, on
//           stdout only; it is never written to disk. Refuses to overwrite files.
//
// The canonical encoding must stay identical to legalIdentityPolicyDigest in
// enclave/src/cases/measuredConfiguration.ts: compact UTF-8 JSON in the field
// order {issuer, audience, clientId, jwks}. Public keys only. No network access.
const fs = require('node:fs');
const { createHash, webcrypto } = require('node:crypto');

const MAX_KEYS = 8;
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

function fail(message) { throw new Error(`legal identity: ${message}`); }
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  const known = ['auth0-output', 'jwks', 'jwks-witness', 'admin-output', 'onboarding-key', 'initial-approval-key', 'config', 'out', 'policy', 'out-key', 'out-public'];
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index], value = rest[index + 1];
    if (typeof flag !== 'string' || !flag.startsWith('--') || typeof value !== 'string' || !value) fail(`invalid argument ${flag}`);
    const name = flag.slice(2);
    if (!known.includes(name) || name in options) fail(`invalid argument ${flag}`);
    options[name] = value;
  }
  return { command, options };
}

function readJson(file, label) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fail(`${label} is not readable JSON`); }
}

/** Public RS256 signing keys only, projected to a fixed member order. */
function publicJwks(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.keys) || !value.keys.length) fail('JWKS has no keys');
  const keys = value.keys.filter(key => key && key.use === 'sig' && key.kty === 'RSA' && (key.alg === undefined || key.alg === 'RS256'));
  if (!keys.length || keys.length > MAX_KEYS) fail(`JWKS must contain 1-${MAX_KEYS} RS256 signing keys`);
  const ids = new Set();
  return { keys: keys.map(key => {
    if (PRIVATE_MEMBERS.some(member => key[member] !== undefined)) fail('JWKS contains private key material');
    if (typeof key.kid !== 'string' || !key.kid || key.kid.length > 256 || ids.has(key.kid)) fail('JWKS key IDs must be unique');
    if (typeof key.n !== 'string' || !/^[A-Za-z0-9_-]{300,1400}$/.test(key.n) || typeof key.e !== 'string' || !/^[A-Za-z0-9_-]{1,16}$/.test(key.e)) {
      fail('JWKS keys must be RSA public keys of at least 2048 bits');
    }
    ids.add(key.kid);
    return { kty: 'RSA', use: 'sig', alg: 'RS256', kid: key.kid, n: key.n, e: key.e };
  }) };
}

function identity(output, label) {
  if (!output || typeof output !== 'object') fail(`${label} missing`);
  const { issuer, audience, clientId } = output;
  let origin;
  try { origin = new URL(issuer); } catch { fail(`${label} issuer invalid`); }
  if (origin.protocol !== 'https:' || issuer !== `${origin.origin}/`) fail(`${label} issuer must be an https origin ending in /`);
  if (typeof audience !== 'string' || !audience || audience.length > 512) fail(`${label} audience invalid`);
  if (typeof clientId !== 'string' || !clientId || clientId.length > 128 || clientId === audience) fail(`${label} clientId invalid`);
  return { issuer, audience, clientId };
}

/** Exact bytes whose sha256 the enclave pins (legalIdentityPolicyDigest). */
function canonicalPolicy(policy) {
  return JSON.stringify({ issuer: policy.issuer, audience: policy.audience, clientId: policy.clientId, jwks: policy.jwks });
}

function pin(options) {
  for (const name of ['auth0-output', 'jwks', 'jwks-witness', 'config', 'out']) if (!options[name]) fail(`pin needs --${name}`);
  if (!!options['admin-output'] !== !!options['onboarding-key']) fail('--admin-output and --onboarding-key go together');
  if (options['initial-approval-key'] && !options['admin-output']) fail('--initial-approval-key requires --admin-output and --onboarding-key');
  const jwks = publicJwks(readJson(options.jwks, 'JWKS'));
  // Two fetches from independent networks must agree before a key is pinned.
  if (JSON.stringify(publicJwks(readJson(options['jwks-witness'], 'witness JWKS'))) !== JSON.stringify(jwks)) {
    fail('JWKS fetches from the two networks differ; do not pin');
  }
  const policy = { ...identity(readJson(options['auth0-output'], 'Auth0 output'), 'legal policy'), jwks };
  const bytes = canonicalPolicy(policy);
  const digest = sha256(bytes);
  const configText = fs.readFileSync(options.config, 'utf8');
  const config = JSON.parse(configText);
  if (config.format !== 'vera-confidential-configuration/v1') fail('not a confidential configuration file');
  config.legalIdentityPolicySha256 = digest;
  if (options['admin-output']) {
    const admin = readJson(options['admin-output'], 'admin output');
    const onboardingPublicKey = fs.readFileSync(options['onboarding-key'], 'utf8').trim();
    if (!onboardingPublicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') || onboardingPublicKey.includes('PRIVATE KEY') ||
        onboardingPublicKey.length > 16384) fail('onboarding key must be an armored OpenPGP public key');
    if (typeof admin.organizationId !== 'string' || !/^org_[a-zA-Z0-9]{1,64}$/.test(admin.organizationId)) fail('admin organizationId invalid');
    const adminIdentity = identity(admin, 'admin policy');
    if (adminIdentity.issuer !== policy.issuer) fail('admin and legal policies must share the issuer (same tenant JWKS)');
    config.legalAdministration = { identity: { ...adminIdentity, jwks }, organizationId: admin.organizationId, onboardingPublicKey };
    if (options['initial-approval-key']) {
      const initialApprovalPublicKey = fs.readFileSync(options['initial-approval-key'], 'utf8').trim();
      if (!initialApprovalPublicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') || initialApprovalPublicKey.includes('PRIVATE KEY') ||
          initialApprovalPublicKey.length > 16384 || initialApprovalPublicKey === onboardingPublicKey) fail('initial approval requires a separate public key');
      config.legalAdministration.initialApprovalPublicKey = initialApprovalPublicKey;
    }
  }
  fs.writeFileSync(options.out, bytes);
  fs.writeFileSync(options.config, `${JSON.stringify(config, null, 2)}\n`);
  return { legalIdentityPolicySha256: digest, keys: jwks.keys.map(key => key.kid), administration: !!options['admin-output'] };
}

function verify(options) {
  if (!options.config) fail('verify needs --config');
  const config = JSON.parse(fs.readFileSync(options.config, 'utf8'));
  const pinned = config.legalIdentityPolicySha256;
  if (pinned === null) return { legalIdentityPolicySha256: null, firmOperations: 'disabled' };
  if (typeof pinned !== 'string' || !/^[a-f0-9]{64}$/.test(pinned) || /^0+$/.test(pinned)) fail('pinned digest invalid');
  if (!options.policy || !fs.existsSync(options.policy)) fail('a pinned configuration needs its policy file');
  const bytes = fs.readFileSync(options.policy);
  if (sha256(bytes) !== pinned) fail('policy file does not match the pinned digest');
  const parsed = JSON.parse(bytes.toString('utf8'));
  if (Object.keys(parsed).join(',') !== 'issuer,audience,clientId,jwks' || canonicalPolicy(parsed) !== bytes.toString('utf8')) {
    fail('policy file is not in canonical form');
  }
  identity(parsed, 'policy');
  if (JSON.stringify(publicJwks(parsed.jwks)) !== JSON.stringify(parsed.jwks)) fail('policy JWKS is not the public projection');
  return { legalIdentityPolicySha256: pinned, firmOperations: 'enabled' };
}

// Onboarding authority key export. Must stay byte-compatible with
// exportFirmIdentity/importFirmIdentity in lib/confidential/firmKey.ts, which is
// what /legal/administration uses to open it (tests/unit/confidential/
// onboardingAuthorityKeygen.test.ts opens this output with that code).
const EXPORT_FORMAT = 'vera-firm-key-export/v1';
const PAYLOAD_FORMAT = 'vera-firm-key-export-payload/v1';
const KDF_ITERATIONS = 600_000;
const RECOVERY_PREFIX = 'VERA-FIRM-1.';
// Export metadata only: the authority is not a legal organization and its
// organization ID and domain are never registered or published.
const AUTHORITY_DOMAIN = 'onboarding-authority.invalid';
const base64url = bytes => Buffer.from(bytes).toString('base64url');

async function exportAuthorityKey(privateKey, recipientKeyId, organizationId, code) {
  const meta = { organizationId, domain: AUTHORITY_DOMAIN, recipientKeyId };
  const salt = webcrypto.getRandomValues(new Uint8Array(16)), nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const secret = new TextEncoder().encode(code.trim().normalize('NFC'));
  const material = await webcrypto.subtle.importKey('raw', secret, 'PBKDF2', false, ['deriveKey']);
  secret.fill(0);
  const key = await webcrypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: KDF_ITERATIONS },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const additionalData = new TextEncoder().encode(JSON.stringify({ format: EXPORT_FORMAT, ...meta }));
  const plaintext = new TextEncoder().encode(JSON.stringify({ format: PAYLOAD_FORMAT, ...meta, privateKey: privateKey.armor() }));
  let ciphertext;
  try {
    ciphertext = new Uint8Array(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, key, plaintext));
  } finally { plaintext.fill(0); }
  // Refuse to hand out an export this code cannot open again.
  const check = new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, key, ciphertext));
  const reopened = JSON.parse(new TextDecoder().decode(check));
  check.fill(0);
  if (reopened.privateKey !== privateKey.armor() || reopened.recipientKeyId !== recipientKeyId) fail('export self-check failed');
  const line = JSON.stringify({ format: EXPORT_FORMAT, ...meta, kdf: { name: 'PBKDF2-SHA256', iterations: KDF_ITERATIONS,
    salt: base64url(salt) }, nonce: base64url(nonce), ciphertext: base64url(ciphertext) });
  return [
    'VERA onboarding authority key — PRIVATE. DO NOT SHARE, EMAIL OR UPLOAD.',
    '',
    'This file holds the encrypted private key that authorizes legal-organization registrations',
    'and invitations at /legal/administration. With its recovery code anyone can admit a legal',
    'organization. It cannot read reports. Store it offline, separately from the recovery code.',
    'Replacing it needs a new measured release.',
    '',
    `Key ID: ${recipientKeyId}`,
    '',
    line,
    '',
  ].join('\n');
}

async function onboardingKeygen(options) {
  if (!options['out-key'] || !options['out-public']) fail('onboarding-keygen needs --out-key and --out-public');
  if (options['out-key'] === options['out-public']) fail('--out-key and --out-public must differ');
  for (const file of [options['out-key'], options['out-public']]) if (fs.existsSync(file)) fail(`${file} already exists; not overwriting`);
  const openpgp = require('openpgp');
  // Same curve and packet layout as generateFirmIdentity.
  const { privateKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'VERA onboarding authority' }], format: 'object' });
  const publicKey = privateKey.toPublic();
  const recipientKeyId = sha256(publicKey.write());
  const organizationId = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString('hex');
  const recoveryCode = RECOVERY_PREFIX + base64url(webcrypto.getRandomValues(new Uint8Array(32)));
  const file = await exportAuthorityKey(privateKey, recipientKeyId, organizationId, recoveryCode);
  fs.writeFileSync(options['out-key'], file, { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(options['out-public'], `${publicKey.armor().trim()}\n`, { flag: 'wx', mode: 0o644 });
  return { keyId: recipientKeyId, keyFile: options['out-key'], publicKey: options['out-public'], recoveryCode };
}

function main(argv) {
  const { command, options } = parseArgs(argv);
  const commands = { pin, verify, 'onboarding-keygen': onboardingKeygen };
  if (!Object.hasOwn(commands, command)) fail('usage: pin | verify | onboarding-keygen (see header)');
  return commands[command](options);
}

module.exports = { canonicalPolicy, publicJwks, parseArgs, main, sha256 };

if (require.main === module) {
  Promise.resolve().then(() => main(process.argv.slice(2))).then(result => {
    if (result && result.recoveryCode) {
      process.stdout.write([
        `Onboarding authority key ${result.keyId}`,
        `  encrypted key file: ${result.keyFile}`,
        `  public key (for pin --onboarding-key): ${result.publicKey}`,
        '',
        'Recovery code (shown once, not saved anywhere; write it down for its holder now):',
        `  ${result.recoveryCode}`,
        '',
      ].join('\n'));
    } else process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch(error => { process.stderr.write(`${error.message}\n`); process.exit(1); });
}
