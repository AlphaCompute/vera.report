#!/usr/bin/env node
'use strict';

// Emits the canonical confidential release manifest for one measured EIF.
//
// The canonical bytes come from the compiled enclave module itself
// (`canonicalReleaseManifest` / `readReleaseManifest`), so the file matches what
// the enclave (`verifySelfRelease`) and the owner's browser accept byte for byte.
// CI runs this script inside the exact measured enclave image with
// `--dist /app/dist`; local runs use `enclave/dist` after `npm --prefix enclave run build`.
//
// Every value is read from a local file produced by the build (no network):
//   sourceRepository/sourceCommit  <- --repository / --commit (GitHub context)
//   eifSha256, PCR0/1/2           <- measurements.json, re-hashed against --eif when given
//   imageSha256                   <- measurements.json docker_image_id (sha256:<hex>)
//   configurationSha256           <- sha256 of the measured /app/confidential-config.json bytes, which CI
//                                    reads back from the image and compares with the selected checked-in
//                                    file (enclave/confidential-config.json, or .staging.json for staging)
//   provenanceSha256              <- sha256 of the signed build-provenance bundle bytes
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const OPTIONS = ['dist', 'measurements', 'eif', 'configuration', 'provenance', 'repository', 'commit', 'out'];
const REQUIRED = OPTIONS.filter(name => name !== 'eif');
const MAX_PROVENANCE = 16 * 1024 * 1024;
const MAX_CONFIGURATION = 64 * 1024;

function fail(message) { throw new Error(`release manifest: ${message}`); }

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index], value = argv[index + 1];
    if (typeof flag !== 'string' || !flag.startsWith('--') || !OPTIONS.includes(flag.slice(2)) ||
        typeof value !== 'string' || !value || Object.hasOwn(options, flag.slice(2))) fail(`invalid argument ${flag}`);
    options[flag.slice(2)] = value;
  }
  for (const name of REQUIRED) if (!options[name]) fail(`missing --${name}`);
  return options;
}

function sha256File(file) {
  const hash = createHash('sha256');
  const descriptor = fs.openSync(file, 'r');
  try {
    const buffer = Buffer.alloc(1024 * 1024);
    for (let read; (read = fs.readSync(descriptor, buffer, 0, buffer.length, null)) > 0;) hash.update(buffer.subarray(0, read));
  } finally { fs.closeSync(descriptor); }
  return hash.digest('hex');
}

function hex(value, length, label) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length}}$`).test(value) || /^0+$/.test(value)) fail(`invalid ${label}`);
  return value;
}

function readMeasurements(file, commit) {
  const record = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!record || typeof record !== 'object' || Array.isArray(record)) fail('invalid measurements');
  if (record.commit !== commit) fail('measurements were produced for a different commit');
  // Nitro CLI 1.5 / sha2 0.10.8 prints Sha384's 48-byte core Debug name.
  if (!['Sha384', 'Sha384 { ... }', 'Sha512_48 { .. }'].includes(record.HashAlgorithm)) fail('unexpected measurement algorithm');
  const image = typeof record.docker_image_id === 'string' && /^sha256:([0-9a-f]{64})$/.exec(record.docker_image_id);
  if (!image) fail('invalid docker_image_id');
  return {
    eifSha256: hex(record.eif_sha256, 64, 'eif_sha256'),
    imageSha256: hex(image[1], 64, 'docker_image_id'),
    pcr0: hex(record.PCR0, 96, 'PCR0'), pcr1: hex(record.PCR1, 96, 'PCR1'), pcr2: hex(record.PCR2, 96, 'PCR2'),
  };
}

/** Public service description only. Refuse anything that looks like key material. */
function readConfiguration(file) {
  const bytes = fs.readFileSync(file);
  if (!bytes.length || bytes.length > MAX_CONFIGURATION) fail('invalid configuration size');
  const configuration = JSON.parse(bytes.toString('utf8'));
  if (configuration?.format !== 'vera-confidential-configuration/v1' ||
      configuration.protocolVersion !== 'vera-confidential-channel/v1' ||
      configuration.dataFormatVersion !== 'vera-confidential-case/v1') fail('configuration does not describe this protocol');
  const pin = configuration.legalIdentityPolicySha256;
  if (pin !== null && (typeof pin !== 'string' || !/^[a-f0-9]{64}$/.test(pin) || /^0+$/.test(pin))) {
    fail('configuration requires a legal identity policy pin or explicit null');
  }
  const admin = configuration.legalAdministration;
  if (admin !== undefined && admin !== null) {
    const identity = admin.identity;
    if (!['identity,onboardingPublicKey,organizationId', 'identity,initialApprovalPublicKey,onboardingPublicKey,organizationId'].includes(Object.keys(admin).sort().join(',')) || !/^org_[a-zA-Z0-9]{1,64}$/.test(admin.organizationId) ||
        typeof admin.onboardingPublicKey !== 'string' || admin.onboardingPublicKey.length > 16384 ||
        !admin.onboardingPublicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') || admin.onboardingPublicKey.includes('PRIVATE KEY') ||
        !identity || Object.keys(identity).sort().join(',') !== 'audience,clientId,issuer,jwks' ||
        typeof identity.issuer !== 'string' || !identity.issuer.startsWith('https://') ||
        typeof identity.audience !== 'string' || typeof identity.clientId !== 'string' ||
        !identity.jwks || Object.keys(identity.jwks).join(',') !== 'keys' || !Array.isArray(identity.jwks.keys) ||
        !identity.jwks.keys.length || identity.jwks.keys.length > 8 || identity.jwks.keys.some(key =>
          !key || Object.keys(key).some(field => !['kty','kid','alg','use','n','e'].includes(field)) ||
          key.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig' ||
          !['kid','n','e'].every(field => typeof key[field] === 'string' && key[field].length > 0 && key[field].length <= 4096))) {
      fail('administration requires public RSA verification keys only');
    }
    if (admin.initialApprovalPublicKey !== undefined && (typeof admin.initialApprovalPublicKey !== 'string' ||
        admin.initialApprovalPublicKey.length > 16384 || !admin.initialApprovalPublicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') ||
        admin.initialApprovalPublicKey.includes('PRIVATE KEY') || admin.initialApprovalPublicKey === admin.onboardingPublicKey)) {
      fail('initial approval requires a separate public key');
    }
  }
  const withdrawal = configuration.releaseWithdrawal;
  if (withdrawal !== undefined && withdrawal !== null && (typeof withdrawal !== 'object' || Array.isArray(withdrawal) ||
      Object.keys(withdrawal).join(',') !== 'publicKey' || typeof withdrawal.publicKey !== 'string' ||
      withdrawal.publicKey.length > 16384 || !withdrawal.publicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') ||
      withdrawal.publicKey.includes('PRIVATE KEY'))) {
    fail('releaseWithdrawal requires only a public OpenPGP verification key');
  }
  // Optional Roughtime servers (enclave/src/cases/measuredConfiguration.ts
  // parseRoughtimePolicy is the enclave's check): public Ed25519 keys only.
  const roughtime = configuration.roughtime;
  if (roughtime !== undefined && roughtime !== null) {
    const servers = roughtime?.servers;
    const port = address => Number(address.slice(address.lastIndexOf(':') + 1));
    if (typeof roughtime !== 'object' || Array.isArray(roughtime) || Object.keys(roughtime).sort().join(',') !== 'quorum,servers,toleranceMs' ||
        !Array.isArray(servers) || !servers.length || servers.length > 8 || servers.some(server =>
          !server || typeof server !== 'object' || Object.keys(server).sort().join(',') !== 'address,name,publicKey' ||
          typeof server.name !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(server.name) ||
          typeof server.address !== 'string' || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?:\d{1,5}$/.test(server.address) ||
          port(server.address) < 1 || port(server.address) > 65535 ||
          typeof server.publicKey !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(server.publicKey) ||
          Buffer.from(server.publicKey, 'base64').length !== 32 ||
          Buffer.from(server.publicKey, 'base64').toString('base64') !== server.publicKey) ||
        new Set(servers.map(server => server.name)).size !== servers.length ||
        new Set(servers.map(server => Buffer.from(server.publicKey, 'base64').toString('hex'))).size !== servers.length ||
        !Number.isSafeInteger(roughtime.quorum) || roughtime.quorum < 1 || roughtime.quorum > servers.length ||
        !Number.isSafeInteger(roughtime.toleranceMs) || roughtime.toleranceMs < 1000 || roughtime.toleranceMs > 600000) {
      fail('roughtime requires 1-8 servers with public Ed25519 keys, a quorum and a tolerance');
    }
  }
  const { legalIdentityPolicySha256: _publicDigest, legalAdministration: _publicAdmin, releaseWithdrawal: _publicWithdrawal,
    roughtime: _publicRoughtime, ...description } = configuration;
  const strings = [];
  (function collect(value) {
    if (typeof value === 'string') strings.push(value);
    else if (value && typeof value === 'object') for (const item of Object.values(value)) collect(item);
  })(description);
  if (strings.some(value => /-----BEGIN |\bAKIA[0-9A-Z]{16}\b|^[A-Za-z0-9+/_-]{40,}={0,2}$|^[0-9a-f]{64,}$/i.test(value))) {
    fail('configuration must not contain key material or credentials');
  }
  return createHash('sha256').update(bytes).digest('hex');
}

/** The signed provenance bundle from actions/attest (Sigstore bundle JSON or JSON lines). */
function readProvenance(file) {
  const stat = fs.statSync(file);
  if (!stat.isFile() || !stat.size || stat.size > MAX_PROVENANCE) fail('invalid provenance bundle size');
  const text = fs.readFileSync(file, 'utf8');
  let documents;
  try { documents = [JSON.parse(text)]; } catch {
    documents = text.split('\n').filter(line => line.trim()).map(line => JSON.parse(line));
  }
  if (!documents.length || !documents.every(document => typeof document?.mediaType === 'string' &&
      document.mediaType.startsWith('application/vnd.dev.sigstore.bundle'))) fail('provenance is not a Sigstore bundle');
  return sha256File(file);
}

async function generate(options) {
  const dist = path.resolve(options.dist);
  const { canonicalReleaseManifest, readReleaseManifest } = require(path.join(dist, 'confidential/releaseManifest.js'));
  const measured = readMeasurements(options.measurements, options.commit);
  if (options.eif && sha256File(options.eif) !== measured.eifSha256) fail('EIF bytes do not match measurements.json');
  const manifest = {
    format: 'vera-confidential-release/v1',
    sourceRepository: options.repository,
    sourceCommit: hex(options.commit, 40, 'commit'),
    eifSha256: measured.eifSha256,
    imageSha256: measured.imageSha256,
    configurationSha256: readConfiguration(options.configuration),
    provenanceSha256: readProvenance(options.provenance),
    protocolVersion: 'vera-confidential-channel/v1',
    dataFormatVersion: 'vera-confidential-case/v1',
    measurements: { pcr0: measured.pcr0, pcr1: measured.pcr1, pcr2: measured.pcr2 },
  };
  const canonical = canonicalReleaseManifest(manifest);
  // Round-trip through the strict reader the enclave and browser use.
  const { digest } = await readReleaseManifest(canonical);
  if (digest !== createHash('sha256').update(canonical, 'utf8').digest('hex')) fail('digest mismatch');
  fs.writeFileSync(options.out, canonical, { flag: 'wx', mode: 0o644 });
  fs.writeFileSync(`${options.out}.sha256`, `${digest}  ${path.basename(options.out)}\n`, { flag: 'wx', mode: 0o644 });
  return { digest, canonical };
}

async function main(argv) {
  const { digest } = await generate(parseArgs(argv));
  process.stdout.write(`${JSON.stringify({ manifestSha256: digest })}\n`);
}

module.exports = { generate, parseArgs, readConfiguration };

if (require.main === module) {
  main(process.argv.slice(2)).catch(error => { process.stderr.write(`${error.message}\n`); process.exit(1); });
}
