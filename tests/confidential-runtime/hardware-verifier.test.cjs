'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
// Refuse to run against an enclave/dist older than enclave/src.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const fs = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { createHash } = require('node:crypto');
const { main } = require('../../scripts/security/verify-confidential-hardware.cjs');
const { canonicalReleaseManifest } = require('../../enclave/dist/confidential/releaseManifest.js');

async function fixture(run) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'vera-hardware-check-'));
  const manifest = canonicalReleaseManifest({ format: 'vera-confidential-release/v1', sourceRepository: 'https://github.com/example/vera',
    sourceCommit: '1'.repeat(40), eifSha256: '2'.repeat(64), imageSha256: '3'.repeat(64), configurationSha256: '4'.repeat(64),
    provenanceSha256: '5'.repeat(64), protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
    measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
  const manifestPath = join(directory, 'manifest.json'), contextPath = join(directory, 'challenge.json'), responsePath = join(directory, 'response.json');
  await fs.writeFile(manifestPath, manifest);
  const digest = createHash('sha256').update(manifest).digest('hex');
  try { await run({ directory, manifestPath, contextPath, responsePath, digest }); }
  finally { await fs.rm(directory, { recursive: true, force: true }); }
}

test('hardware challenge pins reviewed canonical manifest, expires and refuses overwrite', async () => fixture(async f => {
  await assert.rejects(main(['prepare', f.manifestPath, '9'.repeat(64), f.contextPath]));
  const challenge = await main(['prepare', f.manifestPath, f.digest, f.contextPath]);
  assert.match(challenge.nonce, /^[a-f0-9]{64}$/);
  const context = JSON.parse(await fs.readFile(f.contextPath, 'utf8'));
  assert.equal(context.expiresAt - context.createdAt, 60000);
  assert.equal(context.manifestDigest, f.digest);
  assert.equal((await fs.stat(f.contextPath)).mode & 0o777, 0o600);
  await assert.rejects(main(['prepare', f.manifestPath, f.digest, f.contextPath]));
}));

test('invalid quote consumes one challenge and cannot produce a success receipt', async () => fixture(async f => {
  const challenge = await main(['prepare', f.manifestPath, f.digest, f.contextPath]);
  await fs.writeFile(f.responsePath, JSON.stringify({ nonce: challenge.nonce, document: 'AQ==', publicKey: 'AQ==' }));
  await assert.rejects(main(['verify', f.contextPath, f.responsePath]));
  await fs.stat(`${f.contextPath}.consumed`);
  await assert.rejects(main(['verify', f.contextPath, f.responsePath]), { code: 'EEXIST' });
}));

test('expired challenge and unrecognized command cannot be used as offline acceptance', async () => fixture(async f => {
  await main(['prepare', f.manifestPath, f.digest, f.contextPath]);
  const context = JSON.parse(await fs.readFile(f.contextPath, 'utf8'));
  context.createdAt -= 120000; context.expiresAt -= 120000;
  await fs.writeFile(f.contextPath, JSON.stringify(context));
  await assert.rejects(main(['verify', f.contextPath, f.responsePath]));
  await fs.stat(`${f.contextPath}.consumed`);
  await assert.rejects(main(['verify', f.contextPath, f.responsePath, '--allow-synthetic-root']));
}));

test('a correctly signed synthetic chain is rejected even with matching challenge and measurements', async () => fixture(async f => {
  const evidence = require('./attestation-fixture.cjs').createPkiFixture();
  await main(['prepare', f.manifestPath, f.digest, f.contextPath]);
  const context = JSON.parse(await fs.readFile(f.contextPath, 'utf8'));
  // TEST ONLY: align the local context to the independently signed fixture.
  // Production prepare never accepts a supplied nonce.
  context.nonce = evidence.nonce.toString('hex');
  const manifest = JSON.parse(context.manifest);
  for (const [index, value] of evidence.expectedPcrs) manifest.measurements[`pcr${index}`] = value.toString('hex');
  context.manifest = canonicalReleaseManifest(manifest);
  context.manifestDigest = createHash('sha256').update(context.manifest).digest('hex');
  await fs.writeFile(f.contextPath, JSON.stringify(context));
  await fs.writeFile(f.responsePath, JSON.stringify({ nonce: context.nonce,
    document: evidence.document.toString('base64'), publicKey: evidence.publicKey.toString('base64') }));
  await assert.rejects(main(['verify', f.contextPath, f.responsePath]), /Application channel attestation verification failed/);
}));
