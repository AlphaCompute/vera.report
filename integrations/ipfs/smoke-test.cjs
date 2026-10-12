#!/usr/bin/env node
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const compose = ['compose', '-f', path.join(__dirname, 'docker-compose.yml')];
function docker(args) {
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: 120000 });
  if (r.status !== 0) throw new Error(r.stderr || 'Docker operation failed');
  return r.stdout;
}
(async () => {
  docker([...compose, 'up', '-d', '--wait', '--wait-timeout', '90']);
  process.env.NODE_ENV = 'test';
  process.env.IPFS_STORAGE_BACKEND = 'local-enclave';
  process.env.ENCLAVE_IPFS_URL = 'http://127.0.0.1:15002';
  require('ts-node').register({ transpileOnly: true, compilerOptions: { rootDir: path.resolve(__dirname, '../..') } });
  const { EvidenceStorageService } = require('../../src/services/evidenceStorage.ts');
  const service = new EvidenceStorageService();
  const original = Buffer.from('synthetic-only-evidence-' + crypto.randomBytes(24).toString('hex'));
  const key = crypto.randomBytes(32).toString('hex');
  const uploaded = await service.uploadEncryptedFile(original, 'private-name.txt', 'synthetic', key);
  const stored = await service.readCiphertext(uploaded.originalCID);
  assert(!stored.includes(original), 'Plaintext leaked into stored bytes');
  assert.deepEqual(await service.retrieveVaultCiphertext(uploaded.originalCID, key, uploaded.iv, uploaded.authTag, uploaded.salt), original);
  await assert.rejects(service.retrieveVaultCiphertext(uploaded.originalCID, 'wrong-key', uploaded.iv, uploaded.authTag, uploaded.salt));
  const before = uploaded.originalCID;
  docker([...compose, 'restart', 'enclave']);
  docker([...compose, 'up', '-d', '--wait', '--wait-timeout', '90']);
  assert.deepEqual(await service.retrieveVaultCiphertext(before, key, uploaded.iv, uploaded.authTag, uploaded.salt), original);
  for (const endpoint of ['/api/v0/config', '/shutdown', '/unpin']) {
    const r = await fetch(process.env.ENCLAVE_IPFS_URL + endpoint, { method: 'POST' });
    assert.equal(r.status, 404);
  }
  const bad = await fetch(process.env.ENCLAVE_IPFS_URL + '/cat', { method: 'POST', body: '../../config' });
  assert.equal(bad.status, 400);
  await assert.rejects(service.readCiphertext('http://example.com/private'));
  const id = docker([...compose, 'ps', '-q', 'enclave']).trim();
  const inspect = JSON.parse(docker(['inspect', id]))[0];
  assert.deepEqual(Object.keys(inspect.HostConfig.PortBindings), ['5002/tcp']);
  assert.equal(inspect.HostConfig.PortBindings['5002/tcp'][0].HostIp, '127.0.0.1');
  process.env.NODE_ENV = 'production';
  // Without the S3 archive this disposable node cannot be selected in production.
  await assert.rejects(service.readCiphertext(before), /requires the ciphertext archive/);
  console.log('PASS: real application encryption -> co-located Kubo -> restart -> authenticated decryption; administrative routes blocked; production activation rejected.');
  console.log('Local Docker volume persistence is not Nitro durability or attestation. Synthetic data only; local container remains running.');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
