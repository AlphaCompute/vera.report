#!/usr/bin/env node
// Runs the API task's Kubo sidecar image in sidecar mode with a local S3 archive:
// add, cat, restore from S3 on a fresh node, consent-withdrawal removal (Kubo and
// every archive version), and both ECS network modes. Synthetic data only.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const {
  S3Client, CreateBucketCommand, PutBucketVersioningCommand, GetObjectCommand, PutObjectCommand, ListObjectVersionsCommand,
} = require('@aws-sdk/client-s3');
const compose = ['compose', '-f', path.join(__dirname, 'sidecar-compose.yml')];
const IMAGE = 'vera-ipfs:local';
function docker(args, { allowFailure = false } = {}) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 600000 });
  if (result.status && !allowFailure) throw new Error(result.stderr || 'Local container operation failed');
  return result;
}
const probe = source => ['--entrypoint', 'node', IMAGE, '-e', source];
let loopbackContainer;
(async () => {
  docker([...compose, 'up', '-d', '--build', '--wait', '--wait-timeout', '120']);

  // Kubo runs offline with no routing, providing, peers, gateway or remote config.
  const config = JSON.parse(docker([...compose, 'exec', '-T', 'ipfs', 'ipfs', 'config', 'show']).stdout);
  assert.equal(config.Addresses.API, '/ip4/127.0.0.1/tcp/5001');
  assert.deepEqual([config.Addresses.Gateway, config.Addresses.Swarm, config.Bootstrap], [[], [], []]);
  assert.equal(config.Routing.Type, 'none');
  assert.equal(config.Provide.Enabled, false);
  assert.equal(config.AutoConf.Enabled, false);
  assert(!JSON.stringify(config).includes('"auto"'));
  assert.equal(docker([...compose, 'exec', '-T', 'ipfs', 'id', '-u']).stdout.trim(), '1000');

  // Bridge mode: the API reaches the proxy through the `ipfs` link name, never Kubo itself.
  const network = 'vera-ipfs-sidecar-review_default';
  const bridge = docker(['run', '--rm', '--network', network, ...probe(
    `Promise.all([fetch('http://ipfs:15002/healthz').then(r=>r.status),` +
    `fetch('http://ipfs:5001/api/v0/version',{method:'POST'}).then(r=>r.status,e=>e.cause?.code)]).then(r=>console.log(JSON.stringify(r)))`)]).stdout.trim();
  assert.deepEqual(JSON.parse(bridge), [204, 'ECONNREFUSED']);

  // Shared-namespace (Fargate awsvpc) mode: default bind is loopback only.
  loopbackContainer = docker(['run', '-d', '--read-only', '--tmpfs', '/data/ipfs:uid=1000,gid=1000,mode=0700', '--tmpfs', '/tmp', IMAGE]).stdout.trim();
  let healthy = false;
  for (let i = 0; i < 40 && !healthy; i++) {
    healthy = docker(['inspect', '--format', '{{.State.Health.Status}}', loopbackContainer]).stdout.trim() === 'healthy';
    if (!healthy) await new Promise(resolve => setTimeout(resolve, 1000));
  }
  assert(healthy, 'loopback sidecar never became healthy');
  const shared = docker(['run', '--rm', '--network', `container:${loopbackContainer}`, ...probe(
    `const ip=Object.values(require('os').networkInterfaces()).flat().find(a=>a.family==='IPv4'&&!a.internal).address;` +
    `Promise.all([fetch('http://127.0.0.1:15002/healthz').then(r=>r.status),` +
    `fetch('http://'+ip+':15002/healthz').then(r=>r.status,e=>e.cause?.code)]).then(r=>console.log(JSON.stringify(r)))`)]).stdout.trim();
  assert.deepEqual(JSON.parse(shared), [204, 'ECONNREFUSED']);
  docker(['rm', '-f', loopbackContainer]); loopbackContainer = undefined;

  process.env.NODE_ENV = 'test';
  process.env.IPFS_STORAGE_BACKEND = 'local-enclave';
  process.env.ENCLAVE_IPFS_URL = 'http://127.0.0.1:15022';
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'synthetic-sidecar-archive';
  process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT = 'http://127.0.0.1:15476';
  process.env.AWS_REGION = 'us-east-2';
  const s3 = new S3Client({ region: 'us-east-2', endpoint: process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT,
    forcePathStyle: true, credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });
  const Bucket = process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET;
  await s3.send(new CreateBucketCommand({ Bucket, CreateBucketConfiguration: { LocationConstraint: 'us-east-2' } }));
  await s3.send(new PutBucketVersioningCommand({ Bucket, VersioningConfiguration: { Status: 'Enabled' } }));
  require('ts-node').register({ transpileOnly: true, compilerOptions: { rootDir: path.resolve(__dirname, '../..') } });
  const { EvidenceStorageService } = require('../../src/services/evidenceStorage.ts');
  const service = new EvidenceStorageService();

  // add + cat through the application.
  const plaintext = crypto.randomBytes(300 * 1024), key = crypto.randomBytes(32).toString('hex');
  const stored = await service.uploadEncryptedFile(plaintext, 'private-synthetic-name.txt', 'synthetic-report', key);
  assert.match(stored.originalCID, /^Qm/);
  const ciphertext = await service.readCiphertext(stored.originalCID);
  assert(!ciphertext.includes(plaintext.subarray(0, 64)));
  assert.deepEqual(await service.retrieveVaultCiphertext(stored.originalCID, key, stored.iv, stored.authTag, stored.salt), plaintext);
  const object = { Bucket, Key: `ciphertext/v1/${stored.originalCID}` };
  assert.deepEqual(Buffer.from(await (await s3.send(new GetObjectCommand(object))).Body.transformToByteArray()), ciphertext);
  for (const route of ['/api/v0/config', '/api/v0/pin/rm', '/api/v0/repo/gc', '/shutdown', '/unpin']) {
    assert.equal((await fetch(process.env.ENCLAVE_IPFS_URL + route, { method: 'POST' })).status, 404);
  }
  assert.equal((await fetch(process.env.ENCLAVE_IPFS_URL + '/rm', { method: 'POST', body: '../../config' })).status, 400);

  // S3 fallback: destroy the node and its storage, then read through a fresh one.
  docker([...compose, 'rm', '-s', '-f', 'ipfs']);
  process.env.ENCLAVE_IPFS_URL = 'http://127.0.0.1:15023';
  assert.deepEqual(await service.retrieveVaultCiphertext(stored.originalCID, key, stored.iv, stored.authTag, stored.salt), plaintext);
  assert.deepEqual(await service.readCiphertext(stored.originalCID), ciphertext);

  // Consent withdrawal: a second archive version plus the restored Kubo pin must all go.
  await s3.send(new PutObjectCommand({ ...object, Body: ciphertext }));
  const versions = async () => {
    const listed = await s3.send(new ListObjectVersionsCommand({ Bucket, Prefix: object.Key }));
    return [...(listed.Versions || []), ...(listed.DeleteMarkers || [])].filter(v => v.Key === object.Key);
  };
  assert.equal((await versions()).length, 2);
  await service.unpin(stored.originalCID);
  assert.deepEqual(await versions(), []);
  assert.equal((await fetch(process.env.ENCLAVE_IPFS_URL + '/cat', { method: 'POST', body: stored.originalCID })).status, 502);
  await assert.rejects(service.readCiphertext(stored.originalCID));
  await service.unpin(stored.originalCID);

  // Production refuses the test archive endpoint; the real bucket path is covered by unit tests.
  process.env.NODE_ENV = 'production';
  await assert.rejects(service.readCiphertext(stored.originalCID), /non-production/);
  s3.destroy();
  console.log('PASS: sidecar add/cat -> destroyed node -> S3 restore -> unpin removes Kubo blocks and every archive version; bridge link and loopback binds verified; Kubo API unreachable.');
})().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => {
  if (loopbackContainer) docker(['rm', '-f', loopbackContainer], { allowFailure: true });
  docker([...compose, 'down', '-v'], { allowFailure: true });
});
