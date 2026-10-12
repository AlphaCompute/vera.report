#!/usr/bin/env node
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { S3Client, CreateBucketCommand, GetObjectCommand, PutObjectCommand } = require('@aws-sdk/client-s3');
const compose = ['compose', '-f', path.join(__dirname, 'archive-compose.yml')];
function docker(args) {
  const result = spawnSync('docker', [...compose, ...args], { encoding: 'utf8', timeout: 120000 });
  if (result.status) throw new Error(result.stderr || 'Local container operation failed');
}
(async () => {
  docker(['up', '-d', '--wait', '--wait-timeout', '90']);
  process.env.NODE_ENV = 'test';
  process.env.IPFS_STORAGE_BACKEND = 'local-enclave';
  process.env.ENCLAVE_IPFS_URL = 'http://127.0.0.1:15012';
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'synthetic-ciphertext-archive';
  process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT = 'http://127.0.0.1:15466';
  process.env.AWS_REGION = 'us-east-2';
  const s3 = new S3Client({ region: 'us-east-2', endpoint: process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT,
    forcePathStyle: true, credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });
  await s3.send(new CreateBucketCommand({ Bucket: process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET, CreateBucketConfiguration: { LocationConstraint: 'us-east-2' } }));
  require('ts-node').register({ transpileOnly: true, compilerOptions: { rootDir: path.resolve(__dirname, '../..') } });
  const { EvidenceStorageService } = require('../../src/services/evidenceStorage.ts');
  const service = new EvidenceStorageService();
  const plaintext = crypto.randomBytes(1024), key = crypto.randomBytes(32).toString('hex');
  const stored = await service.uploadEncryptedFile(plaintext, 'private-synthetic-name.txt', 'synthetic-report', key);
  const object = { Bucket: process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET, Key: `ciphertext/v1/${stored.originalCID}` };
  const archived = await s3.send(new GetObjectCommand(object));
  assert(!Buffer.from(await archived.Body.transformToByteArray()).includes(plaintext));
  assert(!JSON.stringify(archived.Metadata || {}).includes(key));
  // Destroy the entire first Kubo instance and its ephemeral filesystem.
  docker(['rm', '-s', '-f', 'first']);
  process.env.ENCLAVE_IPFS_URL = 'http://127.0.0.1:15013';
  assert.deepEqual(await service.retrieveVaultCiphertext(stored.originalCID, key, stored.iv, stored.authTag, stored.salt), plaintext);
  await assert.rejects(service.retrieveVaultCiphertext(stored.originalCID, 'wrong-key', stored.iv, stored.authTag, stored.salt));
  // Remove replacement's ephemeral filesystem too, and corrupt the archive.
  docker(['rm', '-s', '-f', 'replacement']);
  docker(['up', '-d', '--wait', '--wait-timeout', '90', 'replacement']);
  await s3.send(new PutObjectCommand({ ...object, Body: Buffer.from('corrupted-ciphertext') }));
  await assert.rejects(service.readCiphertext(stored.originalCID), /CID mismatch/);
  process.env.NODE_ENV = 'production';
  // Production may never point the archive at a test endpoint.
  await assert.rejects(service.readCiphertext(stored.originalCID), /non-production/);
  s3.destroy();
  console.log('PASS: acknowledged ciphertext archive -> destroyed Kubo -> fresh Kubo restore -> authenticated decryption; corruption and production selection rejected.');
})().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => docker(['down', '-v']));
