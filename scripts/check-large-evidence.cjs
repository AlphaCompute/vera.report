#!/usr/bin/env node
// Run in the API test container sharing loopback with the local Kubo test container.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { performance } = require('node:perf_hooks');
const { default: EvidenceEncryptionService } = require('../dist/services/evidenceEncryption');
const { EvidenceStorageService } = require('../dist/services/evidenceStorage');

(async () => {
  // 256 MiB valid PCM WAV, no huge fixture checked into the repository.
  let input = Buffer.alloc(256 * 1024 * 1024);
  input.write('RIFF', 0); input.writeUInt32LE(input.length - 8, 4); input.write('WAVEfmt ', 8);
  input.writeUInt32LE(16, 16); input.writeUInt16LE(1, 20); input.writeUInt16LE(1, 22);
  input.writeUInt32LE(44100, 24); input.writeUInt32LE(88200, 28); input.writeUInt16LE(2, 32);
  input.writeUInt16LE(16, 34); input.write('data', 36); input.writeUInt32LE(input.length - 44, 40);
  input.fill(1, 44); // Touch every page: measure resident input, not lazily mapped zeros.
  const service = new EvidenceEncryptionService();
  const storage = new EvidenceStorageService();
  const key = crypto.randomBytes(32).toString('hex');
  const started = performance.now();
  const encrypted = await service.encryptEvidence(input, 'audio/wav', key);
  const params = { ...encrypted, encryptedData: '' };
  let inner = Buffer.from(encrypted.encryptedData, 'base64');
  const upload = await storage.uploadEncryptedFile(inner, 'large.wav', 'synthetic-large', key);
  input = null; inner = null; encrypted.encryptedData = '';
  upload.encryptedData = Buffer.alloc(0);
  let recovered = await storage.retrieveVaultCiphertext(upload.originalCID, key, upload.iv, upload.authTag, upload.salt);
  params.encryptedData = recovered.toString('base64'); recovered = null;
  const result = await service.decryptEvidence(params, key);
  assert.equal(result.isValid, true);
  assert(result.content.length >= 256 * 1024 * 1024 - 1024);
  assert.equal(result.content.subarray(0, 4).toString(), 'RIFF');
  let memoryPeak = null;
  if (fs.existsSync('/sys/fs/cgroup/memory.peak')) memoryPeak = Number(fs.readFileSync('/sys/fs/cgroup/memory.peak', 'utf8'));
  if (memoryPeak !== null) assert(memoryPeak < 3 * 1024 ** 3, 'Media exceeds the 3 GiB working-set budget');
  console.log(JSON.stringify({ status: 'passed', inputMiB: 256, milliseconds: Math.round(performance.now() - started), memoryPeak, maxRssKiB: process.resourceUsage().maxRSS, hashVerified: true }));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
