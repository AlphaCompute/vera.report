'use strict';

const crypto = require('node:crypto');
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function validateState(state, check) {
  check(state.version === 2 && state.storageLayer === 'application' && state.accepted === true,
    'Private state is not an accepted application probe; use a separate directory for adapter probes.');
  check(/^[a-f0-9]{64}$/.test(state.key) && /^[a-f0-9]{64}$/.test(state.plaintextSha256) &&
    /^[a-f0-9]{64}$/.test(state.ciphertextSha256), 'Invalid application key or expected digest.');
  check(['iv', 'tag', 'salt'].every(field => typeof state[field] === 'string' &&
    /^[A-Za-z0-9+/]{22}==$/.test(state[field]) && Buffer.from(state[field], 'base64').length === 16),
  'Invalid application encryption metadata.');
  check(Number.isInteger(state.sizeBytes) && state.sizeBytes >= 1024 && state.sizeBytes <= 256 * 1024 * 1024,
    'Invalid application probe size.');
}

function load() {
  // The parent has registered TypeScript and selected the isolated local backend.
  const { EvidenceStorageService } = require('../../../src/services/evidenceStorage.ts');
  const { retrieveArchivedCiphertext } = require('../../../src/services/ciphertextArchive.ts');
  const service = new EvidenceStorageService();
  return {
    async store(size, context, check) {
      const plaintext = crypto.randomBytes(size);
      const key = crypto.randomBytes(32).toString('hex');
      const probeId = crypto.randomUUID();
      try {
        const plaintextSha256 = digest(plaintext);
        const result = await service.uploadEncryptedFile(plaintext, 'hardware-probe.bin', `hardware-probe-${probeId}`, key);
        check(result.encryptedData.length === size && digest(result.encryptedData) !== plaintextSha256,
          'Application did not return ciphertext of the expected size.');
        const state = { version: 2, storageLayer: 'application', accepted: true, probeId, key,
          iv: result.iv, tag: result.authTag, salt: result.salt, cid: result.originalCID,
          plaintextSha256, ciphertextSha256: digest(result.encryptedData), sizeBytes: size, ...context };
        validateState(state, check);
        return state;
      } finally { plaintext.fill(0); }
    },
    async verify(state, checks, check) {
      // This vault-read call must itself drive archive recovery on an empty enclave.
      const recovered = await service.retrieveVaultCiphertext(state.cid, state.key, state.iv, state.tag, state.salt);
      try {
        check(recovered.length === state.sizeBytes && digest(recovered) === state.plaintextSha256,
          'Application authenticated decryption mismatch.');
      } finally { recovered.fill(0); }
      checks.applicationVaultRead = true;
      checks.authenticatedRecovery = true;
      const ciphertext = await service.readCiphertext(state.cid);
      check(digest(ciphertext) === state.ciphertextSha256, 'Application ciphertext digest mismatch.');
      checks.ciphertextDigestMatches = true;
      const archived = await retrieveArchivedCiphertext(state.cid);
      check(digest(archived) === state.ciphertextSha256, 'Actual S3 archive differs from application ciphertext.');
      checks.realArchiveCiphertextMatches = true;
      async function rejects(operation, expected, message) {
        let rejection;
        try { const unexpected = await operation(); unexpected?.fill?.(0); } catch (error) { rejection = error; }
        check(expected.test(rejection?.message || ''), message);
      }
      await rejects(() => service.retrieveVaultCiphertext(state.cid, crypto.randomBytes(32).toString('hex'), state.iv, state.tag, state.salt),
        /unable to authenticate data/i, 'Application did not reject the wrong key with an authentication error.');
      checks.wrongKeyRejected = true;
      const alteredTag = Buffer.from(state.tag, 'base64'); alteredTag[0] ^= 1;
      await rejects(() => service.retrieveVaultCiphertext(state.cid, state.key, state.iv, alteredTag.toString('base64'), state.salt),
        /unable to authenticate data/i, 'Application did not reject the altered tag with an authentication error.');
      checks.alteredTagRejected = true;
      check(typeof service.pinJSON === 'undefined', 'Storage service exposes an unencrypted JSON upload.');
      checks.plaintextJsonRejected = true;
      // Verify the actual guard without changing deployment configuration:
      // production never selects the disposable node without the S3 archive.
      const bucket = process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET;
      process.env.NODE_ENV = 'production';
      delete process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET;
      try {
        let guardError;
        try { await service.readCiphertext(state.cid); } catch (error) { guardError = error; }
        check(guardError?.message === 'Local IPFS in production requires the ciphertext archive',
          'The production activation guard did not reject the application read without the archive.');
      } finally {
        process.env.NODE_ENV = 'test';
        if (bucket === undefined) delete process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET;
        else process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = bucket;
      }
      checks.productionGuardRetained = true;
    },
  };
}

module.exports = { load, validateState };
