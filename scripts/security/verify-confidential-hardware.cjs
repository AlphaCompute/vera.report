#!/usr/bin/env node
'use strict';

// Operator-side quote acceptance, using the same fixed-root verifier as the
// browser. No AWS mutations, network calls, case keys or private case data.
const fs = require('node:fs/promises');
const { randomBytes, createHash } = require('node:crypto');
const { readReleaseManifest } = require('../../enclave/dist/confidential/releaseManifest.js');
const { verifyApplicationAttestation } = require('../../enclave/dist/confidential/attestation.js');
const { readKey } = require('../../enclave/dist/confidential/pgp.js');
const { caseRecipientKeyId } = require('../../enclave/dist/confidential/caseObject.js');
const FORMAT = 'vera-hardware-challenge/v1';

async function bounded(path, max) {
  const file = await fs.open(path, 'r');
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > max) throw new Error();
    const bytes = Buffer.alloc(max + 1);
    const { bytesRead } = await file.read(bytes, 0, max + 1, 0);
    if (bytesRead > max) throw new Error();
    return bytes.subarray(0, bytesRead).toString('utf8');
  } finally { await file.close(); }
}
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== fields) throw new Error();
}
function decode(value, max) {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4) throw new Error();
  const bytes = Buffer.from(value, 'base64');
  if (!bytes.length || bytes.length > max || bytes.toString('base64') !== value) throw new Error();
  return new Uint8Array(bytes);
}

async function main(args) {
  if (args[0] === 'prepare' && args.length === 4) {
    const [, manifestPath, expectedDigest, contextPath] = args;
    const manifestWire = await bounded(manifestPath, 8192);
    const release = await readReleaseManifest(manifestWire);
    if (release.digest !== expectedDigest) throw new Error();
    const createdAt = Date.now(), nonce = randomBytes(32).toString('hex');
    const context = { format: FORMAT, nonce, createdAt, expiresAt: createdAt + 60000,
      manifest: manifestWire, manifestDigest: release.digest };
    await fs.writeFile(contextPath, JSON.stringify(context), { flag: 'wx', mode: 0o600 });
    return { nonce, expiresAt: context.expiresAt, manifestDigest: release.digest };
  }
  if (args[0] === 'verify' && args.length === 3) {
    const [, contextPath, responsePath] = args;
    const contextWire = await bounded(contextPath, 12288), context = JSON.parse(contextWire);
    exact(context, 'createdAt,expiresAt,format,manifest,manifestDigest,nonce');
    if (context.format !== FORMAT || typeof context.nonce !== 'string' || !/^[a-f0-9]{64}$/.test(context.nonce) ||
        !Number.isSafeInteger(context.createdAt) || context.createdAt <= 0 || context.expiresAt !== context.createdAt + 60000) throw new Error();
    const release = await readReleaseManifest(context.manifest);
    if (release.digest !== context.manifestDigest) throw new Error();
    // Exclusive marker consumes even a failed verification attempt. Retain both
    // files as evidence; do not remove the marker to retry an old challenge.
    await fs.writeFile(`${contextPath}.consumed`, createHash('sha256').update(contextWire).digest('hex'), { flag: 'wx', mode: 0o600 });
    const now = Date.now();
    if (now < context.createdAt || now >= context.expiresAt) throw new Error();
    const response = JSON.parse(await bounded(responsePath, 24576));
    exact(response, 'document,nonce,publicKey');
    if (response.nonce !== context.nonce) throw new Error();
    const document = decode(response.document, 16384), keyBytes = decode(response.publicKey, 1024);
    const pins = release.manifest.measurements;
    const verified = await verifyApplicationAttestation(document, keyBytes, {
      nonce: new Uint8Array(Buffer.from(context.nonce, 'hex')), now,
      expectedPcrs: new Map([0, 1, 2].map(index => [index, new Uint8Array(Buffer.from(pins[`pcr${index}`], 'hex'))])),
    });
    const key = await readKey({ binaryKey: verified.publicKey });
    if (key.isPrivate() || Date.now() >= context.expiresAt) throw new Error();
    return { status: 'hardware-quote-verified', manifestDigest: release.digest,
      sourceCommit: release.manifest.sourceCommit, eifSha256: release.manifest.eifSha256,
      quoteSha256: createHash('sha256').update(document).digest('hex'),
      channelKeyId: await caseRecipientKeyId(key), verifiedAt: verified.verifiedAt };
  }
  throw new Error();
}

if (require.main === module) {
  main(process.argv.slice(2)).then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(() => {
    process.stderr.write('Confidential hardware verification failed\n'); process.exitCode = 1;
  });
}
module.exports = { main };
