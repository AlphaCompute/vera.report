#!/usr/bin/env node
'use strict';

// Actual HTTP intake and evidence storage acceptance. No service/auth doubles.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn, execFileSync } = require('node:child_process');
const HELP = `Isolated real HTTP / MongoDB / Nitro / S3 storage acceptance.
  node integrations/ipfs/hardware/http.cjs \\
    --expected-instance-id ID --enclave-id ID --enclave-cid CID --expected-pcr0 HEX \\
    --bucket BUCKET --region REGION --account-id ACCOUNT \\
    --mongo-url mongodb://127.0.0.1:27017 \\
    --private-dir ABSOLUTE_NEW_DIRECTORY --evidence ABSOLUTE_NEW_JSON_FILE \\
    --source-revision FULL_COMMIT_SHA [--port 15003]
Creates only a fresh, named test database and test-only ciphertext. Deletes its
database after closing API clients; retains a private recovery key and manifest.
Does not start scoring, dispatch, bot or notification workers.
No browser Auth0 or successful scoring claim is made.
`;
function check(ok, message) { if (!ok) { const error = new Error(message); error.safeAcceptance = true; throw error; } }
function command(binary, args) {
  try { return JSON.parse(execFileSync(binary, args, { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] })); }
  catch { check(false, `Required ${binary} identity check failed.`); }
}
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const childOf = (parent, child) => { const rel = path.relative(parent, child); return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel)); };
function options(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) return null;
  const allowed = ['expected-instance-id', 'enclave-id', 'enclave-cid', 'expected-pcr0', 'bucket', 'region', 'account-id', 'mongo-url', 'private-dir', 'evidence', 'source-revision', 'port'];
  const o = {};
  while (args.length) {
    const flag = args.shift(); const value = args.shift(); const name = flag?.slice(2);
    check(flag?.startsWith('--') && allowed.includes(name) && value && !value.startsWith('--') && !Object.hasOwn(o, name), 'Invalid or repeated option; use --help.'); o[name] = value;
  }
  for (const name of allowed.filter(name => name !== 'port')) check(o[name], `Missing --${name}.`);
  check(/^i-[a-f0-9]{8,17}$/.test(o['expected-instance-id']) && /^i-[a-f0-9]+-enc[a-f0-9]+$/.test(o['enclave-id']), 'Invalid explicitly approved test host/enclave identity.');
  check(/^[a-f0-9]{96}$/i.test(o['expected-pcr0']) && !/^0+$/.test(o['expected-pcr0']), 'Expected nonzero PCR0 required.');
  check(/^[a-f0-9]{40}$/i.test(o['source-revision']), 'Full source revision required.');
  check(/^vera-ipfs-hardware-test-\d{12}$/.test(o.bucket) && o.bucket === `vera-ipfs-hardware-test-${o['account-id']}`, 'Only the dedicated hardware-test archive bucket is permitted.');
  check(/^\d{12}$/.test(o['account-id']) && /^[a-z]{2}(-[a-z]+)+-\d+$/.test(o.region), 'Invalid AWS region/account.');
  o.cid = Number(o['enclave-cid']); o.port = Number(o.port || 15003);
  check(Number.isInteger(o.cid) && o.cid >= 4 && o.cid < 2 ** 32 - 1, 'Invalid enclave CID.');
  check(Number.isInteger(o.port) && o.port >= 1024 && o.port <= 65535, 'Invalid bridge port.');
  const u = new URL(o['mongo-url']);
  check(u.protocol === 'mongodb:' && u.hostname === '127.0.0.1' && u.port && !u.username && !u.password && !u.search && !u.hash && ['', '/'].includes(u.pathname), 'The MongoDB URL must be an explicit unauthenticated loopback origin.');
  check(path.isAbsolute(o['private-dir']) && path.isAbsolute(o.evidence), 'Output paths must be absolute.');
  return o;
}
async function main() {
  const o = options(process.argv.slice(2)); if (!o) { process.stdout.write(HELP); return; }
  check(Number(process.versions.node.split('.')[0]) >= 22, 'Node.js 22 or newer required.');
  check(process.env.NODE_ENV !== 'production', 'Never run against a production process.');
  check(!process.env.ENCLAVE_LOCAL_IPFS_TEST && !process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT && !Object.keys(process.env).some(k => /^AWS_ENDPOINT_URL(?:_|$)/.test(k) && process.env[k]), 'Real AWS and Nitro only; endpoint overrides forbidden.');
  const repo = fs.realpathSync(path.resolve(__dirname, '../../..'));
  const privateDir = path.join(fs.realpathSync(path.dirname(o['private-dir'])), path.basename(o['private-dir']));
  const evidence = path.join(fs.realpathSync(path.dirname(o.evidence)), path.basename(o.evidence));
  check(!childOf(repo, privateDir) && !childOf(privateDir, evidence) && !fs.existsSync(privateDir) && !fs.existsSync(evidence), 'Use new private/output paths, outside the checkout and separate from each other.');
  if (fs.existsSync(path.join(repo, '.git'))) {
    const git = args => execFileSync('git', args, { cwd: repo, encoding: 'utf8', timeout: 10000 }).trim();
    check(git(['rev-parse', 'HEAD']) === o['source-revision'] && !git(['status', '--porcelain']), 'Use the declared clean committed source revision.');
  }
  let instance;
  try { instance = fs.readFileSync('/sys/devices/virtual/dmi/id/board_asset_tag', 'utf8').trim(); } catch { check(false, 'EC2 hardware identity unavailable.'); }
  check(instance === o['expected-instance-id'] && fs.existsSync('/dev/nitro_enclaves'), 'Not the explicitly approved Nitro test host.');
  const enclaves = command('nitro-cli', ['describe-enclaves']);
  const enclave = Array.isArray(enclaves) && enclaves.find(e => e.EnclaveID === o['enclave-id']);
  check(enclave && enclave.State === 'RUNNING' && enclave.Flags === 'NONE' && /^vera-ipfs-hardware-/.test(enclave.EnclaveName || '') && Number(enclave.EnclaveCID) === o.cid && enclave.Measurements?.PCR0?.toLowerCase() === o['expected-pcr0'].toLowerCase(), 'Dedicated measured test enclave identity did not match.');
  const identity = command('aws', ['sts', 'get-caller-identity', '--region', o.region, '--output', 'json']);
  check(identity.Account === o['account-id'] && identity.Arn.includes(':assumed-role/vera-ipfs-hardware-test/'), 'Dedicated hardware-test machine role required.');
  require('ts-node').register({ project: path.join(repo, 'tsconfig.json'), transpileOnly: true, compilerOptions: { rootDir: repo } });
  const { MongoClient } = require('mongodb'); const express = require('express');
  const dbName = `vera_ipfs_http_${crypto.randomBytes(12).toString('hex')}`;
  const mongo = new MongoClient(o['mongo-url'], { serverSelectionTimeoutMS: 5000, writeConcern: { w: 'majority', j: true } });
  const deadline = setTimeout(() => { process.stderr.write('HTTP acceptance exceeded its 10-minute deadline.\n'); process.kill(process.pid, 'SIGTERM'); }, 600000);
  let bridge; let bridgeGroup; let server; let reports; let attempts; let dbCreated = false; let cleanupPromise;
  const oldCwd = process.cwd(); const oldConsole = { ...console }; let privateCreated = false;
  function signalBridgeGroup(signal) {
    if (!bridgeGroup) return false;
    try { process.kill(-bridgeGroup, signal); return true; }
    catch (error) { if (error.code === 'ESRCH') { bridgeGroup = undefined; return false; } throw error; }
  }
  async function stopBridge() {
    if (!signalBridgeGroup('SIGTERM')) return;
    // The listener may exit before its forked vsock child. Observe the owned
    // process group, never just the listener's exit event, before finishing.
    for (let i = 0; i < 20; i++) {
      if (!signalBridgeGroup(0)) return;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    signalBridgeGroup('SIGKILL');
  }
  function cleanup() {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
    clearTimeout(deadline);
    await stopBridge();
    if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    await Promise.allSettled([reports?.close(), attempts?.close()]);
    // The real status route may lazily open its dissemination read store.
    const dissemination = require.cache[path.join(repo, 'src/services/dissemination/disseminationPersistence.ts')]?.exports?.disseminationPersistence;
    await dissemination?.disconnect();
    if (dbCreated) await mongo.db(dbName).dropDatabase();
    await mongo.close(); process.chdir(oldCwd); Object.assign(console, oldConsole);
    })();
    return cleanupPromise;
  }
  const signal = () => { void cleanup().finally(() => process.exit(1)); };
  // Exit hooks cannot await a grace period. Force-stop only our detached group
  // so a transitive module's process.exit cannot orphan any forked vsock child.
  const exit = () => { try { signalBridgeGroup('SIGKILL'); } catch {} };
  process.once('exit', exit);
  process.once('SIGINT', signal); process.once('SIGTERM', signal);
  try {
    await mongo.connect();
    check((await mongo.db('admin').command({ ping: 1 })).ok === 1, 'Actual MongoDB is unavailable.');
    check((await mongo.db(dbName).listCollections().toArray()).length === 0, 'Generated test database already exists.'); dbCreated = true;
    fs.mkdirSync(privateDir, { mode: 0o700 }); privateCreated = true;
    // Empty cwd prevents dotenv from importing deployment credentials.
    process.chdir(privateDir);
    for (const k of Object.keys(process.env)) if (/^(BOT_|WEBHOOK_|SHROUD_|VENICE_|SES_|KMS_|MIDNIGHT_|RELAY_|PINATA_|AUTH0_|MONGODB_|DISSEMINATION_)/.test(k)) delete process.env[k];
    const secret = crypto.randomBytes(32).toString('hex');
    const atRestKey = crypto.randomBytes(32).toString('hex');
    Object.assign(process.env, { NODE_ENV: 'test', RUN_MODE: 'api', LOG_LEVEL: 'silent', MONGODB_URI: o['mongo-url'], MONGODB_DB_NAME: dbName,
      INTERNAL_API_SECRET: secret, AT_REST_LOCAL_KEY: atRestKey,
      ENCLAVE_ENABLED: 'false', IPFS_STORAGE_BACKEND: 'local-enclave', ENCLAVE_IPFS_URL: `http://127.0.0.1:${o.port}`,
      IPFS_CIPHERTEXT_ARCHIVE_BUCKET: o.bucket, AWS_REGION: o.region, AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: 'true' });
    // Application logs may contain tracking capabilities. Suppress them in this
    // isolated harness; only bounded, capability-free acceptance evidence leaves it.
    for (const method of ['log', 'info', 'warn', 'error', 'debug']) console[method] = () => {};
    const free = net.createServer();
    await new Promise((resolve, reject) => { free.once('error', reject); free.listen(o.port, '127.0.0.1', resolve); }); await new Promise(resolve => free.close(resolve));
    bridge = spawn('socat', ['-T', '900', `TCP4-LISTEN:${o.port},bind=127.0.0.1,reuseaddr,fork,max-children=1`, `VSOCK-CONNECT:${o.cid}:5002`], { stdio: 'ignore', detached: true });
    bridgeGroup = bridge.pid;
    let bridgeError; bridge.once('error', e => { bridgeError = e; });
    let ready = false;
    for (let i = 0; i < 30 && !ready; i++) {
      check(!bridgeError && bridge.exitCode === null, 'Private bridge failed to start.');
      try { const response = await fetch(`${process.env.ENCLAVE_IPFS_URL}/health`, { signal: AbortSignal.timeout(1000) }); await response.body?.cancel(); ready = response.status === 204; } catch {}
      if (!ready) await new Promise(resolve => setTimeout(resolve, 100));
    }
    check(ready, 'Measured enclave IPFS health failed.');
    const router = require('../../../src/api/whistleblower.ts').default;
    reports = require('../../../src/services/reportPersistence.ts').reportPersistenceService;
    attempts = require('../../../src/services/submissionAttempt.ts').submissionAttemptStore;
    const { errorMonitor } = require('../../../src/utils/errorMonitor.ts');
    const diagnosticFrames = new Set();
    const framePattern = new RegExp(`${repo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/(src/[A-Za-z0-9_./-]+\\.ts):(\\d+):\\d+`, 'g');
    function retainFrames(stack) {
      if (typeof stack !== 'string') return;
      for (const line of stack.slice(0, 16384).split('\n').slice(0, 24)) {
        if (!/^\s+at\s/.test(line)) continue;
        for (const match of line.matchAll(framePattern)) {
          const file = path.resolve(repo, match[1]);
          if (diagnosticFrames.size < 8 && childOf(path.join(repo, 'src'), file) && fs.existsSync(file)) diagnosticFrames.add(`${match[1]}:${match[2]}`);
        }
      }
    }
    const app = express(); app.use(errorMonitor.middleware());
    app.use((req, _res, next) => {
      // The actual privacy middleware deliberately removes private-route stacks.
      // Retain only allowlisted source locations, then delegate unchanged to it.
      const logError = req.logError;
      req.logError = (message, type, context) => { retainFrames(context?.stack); return logError(message, type, context); };
      next();
    });
    app.use('/api/whistleblower', router);
    server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    const base = `http://127.0.0.1:${server.address().port}/api/whistleblower`;
    const mime = 'text/csv';
    const filename = 'evidence-1.csv';
    const { ALLOWED_EVIDENCE_MIME_TYPES } = require('../../../src/utils/evidenceFiles.ts');
    check(ALLOWED_EVIDENCE_MIME_TYPES.has(mime), 'Acceptance format is not supported by the actual upload route.');
    const plaintext = Buffer.from(`purpose,nonce\nVERA isolated storage acceptance only,${crypto.randomBytes(2048).toString('hex')}\n`);
    const retryKey = crypto.randomBytes(32).toString('hex');
    async function submit() {
      const form = new FormData(); form.set('wantsReward', 'false'); form.set('submitterMode', 'anonymous');
      form.set('consentPsst', 'false'); form.set('consentAgency', 'false'); form.set('consentPress', 'false');
      form.set('files', new Blob([plaintext], { type: mime }), 'acceptance.csv');
      const response = await fetch(`${base}/submit`, { method: 'POST', headers: { 'x-idempotency-key': retryKey }, body: form, signal: AbortSignal.timeout(120000) });
      if (response.status !== 200) {
        const codes = new Set(['invalid_idempotency_key', 'idempotency_payload_mismatch', 'submission_in_progress', 'upload_capacity_busy']);
        let code = 'unclassified'; let body = ''; const reader = response.body?.getReader();
        if (reader) try {
          for (;;) { const { value, done } = await reader.read(); if (done) break; body += Buffer.from(value).toString('utf8'); if (body.length > 4096) { body = ''; break; } }
          try { const candidate = JSON.parse(body).error; if (codes.has(candidate)) code = candidate; } catch {}
        } finally { await reader.cancel(); }
        for (const event of errorMonitor.getStats().recent) retainFrames(event.stack);
        check(false, `Actual submission failed: HTTP ${response.status}; code=${code}; sourceFrames=${JSON.stringify([...diagnosticFrames])}.`);
      }
      return response.json();
    }
    const receipt = await submit(); check(receipt.success && /^VRA-[A-F0-9]{16}$/.test(receipt.trackingId) && receipt.proofStatus === 'not_applicable' && receipt.zkProof === null, 'Unexpected receipt or proof.');
    const again = await submit(); check(again.trackingId === receipt.trackingId, 'Idempotency did not preserve the receipt.');
    const db = mongo.db(dbName); const params = await db.collection('evidence_decryption_params').findOne({ fileKey: `${receipt.trackingId}/${filename}` });
    check(params && params.mimetype === mime && params.encryptionKey.startsWith('enc:local:v1:') && params.contentHash === sha256(plaintext), 'Durable authenticated evidence manifest or wrapped key missing.');
    check(await db.collection('whistleblower_reports').countDocuments({}) === 1 && await db.collection('evidence_decryption_params').countDocuments({}) === 1, 'Retry duplicated durable application records.');
    let processed;
    for (let i = 0; i < 50; i++) {
      processed = await db.collection('whistleblower_reports').findOne({ trackingId: { $eq: String(receipt.trackingId) } });
      if (processed?.processingStatus === 'failed') break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    check(processed?.processingStatus === 'failed' && !processed.verification, 'Unconfigured scoring did not settle without a fabricated result.');
    // Close real persistence clients before reading: retrieval must reopen the
    // database and unwrap its stored key rather than rely on a request-local value.
    await reports.close(); await attempts.close();
    const evidenceUrl = `${base}/evidence/${receipt.trackingId}/${filename}`;
    for (const headers of [{}, { 'x-internal-secret': crypto.randomBytes(32).toString('hex') }]) {
      const rejected = await fetch(evidenceUrl, { headers, signal: AbortSignal.timeout(15000) }); await rejected.body?.cancel(); check(rejected.status === 401, 'Unauthenticated evidence read was not rejected.');
    }
    const downloaded = await fetch(evidenceUrl, { headers: { 'x-internal-secret': secret }, signal: AbortSignal.timeout(120000) });
    check(downloaded.status === 200, 'Authenticated HTTP evidence read failed.');
    const restored = Buffer.from(await downloaded.arrayBuffer()); check(sha256(restored) === sha256(plaintext), 'HTTP evidence plaintext digest mismatch.');
    const status = await fetch(`${base}/status/${receipt.trackingId}`, { signal: AbortSignal.timeout(15000) }); check(status.status === 200, 'Accepted report status was unavailable.');
    const statusBody = await status.json(); check(statusBody.success && statusBody.trackingId === receipt.trackingId, 'Status did not identify the accepted test report.');
    const { retrieveArchivedCiphertext } = require('../../../src/services/ciphertextArchive.ts');
    const { evidenceStorageService } = require('../../../src/services/evidenceStorage.ts');
    const archived = await retrieveArchivedCiphertext(params.originalCID); const stored = await evidenceStorageService.readCiphertext(params.originalCID);
    check(sha256(archived) === sha256(stored) && sha256(stored) !== sha256(plaintext), 'Real S3 ciphertext does not match enclave storage.');
    const record = await db.collection('whistleblower_reports').findOne({ trackingId: { $eq: String(receipt.trackingId) } });
    check(record.proofGeneration?.state === 'not_applicable' && !record.zkProof && !record.submissionNotification, 'Unexpected proof or notification activity.');
    fs.writeFileSync(path.join(privateDir, 'recovery.json'), JSON.stringify({ version: 1, purpose: 'isolated-http-storage-acceptance', atRestKey, params, plaintextSha256: sha256(plaintext), ciphertextSha256: sha256(stored) }), { mode: 0o600, flag: 'wx' });
    restored.fill(0); plaintext.fill(0);
    await cleanup();
    fs.writeFileSync(evidence, JSON.stringify({ version: 1, observedAt: new Date().toISOString(), sourceRevision: o['source-revision'], sourceProvenance: fs.existsSync(path.join(repo, '.git')) ? 'clean Git checkout' : 'operator-declared verified source archive', instanceId: instance, enclaveId: enclave.EnclaveID, pcr0: enclave.Measurements.PCR0,
      checks: { realHttpSubmission: true, durableWrappedEvidenceParams: true, idempotentReceipt: true, authenticatedHttpDownload: true, missingAndWrongSecretRejected: true, plaintextDigestMatches: true, realS3CiphertextMatches: true, proofNotBroadcast: true, testDatabaseDropped: true },
      limitations: ['No blockchain proof is issued', 'Shroud scoring disabled', 'Browser Auth0 and admin audit proxy not tested', 'Only generated test evidence; production unchanged'] }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    process.stdout.write('Real HTTP storage acceptance passed; scoped evidence written.\n');
  } finally {
    await cleanup(); process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal); process.removeListener('exit', exit);
    if (privateCreated) check((fs.statSync(privateDir).mode & 0o077) === 0, 'Private output permissions changed.');
  }
}
main().then(() => process.exit(0)).catch(error => { process.stderr.write((error.safeAcceptance ? error.message : 'HTTP acceptance failed; no success evidence was issued. Check real service prerequisites and private test state.') + '\n'); process.exit(1); });
