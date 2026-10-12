#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { execFileSync, spawn } = require('node:child_process');

const HELP = `Real Nitro / real S3 ciphertext probe. No application reports are created.

  node integrations/ipfs/hardware/probe.cjs store|recover \\
    --expected-instance-id ID --enclave-id ID --enclave-cid CID --expected-pcr0 HEX \\
    --private-dir ABSOLUTE_DIRECTORY --evidence ABSOLUTE_JSON_FILE \\
    --bucket BUCKET --region REGION --account-id ACCOUNT \\
    [--port 15002] [--size-mib 1] [--recovery-kind enclave|host] \\
    [--source-revision FULL_COMMIT_SHA] [--storage-layer adapter|application]

The private directory contains a one-use decryption key. Keep it outside the
checkout and outside published evidence. Transfer it privately for recovery.
The process creates its own loopback-only socat bridge and stops only that child.
It does not start/stop enclaves, change allocators, create buckets or delete data.
Host recovery additionally requires a different EC2 instance and read-only
DescribeInstances evidence that the source instance is stopped or terminated.
`;
function fail(message) { const error = new Error(message); error.safeProbeMessage = true; throw error; }
function check(ok, message) { if (!ok) fail(message); }
function options(args) {
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) return null;
  const phase = args.shift();
  check(['store', 'recover'].includes(phase), 'Select store or recover; use --help for usage.');
  const allowed = new Set(['expected-instance-id', 'enclave-id', 'enclave-cid', 'expected-pcr0', 'private-dir', 'evidence', 'bucket', 'region', 'account-id', 'port', 'size-mib', 'recovery-kind', 'source-revision', 'storage-layer']);
  const out = { phase };
  while (args.length) {
    const flag = args.shift(); const value = args.shift(); const key = flag?.slice(2);
    check(flag?.startsWith('--') && allowed.has(key) && value && !value.startsWith('--') && !Object.hasOwn(out, key), 'Invalid or repeated command option.');
    out[key] = value;
  }
  for (const key of ['expected-instance-id', 'enclave-id', 'enclave-cid', 'expected-pcr0', 'private-dir', 'evidence', 'bucket', 'region', 'account-id']) check(out[key], `Missing --${key}.`);
  check(/^i-[a-f0-9]{8,17}$/.test(out['expected-instance-id']), 'Supply the explicitly approved VERA test instance ID.');
  check(/^i-[a-f0-9]+-enc[a-f0-9]+$/.test(out['enclave-id']), 'Invalid enclave ID.');
  out.cid = Number(out['enclave-cid']); out.port = Number(out.port || 15002); out.bytes = Number(out['size-mib'] || 1) * 1024 * 1024;
  check(Number.isInteger(out.cid) && out.cid >= 4 && out.cid < 2 ** 32 - 1, 'Invalid enclave CID.');
  check(Number.isInteger(out.port) && out.port >= 1024 && out.port <= 65535, 'Invalid loopback port.');
  check(Number.isInteger(out.bytes) && out.bytes >= 1024 && out.bytes <= 256 * 1024 * 1024, 'Probe size must be between 1 KiB and 256 MiB.');
  check(/^[a-f0-9]{96}$/i.test(out['expected-pcr0']) && !/^0+$/.test(out['expected-pcr0']), 'Supply an independently recorded nonzero PCR0.');
  check(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(out.bucket), 'Invalid archive bucket.');
  check(/^[a-z]{2}(-[a-z]+)+-\d+$/.test(out.region) && /^\d{12}$/.test(out['account-id']), 'Invalid AWS region/account.');
  if (out['source-revision']) check(/^[a-f0-9]{40}$/i.test(out['source-revision']), 'Source revision must be a full commit SHA.');
  out['storage-layer'] ||= 'adapter';
  check(['adapter', 'application'].includes(out['storage-layer']), 'Invalid storage layer.');
  out['recovery-kind'] ||= 'enclave';
  check(['enclave', 'host'].includes(out['recovery-kind']), 'Invalid recovery kind.');
  check(path.isAbsolute(out['private-dir']) && path.isAbsolute(out.evidence), 'Output paths must be absolute.');
  return out;
}
function jsonCommand(binary, args, message) {
  try { return JSON.parse(execFileSync(binary, args, { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] })); }
  catch { fail(message); }
}
function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function sameOrChild(parent, child) { const rel = path.relative(parent, child); return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel)); }
function safePaths(o) {
  const repo = fs.realpathSync(path.resolve(__dirname, '../../..'));
  const parent = fs.realpathSync(path.dirname(o['private-dir']));
  const privateDir = path.join(parent, path.basename(o['private-dir']));
  check(!sameOrChild(repo, privateDir), 'Private probe material must be outside the checkout.');
  const evidence = path.join(fs.realpathSync(path.dirname(o.evidence)), path.basename(o.evidence));
  check(!sameOrChild(privateDir, evidence), 'Published evidence must be outside the private directory.');
  check(!fs.existsSync(evidence), 'Refusing to replace an existing evidence file.');
  if (o.phase === 'store') fs.mkdirSync(privateDir, { mode: 0o700 });
  const st = fs.lstatSync(privateDir);
  check(st.isDirectory() && !st.isSymbolicLink() && st.uid === process.getuid() && (st.mode & 0o077) === 0, 'Private directory must be owned by this user with mode 0700.');
  return { privateDir, evidence, repo };
}
function sourceMetadata(repo, declaredRevision) {
  if (!fs.existsSync(path.join(repo, '.git'))) {
    check(declaredRevision, 'An archive checkout requires --source-revision from the verified source package.');
    return { sourceRevision: declaredRevision.toLowerCase(), dirtyCheckout: null, sourceProvenance: 'operator-declared archive revision; Git metadata unavailable' };
  }
  let revision; let dirty;
  try {
    const settings = { cwd: repo, encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] };
    revision = execFileSync('git', ['rev-parse', 'HEAD'], settings).trim();
    dirty = execFileSync('git', ['status', '--porcelain'], settings).trim().length > 0;
  } catch { fail('Cannot inspect source revision before the hardware operation.'); }
  check(!declaredRevision || declaredRevision.toLowerCase() === revision.toLowerCase(), 'Declared source revision differs from the checkout.');
  return { sourceRevision: revision, dirtyCheckout: dirty, sourceProvenance: 'local Git checkout' };
}
function loadAdapter(repo) {
  check(Number(process.versions.node.split('.')[0]) >= 22, 'Node.js 22 or newer is required.');
  try {
    require('ts-node').register({ project: path.join(repo, 'tsconfig.json'), transpileOnly: true, compilerOptions: { rootDir: repo } });
    return require('../../../src/services/localIpfs.ts');
  } catch { fail('Cannot load the real storage adapter; install repository dependencies including ts-node, TypeScript, and the S3 SDK.'); }
}
function readPrivate(dir, layer) {
  const file = path.join(dir, 'state.json'); const st = fs.lstatSync(file);
  check(st.isFile() && !st.isSymbolicLink() && st.uid === process.getuid() && !(st.mode & 0o077) && st.size <= 16384, 'Invalid private state file.');
  const state = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (layer === 'application') {
    require('./application.cjs').validateState(state, check);
  } else check(state.version === 1 && state.accepted === true && /^[a-f0-9]{64}$/.test(state.key) && /^[a-f0-9]{24}$/.test(state.iv) && /^[a-f0-9]{32}$/.test(state.tag), 'Private state is not an accepted probe.');
  check(/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,120})$/.test(state.cid), 'Invalid stored CID.');
  return state;
}
function savePrivate(dir, state, first = false) {
  const file = path.join(dir, 'state.json');
  if (first) fs.writeFileSync(file, JSON.stringify(state), { mode: 0o600, flag: 'wx' });
  else {
    const tmp = path.join(dir, 'state-next.json');
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, file);
  }
}
function hardware(o) {
  let instance;
  try { instance = fs.readFileSync('/sys/devices/virtual/dmi/id/board_asset_tag', 'utf8').trim(); } catch { fail('An EC2 host identity is required; run this on the authorized Nitro host.'); }
  check(/^i-[a-f0-9]{8,17}$/.test(instance), 'Unrecognized EC2 host identity.');
  check(instance === o['expected-instance-id'], 'This is not the explicitly approved VERA test host.');
  check(fs.existsSync('/dev/nitro_enclaves'), 'Nitro Enclaves device is unavailable.');
  const list = jsonCommand('nitro-cli', ['describe-enclaves'], 'Cannot inspect actual Nitro enclaves.');
  check(Array.isArray(list), 'Invalid Nitro inventory.');
  const enclave = list.find(e => e.EnclaveID === o['enclave-id']);
  check(enclave && enclave.State === 'RUNNING' && Number(enclave.EnclaveCID) === o.cid && /^vera-ipfs-hardware-/.test(enclave.EnclaveName || ''), 'Expected dedicated running test enclave was not found.');
  check(enclave.Flags === 'NONE' && enclave.Measurements?.PCR0?.toLowerCase() === o['expected-pcr0'].toLowerCase(), 'Debug flags or unexpected enclave measurements; refusing the test.');
  const identity = jsonCommand('aws', ['sts', 'get-caller-identity', '--region', o.region, '--output', 'json'], 'Cannot verify the AWS account.');
  check(identity.Account === o['account-id'], 'AWS credentials target another account.');
  return { instanceId: instance, enclaveId: enclave.EnclaveID, enclaveCid: o.cid, enclaveName: enclave.EnclaveName, pcr0: enclave.Measurements.PCR0, flags: enclave.Flags, cpuCount: enclave.NumberOfCPUs, memoryMiB: enclave.MemoryMiB };
}
async function unusedPort(port) {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', () => reject(new Error('Loopback port is already occupied or unavailable.'))); server.listen(port, '127.0.0.1', resolve); });
  await new Promise(resolve => server.close(resolve));
}
async function narrowRequest(port, endpoint, body) {
  const response = await fetch(`http://127.0.0.1:${port}${endpoint}`, { method: endpoint === '/health' ? 'GET' : 'POST', body, redirect: 'error', headers: { Connection: 'close' }, signal: AbortSignal.timeout(15_000) });
  await response.body?.cancel(); return response.status;
}
async function main() {
  const o = options(process.argv.slice(2)); if (!o) { process.stdout.write(HELP); return; }
  check(process.env.NODE_ENV !== 'production', 'This is a dedicated host test process, never a production application command.');
  check(!process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT && !Object.keys(process.env).some(key => /^AWS_ENDPOINT_URL(?:_|$)/.test(key) && process.env[key]), 'Custom AWS endpoints are forbidden; use real AWS services.');
  check(process.env.ENCLAVE_LOCAL_IPFS_TEST !== '1', 'Local Docker test mode is forbidden.');
  process.env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS = 'true';
  const repo = fs.realpathSync(path.resolve(__dirname, '../../..'));
  const source = sourceMetadata(repo, o['source-revision']);
  const { requireLocalIpfs, storeLocalCiphertext, readLocalCiphertext } = loadAdapter(repo);
  // Select the isolated backend before importing the application's singleton.
  process.env.NODE_ENV = 'test'; process.env.IPFS_STORAGE_BACKEND = 'local-enclave';
  let application;
  if (o['storage-layer'] === 'application') {
    check(!process.env.PINATA_JWT, 'Application hardware tests must not inherit a Pinata credential.');
    try { application = require('./application.cjs').load(); }
    catch { fail('Cannot load the real application storage service; install axios and form-data as well as adapter dependencies.'); }
  }
  const p = safePaths(o); const hw = hardware(o); const started = Date.now(); const checks = {};
  let state = o.phase === 'recover' ? readPrivate(p.privateDir, o['storage-layer']) : null;
  if (state) {
    check(state.bucket === o.bucket && state.region === o.region && state.accountId === o['account-id'], 'Recovery must use the original archive/account.');
    check(hw.enclaveId !== state.hardware.enclaveId && hw.pcr0 === state.hardware.pcr0, 'Recovery requires a new enclave with the original measured image.');
    if (o['recovery-kind'] === 'host') {
      check(hw.instanceId !== state.hardware.instanceId, 'Host recovery requires a different EC2 instance.');
      const response = jsonCommand('aws', ['ec2', 'describe-instances', '--region', o.region, '--instance-ids', state.hardware.instanceId, '--output', 'json'], 'Cannot independently confirm the source host is unavailable.');
      const instances = (response.Reservations || []).flatMap(r => r.Instances || []);
      check(instances.length === 1 && ['stopped', 'terminated'].includes(instances[0].State?.Name), 'Source host must be stopped or terminated for host-loss evidence.');
      checks.sourceHostUnavailable = true;
    }
  }
  await unusedPort(o.port);
  const bridge = spawn('socat', ['-T', '900', `TCP-LISTEN:${o.port},bind=127.0.0.1,reuseaddr,fork,max-children=1`, `VSOCK-CONNECT:${o.cid}:5002`], { stdio: 'ignore', detached: true });
  let bridgeError = false; bridge.once('error', () => { bridgeError = true; });
  const stopBridge = () => { if (bridge.pid) { try { process.kill(-bridge.pid, 'SIGTERM'); } catch {} } };
  const interrupted = () => { stopBridge(); process.stderr.write('Hardware probe interrupted; no success evidence published.\n'); process.exit(1); };
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted);
  const deadline = setTimeout(interrupted, 20 * 60 * 1000);
  try {
    let ready = false;
    for (let i = 0; i < 30; i++) {
      check(!bridgeError && bridge.exitCode === null, 'The owned loopback-vsock bridge failed.');
      try { if (await narrowRequest(o.port, '/health') === 204) { ready = true; break; } } catch {}
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    check(ready && !bridgeError && bridge.exitCode === null, 'Kubo over the owned hardware bridge did not become ready.'); checks.hardwareBridgeReady = true;
    for (const endpoint of ['/api/v0/config', '/shutdown', '/unpin']) check(await narrowRequest(o.port, endpoint, '') === 404, 'An administrative endpoint was exposed.');
    check(await narrowRequest(o.port, '/cat', '../config') === 400, 'Malformed CID was not rejected.'); checks.narrowInterface = true;
    process.env.NODE_ENV = 'test'; process.env.IPFS_STORAGE_BACKEND = 'local-enclave';
    process.env.ENCLAVE_IPFS_URL = `http://127.0.0.1:${o.port}`;
    process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = o.bucket; process.env.AWS_REGION = o.region;
    process.env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS = 'true';
    check((() => { try { requireLocalIpfs(); return true; } catch { return false; } })(), 'The isolated test process did not enable the local adapter.');
    if (!state) {
      if (application) {
        state = await application.store(o.bytes, { bucket: o.bucket, region: o.region, accountId: o['account-id'], hardware: hw }, check);
        savePrivate(p.privateDir, state, true);
        checks.applicationUpload = true;
      } else {
        const plaintext = crypto.randomBytes(o.bytes); const key = crypto.randomBytes(32); const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        state = { version: 1, accepted: false, probeId: crypto.randomUUID(), key: key.toString('hex'), iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), plaintextSha256: digest(plaintext), ciphertextSha256: digest(ciphertext), sizeBytes: plaintext.length, bucket: o.bucket, region: o.region, accountId: o['account-id'], hardware: hw };
        plaintext.fill(0); key.fill(0);
        savePrivate(p.privateDir, state, true);
        fs.writeFileSync(path.join(p.privateDir, 'ciphertext.bin'), ciphertext, { mode: 0o600, flag: 'wx' });
        state.cid = await storeLocalCiphertext(ciphertext); state.accepted = true;
        savePrivate(p.privateDir, state);
      }
      checks.archiveAcknowledgedBeforeAcceptance = true;
    } else {
      check(await narrowRequest(o.port, '/cat', state.cid) === 502, 'CID already available before recovery; this does not prove empty-enclave recovery.');
      check(await narrowRequest(o.port, '/health') === 204, 'Storage unhealthy; missing CID is not proven.'); checks.cidAbsentBeforeRecovery = true;
    }
    if (application) {
      await application.verify(state, checks, check);
    } else {
      const ciphertext = await readLocalCiphertext(state.cid);
      check(digest(ciphertext) === state.ciphertextSha256, 'Recovered ciphertext digest mismatch.');
      const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(state.key, 'hex'), Buffer.from(state.iv, 'hex'));
      decipher.setAuthTag(Buffer.from(state.tag, 'hex'));
      const recovered = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      check(recovered.length === state.sizeBytes && digest(recovered) === state.plaintextSha256, 'Authenticated recovery mismatch.'); recovered.fill(0);
      checks.ciphertextDigestMatches = true; checks.authenticatedRecovery = true;
      let rejected = false;
      try { const wrong = crypto.createDecipheriv('aes-256-gcm', crypto.randomBytes(32), Buffer.from(state.iv, 'hex')); wrong.setAuthTag(Buffer.from(state.tag, 'hex')); wrong.update(ciphertext); wrong.final(); } catch { rejected = true; }
      check(rejected, 'Wrong-key authentication was not rejected.'); checks.wrongKeyRejected = true;
    }
    if (o.phase === 'recover') check(await narrowRequest(o.port, '/cat', state.cid) === 200, 'Recovered ciphertext was not rehydrated in Kubo.');
    const evidence = { schemaVersion: 1, storageLayer: o['storage-layer'], phase: o.phase, recoveryKind: o.phase === 'recover' ? o['recovery-kind'] : null, checkedAt: new Date().toISOString(), ...source, probeId: state.probeId, hardware: hw, bucket: o.bucket, region: o.region, cid: state.cid, ciphertextSha256: state.ciphertextSha256, sizeBytes: state.sizeBytes, elapsedMs: Date.now() - started, checks, limitations: ['Generated encrypted probe bytes only; no application report or production key.', 'Parent-observed Nitro inventory and PCR match; not a new cryptographic attestation verification.', 'No production activation, historical CID migration, archive corruption injection, load acceptance or complete application recovery is established.', ...(application ? ['Application service acceptance covers uploadEncryptedFile and retrieveVaultCiphertext only; no database, HTTP route, wallet, encrypted-CID legacy API or enclave encryption acceptance.'] : [])] };
    fs.writeFileSync(p.evidence, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    process.stdout.write(`PASS: ${o.phase} hardware ciphertext probe; sanitized evidence written.\n`);
  } finally { clearTimeout(deadline); process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted); stopBridge(); }
}
main().catch(error => {
  const detail = error?.safeProbeMessage ? error.message : 'Inspect prerequisites and private state; external error details are withheld.';
  process.stderr.write(`Hardware probe failed: ${detail} No success evidence is claimed.\n`);
  process.exitCode = 1;
});
