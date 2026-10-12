#!/usr/bin/env node
'use strict';

// Offline release-team tool for the signed confidential release withdrawal list
// (enclave/src/confidential/releaseWithdrawals.ts is the verifier; the canonical
// bytes below must stay identical to its parser).
//
//   keygen  --name <label> --private <file> --public <file>
//           Creates a dedicated signing-only key. Keep the private key offline;
//           pin the public key in enclave/confidential-config.json
//           ("releaseWithdrawal": {"publicKey": ...}) and, base64-encoded, in the
//           frontend build variable NEXT_PUBLIC_CONFIDENTIAL_WITHDRAWAL_KEY.
//   sign    --private <file> [--previous <list.json>] [--withdraw <digest>:<security|defect|retired>]...
//           [--restore <digest>]... [--valid-hours <1-72>] [--now <ms>] --out <list.json>
//           Issues the next list: sequence + 1, previous withdrawals carried forward.
//           Default validity 48 hours, at most 72: the maximum validity bounds how
//           long a host could replay an older list to a verifier with no floor
//           (a restarted enclave, a fresh browser). Publish the output to
//           s3://<enclave-artifacts>/eif/confidential-release-withdrawals.json at
//           least daily (hosts refresh it every five minutes).
//   verify  --public <file> --in <list.json> [--release <digest>] [--now <ms>]
//           Exits 0 only for a valid, unexpired list that does not withdraw --release.
//
// Nothing here touches case data. No network access.
const fs = require('node:fs');
const openpgp = require('openpgp');

const FORMAT = 'vera-confidential-withdrawals/v1';
const REASONS = ['security', 'defect', 'retired'];
const HOUR = 60 * 60 * 1000;
const MAX_VALIDITY = 72 * HOUR;

function fail(message) { throw new Error(`release withdrawals: ${message}`); }

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = { withdraw: [], restore: [] };
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index], value = rest[index + 1];
    if (typeof flag !== 'string' || !flag.startsWith('--') || typeof value !== 'string' || !value) fail(`invalid argument ${flag}`);
    const name = flag.slice(2);
    if (name === 'withdraw' || name === 'restore') options[name].push(value);
    else if (['name', 'private', 'public', 'previous', 'valid-hours', 'now', 'out', 'in', 'release'].includes(name) && !(name in options)) options[name] = value;
    else fail(`invalid argument ${flag}`);
  }
  return { command, options };
}

function digest(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('release digest must be 64 lowercase hex characters');
  return value;
}

/** Same field order and checks as parseReleaseWithdrawalList. */
function canonical(list) {
  const withdrawn = [...list.withdrawn].sort((a, b) => a.releaseDigest < b.releaseDigest ? -1 : 1).map(entry => ({
    releaseDigest: digest(entry.releaseDigest),
    reason: REASONS.includes(entry.reason) ? entry.reason : fail('invalid reason'),
    withdrawnAt: Number.isSafeInteger(entry.withdrawnAt) && entry.withdrawnAt > 0 && entry.withdrawnAt <= list.issuedAt
      ? entry.withdrawnAt : fail('invalid withdrawnAt'),
  }));
  if (new Set(withdrawn.map(entry => entry.releaseDigest)).size !== withdrawn.length) fail('duplicate release');
  if (!Number.isSafeInteger(list.sequence) || list.sequence < 1) fail('invalid sequence');
  if (!(list.expiresAt > list.issuedAt) || list.expiresAt - list.issuedAt > MAX_VALIDITY) fail('invalid validity');
  return JSON.stringify({ format: FORMAT, sequence: list.sequence, issuedAt: list.issuedAt, expiresAt: list.expiresAt, withdrawn });
}

async function keygen(options) {
  if (!options.name || !options.private || !options.public) fail('keygen needs --name, --private and --public');
  const { privateKey, publicKey } = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: options.name }], format: 'armored', keyExpirationTime: 0 });
  fs.writeFileSync(options.private, privateKey, { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(options.public, publicKey, { flag: 'wx', mode: 0o644 });
  return { publicKeyBase64: Buffer.from(publicKey, 'utf8').toString('base64') };
}

async function signList(options) {
  if (!options.private || !options.out) fail('sign needs --private and --out');
  const now = options.now ? Number(options.now) : Date.now();
  if (!Number.isSafeInteger(now) || now <= 0) fail('invalid --now');
  const hours = options['valid-hours'] ? Number(options['valid-hours']) : 48;
  if (!Number.isInteger(hours) || hours < 1 || hours > 72) fail('--valid-hours must be 1-72');
  let previous = { sequence: 0, withdrawn: [] };
  if (options.previous) {
    const envelope = JSON.parse(fs.readFileSync(options.previous, 'utf8'));
    if (envelope?.list?.format !== FORMAT) fail('previous list has the wrong format');
    previous = envelope.list;
  }
  const entries = new Map(previous.withdrawn.map(entry => [entry.releaseDigest, entry]));
  for (const value of options.restore) entries.delete(digest(value));
  for (const value of options.withdraw) {
    const [releaseDigest, reason] = value.split(':');
    if (!REASONS.includes(reason)) fail(`reason must be one of ${REASONS.join(', ')}`);
    if (!entries.has(digest(releaseDigest))) entries.set(releaseDigest, { releaseDigest, reason, withdrawnAt: now });
  }
  const list = { sequence: previous.sequence + 1, issuedAt: now, expiresAt: now + hours * HOUR, withdrawn: [...entries.values()] };
  const text = canonical(list);
  const privateKey = await openpgp.readPrivateKey({ armoredKey: fs.readFileSync(options.private, 'utf8') });
  if (!privateKey.isDecrypted()) fail('decrypt the private key before signing (use an unencrypted offline copy)');
  const signature = await openpgp.sign({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(text) }),
    signingKeys: privateKey, detached: true, format: 'armored' });
  fs.writeFileSync(options.out, JSON.stringify({ list: JSON.parse(text), signature }), { flag: 'wx', mode: 0o644 });
  return { sequence: list.sequence, expiresAt: new Date(list.expiresAt).toISOString(), withdrawn: list.withdrawn.length };
}

async function verifyList(options) {
  if (!options.public || !options.in) fail('verify needs --public and --in');
  const now = options.now ? Number(options.now) : Date.now();
  const envelope = JSON.parse(fs.readFileSync(options.in, 'utf8'));
  if (!envelope || Object.keys(envelope).join(',') !== 'list,signature') fail('invalid envelope');
  const text = canonical(envelope.list);
  if (JSON.stringify(envelope.list) !== text || envelope.list.format !== FORMAT) fail('list is not canonical');
  const publicKey = await openpgp.readKey({ armoredKey: fs.readFileSync(options.public, 'utf8') });
  const result = await openpgp.verify({ message: await openpgp.createMessage({ binary: new TextEncoder().encode(text) }),
    signature: await openpgp.readSignature({ armoredSignature: envelope.signature }), verificationKeys: publicKey,
    expectSigned: true, format: 'binary' });
  await result.signatures[0].verified;
  if (envelope.list.issuedAt > now + 5 * 60 * 1000 || now >= envelope.list.expiresAt) fail('list is not current');
  if (options.release && envelope.list.withdrawn.some(entry => entry.releaseDigest === digest(options.release))) {
    fail('release is withdrawn');
  }
  return { sequence: envelope.list.sequence, expiresAt: new Date(envelope.list.expiresAt).toISOString() };
}

async function main(argv) {
  const { command, options } = parseArgs(argv);
  const commands = { keygen, sign: signList, verify: verifyList };
  if (!commands[command]) fail('usage: keygen | sign | verify (see header)');
  process.stdout.write(`${JSON.stringify(await commands[command](options))}\n`);
}

module.exports = { canonical, parseArgs, main };

if (require.main === module) {
  main(process.argv.slice(2)).catch(error => { process.stderr.write(`${error.message}\n`); process.exit(1); });
}
