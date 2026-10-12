#!/usr/bin/env node
'use strict';

// Sentinel sweep (architecture acceptance test 7, runbook section 7).
//
// 1. generate  --out <sentinels.json>
//      Creates unique synthetic markers for every private field of a report
//      (narrative, contact, identity, file name and content, owner and firm
//      messages, access-request purpose). Keep the file local; it is synthetic.
// 2. Submit them through the stack under test:
//      - mounted local stack: tests/integration/services/confidentialSentinelSweep.test.ts
//        does submit + sweep automatically on every CI run;
//      - deployed rehearsal: `npx ts-node scripts/security/confidentialSentinelSubmit.ts
//        --base https://<rehearsal>/api/confidential --manifest <release manifest> --sentinels <file>`
//        and complete the firm and message steps in the browser with the same values.
// 3. search    --sentinels <file> [--mongo-uri-env VAR] [--mongo-db NAME]... [--path DIR_OR_FILE]...
//              [--log-group NAME]... [--region us-east-2] [--since <ms>]
//      Searches every document of every collection in each database (default
//      vera_confidential and vera), staged-object or exported directories,
//      and CloudWatch log groups (API, enclave console export, WAF, flow logs,
//      error monitors). Each marker is searched raw, base64, base64url, hex and
//      percent-encoded. Exits 1 on any hit, printing only the location and the
//      marker's label (never document contents).
//      When <sentinels>.recovery exists (confidentialSentinelSubmit.ts writes the
//      owner recovery code there), the code is searched too: grouped, ungrouped
//      and lower-case forms, in every encoding above. The result reports
//      recoveryCodeSearched so acceptance can require it.
//
// Read-only everywhere. The Mongo URI is read from an environment variable,
// never from the command line. AWS access uses the caller's AWS CLI credentials.
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { execFile } = require('node:child_process');

const LABELS = ['narrative', 'contact', 'identity', 'fileName', 'fileContent', 'ownerMessage', 'firmMessage', 'requestPurpose'];
const MAX_FILE_BYTES = 512 * 1024 * 1024;

function fail(message) { throw new Error(`sentinel sweep: ${message}`); }

function generateSentinels(runId = randomBytes(8).toString('hex')) {
  if (!/^[a-f0-9]{16}$/.test(runId)) fail('runId must be 16 hex characters');
  return { format: 'vera-sentinels/v1', runId, createdAt: Date.now(),
    values: Object.fromEntries(LABELS.map(label => [label, `VERA-SENTINEL-${runId}-${label}-${randomBytes(6).toString('hex')}`])) };
}

// Current (v2) code: 14 groups of 4 Crockford base32 characters; legacy v1 codes
// carry the VERA-OWNER-1. prefix (enclave/src/confidential/recoveryCode.ts).
const RECOVERY_V2 = /^[0-9A-Za-z]{4}(?:-[0-9A-Za-z]{4}){13}$/;
const RECOVERY_V1 = /^VERA-OWNER-1\.[A-Za-z0-9._-]+$/;

function readRecoveryCode(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  const code = text.trim();
  // Never echo the file content: it is a live recovery code for the sentinel report.
  if (!RECOVERY_V2.test(code) && !RECOVERY_V1.test(code)) fail('invalid recovery code file');
  return code;
}

function readSentinels(file) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (value?.format !== 'vera-sentinels/v1' || !value.values || typeof value.values !== 'object') fail('not a sentinel file');
  for (const [label, marker] of Object.entries(value.values)) {
    if (!LABELS.includes(label) || typeof marker !== 'string' || !marker.startsWith('VERA-SENTINEL-')) fail('invalid sentinel entry');
  }
  const recoveryCode = readRecoveryCode(`${file}.recovery`);
  if (recoveryCode) value.recoveryCode = recoveryCode;
  return value;
}

/** The owner recovery code as it might be typed, pasted or normalized. */
function recoveryCodeForms(code) {
  if (typeof code !== 'string' || !code) return [];
  const forms = RECOVERY_V1.test(code) ? [['recoveryCode', code]] : [
    ['recoveryCode', code.toUpperCase()],
    ['recoveryCodeUngrouped', code.toUpperCase().replace(/-/g, '')],
    ['recoveryCodeLower', code.toLowerCase()],
    ['recoveryCodeUngroupedLower', code.toLowerCase().replace(/-/g, '')],
  ];
  return forms;
}

/** Every encoding a careless code path might persist or log. */
function needles(sentinels) {
  const out = [];
  for (const [label, marker] of [...Object.entries(sentinels.values), ...recoveryCodeForms(sentinels.recoveryCode)]) {
    const raw = Buffer.from(marker, 'utf8');
    for (const [encoding, text] of [['raw', marker], ['base64', raw.toString('base64').replace(/=+$/, '')],
      ['base64url', raw.toString('base64url')], ['hex', raw.toString('hex')], ['percent', encodeURIComponent(marker)],
      ['utf16le', Buffer.from(marker, 'utf16le').toString('latin1')]]) {
      // Base64 of a prefix-aligned marker is stable only from its start; the
      // unpadded form is still a substring of any longer base64 encoding that
      // starts at the marker. Middle-of-buffer base64 is covered by raw scans of
      // the decoded stores (BSON binaries are scanned as bytes).
      out.push({ label, encoding, bytes: Buffer.from(text, 'latin1') });
    }
  }
  return out;
}

function scanBuffer(buffer, list, location, hits) {
  for (const needle of list) {
    if (buffer.indexOf(needle.bytes) !== -1) hits.push({ location, label: needle.label, encoding: needle.encoding });
  }
}

/** Files and directories (staged objects, exported logs, captured stdout). */
function searchPaths(paths, list) {
  const hits = [];
  const visit = entry => {
    let stats;
    try { stats = fs.lstatSync(entry); } catch { return; }
    if (stats.isSymbolicLink()) return;
    if (stats.isDirectory()) { for (const name of fs.readdirSync(entry)) visit(path.join(entry, name)); return; }
    if (!stats.isFile()) return;
    if (stats.size > MAX_FILE_BYTES) { hits.push({ location: `file:${entry}`, label: 'unscanned-oversized', encoding: 'n/a' }); return; }
    scanBuffer(fs.readFileSync(entry), list, `file:${entry}`, hits);
  };
  for (const entry of paths) visit(entry);
  return hits;
}

/** Every document of every collection (GridFS chunks included) as raw BSON bytes. */
async function searchMongo(client, databases, list) {
  const { BSON } = require('mongodb');
  const hits = [];
  for (const name of databases) {
    const db = client.db(name);
    for (const info of await db.listCollections({}, { nameOnly: true }).toArray()) {
      if (info.type === 'view') continue;
      const cursor = db.collection(info.name).find({}, { batchSize: 200 });
      for await (const document of cursor) {
        // _id only as an index into the report; it is never printed with content.
        scanBuffer(Buffer.from(BSON.serialize(document)), list, `mongo:${name}.${info.name}`, hits);
      }
    }
  }
  return dedupe(hits);
}

function awsLogs(args) {
  return new Promise((resolve, reject) => execFile('aws', args, { maxBuffer: 16 * 1024 * 1024 }, (error, stdout) =>
    error ? reject(new Error('aws logs query failed')) : resolve(stdout)));
}

/** CloudWatch: raw and base64 forms, exact-term filter patterns. */
async function searchLogGroups(groups, sentinels, options, query = awsLogs) {
  const hits = [];
  const start = String(options.since ?? sentinels.createdAt - 60_000);
  for (const group of groups) {
    for (const needle of needles(sentinels).filter(item => item.encoding === 'raw' || item.encoding === 'base64')) {
      const pattern = `"${needle.bytes.toString('latin1')}"`;
      const stdout = await query(['logs', 'filter-log-events', '--log-group-name', group, '--start-time', start,
        '--filter-pattern', pattern, '--max-items', '1', '--output', 'json', '--region', options.region || 'us-east-2']);
      const events = JSON.parse(stdout || '{}').events;
      if (Array.isArray(events) && events.length) hits.push({ location: `cloudwatch:${group}`, label: needle.label, encoding: needle.encoding });
    }
  }
  return hits;
}

function dedupe(hits) {
  const seen = new Set();
  return hits.filter(hit => { const key = `${hit.location}|${hit.label}|${hit.encoding}`; if (seen.has(key)) return false; seen.add(key); return true; });
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = { 'mongo-db': [], path: [], 'log-group': [] };
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index], value = rest[index + 1];
    if (typeof flag !== 'string' || !flag.startsWith('--') || typeof value !== 'string' || !value) fail(`invalid argument ${flag}`);
    const name = flag.slice(2);
    if (Array.isArray(options[name])) options[name].push(value);
    else if (['out', 'sentinels', 'mongo-uri-env', 'region', 'since'].includes(name) && !(name in options)) options[name] = value;
    else fail(`invalid argument ${flag}`);
  }
  return { command, options };
}

async function main(argv) {
  const { command, options } = parseArgs(argv);
  if (command === 'generate') {
    if (!options.out) fail('generate needs --out');
    fs.writeFileSync(options.out, `${JSON.stringify(generateSentinels(), null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    return { written: options.out };
  }
  if (command !== 'search') fail('usage: generate | search (see header)');
  if (!options.sentinels) fail('search needs --sentinels');
  const sentinels = readSentinels(options.sentinels);
  const list = needles(sentinels);
  const hits = [...searchPaths(options.path, list)];
  let sources = options.path.length;
  if (options['mongo-uri-env']) {
    const uri = process.env[options['mongo-uri-env']];
    if (!uri) fail(`${options['mongo-uri-env']} is not set`);
    const { MongoClient } = require('mongodb');
    const client = await MongoClient.connect(uri, { readPreference: 'secondaryPreferred', serverSelectionTimeoutMS: 15_000 });
    try { hits.push(...await searchMongo(client, options['mongo-db'].length ? options['mongo-db'] : ['vera_confidential', 'vera'], list)); }
    finally { await client.close(); }
    sources += 1;
  }
  if (options['log-group'].length) {
    hits.push(...await searchLogGroups(options['log-group'], sentinels, { region: options.region, since: options.since && Number(options.since) }));
    sources += options['log-group'].length;
  }
  if (!sources) fail('nothing to search: give --path, --mongo-uri-env or --log-group');
  return { runId: sentinels.runId, sources, recoveryCodeSearched: Boolean(sentinels.recoveryCode), hits };
}

module.exports = { LABELS, generateSentinels, readSentinels, recoveryCodeForms, needles, searchPaths, searchMongo, searchLogGroups, parseArgs, main };

if (require.main === module) {
  main(process.argv.slice(2)).then(result => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (result.hits?.length) process.exit(1);
  }).catch(error => { process.stderr.write(`${error.message}\n`); process.exit(2); });
}
