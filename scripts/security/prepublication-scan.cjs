#!/usr/bin/env node
'use strict';

// Pre-publication scan (docs/security/README.md#publication-and-incident-handling).
//
// Complements gitleaks/TruffleHog with repository-specific checks that generic
// scanners do not report: committed build outputs and source maps, recordings
// and screenshots, internal evidence/handover documents, AWS account IDs and
// KMS ARNs, public IP addresses, non-maintainer e-mail addresses, and
// Next.js preview/server-action keys inside committed .next output.
//
// Usage:
//   node scripts/security/prepublication-scan.cjs [--head-only] [--json <file>]
//        [--min-severity info|low|medium|high|critical] [--fail-on <severity>]
//        [--allow scripts/security/prepublication-allowlist.json] [--repo <dir>]
//
//   default      every blob reachable from any local ref (git rev-list --all),
//                i.e. tracked files AND full history, each unique blob once
//   --head-only  only blobs in HEAD (use against a candidate public mirror)
//
// Output never contains a matched value. Each finding carries a fingerprint:
// the first four characters of the match plus the first 12 hex characters of
// its SHA-256, so the same secret can be recognised across runs and paths
// without being disclosed. --allow names a reviewed-exception file: a JSON
// array of { rule, fingerprint | path, reason }; matching findings are counted
// as "allowed" and never fail the run. Exit status is 1 when any finding at or above
// --fail-on (default high) exists, otherwise 0. --min-severity only filters the
// display, not the failure decision. Incomplete/invalid scans exit 2 without a
// completed report. Read-only; no network access.

const { execFileSync, spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
const headOnly = args.includes('--head-only');
const jsonOut = opt('--json');
const minSeverity = opt('--min-severity', 'low');
const failOn = opt('--fail-on', 'high');
let repo;
const LARGE_BLOB = 1024 * 1024;
const allowFile = opt('--allow');
const isAllowed = (f, allow) => allow.some((a) => a.rule === f.rule &&
  ((a.fingerprint && a.fingerprint === f.fingerprint) || (a.path && (a.path.endsWith('/') ? f.path.startsWith(a.path) : a.path === f.path))));

const git = (a, o = {}) =>
  execFileSync('git', a, { cwd: repo, maxBuffer: 1 << 30, encoding: 'utf8', ...o });

function loadAllowlist() {
  if (!args.includes('--allow')) return [];
  if (!allowFile || allowFile.startsWith('--')) throw new Error('--allow requires an allowlist path');
  let allow;
  try { allow = JSON.parse(fs.readFileSync(path.resolve(allowFile), 'utf8')); }
  catch { throw new Error('Unable to read or parse allowlist'); }
  const nonempty = value => typeof value === 'string' && value.trim().length > 0;
  if (!Array.isArray(allow) || !allow.every(entry => entry && typeof entry === 'object' && !Array.isArray(entry) &&
      nonempty(entry.rule) && (nonempty(entry.fingerprint) || nonempty(entry.path)) &&
      (entry.fingerprint === undefined || nonempty(entry.fingerprint)) && (entry.path === undefined || nonempty(entry.path)))) {
    throw new Error('Invalid allowlist: entries require a rule and a fingerprint or path');
  }
  return allow;
}

// Values that make a candidate obviously synthetic or a reference, not a secret.
const PLACEHOLDER =
  /example|synthetic|placeholder|dummy|fake|fixture|changeme|change_me|your[_-]|a-long-random|random-string|xxxx|test[_-]?(jwt|secret|key|token|encrypt|intern|user)|testuser|PRIVATE-USER|internal\.invalid|<[^>]*>|\$\{|process\.env|REDACTED|\*\*\*|localhost|127\.0\.0\.1|NEW_TOKEN/i;

const MAINTAINER_EMAIL_DOMAINS = /@(example\.(com|org|net)|test|users\.noreply\.github\.com|anthropic\.com|localhost)\b/i;

// id, severity, regex (global), optional value group, optional extra filter
const CONTENT_RULES = [
  // Header followed by a real body (newline or escaped \\n, then base64), not a bare marker string.
  { id: 'private-key-pem', sev: 'critical', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:\r?\n|\\n)(?:[A-Za-z0-9-]+: [^\n]*(?:\r?\n|\\n))*[A-Za-z0-9+/=]{40}/g },
  { id: 'aws-access-key-id', sev: 'high', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, skip: (v) => /EXAMPLE|TEST|FAKE|SYNTH/.test(v) },
  { id: 'aws-secret-access-key', sev: 'critical', re: /aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi, group: 1 },
  { id: 'mongodb-uri-credentials', sev: 'critical', re: /mongodb(?:\+srv)?:\/\/([^\s:/@"'`]+):([^\s@"'`]+)@([^\s/"'`]+)/g, group: 0, skip: (v) => /localhost|127\.0\.0\.1|mongo:27017|user:pass|username:password|<|\$\{/.test(v), classify: classifyUriHost },
  { id: 'db-uri-credentials', sev: 'high', re: /\b(?:postgres(?:ql)?|mysql|redis|rediss|amqps?):\/\/([^\s:/@"'`]+):([^\s@"'`]+)@([^\s/"'`]+)/g, skip: (v) => /localhost|127\.0\.0\.1|user:pass|<|\$\{/.test(v), classify: classifyUriHost },
  { id: 'jwt', sev: 'high', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}/g, classify: classifyJwt },
  { id: 'auth0-client-secret', sev: 'critical', re: /(?:AUTH0_(?:CLIENT_SECRET|SECRET)|client_secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{32,})/gi, group: 1 },
  { id: 'github-token', sev: 'critical', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { id: 'slack-token', sev: 'critical', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, skip: (v) => /wrong|invalid|test|fake/i.test(v) },
  { id: 'slack-webhook', sev: 'critical', re: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/T[A-Z0-9]{6,}\/[A-Z0-9]{6,}\/[A-Za-z0-9]{12,}/g },
  { id: 'discord-webhook', sev: 'critical', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{40,}/g },
  { id: 'sentry-dsn', sev: 'medium', re: /https:\/\/[0-9a-f]{32}@[a-z0-9.-]*sentry\.io\/\d+/g },
  { id: 'stripe-live-key', sev: 'critical', re: /\b[rs]k_live_[A-Za-z0-9]{20,}/g },
  { id: 'anthropic-or-openai-key', sev: 'critical', re: /\bsk-(?:ant-[A-Za-z0-9_-]{20,}|proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{40,})/g },
  { id: 'google-api-key', sev: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'atlassian-api-token', sev: 'high', re: /\bATATT[A-Za-z0-9_=-]{30,}/g },
  { id: 'telegram-bot-token', sev: 'high', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { id: 'sendgrid-key', sev: 'critical', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: 'npm-token', sev: 'critical', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'pinata-secret', sev: 'high', re: /(?:pinata_?(?:api_?)?(?:secret|jwt)|scopedKeySecret)["']?\s*[:=]\s*["']?([A-Za-z0-9_.-]{24,})/gi, group: 1 },
  { id: 'nextjs-preview-or-action-key', sev: 'medium', re: /"(?:previewModeSigningKey|previewModeEncryptionKey|encryptionKey|encryption\.key)"\s*:\s*"([A-Za-z0-9+/=]{20,})"/g, group: 1 },
  {
    id: 'generic-secret-assignment', sev: 'medium',
    re: /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|SEED|MNEMONIC|SIGNING_KEY)[A-Z0-9_]*)\s*[:=]\s*["']?([A-Za-z0-9_+/=.-]{20,})/g,
    group: 2,
    // Skip low-entropy values and kebab/path identifiers such as
    // Secrets Manager names (vera/prod/auth0) or header names (x-nextjs-...).
    skip: (v) => entropy(v) < 3.5 || (/^[a-z0-9._\/-]+$/.test(v) && /[-\/.]/.test(v) && !/\d{6}/.test(v)),
  },
  // Informational, reviewed for publication rather than rotation.
  { id: 'aws-kms-arn', sev: 'info', re: /\barn:aws:kms:[a-z0-9-]+:\d{12}:(?:key|alias)\/[A-Za-z0-9/_-]+/g },
  { id: 'aws-account-id-in-arn', sev: 'low', re: /\barn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):/g, group: 1, skip: (v) => /^(0{12}|1{12}|123456789012)$/.test(v) },
  { id: 'aws-internal-hostname', sev: 'low', re: /\b(?:ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.[a-z0-9.-]*internal|[a-z0-9-]+\.[a-z0-9]{12}\.[a-z0-9-]+\.rds\.amazonaws\.com|[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com|[a-z0-9-]+\.elb\.amazonaws\.com)\b/g },
  { id: 'atlassian-site', sev: 'low', re: /\b[a-z0-9-]+\.atlassian\.net\b/g, skip: (v) => /^(test|example|your)/.test(v) },
  { id: 'public-ipv4', sev: 'low', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, skip: (v) => !isPublicIpv4(v) },
  { id: 'email-address', sev: 'low', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, skip: (v) => MAINTAINER_EMAIL_DOMAINS.test(v) || /\.(png|jpe?g|svg|webp|js|ts)$/i.test(v) || /^[^@]+@\d/.test(v) },
  { id: 'phone-number', sev: 'low', re: /(?<![\w.])\+\d{1,3}[ -]?\(?\d{2,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}(?![\w.])/g },
];

const PATH_RULES = [
  { id: 'dotenv-file', sev: 'high', test: (p) => /(^|\/)\.env(\.[^/]*)?$/.test(p) && !/\.(example|sample|template|test|ci)$/.test(p) },
  // Committed test env files are expected; review that every value is synthetic.
  { id: 'dotenv-test-file', sev: 'medium', test: (p) => /(^|\/)\.env\.(test|ci)$/.test(p) },
  { id: 'key-material-file', sev: 'high', test: (p) => /\.(pem|key|p12|pfx|jks|keystore)$|(^|\/)id_(rsa|ed25519|ecdsa)$/.test(p) && !/nitro.*root\.pem$/.test(p) },
  { id: 'nextjs-build-output', sev: 'medium', test: (p) => /(^|\/)\.next\//.test(p) },
  { id: 'build-output', sev: 'low', test: (p) => /(^|\/)(dist|build|out|coverage)\//.test(p) && !/^node_modules\//.test(p) },
  { id: 'source-map', sev: 'low', test: (p) => /\.map$/.test(p) },
  { id: 'tsbuildinfo', sev: 'low', test: (p) => /\.tsbuildinfo$/.test(p) },
  // Internal delivery evidence, handover/closeout notes and live-environment
  // inspection captures (not the product's "evidence" feature code).
  { id: 'internal-evidence-document', sev: 'medium', test: (p) => /^docs\/(handover|reviews\/evidence|staging-repair-[^/]+)\//.test(p) || /^\.github\/pdr\//.test(p) || /(^|\/)[^/]*(CLOSEOUT|HANDOFF|HANDOVER|COMPLETION_REPORT|chat-history)[^/]*$/i.test(p) },
  { id: 'recording-or-screenshot', sev: 'medium', test: (p) => /\.(webm|mp4|mov|m4a|mp3|wav|ogg|png|jpe?g|gif|tiff?|heic)$/i.test(p) && !/^(public|app|components)\//.test(p) },
  { id: 'office-or-pdf-document', sev: 'medium', test: (p) => /\.(pdf|docx?|xlsx?|pptx?|csv)$/i.test(p) },
  { id: 'data-dump', sev: 'high', test: (p) => /\.(sqlite3?|db|dump|bson|har|pcap|sql\.gz)$/i.test(p) },
];

function entropy(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  return Object.values(f).reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}

function isPublicIpv4(ip) {
  const o = ip.split('.').map(Number);
  if (o.some((n) => n > 255)) return false;
  const [a, b] = o;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 192 && b === 0) return false; // 192.0.0/24, 192.0.2/24 documentation
  if ((a === 198 && (b === 51 || b === 18 || b === 19)) || (a === 203 && b === 0)) return false;
  // Version-like strings (1.2.3.4) are too noisy; require at least one octet > 9.
  return o.some((n) => n > 9);
}

// A JWT whose payload has an exp/iat/scopedKey/email is treated as issued by a
// real service; a claims-only fixture ({"sub":"auth0|lawyer"}) is downgraded.
function classifyJwt(v) {
  try {
    const p = JSON.parse(Buffer.from(v.split('.')[1], 'base64url').toString('utf8'));
    const keys = Object.keys(p);
    const issued = ['exp', 'iat', 'scopedKeyKey', 'userInformation', 'iss', 'email'].some((k) => keys.includes(k));
    const note = `claims=[${keys.join(',')}]${p.exp ? ` exp=${new Date(p.exp * 1000).toISOString().slice(0, 10)}` : ''}`;
    return { sev: issued ? 'critical' : 'info', note };
  } catch {
    return { sev: 'low', note: 'undecodable payload' };
  }
}

// Credentials for a dotless host (a compose service or a test "one:27017") only
// reach a local network; still reported, at low severity, for review.
function classifyUriHost(v) {
  const host = v.split('@').pop().split(/[/:,?]/)[0];
  return host.includes('.') ? { sev: 'critical', note: `host=${host}` } : { sev: 'low', note: `non-FQDN host ${host}` };
}

const fingerprint = (v) =>
  `${v.slice(0, 4)}…sha256:${crypto.createHash('sha256').update(v).digest('hex').slice(0, 12)}`;

function parseObjectHeader(line, expectedSha) {
  const match = /^([a-f0-9]{40}|[a-f0-9]{64}) (blob|tree|commit|tag) (0|[1-9][0-9]*)$/.exec(line);
  if (!match || match[1] !== expectedSha || !Number.isSafeInteger(Number(match[3]))) {
    throw new Error('Invalid or missing git object header');
  }
  return { type: match[2], size: Number(match[3]) };
}

function headBlobs() {
  return git(['ls-tree', '--full-tree', '-r', '-l', '-z', 'HEAD']).split('\0').filter(Boolean).map(record => {
    const tab = record.indexOf('\t');
    const [, type, sha, size] = record.slice(0, tab).trim().split(/\s+/);
    const name = record.slice(tab + 1);
    return type === 'blob' ? { sha, path: name, paths: [name], size: Number(size) } : null;
  }).filter(Boolean);
}

function listBlobs(head) {
  if (headOnly) return head;
  const objs = git(['rev-list', '--all', '--objects']).split('\n').filter(Boolean);
  const withPath = new Map();
  for (const l of objs) {
    const i = l.indexOf(' ');
    if (i > 0 && !withPath.has(l.slice(0, i))) withPath.set(l.slice(0, i), l.slice(i + 1));
  }
  // rev-list emits only one name for each object. Raw changes retain every
  // committed alias, including root files and paths created only by a merge.
  // NUL framing preserves tabs/newlines and disables Git's path quoting.
  const allPaths = new Map();
  const changes = git(['log', '--all', '--full-history', '--raw', '-z', '--no-abbrev', '--no-renames',
    '--root', '--diff-merges=separate', '--format=']).split('\0');
  if (changes.pop() !== '' || changes.length % 2) throw new Error('Incomplete git path inventory');
  for (let i = 0; i < changes.length; i += 2) {
    const match = /^:[0-7]{6} ([0-7]{6}) [a-f0-9]{40,64} ([a-f0-9]{40,64}) [A-Z][0-9]*$/.exec(changes[i].trim());
    const name = changes[i + 1];
    if (!match || !name) throw new Error('Invalid git path inventory');
    const [, mode, sha] = match;
    if (mode === '000000' || mode === '160000') continue;
    if (!allPaths.has(sha)) allPaths.set(sha, new Set());
    allPaths.get(sha).add(name);
    withPath.set(sha, name);
  }
  const shas = [...withPath.keys()];
  if (!shas.length) return [];
  const check = git(['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], {
    input: shas.join('\n') + '\n',
  });
  const headers = check.split('\n');
  if (headers.pop() !== '' || headers.length !== shas.length) {
    throw new Error('Incomplete git object inventory');
  }
  return headers.map((line, i) => {
    const sha = shas[i];
    const { type, size } = parseObjectHeader(line, sha);
    const paths = [...(allPaths.get(sha) || [withPath.get(sha)])];
    return type === 'blob' ? { sha, path: paths[0], paths, size } : null;
  }).filter(Boolean);
}

// blob sha -> earliest commit (short sha + date) that introduced it, one pass.
function introducingCommits() {
  const map = new Map();
  const out = git(['log', '--all', '--reverse', '--raw', '--no-abbrev', '--no-renames', '--format=C %h %ad', '--date=short']);
  let cur = '';
  for (const l of out.split('\n')) {
    if (l.startsWith('C ')) cur = l.slice(2);
    else if (l.startsWith(':')) {
      const sha = l.split(/\s+/)[3];
      if (sha && !/^0+$/.test(sha) && !map.has(sha)) map.set(sha, cur);
    }
  }
  return map;
}

function readBlobs(blobs, onBlob) {
  if (!blobs.length) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const p = spawn('git', ['cat-file', '--batch'], { cwd: repo });
    let buf = Buffer.alloc(0);
    let idx = 0;
    let failed = false;
    const fail = (error) => {
      if (failed) return;
      failed = true;
      p.kill();
      reject(error);
    };
    p.on('error', () => fail(new Error('git cat-file process failed')));
    p.stdin.on('error', () => fail(new Error('git cat-file input stream failed')));
    p.stdout.on('error', () => fail(new Error('git cat-file output stream failed')));
    p.stderr.on('error', () => fail(new Error('git cat-file diagnostic stream failed')));
    // Drain diagnostics to avoid blocking the child; never print raw Git output.
    p.stderr.resume();
    p.stdout.on('data', (d) => {
      if (failed) return;
      buf = Buffer.concat([buf, d]);
      try {
        while (buf.length) {
          if (idx >= blobs.length) throw new Error('Unexpected data after the last git blob');
          const nl = buf.indexOf(10);
          if (nl < 0) return;
          const blob = blobs[idx];
          const { type, size } = parseObjectHeader(buf.subarray(0, nl).toString(), blob.sha);
          if (type !== 'blob' || size !== blob.size) throw new Error('git blob metadata does not match inventory');
          const end = nl + 1 + size;
          if (buf.length <= end) return;
          if (buf[end] !== 10) throw new Error('Invalid git blob delimiter');
          onBlob(blob, buf.subarray(nl + 1, end));
          idx++;
          buf = buf.subarray(end + 1);
        }
      } catch (error) {
        fail(error);
      }
    });
    p.on('close', (code, signal) => {
      if (failed) return;
      if (signal || code !== 0) return fail(new Error('git cat-file did not complete successfully'));
      if (buf.length || idx !== blobs.length) return fail(new Error('Incomplete git blob scan'));
      resolve();
    });
    p.stdin.end(blobs.map((b) => b.sha).join('\n') + '\n');
  });
}

async function main() {
  // A failed scan must not leave a previous successful report at the same path.
  if (args.includes('--json')) {
    if (!jsonOut || jsonOut.startsWith('--')) throw new Error('--json requires an output path');
    fs.rmSync(path.resolve(jsonOut), { force: true });
  }
  const repoArg = opt('--repo', process.cwd());
  if (!repoArg || repoArg.startsWith('--')) throw new Error('--repo requires a repository path');
  repo = path.resolve(repoArg);
  if (!SEVERITIES.includes(minSeverity) || !SEVERITIES.includes(failOn)) {
    throw new Error('--min-severity and --fail-on must name a valid severity');
  }
  const allow = loadAllowlist();
  const current = headBlobs();
  const blobs = listBlobs(current);
  const head = new Set(current.map(b => b.sha));
  const headPaths = new Set(current.map(b => b.path));
  const intro = headOnly ? new Map() : introducingCommits();
  const findings = [];
  let allowed = 0;
  let failingFindings = 0;
  const add = (f) => {
    if (isAllowed(f, allow)) { allowed++; return; }
    if (SEVERITIES.indexOf(f.sev) >= SEVERITIES.indexOf(failOn)) failingFindings++;
    if (SEVERITIES.indexOf(f.sev) >= SEVERITIES.indexOf(minSeverity)) findings.push(f);
  };

  for (const b of blobs) {
    for (const name of b.paths) {
      for (const r of PATH_RULES) {
        if (r.test(name)) add({ rule: r.id, sev: r.sev, path: name, blob: b.sha.slice(0, 12), line: null });
      }
      if (b.size > LARGE_BLOB) add({ rule: 'large-blob', sev: 'info', path: name, blob: b.sha.slice(0, 12), note: `${(b.size / 1048576).toFixed(1)} MiB` });
    }
  }

  await readBlobs(blobs, (b, data) => {
    if (data.subarray(0, 8000).includes(0)) return; // binary: path rules only
    const text = data.toString('utf8');
    for (const r of CONTENT_RULES) {
      r.re.lastIndex = 0;
      let m;
      while ((m = r.re.exec(text))) {
        const v = m[r.group || 0] || m[0];
        // Placeholder markers are checked on the matched value, not surrounding text.
        if (r.sev !== 'info' && PLACEHOLDER.test(v)) continue;
        if (r.skip && r.skip(v)) continue;
        let { sev } = r;
        let note;
        if (r.classify) ({ sev, note } = r.classify(v));
        const line = text.slice(0, m.index).split('\n').length;
        const matchFingerprint = fingerprint(v);
        for (const name of b.paths) {
          add({ rule: r.id, sev, path: name, blob: b.sha.slice(0, 12), line, fingerprint: matchFingerprint, note });
        }
      }
    }
  });

  const byShort = new Map(blobs.map((b) => [b.sha.slice(0, 12), b]));
  for (const f of findings) {
    const full = byShort.get(f.blob);
    f.inHead = head.has(full.sha);
    f.pathInHead = headPaths.has(f.path);
    f.introducedBy = intro.get(full.sha) || (headOnly ? 'HEAD' : 'unknown (merge-only or unreachable from log)');
  }
  findings.sort((a, b) => SEVERITIES.indexOf(b.sev) - SEVERITIES.indexOf(a.sev) || a.rule.localeCompare(b.rule) || a.path.localeCompare(b.path));

  const summary = {};
  for (const f of findings) {
    summary[f.sev] ??= {};
    summary[f.sev][f.rule] = (summary[f.sev][f.rule] || 0) + 1;
  }
  const report = { scope: headOnly ? 'HEAD' : 'all refs (tracked + history)', blobsScanned: blobs.length, allowed, failingFindings, summary, findings };
  if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(report, null, 2));

  console.log(`scope: ${report.scope}; blobs scanned: ${blobs.length}; allowed by reviewed exceptions: ${allowed}`);
  console.log(`findings at or above ${failOn}: ${failingFindings} (independent of --min-severity)`);
  for (const s of [...SEVERITIES].reverse()) if (summary[s]) console.log(`  ${s}: ${JSON.stringify(summary[s])}`);
  const grouped = new Map();
  for (const f of findings.filter((x) => SEVERITIES.indexOf(x.sev) >= SEVERITIES.indexOf('medium'))) {
    const k = `${f.sev}\t${f.rule}\t${f.path}\t${f.fingerprint || ''}`;
    if (!grouped.has(k)) grouped.set(k, { ...f, count: 0 });
    grouped.get(k).count++;
  }
  for (const f of grouped.values()) {
    console.log(`${f.sev.padEnd(8)} ${f.rule.padEnd(30)} ${f.path}${f.line ? `:${f.line}` : ''} ` +
      `${f.fingerprint || ''} intro=${f.introducedBy} head=${f.inHead ? 'yes' : f.pathInHead ? 'path-only' : 'no'}` +
      `${f.count > 1 ? ` x${f.count}` : ''}${f.note ? ` (${f.note})` : ''}`);
  }
  process.exitCode = failingFindings ? 1 : 0;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 2;
});
