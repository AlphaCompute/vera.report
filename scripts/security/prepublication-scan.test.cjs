'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const scanner = path.join(__dirname, 'prepublication-scan.cjs');
const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim();

function fixture(t, files = { 'first.txt': 'hello\n', 'second.txt': 'world\n' }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prepublication-scan-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const repo = path.join(dir, 'repo');
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(repo);
  fs.mkdirSync(bin);
  const git = (...args) => execFileSync(realGit, args, {
    cwd: repo, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  });
  git('init', '--quiet');
  for (const [name, contents] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(repo, name)), { recursive: true });
    fs.writeFileSync(path.join(repo, name), contents);
  }
  git('add', '.');
  git('-c', 'user.name=Scanner QA', '-c', 'user.email=scanner@example.com',
    '-c', 'commit.gpgSign=false', 'commit', '--quiet', '--allow-empty', '-m', 'Scanner fixture');

  // Forward real Git commands, corrupting only the requested batch response.
  fs.writeFileSync(path.join(bin, 'git'), `#!${process.execPath}
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const args = process.argv.slice(2);
const mode = process.env.SCANNER_GIT_MODE;
const batch = args.includes('--batch');
if (batch && mode === 'early-close') process.exit(1);
if (batch && mode === 'signal') process.kill(process.pid, 'SIGTERM');
const result = spawnSync(${JSON.stringify(realGit)}, args, {
  input: args[0] === 'cat-file' ? fs.readFileSync(0) : undefined,
  maxBuffer: 10 * 1024 * 1024,
});
if (result.error || result.signal) process.exit(2);
let output = result.stdout;
if (batch) {
  const nl = output.indexOf(10);
  const [sha, type, size] = output.subarray(0, nl).toString().split(' ');
  const firstEnd = nl + 1 + Number(size) + 1;
  const header = (value) => Buffer.concat([Buffer.from(value + '\\n'), output.subarray(nl + 1)]);
  if (mode === 'empty') output = Buffer.alloc(0);
  if (mode === 'missing') output = Buffer.from(sha + ' missing\\n');
  if (mode === 'malformed') output = header('invalid-header');
  if (mode === 'wrong-sha') output = header('0'.repeat(sha.length) + ' blob ' + size);
  if (mode === 'wrong-type') output = header(sha + ' tree ' + size);
  if (mode === 'wrong-size') output = header(sha + ' blob ' + (Number(size) + 1));
  if (mode === 'negative-size') output = header(sha + ' blob -1');
  if (mode === 'unsafe-size') output = header(sha + ' blob 9007199254740992');
  if (mode === 'partial-header') output = output.subarray(0, 10);
  if (mode === 'partial-body') output = output.subarray(0, nl + 2);
  if (mode === 'missing-delimiter') output = output.subarray(0, firstEnd - 1);
  if (mode === 'bad-delimiter') output[firstEnd - 1] = 33;
  if (mode === 'missing-blob') output = output.subarray(0, firstEnd);
  if (mode === 'extra-blob') output = Buffer.concat([output, output.subarray(0, firstEnd)]);
  if (mode === 'trailing-data') output = Buffer.concat([output, Buffer.from('unexpected')]);
  if (mode === 'stderr-failure') process.stderr.write('PRIVATE-DIAGNOSTIC-MARKER\\n'.repeat(10000));
  if (mode === 'chunked') {
    let i = 0;
    const write = () => {
      if (i < output.length) { process.stdout.write(output.subarray(i, i + 3)); i += 3; setImmediate(write); }
    };
    write();
  } else process.stdout.write(output);
  process.exitCode = mode === 'nonzero' || mode === 'stderr-failure' ? 1 : result.status;
} else {
  if (args[0] === 'log' && args.includes('-z')) {
    if (mode === 'paths-truncated') output = output.subarray(0, output.length - 1);
    if (mode === 'paths-missing-name') output = Buffer.from(output.toString().split('\\0')[0] + '\\0');
    if (mode === 'paths-malformed') output = Buffer.from('invalid-header\\0file.txt\\0');
  }
  if (args.some((arg) => arg.startsWith('--batch-check='))) {
    const lines = output.toString().trimEnd().split('\\n');
    if (mode === 'inventory-missing') lines[0] = lines[0].split(' ')[0] + ' missing';
    if (mode === 'inventory-truncated') lines.pop();
    if (mode === 'inventory-wrong-sha') lines[0] = '0'.repeat(40) + ' blob 6';
    output = Buffer.from(lines.join('\\n') + '\\n');
  }
  process.stdout.write(output);
  process.stderr.write(result.stderr);
  process.exitCode = result.status;
}
`, { mode: 0o755 });

  return {
    dir, repo, git,
    run(args = [], mode = '', options = {}) {
      const json = path.join(dir, 'report.json');
      if (!options.keepReport) fs.rmSync(json, { force: true });
      const result = spawnSync(process.execPath, [scanner, ...(options.defaultRepo ? [] : ['--repo', options.repo || repo]), '--json', json, ...args], {
        cwd: options.cwd || repo, encoding: 'utf8', timeout: 15000,
        env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, SCANNER_GIT_MODE: mode },
      });
      assert.ifError(result.error);
      assert.equal(result.signal, null);
      return { ...result, report: fs.existsSync(json) ? JSON.parse(fs.readFileSync(json, 'utf8')) : null };
    },
  };
}

for (const headOnly of [false, true]) {
  test(`clean ${headOnly ? 'HEAD' : 'history'} scan completes with real Git`, (t) => {
    const f = fixture(t, { 'empty.txt': '', 'utf8.txt': '\u00e9\n', 'binary.bin': Buffer.from([0, 10, 255]) });
    const result = f.run(headOnly ? ['--head-only'] : []);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.report.blobsScanned, 3);
    assert.deepEqual(result.report.findings, []);
  });

  test(`empty ${headOnly ? 'HEAD' : 'history'} scan needs no batch reader`, (t) => {
    const result = fixture(t, {}).run(headOnly ? ['--head-only'] : [], 'early-close');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.report.blobsScanned, 0);
  });
}

test('handles headers and blob bodies split across chunks', (t) => {
  const result = fixture(t).run(['--head-only'], 'chunked');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.blobsScanned, 2);
});

for (const mode of [
  'early-close', 'signal', 'nonzero', 'stderr-failure', 'empty', 'missing', 'malformed',
  'wrong-sha', 'wrong-type', 'wrong-size', 'negative-size', 'unsafe-size', 'partial-header',
  'partial-body', 'missing-delimiter', 'bad-delimiter', 'missing-blob', 'extra-blob', 'trailing-data',
  'inventory-missing', 'inventory-truncated', 'inventory-wrong-sha',
]) {
  test(`fails closed without a completed report: ${mode}`, (t) => {
    const result = fixture(t).run(mode.startsWith('inventory-') ? [] : ['--head-only'], mode);
    assert.equal(result.status, 2, result.stdout + result.stderr);
    assert.equal(result.report, null);
    assert.doesNotMatch(result.stdout, /blobs scanned:/);
    assert.match(result.stderr, /git|blob/i);
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE-DIAGNOSTIC-MARKER/);
  });
}

for (const mode of ['paths-truncated', 'paths-missing-name', 'paths-malformed']) {
  test(`invalid history path inventory fails closed: ${mode}`, (t) => {
    const result = fixture(t).run([], mode);
    assert.equal(result.status, 2, result.stdout + result.stderr);
    assert.equal(result.report, null);
    assert.match(result.stderr, /git path inventory/i);
  });
}

test('display filtering cannot hide a failing high-severity finding', (t) => {
  const result = fixture(t, { '.env': 'SETTING=1\n' })
    .run(['--head-only', '--min-severity', 'critical', '--fail-on', 'high']);
  assert.equal(result.status, 1, result.stderr);
  assert.deepEqual(result.report.findings, []);
  assert.equal(result.report.failingFindings, 1);
});

test('reviewed allowlist exceptions remain excluded from failure decisions', (t) => {
  const f = fixture(t, { '.env': 'SETTING=1\n' });
  const allow = path.join(f.dir, 'allow.json');
  fs.writeFileSync(allow, JSON.stringify([{ rule: 'dotenv-file', path: '.env', reason: 'Synthetic fixture' }]));
  const result = f.run(['--head-only', '--allow', allow, '--min-severity', 'critical']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.allowed, 1);
  assert.equal(result.report.failingFindings, 0);
});

test('history checks every path for shared blobs across commits, including removed aliases', (t) => {
  const f = fixture(t, { '.env.example': 'SETTING=1\n', 'source.txt': 'hello\n', 'empty.txt': '' });
  const aliases = {
    '.env': 'SETTING=1\n', '.env.production': '',
    '.next/output with spaces.txt': 'hello\n', 'docs/handover/notes.md': 'hello\n',
  };
  for (const [name, content] of Object.entries(aliases)) {
    fs.mkdirSync(path.dirname(path.join(f.repo, name)), { recursive: true });
    fs.writeFileSync(path.join(f.repo, name), content);
  }
  const commit = message => f.git('-c', 'user.name=Scanner QA', '-c', 'user.email=scanner@example.com',
    '-c', 'commit.gpgSign=false', 'commit', '--quiet', '-m', message);
  f.git('add', '.');
  commit('Add aliases');
  f.git('mv', '.env', '.env.local');
  commit('Rename alias');
  f.git('rm', '.env.local', '.env.production', '.next/output with spaces.txt', 'docs/handover/notes.md');
  commit('Remove aliases');
  const result = f.run();
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.report.blobsScanned, 3, 'shared blob contents are scanned once');
  assert.deepEqual(result.report.findings.map(finding => finding.path).sort(),
    [...Object.keys(aliases), '.env.local'].sort());
  assert.ok(result.report.findings.every(finding => finding.pathInHead === false));
  const head = f.run(['--head-only']);
  assert.equal(head.status, 0, head.stderr);
  assert.deepEqual(head.report.findings, []);
});

test('history includes shared-blob paths introduced only by a merge commit', (t) => {
  const f = fixture(t, { '.env.example': 'SETTING=1\n' });
  const main = f.git('branch', '--show-current').trim();
  const commit = message => f.git('-c', 'user.name=Scanner QA', '-c', 'user.email=scanner@example.com',
    '-c', 'commit.gpgSign=false', 'commit', '--quiet', '-m', message);
  f.git('checkout', '--quiet', '-b', 'side');
  fs.writeFileSync(path.join(f.repo, 'side.txt'), 'side\n');
  f.git('add', '.'); commit('Side');
  f.git('checkout', '--quiet', main);
  fs.writeFileSync(path.join(f.repo, 'main.txt'), 'main\n');
  f.git('add', '.'); commit('Main');
  f.git('-c', 'user.name=Scanner QA', '-c', 'user.email=scanner@example.com', 'merge', '--no-commit', '--no-ff', 'side');
  fs.writeFileSync(path.join(f.repo, '.env'), 'SETTING=1\n');
  f.git('add', '.'); commit('Merge with alias');
  f.git('rm', '.env'); commit('Remove alias');
  f.git('config', 'log.diffMerges', 'combined');
  const result = f.run();
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.report.blobsScanned, 3);
  assert.ok(result.report.findings.some(finding => finding.rule === 'dotenv-file' && finding.path === '.env'));
});

test('findings below fail-on remain visible without failing the scan', (t) => {
  const result = fixture(t, { '.env': 'SETTING=1\n' }).run(['--head-only', '--fail-on', 'critical']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.findings[0].rule, 'dotenv-file');
  assert.equal(result.report.failingFindings, 0);
});

test('full history catches a finding removed from HEAD', (t) => {
  const f = fixture(t, { '.env': 'SETTING=1\n' });
  f.git('rm', '.env');
  f.git('-c', 'user.name=Scanner QA', '-c', 'user.email=scanner@example.com',
    '-c', 'commit.gpgSign=false', 'commit', '--quiet', '-m', 'Remove fixture');
  assert.equal(f.run(['--head-only']).status, 0);
  const result = f.run();
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.report.findings[0].inHead, false);
});

test('history checks every path when several files share one blob', (t) => {
  const result = fixture(t, {
    '.env': '', '.env.example': '', '.next/output.js': '', 'docs/handover/notes.md': '',
  }).run();
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.report.blobsScanned, 1);
  for (const [rule, name] of [
    ['dotenv-file', '.env'], ['nextjs-build-output', '.next/output.js'],
    ['internal-evidence-document', 'docs/handover/notes.md'],
  ]) assert.ok(result.report.findings.some(f => f.rule === rule && f.path === name), `${rule}: ${name}`);
});

test('history retains a sensitive path after a content-preserving rename', (t) => {
  const f = fixture(t, { '.env': 'SETTING=1\n' });
  f.git('mv', '.env', 'settings.txt');
  f.git('-c', 'user.name=Scanner QA', '-c', 'user.email=scanner@example.com',
    '-c', 'commit.gpgSign=false', 'commit', '--quiet', '-m', 'Rename fixture');
  assert.equal(f.run(['--head-only']).status, 0);
  const result = f.run();
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.report.blobsScanned, 1);
  const finding = result.report.findings.find(f => f.rule === 'dotenv-file');
  assert.equal(finding.path, '.env');
  assert.equal(finding.inHead, true);
  assert.equal(finding.pathInHead, false);
});

test('history includes aliases reachable only from another branch', (t) => {
  const f = fixture(t, { 'settings.txt': 'SETTING=1\n' });
  const original = f.git('branch', '--show-current').trim();
  f.git('checkout', '--quiet', '-b', 'other');
  f.git('mv', 'settings.txt', '.env');
  f.git('-c', 'user.name=Scanner QA', '-c', 'user.email=scanner@example.com',
    '-c', 'commit.gpgSign=false', 'commit', '--quiet', '-m', 'Other branch alias');
  f.git('checkout', '--quiet', original);
  assert.equal(f.run(['--head-only']).status, 0);
  const result = f.run();
  assert.equal(result.status, 1, result.stderr);
  assert.ok(result.report.findings.some(f => f.rule === 'dotenv-file' && f.path === '.env' && !f.pathInHead));
});

test('HEAD path metadata does not follow uncommitted index renames', (t) => {
  const f = fixture(t, { '.env': 'SETTING=1\n' });
  f.git('mv', '.env', 'settings.txt');
  const result = f.run(['--head-only']);
  assert.equal(result.status, 1, result.stderr);
  assert.ok(result.report.findings.some(f => f.rule === 'dotenv-file' && f.path === '.env' && f.pathInHead));
});

for (const headOnly of [false, true]) {
  test(`path rules preserve unusual filenames in ${headOnly ? 'HEAD' : 'history'}`, (t) => {
    const name = 'odd\tline\n\u00e9/.env';
    const result = fixture(t, { [name]: 'SETTING=1\n' }).run(headOnly ? ['--head-only'] : []);
    assert.equal(result.status, 1, result.stderr);
    assert.ok(result.report.findings.some(f => f.rule === 'dotenv-file' && f.path === name && f.pathInHead));
  });
}

test('an allowed content path cannot suppress a second path for the same blob', (t) => {
  const contents = ['AWS_SECRET_ACCESS_KEY=', 'AbCdEfGhIjKlMnOpQrSt', 'UvWxYz0123456789abcd', '\n'].join('');
  const f = fixture(t, { 'a-reviewed.txt': contents, 'z-unreviewed.txt': contents });
  const allow = path.join(f.dir, 'allow.json');
  fs.writeFileSync(allow, JSON.stringify([{ rule: 'aws-secret-access-key', path: 'a-reviewed.txt' }]));
  const result = f.run(['--allow', allow]);
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.report.blobsScanned, 1);
  assert.equal(result.report.allowed, 1);
  assert.ok(result.report.findings.some(f => f.rule === 'aws-secret-access-key' && f.path === 'z-unreviewed.txt'));
});

for (const [name, value] of [
  ['missing file', undefined], ['invalid JSON', 'PRIVATE-ALLOWLIST-MARKER'],
  ['object', '{}'], ['null', 'null'], ['null entry', '[null]'], ['string entry', '["rule"]'],
  ['array entry', '[[]]'], ['missing rule', '[{"path":".env"}]'],
  ['missing selector', '[{"rule":"dotenv-file"}]'],
  ['non-string rule', '[{"rule":1,"path":".env"}]'],
  ['non-string path', '[{"rule":"dotenv-file","path":1}]'],
  ['non-string fingerprint', '[{"rule":"dotenv-file","fingerprint":true}]'],
  ['empty rule', '[{"rule":"","path":".env"}]'],
  ['empty selector', '[{"rule":"dotenv-file","path":""}]'],
]) {
  test(`invalid allowlist fails closed without a report: ${name}`, (t) => {
    const f = fixture(t);
    const allow = path.join(f.dir, 'allow.json');
    if (value !== undefined) fs.writeFileSync(allow, value);
    const result = f.run(['--allow', allow]);
    assert.equal(result.status, 2, result.stdout + result.stderr);
    assert.equal(result.report, null);
    assert.match(result.stderr, /allowlist/i);
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE-ALLOWLIST-MARKER/);
  });
}

test('an allowlist option without a path fails closed', (t) => {
  const result = fixture(t).run(['--allow']);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(result.report, null);
});

test('line-context placeholder words cannot suppress a real secret value', (t) => {
  // Assemble at runtime so static secret scanners do not treat the fixture source as a leak.
  const leak = ['AWS_SECRET_ACCESS_KEY=', 'AbCdEfGhIjKlMnOpQrSt', 'UvWxYz0123456789abcd', ' // example\n'].join('');
  const result = fixture(t, { 'leak.env': leak }).run(['--head-only']);
  assert.equal(result.status, 1, result.stderr);
  assert.ok(result.report.failingFindings >= 1);
  assert.ok(result.report.findings.some((f) => f.rule === 'aws-secret-access-key'));
});

for (const headOnly of [true, false]) {
  test(`uppercase secret assignments are reported in ${headOnly ? 'HEAD' : 'history'} scans`, (t) => {
    // The reported synthetic value is assembled so this test is not itself a credential assignment.
    const value = ['JBSWY3DPEHPK3PXP', '5P2A7Q9ZK4M6N8R2'].join('');
    const f = fixture(t, { 'settings.txt': `INTERNAL_API_SECRET=${value}\n` });
    const scope = headOnly ? ['--head-only'] : [];
    const result = f.run([...scope, '--fail-on', 'medium']);
    assert.equal(result.report.findings.length, 1, result.stdout + result.stderr);
    assert.equal(result.report.findings[0].rule, 'generic-secret-assignment');
    assert.equal(result.report.findings[0].path, 'settings.txt');
    assert.equal(result.report.findings[0].sev, 'medium');
    assert.equal(result.report.failingFindings, 1);
    assert.equal(result.status, 1);
    assert.ok(!(result.stdout + result.stderr + JSON.stringify(result.report)).includes(value));
    // The default high threshold still reports the medium finding without failing.
    const defaultThreshold = f.run(scope);
    assert.equal(defaultThreshold.status, 0, defaultThreshold.stderr);
    assert.equal(defaultThreshold.report.findings[0].rule, 'generic-secret-assignment');
    assert.equal(defaultThreshold.report.failingFindings, 0);
  });
}

test('placeholder markers in the matched value itself still suppress findings', (t) => {
  const result = fixture(t, {
    'synth.env': 'AWS_SECRET_ACCESS_KEY=changemechangemechangemechangemechange1\n',
  }).run(['--head-only']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.failingFindings, 0);
  assert.ok(!result.report.findings.some((f) => f.rule === 'aws-secret-access-key'));
});

for (const args of [['--fail-on', 'hgh'], ['--min-severity', 'wrong'], ['--fail-on']]) {
  test(`invalid severity fails closed: ${args.join(' ')}`, (t) => {
    const result = fixture(t).run(args);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(result.report, null);
  });
}

for (const headOnly of [false, true]) {
  for (const defaultRepo of [false, true]) {
    test(`subdirectory scan keeps root paths and HEAD flags (${headOnly}, cwd=${defaultRepo})`, t => {
      const f = fixture(t, { '.env': 'SETTING=1\n', 'scripts/clean.txt': 'hello\n' });
      const subdirectory = path.join(f.repo, 'scripts');
      const result = f.run(headOnly ? ['--head-only'] : [], '',
        { repo: subdirectory, cwd: subdirectory, defaultRepo });
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(result.report.blobsScanned, 2);
      assert.ok(result.report.findings.some(f => f.rule === 'dotenv-file' && f.path === '.env' && f.inHead && f.pathInHead));
    });
  }
}

for (const failure of ['allowlist', 'severity', 'git', 'repo']) {
  test(`invalid ${failure} clears a stale report from a previous successful scan`, t => {
    const f = fixture(t);
    const passed = f.run(['--head-only']);
    assert.equal(passed.status, 0);
    assert.equal(passed.report.failingFindings, 0);
    const args = failure === 'allowlist' ? ['--allow', path.join(f.dir, 'missing.json')]
      : failure === 'severity' ? ['--fail-on', 'unknown'] : failure === 'repo' ? ['--repo'] : [];
    const result = f.run(args, failure === 'git' ? 'early-close' : '', { keepReport: true, defaultRepo: failure === 'repo' });
    assert.equal(result.status, 2, result.stderr);
    assert.equal(result.report, null);
  });
}
