#!/usr/bin/env node
// Synthetic local acceptance only. No real inference or chain transport.
// Record current encrypted browser intake and separately validate the retained legacy API.
const { spawnSync, execFileSync } = require('node:child_process');
const fs = require('node:fs'),
    path = require('node:path'),
    crypto = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const source = {
    commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    dirty: !!execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim(),
};
const output = path.resolve(root, 'artifacts/delivery', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(output, { recursive: true });
function run(command, args, extra = {}) {
    const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', env: { ...process.env, ...extra } });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`${command} failed (${result.status}); evidence is incomplete: ${output}`);
}
run('ffmpeg', ['-version']);
run('pdftoppm', ['-v']);
run('pdftotext', ['-v']);
if (!fs.existsSync(path.join(root, 'qa/node_modules/@playwright/test')))
    run('npm', ['ci', '--prefix', 'qa', '--legacy-peer-deps']);
run(process.execPath, [path.join(root, 'qa/node_modules/@playwright/test/cli.js'), 'install', 'chromium']);
run('npm', ['test', '--', '--runInBand', '--forceExit', '--testPathPatterns=mvpCoreLoop'], {
    MVP_SOURCE_SNAPSHOT: JSON.stringify(source),
    MVP_BROWSER_ACCEPTANCE: 'false',
    MVP_EVIDENCE_DIR: output,
    MVP_DISABLE_WEBGL: 'true',
});
const browserOutput = path.join(output, 'encrypted-browser');
run(process.execPath, [path.join(root, 'qa/node_modules/@playwright/test/cli.js'), 'test',
    '--config', 'qa/playwright.e2e.config.ts', 'confidential-journey.spec.ts',
    '--grep', 'reporter submits a confidential report and saves the recovery file$', '--output', browserOutput], {
    VERA_E2E_VIDEO_DIR: browserOutput,
});
fs.writeFileSync(path.join(output, 'browser-scope.json'), JSON.stringify({
    journey: 'Current encrypted reporter intake, evidence upload, required contact, and local recovery download',
    real: ['Browser UI', 'confidential HTTP API', 'MongoDB', 'enclave composition', 'host plaintext leak sweep'],
    synthetic: ['Nitro attestation', 'identity-provider responses'],
    legacyApiEvidence: 'measurements.json and metadata-checks.json validate retained API endpoints, not current browser intake',
}, null, 2));
run(process.execPath, [path.join(__dirname, 'security-report.cjs'), output]);
const evidence = JSON.parse(fs.readFileSync(path.join(output, 'measurements.json')));
fs.writeFileSync(
    path.join(output, 'HANDOVER.md'),
    `# VERA local delivery evidence\n\nCommit: ${evidence.commit}; dirty: ${evidence.dirty}.\n\nVideo shows the current encrypted reporter intake and recovery download with synthetic Nitro attestation. Separate API checks validate retained legacy endpoints, metadata processing and local one-use legal packets. The browser does not use these legacy intake endpoints. Shroud result, chain proof/finality, IPFS transport and email are substituted. See measurements.json and concurrency.json for the measured workload and failures. No contractual latency target has been agreed.\n\nThis is not an independent penetration test, stakeholder signoff, live inference benchmark or production cutover. Refer to docs/security/README.md and qa/e2e/README.md in the matching source revision. Upload selected videos to your private handover service only after reviewing them.\n`,
);
const names = fs.readdirSync(output, { recursive: true }).filter((n) => n !== 'SHA256SUMS' && fs.statSync(path.join(output, n)).isFile()).sort();
fs.writeFileSync(
    path.join(output, 'SHA256SUMS'),
    names
        .map(
            (n) =>
                crypto
                    .createHash('sha256')
                    .update(fs.readFileSync(path.join(output, n)))
                    .digest('hex') +
                '  ' +
                n,
        )
        .join('\n') + '\n',
);
console.log(`Delivery evidence: ${output}`);
