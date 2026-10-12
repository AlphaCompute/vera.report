const fs = require('node:fs'),
    path = require('node:path'),
    os = require('node:os'),
    crypto = require('node:crypto'),
    { execFileSync } = require('node:child_process');
const timings = [];
let webFiles = [];
exports.setWebFiles = (files) => {
    webFiles = files.map((file) => ({ name: file.name, mime: file.mime, bytes: file.bytes.length }));
};
exports.measure = (stage, ms, source) => timings.push({ stage, source, milliseconds: Math.round(ms * 100) / 100 });
exports.write = (directory) => {
    if (!directory) return;
    fs.mkdirSync(directory, { recursive: true });
    const source = process.env.MVP_SOURCE_SNAPSHOT
        ? JSON.parse(process.env.MVP_SOURCE_SNAPSHOT)
        : {
              commit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
              dirty: !!execFileSync('git', ['status', '--porcelain'], { encoding: 'utf8' }).trim(),
          };
    const evidence = {
        schemaVersion: 1,
        recordedAt: new Date().toISOString(),
        commit: source.commit,
        dirty: source.dirty,
        sourceCapturedBeforeBuild: !!process.env.MVP_SOURCE_SNAPSHOT,
        environment: 'synthetic-local',
        scope: 'Retained legacy API endpoints; current encrypted browser evidence is recorded separately in encrypted-browser',
        network: 'none',
        runtime: {
            node: process.version,
            platform: os.platform(),
            architecture: os.arch(),
            cpu: os.cpus()[0]?.model,
            cpuCount: os.cpus().length,
            memoryBytes: os.totalmem(),
        },
        workload: {
            description: 'Synthetic workplace report; API intake uses tagged fixtures, concurrency probe uses CSV',
            webFiles,
            fileBytes: Buffer.byteLength('date,event\n2026-01-01,synthetic-test\n'),
            concurrency: [1, 2, 4],
        },
        real: [
            'HTTP intake routes',
            'MongoDB restart',
            'evidence encryption/decryption',
            'mandatory metadata processing and independent content checks',
            'authorization and legal handling',
        ],
        substituted: [
            'Shroud inference result',
            'IPFS transport',
            'email delivery',
            'notification delivery',
        ],
        unmeasured: [
            'real Shroud latency',
        ],
        thresholds: { status: 'not agreed', note: 'No contractual performance threshold has been invented.' },
        timings,
    };
    fs.writeFileSync(path.join(directory, 'measurements.json'), JSON.stringify(evidence, null, 2) + '\n');
    const files = fs
        .readdirSync(directory)
        .filter((f) => !f.endsWith('.sha256') && fs.statSync(path.join(directory, f)).isFile());
    fs.writeFileSync(
        path.join(directory, 'SHA256SUMS'),
        files
            .filter((f) => f !== 'SHA256SUMS')
            .map(
                (f) =>
                    crypto
                        .createHash('sha256')
                        .update(fs.readFileSync(path.join(directory, f)))
                        .digest('hex') +
                    '  ' +
                    f,
            )
            .join('\n') + '\n',
    );
};
