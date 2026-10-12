/**
 * The sentinel sweep must prove the owner recovery code never reaches host
 * stores or logs: it loads <sentinels>.recovery (written by
 * confidentialSentinelSubmit.ts) and searches the grouped, ungrouped and
 * lower-case forms of the code in every encoding it uses for markers.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes, webcrypto } from 'node:crypto';
import { encodeRecoveryCodeV2 } from '../../../enclave/src/confidential/recoveryCode';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const sweep = require('../../../scripts/security/confidential-sentinel-sweep.cjs');

type Hit = { location: string; label: string; encoding: string };

describe('sentinel sweep searches the owner recovery code', () => {
  let dir: string, file: string, code: string;

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    code = await encodeRecoveryCodeV2(new Uint8Array(randomBytes(32)));
  });
  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'vera-sweep-recovery-'));
    file = path.join(dir, 'sentinels.json');
    writeFileSync(file, JSON.stringify(sweep.generateSentinels()));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('loads <sentinels>.recovery and derives every form in every encoding', () => {
    writeFileSync(`${file}.recovery`, `${code}\n`, { mode: 0o600 });
    const sentinels = sweep.readSentinels(file);
    expect(sentinels.recoveryCode).toBe(code);
    const recovery = sweep.needles(sentinels).filter((item: Hit) => item.label.startsWith('recoveryCode'));
    const labels = ['recoveryCode', 'recoveryCodeUngrouped', 'recoveryCodeLower', 'recoveryCodeUngroupedLower'];
    const encodings = ['raw', 'base64', 'base64url', 'hex', 'percent', 'utf16le'];
    expect(recovery.map((item: Hit) => `${item.label}/${item.encoding}`).sort())
      .toEqual(labels.flatMap(label => encodings.map(encoding => `${label}/${encoding}`)).sort());
  });

  test.each([
    ['grouped', (value: string) => value, 'recoveryCode', 'raw'],
    ['ungrouped', (value: string) => value.replace(/-/g, ''), 'recoveryCodeUngrouped', 'raw'],
    ['lower case', (value: string) => value.toLowerCase(), 'recoveryCodeLower', 'raw'],
    ['lower case ungrouped', (value: string) => value.toLowerCase().replace(/-/g, ''), 'recoveryCodeUngroupedLower', 'raw'],
    ['hex', (value: string) => Buffer.from(value).toString('hex'), 'recoveryCode', 'hex'],
    ['base64 of the ungrouped form', (value: string) => Buffer.from(value.replace(/-/g, '')).toString('base64'), 'recoveryCodeUngrouped', 'base64'],
    ['percent-encoded lower case', (value: string) => encodeURIComponent(value.toLowerCase()), 'recoveryCodeLower', 'percent'],
  ])('detects a planted %s recovery code in a log file', (_name, encode, label, encoding) => {
    writeFileSync(`${file}.recovery`, `${code}\n`);
    const list = sweep.needles(sweep.readSentinels(file));
    const logs = path.join(dir, 'logs');
    mkdirSync(logs);
    writeFileSync(path.join(logs, 'api.log'), `{"level":"error","message":"restore ${encode(code)} failed"}\n`);
    const hits: Hit[] = sweep.searchPaths([logs], list);
    expect(hits).toEqual(expect.arrayContaining([{ location: `file:${path.join(logs, 'api.log')}`, label, encoding }]));
    // Only locations and labels are reported, never the code itself.
    expect(JSON.stringify(hits)).not.toContain(code.slice(0, 9));
  });

  test('CloudWatch search queries the recovery-code forms too', async () => {
    writeFileSync(`${file}.recovery`, `${code}\n`);
    const sentinels = sweep.readSentinels(file);
    const patterns: string[] = [];
    const hits = await sweep.searchLogGroups(['/ecs/vera-rehearsal-api'], sentinels, { region: 'us-east-2' }, async (args: string[]) => {
      const pattern = args[args.indexOf('--filter-pattern') + 1];
      patterns.push(pattern);
      return JSON.stringify({ events: pattern === `"${code.replace(/-/g, '')}"` ? [{ message: 'x' }] : [] });
    });
    expect(patterns).toEqual(expect.arrayContaining([`"${code}"`, `"${code.replace(/-/g, '')}"`, `"${code.toLowerCase()}"`]));
    expect(patterns).toHaveLength((sweep.LABELS.length + 4) * 2);
    expect(hits).toEqual([{ location: 'cloudwatch:/ecs/vera-rehearsal-api', label: 'recoveryCodeUngrouped', encoding: 'raw' }]);
  });

  test('reports whether the recovery code was searched, and rejects a malformed file without echoing it', async () => {
    const logs = path.join(dir, 'empty');
    mkdirSync(logs);
    await expect(sweep.main(['search', '--sentinels', file, '--path', logs]))
      .resolves.toEqual(expect.objectContaining({ recoveryCodeSearched: false, hits: [] }));
    writeFileSync(`${file}.recovery`, `${code}\n`);
    await expect(sweep.main(['search', '--sentinels', file, '--path', logs]))
      .resolves.toEqual(expect.objectContaining({ recoveryCodeSearched: true, hits: [] }));
    writeFileSync(`${file}.recovery`, 'not-a-code SECRETVALUE\n');
    await expect(sweep.main(['search', '--sentinels', file, '--path', logs])).rejects.toThrow('sentinel sweep: invalid recovery code file');
    await expect(sweep.main(['search', '--sentinels', file, '--path', logs])).rejects.not.toThrow(/SECRETVALUE/);
  });
});
