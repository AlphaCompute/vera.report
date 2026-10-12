import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

// enclave/dist is gitignored and not rebuilt by `node --test` or jest, so suites
// that load it must refuse to run when it is older than enclave/src.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { staleEnclaveModules, assertEnclaveDistFresh } = require('../../../scripts/security/enclave-dist-freshness.cjs');

const ROOT = path.resolve(__dirname, '../../..');

describe('enclave dist freshness guard', () => {
  let dir: string;
  const at = (seconds: number) => new Date(1_800_000_000_000 + seconds * 1000);
  const put = (relative: string, seconds: number) => {
    const file = path.join(dir, relative);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, '');
    utimesSync(file, at(seconds), at(seconds));
  };

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'vera-enclave-dist-'));
    put('tsconfig.json', 0);
    put('src/server.ts', 10);
    put('src/confidential/releaseWithdrawals.ts', 10);
    put('src/types.d.ts', 50);
    put('dist/server.js', 20);
    put('dist/confidential/releaseWithdrawals.js', 20);
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('passes when every compiled module is at least as new as its source', () => {
    expect(staleEnclaveModules(dir)).toEqual([]);
    expect(() => assertEnclaveDistFresh(dir)).not.toThrow();
  });

  test('fails when a source file is newer than its compiled module', () => {
    put('src/confidential/releaseWithdrawals.ts', 30);
    expect(staleEnclaveModules(dir)).toEqual([path.join('confidential', 'releaseWithdrawals.ts') + ' (source is newer)']);
    expect(() => assertEnclaveDistFresh(dir)).toThrow(/out of date.*releaseWithdrawals\.ts.*npm run build:enclave/);
  });

  test('fails when a source file has never been compiled', () => {
    put('src/legal/enrollment.ts', 5);
    expect(staleEnclaveModules(dir)).toEqual([path.join('legal', 'enrollment.ts') + ' (not compiled)']);
    expect(() => assertEnclaveDistFresh(dir)).toThrow(/not compiled/);
  });

  test('fails when the compiler configuration changed after the build', () => {
    put('tsconfig.json', 25);
    expect(staleEnclaveModules(dir)).toHaveLength(2);
  });

  test('every suite that loads enclave/dist checks freshness before loading it', () => {
    const guard = "require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();";
    const runtime = path.join(ROOT, 'tests/confidential-runtime');
    const suites = readdirSync(runtime).filter((f) => f.endsWith('.test.cjs'));
    expect(suites.length).toBeGreaterThan(0);
    for (const suite of suites) {
      const lines = readFileSync(path.join(runtime, suite), 'utf8').split('\n');
      const guardLine = lines.findIndex((l) => l.includes(guard));
      const firstLoad = lines.findIndex((l) => /require\(|enclaveRequire|createRequire\(/.test(l) && !/node:/.test(l) && !l.includes(guard) && !l.includes('attestation-fixture'));
      expect({ suite, guarded: guardLine >= 0 }).toEqual({ suite, guarded: true });
      expect({ suite, beforeLoad: guardLine < firstLoad || firstLoad < 0 }).toEqual({ suite, beforeLoad: true });
    }

  });

  test('the runtime script builds the enclave before running the compiled suites', () => {
    const scripts = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8')).scripts;
    expect(scripts['build:enclave']).toMatch(/tsc(\.js)? -p enclave\/tsconfig\.json/);
    expect(scripts['test:runtime']).toMatch(/^npm run build:enclave && node --test tests\/confidential-runtime\//);
  });
});
