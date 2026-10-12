import { spawnSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(__dirname, '../../..');

describe('housekeeping lifecycle', () => {
  it.each(['errorMonitor', 'cache'])('%s permits normal process exit after import', name => {
    const child = spawnSync(process.execPath, [
      '-r', require.resolve('ts-node/register/transpile-only'),
      '-e', `require(${JSON.stringify(path.join(root, 'src/utils', name))}); process.stdout.write('imported');`,
    ], {
      cwd: root,
      env: { ...process.env, NODE_ENV: 'test' },
      encoding: 'utf8',
      timeout: 10_000,
    });
    expect(child.error).toBeUndefined();
    expect(child.stderr).toBe('');
    expect(child.stdout).toBe('imported');
    expect(child.status).toBe(0);
    expect(child.signal).toBeNull();
  });
});
