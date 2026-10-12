import { spawnSync } from 'node:child_process';
import path from 'node:path';

function run(extra: Record<string, string> = {}) {
  const result = spawnSync(process.execPath, [path.resolve('tests/helpers/applicationShutdown.cjs')], {
    cwd: process.cwd(), encoding: 'utf8', timeout: extra.TEST_DRAIN_HANG ? 35_000 : 15_000,
    env: { ...process.env, RUN_MODE: 'api', TS_NODE_PROJECT: 'tsconfig.server.json', ...extra },
  });
  expect(result.error).toBeUndefined();
  expect(result.signal).toBeNull();
  return { ...result, events: result.stdout.trim().split('\n') };
}

test('entry point drains ingress and all workers before the error monitor and storage closure', () => {
  const result = run();
  expect(result.status).toBe(0);
  const monitor = result.events.indexOf('error-monitor:drain');
  expect(monitor).toBeGreaterThan(-1);
  expect(result.events.filter(event => event === 'error-monitor:drain')).toHaveLength(1);
  for (const worker of ['dispatch', 'critical-alert', 'alert', 'notification', 'scoring', 'audit']) {
    expect(result.events.indexOf(`${worker}:drain`)).toBeGreaterThan(result.events.indexOf('api:stop'));
    expect(result.events.indexOf(`${worker}:done`)).toBeLessThan(monitor);
  }
  expect(result.events.indexOf('error-monitor:done')).toBeLessThan(result.events.indexOf('reports:close'));
  for (const storage of ['reports:close', 'dissemination:close', 'admin-audit:close']) {
    expect(result.events.indexOf(storage)).toBeGreaterThan(monitor);
  }
});

test('entry point drains peers but exits unsuccessfully without closing storage after worker failure', () => {
  const result = run({ TEST_DRAIN_FAIL: '1' });
  expect(result.status).toBe(1);
  expect(result.events).toContain('scoring:done');
  expect(result.events).not.toContain('error-monitor:drain');
  expect(result.events).not.toContain('reports:close');
});

test('entry point cleans partially started resources and preserves startup failure exit status', () => {
  const result = run({ TEST_STARTUP_FAIL: '1' });
  expect(result.status).toBe(1);
  expect(result.events).toContain('api:stop');
  expect(result.events).toContain('reports:close');
});

test('entry point exits unsuccessfully at its real deadline when a worker never drains', () => {
  const result = run({ TEST_DRAIN_HANG: '1' });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Shutdown timed out');
  expect(result.events).not.toContain('reports:close');
}, 40_000);
