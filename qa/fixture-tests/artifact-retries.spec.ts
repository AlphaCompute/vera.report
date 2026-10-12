import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { type AddressInfo } from 'node:net';
import * as path from 'node:path';
import { promisify } from 'node:util';

type Attempt = {
  status: string;
  attachments: Array<{ name: string; path?: string; body?: string }>;
};
type Suite = {
  specs?: Array<{ tests: Array<{ results: Attempt[] }> }>;
  suites?: Suite[];
};

// This runs a real staging spec against loopback, not Auth0 or deployed staging.
test('failed and retried API checks retain separate findings', async ({}, testInfo) => {
  let requests = 0;
  const server = createServer((request, response) => {
    if (request.url !== '/api/whistleblower/status/NOT-A-VALID-ID') {
      response.writeHead(404).end();
      return;
    }
    requests++;
    response.writeHead(requests === 1 ? 500 : 400, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: 'synthetic validation fixture' }));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const reportPath = testInfo.outputPath('retry-report.json');
    await promisify(execFile)(process.execPath, [
      require.resolve('@playwright/test/cli'), 'test',
      '--config', path.resolve(__dirname, '../staging.config.ts'),
      'api-checks.spec.ts', '--grep', 'invalid tracking ID format',
      '--retries', '1', '--reporter', 'json',
      '--output', testInfo.outputPath('attempts'),
    ], {
      cwd: path.resolve(__dirname, '..'),
      timeout: 30_000,
      env: {
        ...process.env,
        QA_STAGING_URL: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        PLAYWRIGHT_JSON_OUTPUT_NAME: reportPath,
      },
    });
    const report = JSON.parse(await readFile(reportPath, 'utf8')) as { suites: Suite[] };
    const attempts: Attempt[] = [];
    const visit = (suite: Suite) => {
      for (const spec of suite.specs ?? []) {
        for (const result of spec.tests) attempts.push(...result.results);
      }
      for (const child of suite.suites ?? []) visit(child);
    };
    report.suites.forEach(visit);
    expect(attempts.map(attempt => attempt.status)).toEqual(['failed', 'passed']);
    const logs = await Promise.all(attempts.map(async attempt => {
      const attachment = attempt.attachments.find(item => item.name === 'api-checks-findings');
      expect(attachment).toBeDefined();
      return attachment!.path
        ? readFile(attachment!.path, 'utf8')
        : Buffer.from(attachment!.body!, 'base64').toString('utf8');
    }));
    expect(logs[0]).toContain('500');
    expect(logs[0]).not.toContain('400');
    expect(logs[1]).toContain('400');
    expect(logs[1]).not.toContain('500');
    expect(requests).toBe(2);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
