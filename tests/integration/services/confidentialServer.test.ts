/**
 * Confidential-only run mode (RUN_MODE=confidential): the process that serves
 * /api/confidential/* without any legacy secret, service or configuration.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import ts from 'typescript';
import type { AddressInfo } from 'node:net';
import { createServer as createTcpServer } from 'node:net';
import type { Server } from 'node:http';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import {
  LEGACY_SECRET_VARIABLES, confidentialServerConfigurationError, createConfidentialApp,
} from '../../../src/confidentialServer';
import { requestRateLimitKey } from '../../../src/utils/proxyRateLimit';

const ROOT = path.resolve(__dirname, '../../..');
const ADMIN_SECRET = 'a'.repeat(48);
const baseEnv = (extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({
  RUN_MODE: 'confidential', CONFIDENTIAL_CASES_ENABLED: 'true', NODE_ENV: 'test',
  CONFIDENTIAL_MONGODB_URI: 'mongodb://127.0.0.1:1/unused', CONFIDENTIAL_ADMIN_SECRET: ADMIN_SECRET, ...extra,
});

describe('confidential-only configuration', () => {
  test('accepts only the confidential inputs', () => {
    expect(confidentialServerConfigurationError(baseEnv())).toBeUndefined();
    expect(confidentialServerConfigurationError(baseEnv({ RUN_MODE: 'api' }))).toBe('RUN_MODE must be confidential');
    expect(confidentialServerConfigurationError(baseEnv({ CONFIDENTIAL_CASES_ENABLED: 'false' }))).toBe('CONFIDENTIAL_CASES_ENABLED must be true');
    expect(confidentialServerConfigurationError(baseEnv({ CONFIDENTIAL_MONGODB_URI: '' }))).toBe('CONFIDENTIAL_MONGODB_URI is required');
    expect(confidentialServerConfigurationError(baseEnv({ CONFIDENTIAL_ADMIN_SECRET: 'short' }))).toMatch(/at least 32/);
  });

  test('refuses to start with any legacy secret present, naming variables but never values', () => {
    for (const name of LEGACY_SECRET_VARIABLES) {
      const message = confidentialServerConfigurationError(baseEnv({ [name]: 'SENTINEL-LEGACY-VALUE' }));
      expect(message).toContain(name);
      expect(message).not.toContain('SENTINEL-LEGACY-VALUE');
    }
  });

  test('worker signing and socket custody never reach the backend, and its API credential is independent', () => {
    for (const name of ['SLACK_APPLICATION_APP_TOKEN', 'SLACK_APPLICATION_BOT_TOKEN', 'LEGAL_APPROVAL_KEY_FILE', 'LEGAL_APPROVAL_JOURNAL']) {
      expect(confidentialServerConfigurationError(baseEnv({ [name]: 'worker-only' }))).toMatch(/must not reach/);
    }
    for (const secret of ['short', ADMIN_SECRET]) {
      expect(confidentialServerConfigurationError(baseEnv({ LEGAL_APPROVAL_BACKEND_SECRET: secret }))).toMatch(/distinct secret/);
    }
    expect(confidentialServerConfigurationError(baseEnv({ LEGAL_APPROVAL_BACKEND_SECRET: 'w'.repeat(48) }))).toBeUndefined();
  });

  test('under NODE_ENV=production only the prod, staging and rehearsal stacks may run it', () => {
    expect(confidentialServerConfigurationError(baseEnv({ NODE_ENV: 'production' })))
      .toMatch(/requires DEPLOY_ENV to be prod, staging or rehearsal/);
    expect(confidentialServerConfigurationError(baseEnv({ NODE_ENV: 'production', DEPLOY_ENV: 'production' })))
      .toMatch(/requires DEPLOY_ENV/);
    expect(confidentialServerConfigurationError(baseEnv({ NODE_ENV: 'production', DEPLOY_ENV: 'prod' }))).toBeUndefined();
    expect(confidentialServerConfigurationError(baseEnv({ NODE_ENV: 'production', DEPLOY_ENV: 'rehearsal' }))).toBeUndefined();
    expect(confidentialServerConfigurationError(baseEnv({ NODE_ENV: 'production', DEPLOY_ENV: 'staging' }))).toBeUndefined();
    // The confidential-only checks still apply in production.
    expect(confidentialServerConfigurationError(baseEnv({ NODE_ENV: 'production', DEPLOY_ENV: 'prod', MONGODB_URI: 'mongodb://legacy' })))
      .toMatch(/Legacy configuration must not reach/);
  });
});

describe('confidential-only per-client quotas behind CloudFront and the ALB', () => {
  /** A request as the app sees it: the ALB appended the CloudFront edge address
   * to the reporter's, and stunnel connects from loopback without another hop. */
  async function rateLimitKey(env: NodeJS.ProcessEnv, forwardedFor: string): Promise<string> {
    const { app, runtime } = createConfidentialApp({ ...env, CONFIDENTIAL_RELEASE_MANIFEST_FILE: '/nonexistent/vera-manifest.json' });
    try {
      const socket = { remoteAddress: '127.0.0.1' };
      const req = Object.assign(Object.create(app.request), {
        app, method: 'POST', originalUrl: '/api/confidential/channel/open', url: '/api/confidential/channel/open',
        headers: { 'x-forwarded-for': forwardedFor }, socket, connection: socket,
      });
      return requestRateLimitKey(req);
    } finally {
      await runtime.settled;
      await runtime.close();
    }
  }

  test('with the deployed hop count, the quota key is the reporter, not the edge', async () => {
    const env = baseEnv({ API_TRUST_PROXY_HOPS: '2' });
    expect(await rateLimitKey(env, '198.51.100.1, 203.0.113.9')).toBe('ip:198.51.100.1');
    expect(await rateLimitKey(env, '198.51.100.2, 203.0.113.9')).toBe('ip:198.51.100.2');
    // A client-supplied entry left of CloudFront's cannot choose the quota.
    expect(await rateLimitKey(env, '192.0.2.77, 198.51.100.1, 203.0.113.9')).toBe('ip:198.51.100.1');
  });

  test('without the variable it falls back to one load balancer, like the legacy API', async () => {
    expect(await rateLimitKey(baseEnv(), '198.51.100.1, 203.0.113.9')).toBe('ip:203.0.113.9');
  });

  test('an invalid hop count is a configuration error, never a silent default', () => {
    expect(confidentialServerConfigurationError(baseEnv({ API_TRUST_PROXY_HOPS: 'true' }))).toBe('API_TRUST_PROXY_HOPS must be an integer from 0 to 9');
    expect(confidentialServerConfigurationError(baseEnv({ API_TRUST_PROXY_HOPS: '2' }))).toBeUndefined();
  });

});

describe('confidential-only process loads no legacy module', () => {
  /** Transitive runtime imports (type-only imports erased) from the entry point. */
  function graph(entry: string): Set<string> {
    const seen = new Set<string>();
    const resolve = (from: string, specifier: string) => {
      const base = path.resolve(path.dirname(from), specifier);
      for (const candidate of [`${base}.ts`, path.join(base, 'index.ts')]) {
        try { readFileSync(candidate); return candidate; } catch { /* next */ }
      }
      return null;
    };
    const visit = (file: string) => {
      if (seen.has(file)) return;
      seen.add(file);
      const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
      const specifiers: string[] = [];
      const walk = (node: ts.Node) => {
        if (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly && ts.isStringLiteral(node.moduleSpecifier)) {
          specifiers.push(node.moduleSpecifier.text);
        } else if (ts.isExportDeclaration(node) && !node.isTypeOnly && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
          specifiers.push(node.moduleSpecifier.text);
        } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword &&
            node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
          specifiers.push(node.arguments[0].text);
        }
        ts.forEachChild(node, walk);
      };
      walk(source);
      for (const specifier of specifiers) {
        if (!specifier.startsWith('.')) continue;
        const resolved = resolve(file, specifier);
        if (resolved) visit(resolved);
      }
    };
    visit(entry);
    return new Set([...seen].map(file => path.relative(ROOT, file).split(path.sep).join('/')));
  }

  test('the import graph stays inside the confidential path', () => {
    const files = graph(path.join(ROOT, 'src/confidentialServer.ts'));
    expect(files).toContain('src/api/confidentialService.ts');
    expect(files).toContain('src/services/confidentialCaseStore.ts');
    // Explicit exceptions only: application review has dedicated credentials.
    // The membership worker uses the confidential database and injected legal
    // provider; it imports no legacy Auth0 configuration or credentials.
    const dedicatedAlertModules = new Set(['src/services/legalApplicationSlack.ts', 'src/services/legalApplicationAuth0.ts', 'src/services/auth0LegalApplications.ts',
      'src/services/legalAuth0Memberships.ts']);
    expect(files).not.toContain('src/services/confidentialAdminAlerts.ts');
    expect(files).toContain('src/services/legalApplicationSlack.ts');
    expect(files).toContain('src/services/legalAuth0Memberships.ts');
    expect(files).not.toContain('src/services/slackNotification.ts');
    expect(files).not.toContain('src/services/submissionWebhook.ts');
    expect(files).not.toContain('lib/auth0Management.ts');
    const forbidden = [...files].filter(file => !dedicatedAlertModules.has(file) &&
      /midnight|wallet|reportPersistence|whistleblower|dissemination|pinata|evidenceStorage|localIpfs|venice|shroud|keyEnvelope|atRest|kms|config\/env|env-validation|reportAlert|relay|auth0|submissionWebhook|slack/i.test(file));
    expect(forbidden).toEqual([]);
  });
});

describe('confidential-only HTTP surface', () => {
  let mongo: MongoMemoryReplSet;
  let dir: string;
  const servers: Server[] = [];
  const listen = async (app: ReturnType<typeof createConfidentialApp>['app']) => {
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    servers.push(server);
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  };

  beforeAll(async () => {
    mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    dir = mkdtempSync(path.join(tmpdir(), 'vera-confidential-server-'));
    writeFileSync(path.join(dir, 'manifest.json'), '{"format":"synthetic"}');
  }, 120_000);
  afterAll(async () => {
    for (const server of servers) { server.closeAllConnections(); server.close(); }
    await mongo?.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  test('unavailable configuration fails closed and exposes no legacy route', async () => {
    const unavailable = jest.fn();
    const { app, runtime } = createConfidentialApp(baseEnv({ CONFIDENTIAL_RELEASE_MANIFEST_FILE: path.join(dir, 'missing.json') }), unavailable);
    await runtime.settled;
    const base = await listen(app);
    expect(unavailable).toHaveBeenCalledTimes(1);
    expect((await fetch(`${base}/health`)).status).toBe(503);
    const channel = await fetch(`${base}/api/confidential/channel/open`, { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } });
    expect(channel.status).toBe(503);
    expect(await channel.json()).toEqual({ success: false, error: 'confidential_unavailable' });
    for (const legacy of ['/api/whistleblower/submit', '/api/admin/reports', '/internal/relay/submission-proof', '/api/monitoring/dataflow']) {
      const response = await fetch(`${base}${legacy}`, { method: 'POST' });
      expect({ legacy, status: response.status }).toEqual({ legacy, status: 404 });
    }
    await runtime.close();
  });

  test('ready service: health, strict headers and admin listing only with the confidential admin secret', async () => {
    // The production Unix-socket transport is unavailable on Windows. Exercise
    // the service's existing loopback TCP transport there, as the local QA stack does.
    let transport: Record<string, string> = { CONFIDENTIAL_STORAGE_SOCKET: path.join(dir, 'storage.sock'), CONFIDENTIAL_ENCLAVE_SOCKET: path.join(dir, 'no-enclave.sock') };
    if (process.platform === 'win32') {
      const probe = createTcpServer();
      await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve));
      const port = (probe.address() as AddressInfo).port;
      await new Promise<void>(resolve => probe.close(() => resolve()));
      transport = { CONFIDENTIAL_STORAGE_PORT: String(port), CONFIDENTIAL_ENCLAVE_PORT: '1' };
    }
    const env = baseEnv({ CONFIDENTIAL_MONGODB_URI: mongo.getUri(), CONFIDENTIAL_MONGODB_DB_NAME: 'confidential_server_test',
      CONFIDENTIAL_RELEASE_MANIFEST_FILE: path.join(dir, 'manifest.json'), ...transport });
    const { app, runtime } = createConfidentialApp(env);
    await runtime.settled;
    expect(runtime.status()).toBe('ready');
    const base = await listen(app);
    const health = await fetch(`${base}/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: 'healthy', service: 'vera-confidential' });
    expect(health.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(health.headers.get('x-powered-by')).toBeNull();

    // Channel frames are parsed: a well-formed open reaches the (absent) enclave
    // transport and fails as unavailable, not as a malformed request.
    const open = await fetch(`${base}/api/confidential/channel/open`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nonce: 'a'.repeat(64) }) });
    expect(open.status).toBe(503);
    expect(await open.json()).toEqual({ error: 'Secure connection unavailable' });
    const malformed = await fetch(`${base}/api/confidential/channel/open`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ nonce: 'x' }) });
    expect(malformed.status).toBe(400);

    const listings = (secret?: string) => fetch(`${base}/api/admin/confidential/listings`, { method: 'POST',
      headers: { 'content-type': 'application/json', ...(secret ? { 'x-internal-secret': secret } : {}) }, body: '{}' });
    expect((await listings()).status).toBe(401);
    // The legacy INTERNAL_API_SECRET is not this process's secret.
    expect((await listings('b'.repeat(48))).status).toBe(401);
    const ok = await listings(ADMIN_SECRET);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ success: true, listings: [], next: null });
    await runtime.close();
  }, 60_000);
});
