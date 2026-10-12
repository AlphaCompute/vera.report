// Local confidential-case stack for click-through tests:
//   MongoDB (mongodb-memory-server, replica set)
//   <- confidential-only API process (src/confidentialServer.ts createConfidentialApp:
//      attested-channel relay, ciphertext staging, storage RPC, admin routes)
//   <- enclave composition (enclave/src/confidential-server.ts composeConfidentialServer:
//      session core, owner/legal dispatchers, sealed store, trusted clock, release checks)
//   <- Next production server (the real pages and Next API routes)
// NSM attestation (./syntheticNitro.ts) and identity-provider responses are
// synthetic. Tokens are signed by a local issuer whose JWKS the measured
// configuration pins, exactly as a production Auth0 tenant's would be.
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import type { Server as NetServer, AddressInfo } from 'node:net';
import { createServer, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';
import * as jose from 'jose';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { createSyntheticNitro } from './syntheticNitro';
import { createStackTimeShift, startTimeControl } from './timeShift';
import { applicationFixtures, installApplicationFixtures } from './legalApplications';
import { startCombinedApprovalFixture } from './combinedApproval';
import { describeHostLeaks, parseSecretRegister, recoveryCodeForms, sweepHostRecords } from '../support/leaks';
import type { HostRecord } from '../support/leaks';
import { captureProcessOutput, storedRecords } from './hostRecords';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { legalIdentityPolicyDigest } from '../../../enclave/src/cases/measuredConfiguration';
import { composeConfidentialServer } from '../../../enclave/src/confidential-server';
import { createConfidentialApp } from '../../../src/confidentialServer';
import { exportFirmIdentity, generateFirmIdentity, generateFirmRecoveryCode } from '../../../lib/confidential/firmKey';

export const ROOT = resolve(__dirname, '../../..');
export const IDENTITY_DOMAIN = 'identity.example';
export const ISSUER = `https://${IDENTITY_DOMAIN}/`;
export const LEGAL_CLIENT = 'legal-e2e-client';
export const LEGAL_AUDIENCE = 'https://legal-api.example';
export const ONBOARDING_CLIENT = 'onboarding-e2e-client';
export const ONBOARDING_AUDIENCE = 'https://onboarding-api.example';
export const ONBOARDING_ORG = 'org_veraonboarding';
export const FIRM_DOMAIN = 'counsel.example';
export const APPLICATION_FIRM_DOMAIN = 'approved.example';
/** The time-shifted spec's organization (access-expiry.spec.ts; one live organization per domain). */
export const SECOND_FIRM_DOMAIN = 'second-counsel.example';
/** Synthetic firm domains stay offline: key approval must use the signed VERA roster. */
export const FIRM_DOMAINS = [FIRM_DOMAIN, APPLICATION_FIRM_DOMAIN, 'north-counsel.example', 'south-counsel.example', SECOND_FIRM_DOMAIN] as const;
export const ADMIN_EMAIL = 'qa@example.org';

export type StackState = {
  baseURL: string; apiOrigin: string; mongoUri: string; confidentialDb: string;
  attestationRoot: string; attestationRootSha256: string;
  issuerKey: jose.JWK; issuerKid: string;
  authorityKeyFile: string; authorityCode: string;
  adminCookie: string; releaseManifest: string;
  /** The same measured image under a later release manifest (a new source
   * commit): what a browser receives after VERA ships a new version. */
  nextReleaseManifest: string;
  /** JSON-lines file of sentinels and device secrets that specs register
   * (support/state.ts sweptFromHost); global teardown sweeps host logs and
   * stored records for every one of them. */
  secretRegister: string;
  /** Loopback control of the stack's forward-only time shift (./timeShift.ts). */
  timeControl: { url: string; token: string };
};


const free = () => new Promise<number>((done, fail) => {
  const probe: NetServer = createServer();
  probe.once('error', fail);
  probe.listen(0, '127.0.0.1', () => { const { port } = probe.address() as AddressInfo; probe.close(() => done(port)); });
});

async function waitFor(url: string, child: ChildProcess, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Next exited with ${child.exitCode}`);
    try { const response = await fetch(url, { signal: AbortSignal.timeout(20_000) }); if (response.status < 500) return; } catch { /* starting */ }
    await new Promise(done => setTimeout(done, 500));
  }
  throw new Error('Next production server did not become ready');
}

export async function startStack(options: { nextPort: number; stateFile: string; logDir: string; development?: boolean }) {
  const stops: (() => Promise<void> | void)[] = [];
  const stop = async () => { for (const step of stops.reverse()) { try { await step(); } catch { /* best effort */ } } };
  try {
    mkdirSync(options.logDir, { recursive: true });
    const work = mkdtempSync(join(tmpdir(), 'vera-e2e-stack-'));
    stops.push(() => rmSync(work, { recursive: true, force: true }));
    const timeShift = createStackTimeShift();
    stops.push(() => timeShift.restore());
    const nitro = createSyntheticNitro({ now: timeShift.now });
    const secretRegister = join(work, 'secret-register.jsonl');
    writeFileSync(secretRegister, '', { mode: 0o600 });
    // The API and enclave run in this process: capture what they print.
    const hostOutput = captureProcessOutput();
    stops.push(() => hostOutput.restore());
    const applications = installApplicationFixtures();
    stops.push(() => applications.restore());

    // Synthetic identity issuer (stands in for the legal and onboarding Auth0 tenants).
    const issuerKid = 'e2e-issuer';
    const pair = await jose.generateKeyPair('RS256', { extractable: true });
    const jwks = { keys: [{ ...await jose.exportJWK(pair.publicKey), alg: 'RS256', use: 'sig', kid: issuerKid }] };
    const legalPolicy = { issuer: ISSUER, audience: LEGAL_AUDIENCE, clientId: LEGAL_CLIENT, jwks };
    const onboardingPolicy = { issuer: ISSUER, audience: ONBOARDING_AUDIENCE, clientId: ONBOARDING_CLIENT, jwks };

    // Onboarding authority: an independent operator key that can authorize
    // membership, never case grants. Exported like any firm key file.
    const authority = await generateFirmIdentity({ organizationId: '0'.repeat(63) + '1', domain: 'onboarding.vera.example' });
    const initialAuthority = await generateFirmIdentity({ organizationId: '0'.repeat(63) + '2', domain: 'approval.vera.example' });
    const authorityCode = generateFirmRecoveryCode();
    const authorityKeyFile = await exportFirmIdentity(authority, authorityCode);

    // Measured configuration and release manifest bound to the synthetic PCRs.
    const measured = Buffer.from(JSON.stringify({
      format: 'vera-confidential-configuration/v1', enabled: true, description: 'Synthetic E2E configuration',
      protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
      channelAudience: 'vera-confidential-cases', legalIdentityPolicySha256: legalIdentityPolicyDigest(legalPolicy),
      legalAdministration: { identity: onboardingPolicy, organizationId: ONBOARDING_ORG, onboardingPublicKey: authority.privateKey.toPublic().armor(), initialApprovalPublicKey: initialAuthority.privateKey.toPublic().armor() },
    }));
    const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
    const releaseManifest = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
      sourceRepository: 'https://github.com/AlphaCompute/vera', sourceCommit: sha('synthetic-e2e-commit').slice(0, 40),
      eifSha256: sha('synthetic-e2e-eif'), imageSha256: sha('synthetic-e2e-image'), configurationSha256: sha(measured),
      provenanceSha256: sha('synthetic-e2e-provenance'), protocolVersion: 'vera-confidential-channel/v1',
      dataFormatVersion: 'vera-confidential-case/v1', measurements: nitro.pcrs });
    // Same PCRs and configuration, another declared source commit: a new release
    // ID that the running enclave's measurements still satisfy.
    const nextReleaseManifest = canonicalReleaseManifest({ ...JSON.parse(releaseManifest),
      sourceCommit: sha('synthetic-e2e-next-commit').slice(0, 40) });
    const manifestFile = join(work, 'release-manifest.json'), policyFile = join(work, 'legal-identity.json');
    writeFileSync(manifestFile, releaseManifest);
    writeFileSync(policyFile, JSON.stringify(legalPolicy));

    const mongo = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    stops.push(async () => { await mongo.stop(); });
    const mongoUri = mongo.getUri();

    const [apiPort, storagePort, enclavePort] = [await free(), await free(), await free()];
    const baseURL = `http://${options.development ? '127.0.0.1' : 'localhost'}:${options.nextPort}`;
    const adminSecret = randomBytes(32).toString('hex');
    const approvalSecret = randomBytes(32).toString('hex');
    const confidentialDb = 'vera_confidential_e2e';
    const apiEnv: NodeJS.ProcessEnv = {
      ...applicationFixtures.backend,
      RUN_MODE: 'confidential', CONFIDENTIAL_CASES_ENABLED: 'true', NEXT_PUBLIC_CONFIDENTIAL_CASES: '1',
      CONFIDENTIAL_MONGODB_URI: mongoUri, CONFIDENTIAL_MONGODB_DB_NAME: confidentialDb, CONFIDENTIAL_ADMIN_SECRET: adminSecret,
      LEGAL_APPROVAL_BACKEND_SECRET: approvalSecret,
      CONFIDENTIAL_RELEASE_MANIFEST_FILE: manifestFile, CONFIDENTIAL_LEGAL_IDENTITY_FILE: policyFile,
      CONFIDENTIAL_ENCLAVE_PORT: String(enclavePort), CONFIDENTIAL_STORAGE_PORT: String(storagePort), API_PORT: String(apiPort),
      NODE_ENV: 'test',
    };
    // The channel request guard reads the allowed frontend origins from this process.
    process.env.CORS_ALLOWED_ORIGINS = baseURL;
    const { app, runtime, lifecycle } = createConfidentialApp(apiEnv, () => process.stderr.write('[e2e] confidential service unavailable\n'));
    await runtime.settled;
    if (runtime.status() !== 'ready') throw new Error('Confidential service did not start');
    stops.push(() => runtime.close());
    const api: Server = await new Promise((done, fail) => { const server = app.listen(apiPort, '127.0.0.1', () => done(server)); server.once('error', fail); });
    lifecycle.attach(api);
    // VERA_E2E_DEBUG=1: method, path, status, monotonic time and numeric quota
    // diagnostics only (never bodies, identity or authorization headers).
    if (process.env.VERA_E2E_DEBUG) api.on('request', (req, res) => res.on('finish', () =>
      process.stderr.write(`[e2e api] ${req.method} ${req.url?.split('?')[0]} ${res.statusCode} t=${Math.round(performance.now())} remaining=${res.getHeader('ratelimit-remaining') ?? '-'} retry=${res.getHeader('retry-after') ?? '-'}\n`)));
    stops.push(() => lifecycle.close());

    const enclave = await composeConfidentialServer({ measuredConfiguration: new Uint8Array(measured), identityFactory: nitro.identityFactory,
      storage: { port: storagePort }, port: enclavePort, sessionClock: () => performance.now(), retry: { attempts: 3, initialDelayMs: 200 }, timeShift });
    stops.push(() => new Promise<void>(done => enclave.close(() => done())));
    const timeControl = await startTimeControl(timeShift);
    stops.push(() => timeControl.close());

    // Synthetic VERA admin session (same technique as scripts/test-legal-onboarding-admin.cjs).
    const authSecret = randomBytes(32).toString('hex');
    const { encrypt } = await import(pathToFileURL(join(ROOT, 'node_modules/@auth0/nextjs-auth0/dist/server/cookies.js')).href) as { encrypt: (value: unknown, secret: string, expires: number) => Promise<string> };
    const now = Math.floor(Date.now() / 1000);
    const adminCookie = await encrypt({ user: { sub: 'synthetic-admin', email: ADMIN_EMAIL, email_verified: true, 'https://vera.app/roles': ['admin'] },
      tokenSet: { accessToken: 'synthetic', expiresAt: now + 86_400 }, internal: { sid: 'synthetic-e2e', createdAt: now } }, authSecret, now + 86_400);

    // Build once and serve immutable production assets. Dev Fast Refresh can
    // remount parked participant pages when another route compiles, opening
    // unrelated sessions and invalidating the long-running security journey.
    const nextOutput: string[] = [];
    stops.push(() => writeFileSync(join(options.logDir, 'next.log'), nextOutput.join('')));
    const apiOrigin = `http://127.0.0.1:${apiPort}`;
    const combined = startCombinedApprovalFixture(initialAuthority.privateKey, apiOrigin, approvalSecret, legalPolicy);
    stops.push(combined.stop);
    const nextEnv: NodeJS.ProcessEnv = { ...process.env, NODE_ENV: options.development ? 'development' : 'production', CORS_ALLOWED_ORIGINS: undefined,
        NEXT_PUBLIC_VERA_LOCAL_REVIEW: options.development ? '1' : undefined,
        VERA_DEV_CONFIDENTIAL_API_ORIGIN: apiOrigin,
        ...applicationFixtures.frontend,
        NODE_OPTIONS: `${process.env.NODE_OPTIONS || ''} --require="${join(ROOT, 'scripts/test-admin-provider.cjs').replace(/\\/g, '/')}"`,
        NEXT_TELEMETRY_DISABLED: '1',
        NEXT_PUBLIC_CONFIDENTIAL_CASES: '1', NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST: releaseManifest,
        CONFIDENTIAL_CASES_ENABLED: 'true',
        NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN: IDENTITY_DOMAIN, NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID: LEGAL_CLIENT, NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE: LEGAL_AUDIENCE,
        NEXT_PUBLIC_LEGAL_AUTH0_CONNECTION: 'email',
        NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN: IDENTITY_DOMAIN, NEXT_PUBLIC_ONBOARDING_AUTH0_CLIENT_ID: ONBOARDING_CLIENT,
        NEXT_PUBLIC_ONBOARDING_AUTH0_AUDIENCE: ONBOARDING_AUDIENCE,
        CONFIDENTIAL_BACKEND_URL: apiOrigin, CONFIDENTIAL_ADMIN_SECRET: adminSecret,
        AUTH0_SECRET: authSecret, AUTH0_DOMAIN: 'synthetic.invalid', AUTH0_CLIENT_ID: 'synthetic', AUTH0_CLIENT_SECRET: 'synthetic',
        AUTH0_MGMT_CLIENT_ID: 'synthetic-browser-test', AUTH0_MGMT_CLIENT_SECRET: 'synthetic-browser-test',
        ADMIN_ALLOWED_DOMAINS: 'example.org', APP_BASE_URL: baseURL, TENANT_ORG_ID: '',
        // No legacy backend in this stack: legacy proxies fail closed.
        BACKEND_URL: 'http://127.0.0.1:1', INTERNAL_API_SECRET: 'synthetic-e2e-internal-secret-not-live',
    };
    const startNext = (args: string[]) => {
      const child = spawn(process.execPath, [join(ROOT, 'node_modules/next/dist/bin/next'), ...args], {
        cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], env: nextEnv,
      });
      for (const stream of [child.stdout!, child.stderr!]) stream.on('data', (chunk: Buffer) => nextOutput.push(chunk.toString('latin1')));
      stops.push(() => new Promise<void>(done => {
        if (child.exitCode !== null || child.signalCode !== null) return done();
        child.once('exit', () => done());
        child.kill('SIGTERM');
        setTimeout(() => { child.kill('SIGKILL'); done(); }, 10_000).unref();
      }));
      return child;
    };
    // Worktrees sharing node_modules through a Windows junction need webpack:
    // Turbopack rejects dependencies outside its filesystem root. CI keeps the
    // default production bundler; both modes serve a production build.
    if (!options.development) {
      const build = startNext(process.env.VERA_E2E_WEBPACK === '1' ? ['build', '--webpack'] : ['build']);
      await new Promise<void>((done, fail) => {
        const timeout = setTimeout(() => { build.kill('SIGTERM'); fail(new Error('Next production build timed out')); }, 600_000);
        build.once('error', error => { clearTimeout(timeout); fail(error); });
        build.once('exit', code => { clearTimeout(timeout); code === 0 ? done() : fail(new Error(`Next production build failed (${code}); inspect next.log`)); });
      });
    }
    const frontendPort = await free();
    const next = startNext([...(options.development ? ['dev', '--webpack'] : ['start']), '--hostname', '127.0.0.1', '--port', String(frontendPort)]);
    await waitFor(`http://127.0.0.1:${frontendPort}/report`, next, 60_000);

    // Match deployed ingress routing: /api/confidential goes to the opaque
    // confidential relay; all other requests reach the real Next server. No
    // production rewrite or application authorization is changed for tests.
    const ingress = createHttpServer((req, res) => {
      const path = (req.url || '/').split('?')[0];
      if (['/__e2e/native-email', '/__e2e/existing-email'].includes(path) && req.method === 'POST') {
        if (req.headers['x-e2e-review-key'] !== adminCookie) { res.writeHead(403); res.end(); return; }
        let data = '';
        req.on('data', chunk => { data += String(chunk); if (data.length > 2048) req.destroy(); });
        req.on('end', () => { void (async () => {
          try {
            const { email } = JSON.parse(data);
            if (typeof email !== 'string' || !/^[a-z0-9-]+@[a-z0-9.-]+\.example$/.test(email)) throw new Error();
            const result = path === '/__e2e/native-email' ? await applications.nativeEmail(email, LEGAL_CLIENT) : { subject: applications.seedUser(email) };
            res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(result));
          } catch { res.writeHead(403); res.end(); }
        })(); });
        return;
      }
      if (path === '/__e2e/combined-approval' && req.method === 'POST') {
        // Pin the synthetic harness credential explicitly: Next can rotate its
        // session cookie after a successful admin request.
        if (req.headers['x-e2e-review-key'] !== adminCookie) { res.writeHead(403); res.end(); return; }
        let data = '';
        req.on('data', chunk => { data += String(chunk); if (data.length > 8192) req.destroy(); });
        req.on('end', () => { void (async () => {
          try { res.writeHead(await combined.decide(JSON.parse(data))); res.end(); }
          catch { res.writeHead(400); res.end(); }
        })(); });
        return;
      }
      if (path === '/__e2e/legal-applications' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify(applications.snapshot())); return;
      }
      const targetPort = path === '/api/confidential' || path.startsWith('/api/confidential/') ? apiPort : frontendPort;
      const upstream = httpRequest({ hostname: '127.0.0.1', port: targetPort, method: req.method, path: req.url,
        headers: { ...req.headers, ...(options.development ? { 'accept-encoding': 'identity' } : {}) } }, response => {
        // Loopback review only: trust the synthetic root without changing shipped browser code.
        if (options.development && path.startsWith('/_next/') && path.endsWith('.js')) {
          const chunks: Buffer[] = [];
          response.on('data', chunk => chunks.push(Buffer.from(chunk)));
          response.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf8')
              .replace(/MIICETCCAZagAwIBAgIRAPkxdWgbkK\/hHUbMtOTn\+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMw[A-Za-z0-9+/=]+/g, nitro.rootDer.toString('base64'))
              .split('641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b').join(sha(nitro.rootDer));
            const headers = { ...response.headers };
            delete headers['content-length']; delete headers['content-encoding']; delete headers.etag;
            res.writeHead(response.statusCode || 502, { ...headers, 'cache-control': 'no-store' }); res.end(body);
          });
          return;
        }
        res.writeHead(response.statusCode || 502, response.headers);
        response.pipe(res);
      });
      upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      req.on('aborted', () => upstream.destroy());
      req.pipe(upstream);
    });
    if (options.development) ingress.on('upgrade', (req, socket, head) => {
      const upstream = connect(frontendPort, '127.0.0.1', () => {
        upstream.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n` +
          Object.entries(req.headers).map(([key, value]) => `${key}: ${value}`).join('\r\n') + '\r\n\r\n');
        if (head.length) upstream.write(head);
        socket.pipe(upstream).pipe(socket);
      });
      upstream.on('error', () => socket.destroy()); socket.on('error', () => upstream.destroy());
    });
    await new Promise<void>((done, fail) => { ingress.once('error', fail); ingress.listen(options.nextPort, options.development ? '127.0.0.1' : 'localhost', done); });
    stops.push(() => new Promise<void>(done => { ingress.close(() => done()); ingress.closeAllConnections(); }));

    const state: StackState = { baseURL, apiOrigin, mongoUri, confidentialDb,
      attestationRoot: nitro.rootDer.toString('base64'), attestationRootSha256: sha(nitro.rootDer),
      issuerKey: await jose.exportJWK(pair.privateKey), issuerKid, authorityKeyFile, authorityCode, adminCookie, releaseManifest, nextReleaseManifest,
      secretRegister, timeControl: { url: timeControl.url, token: timeControl.token } };
    writeFileSync(options.stateFile, JSON.stringify(state), { mode: 0o600 });
    stops.push(() => rmSync(options.stateFile, { force: true }));

    /**
     * Architecture acceptance test 7, for the real browser flows: no sentinel
     * or device secret any spec registered appears in the Next log, the API and
     * enclave output, or any stored record. Run before stop(), while Mongo is up.
     */
    const sweep = async () => {
      // Runtime-generated test values for negative leak checks; no deployed credentials.
      // The rule mistakes the UTF-8 read of the secret-register file for a literal secret.
      // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_secret
      const leakProbes = [...parseSecretRegister(readFileSync(secretRegister, 'utf8')),
        ...recoveryCodeForms(authorityCode), authorityKeyFile, initialAuthority.privateKey.armor(), approvalSecret];
      const records = async function* (): AsyncGenerator<HostRecord> {
        yield { source: 'next.log (Next production build and server output)', text: nextOutput.join('') };
        yield { source: 'confidential API and enclave output', text: hostOutput.text() };
        yield* storedRecords(mongoUri);
      };
      const leaks = [];
      let scanned = 0;
      for await (const record of records()) { scanned += 1; leaks.push(...sweepHostRecords([record], leakProbes)); }
      if (leaks.length) throw new Error(describeHostLeaks(leaks));
      return { secrets: leakProbes.length, records: scanned };
    };
    return { state, stop, sweep };
  } catch (error) { await stop(); throw error; }
}
