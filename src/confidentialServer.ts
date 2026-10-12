#!/usr/bin/env node
/**
 * Confidential-only API process (RUN_MODE=confidential, `node dist/confidentialServer.js`).
 *
 * Serves exactly the confidential routes: the opaque attested-channel relay, the
 * ciphertext staging route, the signed release withdrawal list and the admin
 * listing, plus the enclave's outbound storage RPC. It never loads the legacy
 * API, workers, Midnight wallet, KMS clients, IPFS, AI providers or their
 * configuration. Its core secrets are the dedicated confidential database URI
 * (CONFIDENTIAL_MONGODB_URI) and admin header secret (CONFIDENTIAL_ADMIN_SECRET).
 * Optional operational alerts use separate credentials. Reporter contact stays encrypted.
 */
import express from 'express';
import helmet from 'helmet';
import type { Server } from 'node:http';
import { confidentialStartupAbandonedMessage, createConfidentialService } from './api/confidentialService';
import type { ConfidentialStartupPhase } from './api/confidentialService';
import { requireHeaderSecret } from './middleware/internalSecret';
import { exceptConfidentialApi } from './middleware/confidentialRequestGuard';
import { HttpServerLifecycle } from './utils/applicationLifecycle';
import { confidentialCasesConfigurationError } from './utils/confidentialConfiguration';
import { apiTrustProxyHops } from './utils/trustProxy';

/** Legacy configuration that must never reach this process. Presence means the
 * task definition regressed to the shared layout; refuse to start. */
export const LEGACY_SECRET_VARIABLES = [
  'MONGODB_URI', 'INTERNAL_API_SECRET', 'ENCRYPTION_MASTER_KEY', 'NULLIFIER_SEED', 'WALLET_ENCRYPTION_KEY',
  'REWARD_ENCRYPTION_KEY', 'WALLET_SEED', 'MIDNIGHT_MNEMONIC', 'MIDNIGHT_RELAY_MNEMONIC', 'PINATA_JWT', 'VENICE_API_KEY',
  'SHROUD_API_KEY', 'REDIS_URL', 'AUTH0_SECRET', 'AUTH0_CLIENT_SECRET', 'AUTH0_MGMT_CLIENT_SECRET', 'DISSEMINATION_WEBHOOK_SECRET',
  'RECIPIENT_CAPABILITY_SECRET', 'WEBHOOK_SECRET', 'SLACK_WEBHOOK_URL', 'KMS_AT_REST_KEY_ID',
] as const;

export function confidentialServerConfigurationError(env: NodeJS.ProcessEnv): string | undefined {
  const base = confidentialCasesConfigurationError(env);
  if (base) return base;
  if (env.RUN_MODE !== 'confidential') return 'RUN_MODE must be confidential';
  if (env.CONFIDENTIAL_CASES_ENABLED !== 'true') return 'CONFIDENTIAL_CASES_ENABLED must be true';
  if (!env.CONFIDENTIAL_MONGODB_URI?.trim()) return 'CONFIDENTIAL_MONGODB_URI is required';
  if (!env.CONFIDENTIAL_ADMIN_SECRET || env.CONFIDENTIAL_ADMIN_SECRET.length < 32) return 'CONFIDENTIAL_ADMIN_SECRET must be at least 32 characters';
  if (env.LEGAL_APPROVAL_BACKEND_SECRET !== undefined && (env.LEGAL_APPROVAL_BACKEND_SECRET.length < 32 ||
      [env.CONFIDENTIAL_ADMIN_SECRET, env.LEGAL_AUTH0_ENTRY_SECRET, env.LEGAL_AUTH0_MGMT_CLIENT_SECRET].includes(env.LEGAL_APPROVAL_BACKEND_SECRET))) {
    return 'LEGAL_APPROVAL_BACKEND_SECRET must be a distinct secret of at least 32 characters';
  }
  if (env.SLACK_APPLICATION_APP_TOKEN || env.SLACK_APPLICATION_BOT_TOKEN || env.LEGAL_APPROVAL_KEY_FILE || env.LEGAL_APPROVAL_JOURNAL) {
    return 'Approval worker credentials must not reach the confidential backend';
  }
  try { apiTrustProxyHops(env); } catch { return 'API_TRUST_PROXY_HOPS must be an integer from 0 to 9'; }
  const present = LEGACY_SECRET_VARIABLES.filter(name => env[name] !== undefined && env[name] !== '');
  // Names only; never values.
  if (present.length) return `Legacy configuration must not reach the confidential-only process: ${present.join(', ')}`;
}

export function createConfidentialApp(env: NodeJS.ProcessEnv = process.env, onUnavailable: (phase: ConfidentialStartupPhase) => void = () => {},
  onAbandoned: (phase: ConfidentialStartupPhase, attempts: number) => void = () => {}) {
  const app = express();
  app.disable('x-powered-by');
  // Same hop count as the legacy API: deployed, this task sits behind
  // CloudFront -> ALB (stunnel adds no hop), so API_TRUST_PROXY_HOPS=2 keeps
  // req.ip, and every per-client quota, on the reporter's address rather than
  // the CloudFront edge's (src/utils/trustProxy.ts).
  app.set('trust proxy', apiTrustProxyHops(env));
  // JSON-only API: nothing here is ever rendered or framed.
  app.use(helmet({
    contentSecurityPolicy: { useDefaults: false, directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'none'"] } },
    hsts: { maxAge: 31536000, includeSubDomains: true },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
  }));
  const lifecycle = new HttpServerLifecycle();
  app.use(lifecycle.admission);
  const service = createConfidentialService({ env, adminGuard: requireHeaderSecret('CONFIDENTIAL_ADMIN_SECRET', env), onUnavailable, onAbandoned });

  // Health reports readiness only (no counts, identifiers or configuration).
  app.get('/health', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const status = service.runtime.status();
    res.status(status === 'unavailable' || status === 'closed' ? 503 : 200)
      .json({ status: status === 'ready' ? 'healthy' : status, service: 'vera-confidential' });
  });
  app.use(['/api/confidential', '/api/admin/confidential', '/api/auth0/legal-entry', '/api/internal/legal-approval'], service.runtime.admission);
  app.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  // The confidential routes parse their own bodies under tight per-route limits and
  // content types (src/middleware/confidentialRequestGuard.ts); only the admin
  // routes use this general parser, with the legacy API's ceiling.
  app.use(exceptConfidentialApi(express.json({ limit: '10mb', strict: true })));
  service.mount(app);
  // Every other path: no legacy route exists in this process.
  app.use((_req, res) => { res.status(404).json({ success: false, error: 'Not found' }); });
  // Generic errors only: no request detail, identifiers or stack in responses or logs.
  app.use((_error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (res.headersSent) return;
    res.status(500).json({ success: false, error: 'Internal error' });
  });
  return { app, runtime: service.runtime, lifecycle, outcomes: service.outcomes };
}

export async function startConfidentialServer(env: NodeJS.ProcessEnv = process.env): Promise<{ server: Server; stop: () => Promise<void> }> {
  const error = confidentialServerConfigurationError(env);
  if (error) throw new Error(error);
  const { app, runtime, lifecycle, outcomes } = createConfidentialApp(env,
    phase => console.error('Confidential service unavailable; confidential intake remains closed', { phase }),
    (phase, attempts) => console.error(confidentialStartupAbandonedMessage, { phase, attempts }));
  const port = Number(env.API_PORT || 3002);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid API_PORT');
  const server = await new Promise<Server>((resolve, reject) => {
    const listening = app.listen(port, '0.0.0.0', () => resolve(listening));
    listening.once('error', reject);
  });
  lifecycle.attach(server);
  // Requests have drained once the lifecycle closes; emit their last counts.
  return { server, stop: async () => { await lifecycle.close(); outcomes.close(); await runtime.close(); } };
}

if (require.main === module) {
  startConfidentialServer().then(({ stop }) => {
    let stopping = false;
    const shutdown = () => {
      if (stopping) return;
      stopping = true;
      const deadline = setTimeout(() => process.exit(1), 20_000);
      deadline.unref();
      stop().then(() => process.exit(0), () => process.exit(1));
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    console.log('Confidential service listening');
  }).catch(error => {
    // Configuration messages name variables only, never values.
    console.error(`Confidential service failed to start: ${error instanceof Error ? error.message : 'unknown error'}`);
    process.exit(1);
  });
}
