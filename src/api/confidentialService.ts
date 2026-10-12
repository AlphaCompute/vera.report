import { createLegalApplicationsRouter } from './legalApplications';
import { requireHeaderSecret } from '../middleware/internalSecret';
import { notifyLegalApplication } from '../services/legalApplicationSlack';
import { legalApplicationProvisioner, provisionLegalApplication } from '../services/legalApplicationAuth0';
import { readFileSync } from 'node:fs';
import type { Express, RequestHandler } from 'express';
import { PERMANENT_FAILURE_ATTEMPTS, createConfidentialAvailability } from '../services/confidentialAvailability';
import type { ConfidentialAvailability } from '../services/confidentialAvailability';
import { MongoConfidentialCaseStore } from '../services/confidentialCaseStore';
import { createConfidentialStorageServer, listenConfidentialStorage } from '../services/confidentialStorageRpc';
import { releaseWithdrawalsSource } from '../services/confidentialReleaseWithdrawals';
import { parseRoughtimeAllowlist, udpRoughtimeRelay } from '../services/confidentialRoughtime';
import { createConfidentialAdminListingRouter } from './confidentialAdminListings';
import { createConfidentialChannelRouter, socketEnclaveTransport, tcpEnclaveTransport } from './confidentialChannel';
import { createChannelOutcomeCounter } from '../utils/confidentialChannelOutcomes';
import { createConfidentialObjectRouter } from './confidentialObjects';
import { createConfidentialLegalOnboardingRouter } from './confidentialLegalOnboarding';
import { createConfidentialReleaseWithdrawalsRouter } from './confidentialReleaseWithdrawals';
import { WeeklySubmissionSummaryWorker } from '../services/weeklySubmissionSummary';

/** The only place that opens the confidential store, the storage RPC and the
 * confidential routes. Used by the legacy API (shared layout, `src/api/server.ts`)
 * and by the confidential-only process (`src/confidentialServer.ts`, RUN_MODE=confidential),
 * which holds no legacy secret.
 *
 * Database: `CONFIDENTIAL_MONGODB_URI` (dedicated cluster; the only form the
 * confidential-only task receives) or, in the shared layout, `MONGODB_URI`. The
 * database name must differ from the legacy one either way. */
export type ConfidentialResources = { legalClientId?: string; applicationProvider?: ReturnType<typeof legalApplicationProvisioner>; applicationProvisioningEnabled?: boolean; store: MongoConfidentialCaseStore; transport: ReturnType<typeof tcpEnclaveTransport> };
/** Fixed startup stages only: never expose exception messages or configuration values. */
export type ConfidentialStartupPhase = 'configuration' | 'database' | 'storage';
/** Fixed token for the one log line written when initialization stops retrying.
 * terraform-prod/modules/monitoring/runtime.tf alarms on it (ConfidentialStartupAbandoned). */
export const CONFIDENTIAL_STARTUP_ABANDONED_LOG = 'CONFIDENTIAL_STARTUP_ABANDONED';
export const confidentialStartupAbandonedMessage =
  `${CONFIDENTIAL_STARTUP_ABANDONED_LOG}: confidential initialization stopped retrying; fix the configuration and redeploy. Confidential intake remains closed`;

export function createConfidentialService(options: {
  env?: NodeJS.ProcessEnv;
  /** Gate for POST /api/admin/confidential/listings (header secret). */
  adminGuard: RequestHandler;
  onUnavailable: (phase: ConfidentialStartupPhase) => void;
  /** Invalid configuration cannot recover by retrying: after a few attempts
   * initialization stops and this runs once. The feature stays closed. */
  onAbandoned?: (phase: ConfidentialStartupPhase, attempts: number) => void;
}): { runtime: ConfidentialAvailability<ConfidentialResources>; outcomes: ReturnType<typeof createChannelOutcomeCounter>;
  mount(app: Express): void } {
  const env = options.env ?? process.env;
  const releaseWithdrawals = releaseWithdrawalsSource(env.CONFIDENTIAL_RELEASE_WITHDRAWALS_FILE?.trim() || undefined);
  let startupPhase: ConfidentialStartupPhase = 'configuration';
  const runtime = createConfidentialAvailability<ConfidentialResources>(async () => {
    startupPhase = 'configuration';
    // Production enablement is refused at startup (confidentialConfiguration.ts).
    // In a nonproduction mismatch, fail this feature closed.
    if (env.CONFIDENTIAL_CASES_ENABLED !== 'true' ||
        (env.NEXT_PUBLIC_CONFIDENTIAL_CASES !== undefined && env.NEXT_PUBLIC_CONFIDENTIAL_CASES !== '1')) {
      throw new Error('Confidential frontend/backend configuration mismatch');
    }
    const uri = (env.CONFIDENTIAL_MONGODB_URI || env.MONGODB_URI)?.trim();
    if (!uri) throw new Error('Confidential database configuration missing');
    const confidentialDbName = env.CONFIDENTIAL_MONGODB_DB_NAME || 'vera_confidential';
    if (confidentialDbName === (env.MONGODB_DB_NAME || 'vera')) throw new Error('CONFIDENTIAL_MONGODB_DB_NAME must differ from the legacy MONGODB_DB_NAME');
    const manifestFile = env.CONFIDENTIAL_RELEASE_MANIFEST_FILE;
    if (!manifestFile) throw new Error('Confidential release manifest missing');
    const releaseManifest = readFileSync(manifestFile, 'utf8').trim();
    if (!releaseManifest || releaseManifest.length > 8192) throw new Error('Confidential release manifest invalid');
    // Public {issuer, audience, clientId, jwks}. The enclave independently verifies
    // it against the digest pinned in its measured configuration; the host cannot
    // enable another issuer. A configured but unreadable file fails closed.
    const legalIdentityFile = env.CONFIDENTIAL_LEGAL_IDENTITY_FILE?.trim();
    const legalIdentityPolicy = legalIdentityFile ? JSON.parse(readFileSync(legalIdentityFile, 'utf8')) : undefined;
    const sessionSocket = env.CONFIDENTIAL_ENCLAVE_SOCKET?.trim();
    const sessionPort = Number(env.CONFIDENTIAL_ENCLAVE_PORT || 5004);
    if (!sessionSocket && (!Number.isInteger(sessionPort) || sessionPort < 1 || sessionPort > 65535)) throw new Error('Invalid session port');
    const transport = sessionSocket ? socketEnclaveTransport(sessionSocket) : tcpEnclaveTransport(sessionPort);
    const storageSocket = env.CONFIDENTIAL_STORAGE_SOCKET?.trim();
    const storagePort = Number(env.CONFIDENTIAL_STORAGE_PORT || 5005);
    if (!storageSocket && (!Number.isInteger(storagePort) || storagePort < 1 || storagePort > 65535)) throw new Error('Invalid storage port');
    // Validate optional operational configuration before acquiring database resources.
    const applicationProvider = legalApplicationProvisioner(env, legalIdentityPolicy);
    // Roughtime relay allowlist (optional; must list the measured servers when
    // the enclave configuration pins any, or the enclave cannot establish time).
    const roughtimeServers = parseRoughtimeAllowlist(env.CONFIDENTIAL_ROUGHTIME_SERVERS);
    startupPhase = 'database';
    const store = await MongoConfidentialCaseStore.connect(uri, confidentialDbName, env.MONGODB_TLS_CA_FILE, applicationProvider?.applicationOrganizations ?? null);
    store.configureLegalMemberInvitations(applicationProvider);
    startupPhase = 'storage';
    const storageServer = createConfidentialStorageServer(store as unknown as Record<string, unknown>,
      { releaseManifest, legalIdentityPolicy, releaseWithdrawals,
        ...(roughtimeServers.length ? { roughtime: udpRoughtimeRelay(roughtimeServers) } : {}) });
    let applicationDelivery: Promise<unknown> | null = null;
    let applicationProvisioning: Promise<unknown> | null = null;
    let membershipProvisioning: Promise<unknown> | null = null;
    let membershipTimer: ReturnType<typeof setInterval> | null = null;
    let applicationTimer: ReturnType<typeof setInterval> | null = null;
    const weeklySummary = new WeeklySubmissionSummaryWorker(store.weeklySubmissionSummaries, env);
    const deliverApplication = () => {
      if (applicationDelivery || !env.SLACK_APPLICATION_WEBHOOK_URL) return;
      applicationDelivery = store.applications.deliverOne(application => notifyLegalApplication(application, env))
        .catch(() => { /* Durable retry, no applicant details logged. */ })
        .finally(() => { applicationDelivery = null; });
    };
    const provisionApplication = () => {
      if (applicationProvisioning || !applicationProvider) return;
      applicationProvisioning = store.applications.provisionOne((application, signal) => provisionLegalApplication(application, applicationProvider, store, signal), Date.now(),
        outcome => { (outcome.status === 'ready' ? console.info : console.warn)('Legal application provisioning', outcome); })
        .catch(() => { console.warn('Legal application provisioning worker unavailable; retrying.'); })
        .finally(() => { applicationProvisioning = null; });
    };
    const close = async () => {
      if (applicationTimer) clearInterval(applicationTimer);
      if (membershipTimer) clearInterval(membershipTimer);
      await weeklySummary.close();
      await applicationDelivery;
      await applicationProvisioning;
      await membershipProvisioning;
      try {
        if (storageServer.listening) await new Promise<void>((resolve, reject) => storageServer.close(error => error ? reject(error) : resolve()));
      } finally { await store.close(); }
    };
    try {
      await listenConfidentialStorage(storageServer, storageSocket ? { path: storageSocket } : { port: storagePort });
      // Slack decisions belong exclusively to the isolated signing worker.
      // Never open a competing socket here, even if an older deployment still
      // supplies its app token. Notifications and Auth0 provisioning stay here.
      applicationTimer = setInterval(() => { deliverApplication(); provisionApplication(); }, 15_000);
      applicationTimer.unref();
      weeklySummary.start();
      if (applicationProvider?.nativeEntry) {
        const provisionMembership = () => {
          if (membershipProvisioning) return;
          membershipProvisioning = (async () => {
            for (let i = 0; i < 20 && await store.provisionLegalAuth0Membership(); i++) { /* Bounded drain. */ }
          })().catch(() => { console.warn('Legal membership provisioning unavailable; retrying.'); })
            .finally(() => { membershipProvisioning = null; });
        };
        membershipTimer = setInterval(provisionMembership, 2000);
        membershipTimer.unref();
        provisionMembership();
      }
      return { value: { store, transport, legalClientId: legalIdentityPolicy?.clientId, applicationProvider, applicationProvisioningEnabled: applicationProvider !== null }, close };
    } catch (error) { await close(); throw error; }
  }, () => options.onUnavailable(startupPhase), {
    // Transient dependencies (database, storage listener) keep retrying; a
    // configuration error needs an operator and a redeploy.
    permanent: () => startupPhase === 'configuration',
    onAbandoned: () => options.onAbandoned?.(startupPhase, PERMANENT_FAILURE_ATTEMPTS),
  });

  /** Retained so shutdown can flush the last minute's counts. */
  const outcomes = createChannelOutcomeCounter();
  return {
    runtime,
    outcomes,
    mount(app) {
      // Legal sign-in Actions read Auth0 directly. Do not mount the retired
      // callback, including when an old deployment still supplies its secret.
      // Signed release withdrawal list, refreshed on the parent from the release
      // bucket. Served unchanged to the enclave (storage RPC) and to participant devices.
      app.use('/api/confidential', createConfidentialReleaseWithdrawalsRouter(releaseWithdrawals));
      app.use('/api/confidential', createConfidentialObjectRouter({
        async stageObject(digest, ciphertext, now) { await (await runtime.get()).store.stageObject(digest, ciphertext, now); },
        async stageChunk(digest, data, now) { await (await runtime.get()).store.stageChunk(digest, data, now); },
      }));
      // Admin directory: case IDs and owner-signed summaries only, verified on the host.
      app.use('/api/admin/confidential', createConfidentialAdminListingRouter(async () => (await runtime.get()).store, options.adminGuard));
      // Legal organization onboarding roster (names, domains, public keys, invitations,
      // member leases, audit trail). No case data; cannot approve a firm key.
      app.use('/api/admin/confidential/legal-applications', createLegalApplicationsRouter(async () => (await runtime.get()).store.applications, options.adminGuard, async () => (await runtime.get()).store, async () => (await runtime.get()).applicationProvisioningEnabled === true));
      app.use('/api/internal/legal-approval', (req, res, next) => {
        const secret = env.LEGAL_APPROVAL_BACKEND_SECRET;
        if (!secret || secret.length < 32 || [env.CONFIDENTIAL_ADMIN_SECRET, env.INTERNAL_API_SECRET, env.LEGAL_AUTH0_ENTRY_SECRET,
          env.LEGAL_AUTH0_MGMT_CLIENT_SECRET].includes(secret)) { res.sendStatus(503); return; }
        requireHeaderSecret('LEGAL_APPROVAL_BACKEND_SECRET', env)(req, res, next);
      }, createLegalApplicationsRouter(async () => (await runtime.get()).store.applications, (_req, _res, next) => next(),
        undefined, async () => true, 'worker'));
      app.use('/api/admin/confidential/legal', createConfidentialLegalOnboardingRouter(async () => (await runtime.get()).store,
        Date.now, options.adminGuard));
      app.use('/api/confidential', createConfidentialChannelRouter(async frame => (await runtime.get()).transport(frame),
        { onOutcome: outcomes.record }));
    },
  };
}
