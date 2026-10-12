import { confidentialIntakeOnly, confidentialIntakeRequired } from '../middleware/confidentialIntakeOnly';
import { confidentialCasesConfigurationError, confidentialServiceHostedHere, legacyApiConfidentialHostingError } from '../utils/confidentialConfiguration';
import { confidentialStartupAbandonedMessage, createConfidentialService } from './confidentialService';
import type { ConfidentialResources } from './confidentialService';
import type { ConfidentialAvailability } from '../services/confidentialAvailability';
import { attestedNarrativeConfiguration, closeAttestedNarrative } from '../services/attestedNarrative';
import { configuredAttestedReporterVerification } from '../services/attestedReporterVerification';
import { createAttestedReporterVerificationRouter } from './attestedReporterVerification';
import { reportPersistenceService } from '../services/reportPersistence';
import { EVIDENCE_TRANSFER_TIMEOUT_MS } from '../utils/evidenceLimits';
import { apiTrustProxyHops } from '../utils/trustProxy';
import { configureUploadReadiness } from '../middleware/uploadBudget';
import { HttpServerLifecycle } from '../utils/applicationLifecycle';
import { captureWebhookBody, isSignedWebhook } from '../middleware/webhookIntegrity';
import { runtimeTelemetry, clientTelemetry, parseClientTelemetry } from '../utils/runtimeTelemetry';
import { logger } from '../utils/logger';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import whistleblowerRouter from './whistleblower';
import auditRouter from './audit';
import disseminationRouter from './dissemination';
import { trackDataFlow, getDataFlowLogs, getDataFlowMetrics, clearDataFlowLogs } from '../middleware/dataFlowTracking';
import {
  securityHeaders,
  apiRateLimiter,
  rateLimiters,
  validateRequestBody,
  securityErrorHandler,
  requestTimeout
} from '../middleware/security';
import { addRequestId } from '../utils/errorResponse';
import { errorMonitor } from '../utils/errorMonitor';
import { requireInternalSecret } from '../middleware/internalSecret';
import { configuredFrontendOrigins, exceptConfidentialApi } from '../middleware/confidentialRequestGuard';

const confidentialConfigurationError = confidentialCasesConfigurationError() ?? legacyApiConfidentialHostingError();
if (confidentialConfigurationError) throw new Error(confidentialConfigurationError);

const app = express();
// Headers run before early refusal; no parser, telemetry or body inspection does.
app.use(securityHeaders);
app.post(['/api/whistleblower/submit', '/api/whistleblower/analyze'], confidentialIntakeOnly);
// Express must not disclose its implementation on any route.
app.disable('x-powered-by');
const httpLifecycle = new HttpServerLifecycle();
let confidentialRuntime: ConfidentialAvailability<ConfidentialResources> | undefined;
app.use(httpLifecycle.admission);
app.set('trust proxy', apiTrustProxyHops());
const PORT = process.env.API_PORT || 3001;

// Request ID and error monitoring (must be before all other middleware)
app.use(addRequestId);
app.use(errorMonitor.middleware());
app.use(runtimeTelemetry);
// Isolated budget: telemetry must not consume the report submission limit.
app.post('/api/monitoring/client', rateLimiters.clientTelemetry, parseClientTelemetry, clientTelemetry);

// Nothing in this process competes with uploads for memory, so the second
// concurrent transfer slot is always available.
configureUploadReadiness(async () => true);
attestedNarrativeConfiguration(process.env);
const attestedReporterVerification = configuredAttestedReporterVerification(process.env, reportPersistenceService);
export const stopApiServer = async () => {
  // Drain admitted HTTP work before closing the stores those requests still use.
  await httpLifecycle.close();
  await Promise.all([attestedReporterVerification?.close(), closeAttestedNarrative(), confidentialRuntime?.close()]);
};

// Health check — must be BEFORE timeout/rate-limit middleware so it responds
// instantly even when the event loop is under pressure.
app.get('/health', (_req, res) => {
    const uptime = process.uptime();
    res.status(200).json({
        status: 'healthy',
        service: 'vera-api',
        timestamp: new Date().toISOString(),
        uptime: {
            seconds: Math.floor(uptime),
            human: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`,
        },
        confidential: { status: confidentialRuntime?.status() ?? 'disabled' },
    });
});

// Security headers are already applied before early intake refusal.
app.use(requestTimeout(30000)); // 30 second timeout
app.use(apiRateLimiter); // Public and authenticated dashboard quotas are independent.

// Standard middleware
// Scope CORS to known frontend origins instead of reflecting every origin (#454).
// Requests with no Origin header (same-origin browsers, server-to-server, ALB
// health checks) are allowed; unknown cross-origin requests get no ACAO header.
const CORS_ALLOWED_ORIGINS = configuredFrontendOrigins();
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || CORS_ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
  }),
);
app.use(['/api/confidential', '/api/admin/confidential'], (req, res, next) => {
  if (confidentialRuntime) confidentialRuntime.admission(req, res, next);
  else next();
});
// Confidential routes parse their own bodies under tight per-route limits and
// content types (src/middleware/confidentialRequestGuard.ts); the general 10 MB
// parsers must not buffer those requests first.
app.use(exceptConfidentialApi(bodyParser.json({ limit: '10mb', verify: captureWebhookBody }))); // Limit payload size
app.use(exceptConfidentialApi(bodyParser.urlencoded({ extended: true, limit: '10mb' })));
app.use((req, res, next) => isSignedWebhook(req.path) ? next() : validateRequestBody(req, res, next));
app.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer'); next(); });
app.use(trackDataFlow); // Add data flow tracking


// API Routes


// Mount whistleblower routes
app.use('/api/whistleblower', createAttestedReporterVerificationRouter(attestedReporterVerification));
app.use('/api/whistleblower', whistleblowerRouter);

// Confidential-case routes. Off unless explicitly enabled; they accept only
// participant-encrypted data and have no read or decrypt route. In the dedicated
// layout (CONFIDENTIAL_INTAKE_REQUIRED only) a separate RUN_MODE=confidential task
// serves them and this process only refuses legacy intake (above).
if (confidentialIntakeRequired() && confidentialServiceHostedHere()) {
    const service = createConfidentialService({ adminGuard: requireInternalSecret,
        onUnavailable: phase => logger.error('Confidential service unavailable; confidential and legacy intake remain closed', { phase }),
        onAbandoned: (phase, attempts) => logger.error(confidentialStartupAbandonedMessage, { phase, attempts }) });
    confidentialRuntime = service.runtime;
    service.mount(app);
}

// Mount admin audit routes
app.use('/api/admin', auditRouter);

// Mount dissemination routes (agency submission pipeline, VERA-PDR-001)
app.use('/api/dissemination', disseminationRouter);

app.get('/api/monitoring/dataflow', requireInternalSecret, rateLimiters.monitoring, (req, res) => {
    const { userId, dataType, destination, status, start, end } = req.query;
    // Flow records carry no identity (#1113); an ignored filter would return
    // every flow as if it matched the requested user.
    if (userId !== undefined) {
        res.status(400).json({ success: false, error: 'userId filter is not supported: data-flow records carry no identity' });
        return;
    }

    const filters: any = {};
    if (dataType) filters.dataType = dataType as string;
    if (destination) filters.destination = destination as string;
    if (status) filters.status = status as string;
    if (start && end) {
        filters.timeRange = {
            start: parseInt(start as string),
            end: parseInt(end as string)
        };
    }

    const logs = getDataFlowLogs(filters);
    res.json({ success: true, logs, total: logs.length });
});

app.get('/api/monitoring/metrics', requireInternalSecret, rateLimiters.monitoring, (req, res) => {
    const metrics = getDataFlowMetrics();
    res.json({ success: true, metrics });
});

app.post('/api/monitoring/clear', requireInternalSecret, rateLimiters.auth, (req, res) => {
    clearDataFlowLogs();
    res.json({ success: true, message: 'Data flow logs cleared' });
});

// NOTE: /health is registered early (before timeout middleware) for fast ALB responses.



// Security error handler (must be last middleware)
app.use(securityErrorHandler);

// Start server function
export async function startApiServer() {
    return listen();
}

function listen() {
    return new Promise((resolve, reject) => {
        const server = app.listen(PORT, () => {
            logger.info(`🌐 API Server running on port ${PORT}`);
            logger.info(`📱 Mini app available at http://localhost:${PORT}`);
            resolve(app);
        });
        server.requestTimeout = EVIDENCE_TRANSFER_TIMEOUT_MS;
        server.once('error', reject);
        httpLifecycle.attach(server);
    });
}

export default app;
