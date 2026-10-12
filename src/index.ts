#!/usr/bin/env node
import { createShutdown } from './utils/applicationLifecycle';
import { logger } from './utils/logger';
import { env } from './config/env';
import { startApiServer, stopApiServer } from './api/server';

const RUN_MODE = process.env.RUN_MODE || 'api';

async function main() {
    logger.info(`🚀 Starting VERA (mode: ${RUN_MODE})...`);

    try {
        // No Venice fallback: without a Shroud key every report degrades to `pending`.
        const { isShroudConfigured } = await import('./services/shroudClient');
        if (!isShroudConfigured()) {
            logger.warn('⚠️ SHROUD_API_KEY not set — report scoring disabled, submissions will stay pending');
        }

        // Start the API server
        logger.info('🌐 Starting API server...');
        await startApiServer();
        logger.info('🌐 API server running on port', env.PORT);

        // Dissemination dispatch worker (agency submission pipeline).
        // Claims are atomic, so running alongside the API is safe.
        const { dispatchWorker } = await import('./services/dissemination/dispatchWorker');
        dispatchWorker.start();
        const { reportAlertWorker } = await import('./services/reportAlertWorker');
        reportAlertWorker.start();
        const { criticalAdminAlertWorker } = await import('./services/criticalAdminAlertWorker');
        criticalAdminAlertWorker.start();
        const { submissionNotificationWorker } = await import('./services/submissionNotificationWorker');
        submissionNotificationWorker.start();
        const { reportScoringWorker } = await import('./services/reportScoringWorker');
        reportScoringWorker.start();

        logger.info('VERA API services started');
        logger.info('Check runtime health before accepting reports.');
    } catch (error) {
        console.error('❌ Failed to start application:', error);
        throw error;
    }
}

const stopApplication = createShutdown([
    // Startup may be partially complete. Wait until it settles so nothing starts
    // after its shutdown phase. The process deadline also bounds this wait.
    [async () => { await startup.catch(() => {}); }],
    [async () => { await stopApiServer(); }],
    [async () => { await (await import('./services/dissemination/dispatchWorker')).dispatchWorker.close(); },
     async () => { await (await import('./services/reportAlertWorker')).reportAlertWorker.close(); },
     async () => { await (await import('./services/criticalAdminAlertWorker')).criticalAdminAlertWorker.close(); },
     async () => { await (await import('./services/submissionNotificationWorker')).submissionNotificationWorker.close(); },
     async () => { await (await import('./services/reportScoringWorker')).reportScoringWorker.close(); },
     async () => { await (await import('./services/dissemination/auditAnchor')).auditAnchorService.close(); }],
    [async () => { await (await import('./utils/errorMonitor')).errorMonitor.close(); }],
    [async () => { await (await import('./services/reportPersistence')).reportPersistenceService.close(); },
     async () => { await (await import('./services/dissemination/disseminationPersistence')).disseminationPersistence.disconnect(); },
     async () => { await (await import('./services/adminAuditLog')).adminAuditLog.close(); },
     async () => { await (await import('./utils/mongoRateLimitStore')).closeRateLimitStore(); }],
]);
let exiting = false;
let applicationFailed = false;
function shutdown(signal: string, failed = false): void {
    applicationFailed ||= failed;
    if (exiting) return;
    exiting = true;
    logger.info(`Shutting down (${signal})`);
    // Leave margin before the default ECS 30-second termination deadline.
    const deadline = setTimeout(() => {
        console.error('Shutdown timed out; clean drain is unverified');
        process.exit(1);
    }, 25_000);
    void stopApplication().then(() => {
        clearTimeout(deadline);
        process.exit(applicationFailed ? 1 : 0);
    }, () => {
        clearTimeout(deadline);
        console.error('Shutdown failed; clean drain is unverified');
        process.exit(1);
    });
}
const startup = main();
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
void startup.catch(() => shutdown('startup failure', true));
