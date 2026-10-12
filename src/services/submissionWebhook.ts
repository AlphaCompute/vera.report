import { createHash } from 'node:crypto';
import { logger } from '../utils/logger';
import { notifySlackSubmission, slackConfigurationError } from './slackNotification';

// Historical queued notifications retain their original source.
export type SubmissionSource = 'web' | 'telegram';
export type WebhookResult = 'disabled' | 'delivered' | 'failed' | { status: 'rate_limited'; retryAfterMs: number };

export function submissionNotificationsEnabled(): boolean {
  return !!(process.env.SLACK_WEBHOOK_URL?.trim() || process.env.WEBHOOK_URL?.trim());
}

export function submissionNotificationConfigurationError(): string | undefined {
  return process.env.SLACK_WEBHOOK_URL?.trim() ? slackConfigurationError() : webhookConfigurationError();
}

/** Shared-secret header auth matches n8n's native Webhook Header Auth credential. */
export function webhookConfigurationError(): string | undefined {
  const url = process.env.WEBHOOK_URL?.trim();
  if (!url) return;
  if (!process.env.WEBHOOK_SECRET?.trim()) return 'WEBHOOK_SECRET is required when WEBHOOK_URL is set';
  try {
    const parsed = new URL(url);
    const local = process.env.NODE_ENV !== 'production' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !(local && parsed.protocol === 'http:')) {
      return 'WEBHOOK_URL must use HTTPS (HTTP loopback is allowed outside production)';
    }
    if (parsed.username || parsed.password || parsed.hash) return 'WEBHOOK_URL must not contain credentials or a fragment';
  } catch {
    return 'WEBHOOK_URL must be a valid URL';
  }
}

/**
 * A single transport attempt after intake persistence. The durable worker owns
 * retries. Direct Slack takes precedence over the legacy webhook, without a
 * fallback or dual delivery on Slack failure. SES is independent.
 */
export async function notifySubmission(
  trackingId: string,
  createdAt: Date,
  source: SubmissionSource,
): Promise<WebhookResult> {
  if (process.env.SLACK_WEBHOOK_URL?.trim()) return notifySlackSubmission(createdAt, source);
  const url = process.env.WEBHOOK_URL?.trim();
  if (!url) return 'disabled';
  const configurationError = webhookConfigurationError();
  if (configurationError) {
    logger.error(`[SUBMISSION_WEBHOOK] ${configurationError}`);
    return 'failed';
  }

  try {
    // Tracking IDs can grant access to report status. Do not export them, report
    // content, contact details, evidence, consent, or proof material to n8n.
    const event = {
      schemaVersion: 1,
      event: 'submission.accepted',
      eventId: createHash('sha256').update(`submission.accepted:${trackingId}`).digest('hex'),
      submittedAt: createdAt.toISOString(),
      source,
    };
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-VERA-Webhook-Secret': process.env.WEBHOOK_SECRET!.trim(),
        'X-VERA-Event-ID': event.eventId,
      },
      body: JSON.stringify(event),
      redirect: 'error', // Never forward the secret to a redirected destination.
      signal: AbortSignal.timeout(5000),
    });
    // Do not log arbitrary receiver bodies, URLs, headers, or fetch error text.
    await response.body?.cancel();
    if (!response.ok) {
      logger.error(`[SUBMISSION_WEBHOOK] Delivery failed: HTTP ${response.status}; event=${event.eventId}`);
      return 'failed';
    }
    logger.info(`[SUBMISSION_WEBHOOK] Delivered event=${event.eventId}`);
    return 'delivered';
  } catch {
    logger.error('[SUBMISSION_WEBHOOK] Delivery failed or timed out; accepted report retained');
    return 'failed';
  }
}

export type OperationalEvent = 'operations.error_threshold';
const lastOperationalEvent = new Map<OperationalEvent, number>();

/** Fixed event schema: never export error messages or request data. */
export async function notifyOperationalEvent(event: OperationalEvent): Promise<WebhookResult> {
  if (!process.env.WEBHOOK_URL?.trim()) return 'disabled';
  if (webhookConfigurationError()) return 'failed';
  const now = Date.now();
  if (now - (lastOperationalEvent.get(event) ?? -Infinity) < 300_000) return 'disabled';
  lastOperationalEvent.set(event, now); // Includes failed sends to bound outage storms.
  try {
    const response = await fetch(process.env.WEBHOOK_URL!.trim(), {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/json', 'X-VERA-Webhook-Secret': process.env.WEBHOOK_SECRET!.trim() },
      body: JSON.stringify({ schemaVersion: 1, event, occurredAt: new Date(now).toISOString() }),
    });
    await response.body?.cancel();
    if (!response.ok) logger.warn('[OPERATIONAL_WEBHOOK] Delivery failed');
    return response.ok ? 'delivered' : 'failed';
  } catch {
    logger.warn('[OPERATIONAL_WEBHOOK] Delivery failed or timed out');
    return 'failed';
  }
}
