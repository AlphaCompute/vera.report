import { logger } from '../utils/logger';
import type { SubmissionSource, WebhookResult } from './submissionWebhook';

import { slackConfigurationError } from '../utils/slackConfiguration';
export { slackConfigurationError } from '../utils/slackConfiguration';

/** One transport attempt; the existing durable worker owns retries. */
export async function notifySlackSubmission(createdAt: Date, source: SubmissionSource): Promise<WebhookResult> {
  const webhook = process.env.SLACK_WEBHOOK_URL?.trim();
  if (!webhook) return 'disabled';
  const error = slackConfigurationError();
  if (error) {
    logger.error(`[SUBMISSION_SLACK] ${error}`);
    return 'failed';
  }
  try {
    if (!(createdAt instanceof Date) || !Number.isFinite(createdAt.getTime()) ||
        !['web', 'telegram'].includes(source)) return 'failed';
    // Production deploys set DEPLOY_ENV=prod; label it as production.
    const configuredEnv = process.env.DEPLOY_ENV === 'prod' ? 'production' : process.env.DEPLOY_ENV;
    const environment = ['staging', 'production', 'development', 'test'].includes(configuredEnv || '')
      ? configuredEnv : 'unspecified';
    // Only fixed labels and an acceptance timestamp leave VERA.
    // Never pass the report record or a reporter capability here.
    const response = await fetch(webhook, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `[VERA ${environment}] A new report is awaiting review.`,
        blocks: [
          { type: 'section', text: { type: 'plain_text', text: `[VERA ${environment}] A new report is awaiting review.` } },
          { type: 'section', fields: [
            { type: 'plain_text', text: `Accepted (UTC): ${createdAt.toISOString()}` },
            { type: 'plain_text', text: `Source: ${source === 'web' ? 'Web' : 'Telegram'}` },
          ] },
        ],
        unfurl_links: false, unfurl_media: false,
      }),
    });
    if (response.status === 429) {
      const header = response.headers.get('retry-after') || '';
      const seconds = /^\d+$/.test(header) ? Number(header) : NaN;
      const retryAfterMs = Number.isSafeInteger(seconds) && seconds > 0 && seconds <= 86_400
        ? seconds * 1000 : 60_000;
      await response.body?.cancel();
      logger.warn('[SUBMISSION_SLACK] Rate limited; delivery deferred');
      return { status: 'rate_limited', retryAfterMs };
    }
    if (response.status !== 200) {
      await response.body?.cancel();
      logger.error(`[SUBMISSION_SLACK] Delivery failed: HTTP ${response.status}`);
      return 'failed';
    }
    if ((await response.text()).trim() !== 'ok') {
      logger.error('[SUBMISSION_SLACK] Delivery acknowledgement invalid');
      return 'failed';
    }
    logger.info('[SUBMISSION_SLACK] Delivered');
    return 'delivered';
  } catch {
    // Slack webhook URLs are credentials. Do not log errors or response bodies.
    logger.error('[SUBMISSION_SLACK] Delivery failed or timed out; accepted report retained');
    return 'failed';
  }
}
