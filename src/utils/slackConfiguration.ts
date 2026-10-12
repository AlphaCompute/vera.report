/** Side-effect-free URL validation shared by independent Slack transports. */
export function slackConfigurationError(env: Readonly<Record<string, string | undefined>> = process.env): string | undefined {
  const webhook = env.SLACK_WEBHOOK_URL?.trim();
  if (!webhook) return;
  try {
    const url = new URL(webhook);
    if (url.protocol !== 'https:' || url.hostname !== 'hooks.slack.com' || url.port ||
        url.username || url.password || url.search || url.hash ||
        !/^\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/.test(url.pathname)) {
      return 'SLACK_WEBHOOK_URL must be a Slack HTTPS incoming webhook';
    }
  } catch { return 'SLACK_WEBHOOK_URL must be a valid URL'; }
  try {
    const url = new URL(env.SLACK_ADMIN_URL?.trim() || '');
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
        !['/admin', '/admin/'].includes(url.pathname)) {
      return 'SLACK_ADMIN_URL must be an HTTPS /admin URL without credentials, query or fragment';
    }
  } catch { return 'SLACK_ADMIN_URL is required when SLACK_WEBHOOK_URL is set'; }
}

