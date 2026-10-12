import { LogLevel, SocketModeClient } from '@slack/socket-mode';
import { authorizeSlackApplicationDecision, authorizeSlackApplicationKeyReview,
  KEY_REVIEW_CALLBACK, updateSlackApplicationMessage, refreshSlackApplicationMessage, notifySlackApplicationDecisionFailure } from './legalApplicationSlack';
import type { SlackApplicationDecision, SlackApplicationPolicy } from './legalApplicationSlack';
import type { LegalApplicationView } from '../utils/legalApplications';

type Settings = { appToken: string; botToken: string; policy: SlackApplicationPolicy };
type SocketEvent = { type: string; body: unknown; ack: (response?: unknown) => Promise<void> };
type Outcome = 'approved' | 'denied' | 'rejected' | 'conflict' | 'ignored';
type Status = 'connected' | 'disconnected' | 'unavailable';

export function legalApplicationSocketSettings(env: NodeJS.ProcessEnv): Settings | null {
  const appToken = env.SLACK_APPLICATION_APP_TOKEN?.trim();
  if (!appToken) return null;
  const team = env.SLACK_APPLICATION_TEAM_ID?.trim();
  const botToken = env.SLACK_APPLICATION_BOT_TOKEN?.trim();
  const reviewers = (env.SLACK_APPLICATION_APPROVERS || '').split(',').map(value => value.trim());
  if (!/^xapp-[A-Za-z0-9-]+$/.test(appToken) || !team || !/^T[A-Z0-9]+$/.test(team) ||
      !reviewers.length || reviewers.some(value => !/^U[A-Z0-9]+$/.test(value)) ||
      !botToken || !/^xoxb-[A-Za-z0-9-]+$/.test(botToken)) {
    throw new Error('Invalid legal application Socket Mode configuration');
  }
  return { appToken, botToken, policy: { SLACK_APPLICATION_TEAM_ID: team, SLACK_APPLICATION_APPROVERS: reviewers.join(',') } };
}

/** Receives only SDK events from the app-token-authenticated socket, never public JSON. */
export class LegalApplicationSocketWorker {
  private readonly client: SocketModeClient;
  private stopped = true;
  private retry: ReturnType<typeof setTimeout> | undefined;
  private connecting: Promise<void> | undefined;
  private readonly pending = new Set<Promise<void>>();

  constructor(private readonly options: {
    settings: Settings;
    decide: (decision: SlackApplicationDecision) => Promise<boolean>;
    getApplication: (id: string) => Promise<LegalApplicationView | null>;
    onStatus?: (status: Status) => void;
    onDecision?: (outcome: Outcome, decision: SlackApplicationDecision | null) => void;
    onMessageUpdate?: (updated: boolean, application: LegalApplicationView) => void;
  }) {
    // SDK errors can contain authenticated URLs or applicant payloads. Emit only
    // our fixed status/outcome values; never forward SDK diagnostic arguments.
    const noop = () => {};
    this.client = new SocketModeClient({ appToken: options.settings.appToken, autoReconnectEnabled: false,
      logger: { debug: noop, info: noop, warn: noop, error: noop, setLevel: noop, setName: noop, getLevel: () => LogLevel.ERROR },
      clientOptions: { timeout: 5000, retryConfig: { retries: 0 }, rejectRateLimitedCalls: true },
    });
    this.client.on('connecting', () => {
      // apps.connections.open may finish after stop() disconnected an earlier
      // socket. The SDK creates/connects this new socket after that request, and
      // start() stays pending until hello or disconnect. Cancel the late socket
      // after the synchronous connect step, before waiting for start() to settle.
      if (this.stopped) queueMicrotask(() => {
        void this.client.disconnect().catch(() => this.status('unavailable'));
      });
    });
    this.client.on('connected', () => this.status('connected'));
    this.client.on('disconnected', () => { this.status('disconnected'); this.scheduleReconnect(); });
    this.client.on('error', () => this.status('unavailable'));
    this.client.on('slack_event', (event: SocketEvent) => {
      if (this.stopped) return; // Leave unacknowledged so Slack can retry on another worker.
      const work = this.handle(event).catch(() => this.status('unavailable')).finally(() => this.pending.delete(work));
      this.pending.add(work);
    });
  }

  private status(status: Status) { try { this.options.onStatus?.(status); } catch { /* Diagnostics cannot affect decisions. */ } }

  private async handle(event: SocketEvent) {
    const body = event.body as { type?: string; view?: { callback_id?: string }; response_url?: unknown } | null;
    if (event.type === 'interactive' && body?.type === 'view_submission' && body.view?.callback_id === KEY_REVIEW_CALLBACK) {
      // An old dialog may still be open during rollout. Do not silently approve
      // it or wait on the backend: direct the reviewer to the updated controls.
      await event.ack({ response_action: 'update', view: { type: 'modal',
        title: { type: 'plain_text', text: 'Approval updated' }, close: { type: 'plain_text', text: 'Close' },
        blocks: [{ type: 'section', text: { type: 'plain_text', text: 'Close this dialog and use Approve or Deny on the application message. If it still says Review firm and key, choose it once to refresh the buttons. This dialog has not recorded a decision.' } }],
      } });
      return;
    }
    // Slack's three-second deadline covers receipt, not persistence or signing.
    // Acknowledgement never means approval. Controls stay usable until a stored
    // outcome is confirmed; failures are reported privately for an explicit retry.
    await event.ack();
    const review = event.type === 'interactive' ? authorizeSlackApplicationKeyReview(event.body, this.options.settings.policy) : null;
    if (review) {
      try {
        const id = review.metadata.split(':')[1];
        const application = await this.options.getApplication(id);
        if (!application || application.id !== id || !await refreshSlackApplicationMessage(review.responseUrl, application, this.options.settings.policy)) throw new Error();
      } catch {
        this.status('unavailable');
        await notifySlackApplicationDecisionFailure(review.responseUrl, this.options.settings.policy);
      }
      return;
    }
    const decision = event.type === 'interactive' ? authorizeSlackApplicationDecision(event.body, this.options.settings.policy) : null;
    let accepted = false;
    try { if (decision) accepted = await this.options.decide(decision); }
    catch { this.status('unavailable'); }
    const outcome: Outcome = decision ? (accepted ? decision.status : 'conflict') : (event.type === 'interactive' ? 'rejected' : 'ignored');
    try { this.options.onDecision?.(outcome, decision); } catch { /* Diagnostics only. */ }
    if (decision) {
      // Read the immutable stored choice, including when an older/conflicting
      // click loses. The clicked action must never overwrite the displayed result.
      try {
        const application = await this.options.getApplication(decision.id);
        if (application && application.id === decision.id && application.status !== 'pending') {
          const updated = await updateSlackApplicationMessage(body?.response_url, application, this.options.settings.policy);
          try { this.options.onMessageUpdate?.(updated, application); } catch { /* Diagnostics only. */ }
          if (updated) return;
        }
      } catch { this.status('unavailable'); }
      await notifySlackApplicationDecisionFailure(body?.response_url, this.options.settings.policy);
    }
  }

  private scheduleReconnect() {
    if (this.stopped || this.retry) return;
    this.retry = setTimeout(() => { this.retry = undefined; this.connect(); }, 5000);
    this.retry.unref();
  }

  private connect() {
    if (this.stopped || this.connecting) return;
    this.connecting = this.client.start().then(() => {}, () => {
      this.status('unavailable'); this.scheduleReconnect();
    }).finally(() => { this.connecting = undefined; });
  }

  start(): void { if (!this.stopped) return; this.stopped = false; this.connect(); }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.retry) clearTimeout(this.retry);
    this.retry = undefined;
    // Cancel an in-flight greeting handshake first: start() cannot finish until
    // hello or disconnect. The connecting listener also cancels sockets created
    // by a token response arriving after this first disconnect.
    await this.client.disconnect();
    await this.connecting;
    await this.client.disconnect();
    // Drain accepted decisions before DB close.
    await Promise.allSettled([...this.pending]);
  }
}
