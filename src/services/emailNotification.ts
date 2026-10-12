import { logger } from '../utils/logger';
/**
 * Email notification service using AWS SES v2.
 *
 * Singleton pattern (like adminAuditLog.ts). Fire-and-forget — all sends
 * are wrapped in try/catch and never throw. No-op when SES_SENDER_EMAIL
 * is not configured.
 *
 * Admin recipients are fetched dynamically from Auth0 Management API
 * (direct admin roles in this organization when scoped). Rechecked for every send.
 */

import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';
import { getAdminRecipientEmails } from './adminAlertRecipients';

export type AlertType =
  | 'new_report'
  | 'critical_admin_action'
  | 'error_threshold';

export interface ReportAlertMetadata {
  acceptedAt?: Date;
  reportType?: string;
}

// Only a fixed taxonomy label may leave the report store. Unknown or historical
// categories never fall back to reporter-supplied text.
const REPORT_ALERT_TYPES: Record<string, string> = {
  'ai-safety': 'AI Safety', 'trust-safety': 'Trust and Safety',
  encryption: 'Encryption', 'financial-fraud': 'Financial Fraud',
  'discrimination-harassment': 'Discrimination or Harassment',
  'cyber-security': 'Cyber Security', crypto: 'Crypto',
  'environment-climate': 'Environment or Climate',
  'government-accountability': 'Government Accountability',
  'illegal-government-activity': 'Illegal Government Activity',
};

export class EmailNotificationService {
  private sesClient: SESv2Client | null = null;
  private senderEmail: string | null = null;

  /** Auth0 M2M token cache */
  private mgmtToken: string | null = null;
  private mgmtTokenExpiresAt = 0;

  private managementOrigin(): string {
    const domain = process.env.AUTH0_DOMAIN;
    if (!domain || !/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(domain)) {
      throw new Error('Invalid identity provider configuration');
    }
    return new URL(`https://${domain}`).origin;
  }

  private initialise(): boolean {
    if (this.sesClient) return true;

    const sender = process.env.SES_SENDER_EMAIL?.trim();
    if (!sender) return false;

    this.senderEmail = sender;

    const endpointUrl = process.env.AWS_ENDPOINT_URL?.trim();
    this.sesClient = new SESv2Client({
      maxAttempts: 1,
      requestHandler: { connectionTimeout: 5000, requestTimeout: 20000 },
      region: process.env.SES_REGION || process.env.AWS_REGION || 'us-east-2',
      ...(endpointUrl && { endpoint: endpointUrl }),
    });

    return true;
  }

  // ── Auth0 M2M token (mirrors lib/auth0Management.ts pattern) ──────

  private async getMgmtToken(): Promise<string> {
    const now = Date.now();
    if (this.mgmtToken && now < this.mgmtTokenExpiresAt) {
      return this.mgmtToken;
    }

    const origin = this.managementOrigin();
    const clientId = process.env.AUTH0_MGMT_CLIENT_ID;
    const clientSecret = process.env.AUTH0_MGMT_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      throw new Error(
        'Missing Auth0 Management API credentials (AUTH0_DOMAIN, AUTH0_MGMT_CLIENT_ID, AUTH0_MGMT_CLIENT_SECRET)',
      );
    }

    const res = await fetch(`${origin}/oauth/token`, {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        audience: `${origin}/api/v2/`,
        scope: ['read:users', 'read:roles',
          ...(process.env.TENANT_ORG_ID?.trim() ? ['read:organization_members'] : []),
          ...(process.env.TENANT_ORG_ID?.trim() && process.env.ADMIN_ALERT_ROLE_MODE !== 'global-in-org'
            ? ['read:organization_member_roles'] : []),
        ].join(' '),
      }),
    });

    if (!res.ok) {
      throw new Error('Identity provider token unavailable');
    }

    const data = await res.json();
    if (typeof data?.access_token !== 'string' || !data.access_token ||
        typeof data.expires_in !== 'number' || !Number.isFinite(data.expires_in) || data.expires_in <= 0) {
      throw new Error('Invalid identity provider token');
    }
    this.mgmtToken = data.access_token;
    // Cache with 5-minute safety margin
    this.mgmtTokenExpiresAt = now + (data.expires_in - 300) * 1000;

    return this.mgmtToken!;
  }

  // ── Fetch admin recipients from Auth0 ─────────────────────────────

  private async getAdminEmails(): Promise<string[]> {
    try {
      const org = process.env.TENANT_ORG_ID?.trim();
      const mode = process.env.ADMIN_ALERT_ROLE_MODE || 'organization';
      if (mode !== 'organization' && mode !== 'global-in-org') throw new Error('Invalid alert role mode');
      const scoped = !!org || process.env.AUTH0_ORG_SCOPED_ADMIN === 'true' || mode === 'global-in-org';
      if (scoped && !org) throw new Error('TENANT_ORG_ID is required for organization-scoped alerts');
      const token = await this.getMgmtToken();
      const origin = this.managementOrigin();
      return await getAdminRecipientEmails(async path => {
        const response = await fetch(`${origin}/api/v2${path}`, {
          headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(20000),
          redirect: 'error',
        });
        if (!response.ok) throw new Error(`Admin recipient lookup failed (${response.status})`);
        return response.json();
      }, scoped ? org : undefined, mode);
    } catch {
      logger.error('[EMAIL] Cannot establish authorized admin recipients');
      return [];
    }
  }

  // ── Core send method ──────────────────────────────────────────────

  async sendAlert(
    type: AlertType,
    subject: string,
    bodyHtml: string,
  ): Promise<{ sent: boolean; error?: string }> {
    try {
      if (!this.initialise()) return { sent: false, error: 'ses_unconfigured' };

      const recipients = await this.getAdminEmails();
      if (recipients.length === 0) return { sent: false, error: 'no_admin_recipients' };

      const fullSubject = `[VERA ${this.deployEnvLabel()}] ${subject}`;

      // Partial batch acceptance may duplicate alerts on an at-least-once retry.
      for (let offset = 0; offset < recipients.length; offset += 50) await this.sesClient!.send(
        new SendEmailCommand({
          FromEmailAddress: this.senderEmail!,
          Destination: { BccAddresses: recipients.slice(offset, offset + 50) },
          Content: {
            Simple: {
              Subject: { Data: fullSubject, Charset: 'UTF-8' },
              Body: {
                Html: { Data: bodyHtml, Charset: 'UTF-8' },
              },
            },
          },
        }),
      );

      logger.info(`[EMAIL] Alert sent: ${type}`);
      return { sent: true };
    } catch (err: unknown) {
      logger.error(`[EMAIL] Failed to send ${type} alert`);
      return { sent: false, error: 'provider_failed' };
    }
  }

  // ── Direct send (to a specific recipient, not admins) ────────────

  /**
   * Deployment environment for the subject prefix.
   *
   * NOT NODE_ENV. NODE_ENV is a build mode and is "production" on staging as
   * well as prod, which made every staging alert announce itself as
   * "[VERA production]" — including recipient-facing secure-packet mail with a
   * working link in it. Staging and prod were indistinguishable by subject
   * line, which is the wrong thing to be ambiguous about in a whistleblower
   * tool. DEPLOY_ENV is set per environment by Terraform; the NODE_ENV
   * fallback only applies to local runs where nothing sets it.
   */
  private deployEnvLabel(): string {
    return process.env.DEPLOY_ENV || process.env.NODE_ENV || 'development';
  }

  async sendToRecipient(
    recipient: string,
    subject: string,
    bodyHtml: string,
    replyTo?: string,
  ): Promise<{ sent: boolean; error?: string }> {
    try {
      if (!this.initialise()) return { sent: false, error: 'SES not configured (SES_SENDER_EMAIL missing)' };

      const fullSubject = `[VERA ${this.deployEnvLabel()}] ${subject}`;

      await this.sesClient!.send(
        new SendEmailCommand({
          FromEmailAddress: this.senderEmail!,
          Destination: { ToAddresses: [recipient] },
          ...(replyTo ? { ReplyToAddresses: [replyTo] } : {}),
          Content: {
            Simple: {
              Subject: { Data: fullSubject, Charset: 'UTF-8' },
              Body: {
                Html: { Data: bodyHtml, Charset: 'UTF-8' },
              },
            },
          },
        }),
      );

      logger.info('[EMAIL] Direct message accepted by provider');
      return { sent: true };
    } catch {
      logger.error('[EMAIL] Direct message delivery failed');
      return { sent: false, error: 'provider_failed' };
    }
  }

  // ── Convenience methods ───────────────────────────────────────────

  async notifyNewReport(
    _trackingId: string,
    _urgency: string,
    metadata?: ReportAlertMetadata,
  ): Promise<{ sent: boolean; error?: string }> {
    // Tracking IDs grant access to the anonymous status thread. Keep them, and
    // all free-form reporter content, out of email and provider logs.
    const category = metadata?.reportType;
    const type = category && Object.prototype.hasOwnProperty.call(REPORT_ALERT_TYPES, category)
      ? REPORT_ALERT_TYPES[category] : 'Confidential report';
    const acceptedAt = metadata?.acceptedAt;
    const timestamp = acceptedAt instanceof Date && Number.isFinite(acceptedAt.getTime())
      ? acceptedAt.toISOString() : 'Unavailable';
    return this.sendAlert('new_report', 'New report awaiting review',
      `<p>A new report is awaiting review. Sign in to the VERA admin dashboard.</p>` +
      `<p>Accepted (UTC): ${timestamp}</p><p>Report type: ${type}</p>`);
  }

  async notifyCriticalAdminAction(): Promise<{ sent: boolean; error?: string }> {
    // Keep report identifiers, endpoints and user-provided strings out of mail.
    const subject = 'Critical Admin Action';
    const bodyHtml = '<h2>Critical Admin Action</h2><p>A critical action was recorded. Review the authenticated admin audit log for details.</p>';
    return this.sendAlert('critical_admin_action', subject, bodyHtml);
  }

  async notifyErrorThreshold(
    count: number,
    _errors: Array<{ message: string; timestamp: Date }> = [],
  ): Promise<void> {
    const safeCount = Number.isSafeInteger(count) && count >= 0 ? count : 0;
    // Exception samples can carry report capabilities, credentials or content.
    await this.sendAlert('error_threshold', `Error threshold breached: ${safeCount} errors`,
      `<p>${safeCount} errors detected within the monitoring window.</p>` +
      '<p>Please investigate in the authenticated monitoring dashboard.</p>');
  }
  async sendInviteEmail(
    recipientEmail: string,
    role: string,
    passwordResetUrl: string,
    invitedBy: string,
  ): Promise<{ sent: boolean; error?: string }> {
    const esc = (s: string) =>
      s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    const subject = 'You have been invited to VERA';
    const bodyHtml = `
      <div style="font-family:sans-serif;max-width:600px;">
        <h2>Welcome to VERA</h2>
        <p>You have been invited to join the VERA admin panel by <strong>${esc(invitedBy)}</strong>.</p>
        <table style="border-collapse:collapse;margin:16px 0;">
          <tr>
            <td style="padding:4px 12px;font-weight:bold;">Email</td>
            <td style="padding:4px 12px;">${esc(recipientEmail)}</td>
          </tr>
          <tr>
            <td style="padding:4px 12px;font-weight:bold;">Role</td>
            <td style="padding:4px 12px;">${esc(role)}</td>
          </tr>
        </table>
        <p>Please set your password using the link below to activate your account:</p>
        <p style="margin:20px 0;">
          <a href="${esc(passwordResetUrl)}"
             style="background:#000;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;">
            Set Your Password
          </a>
        </p>
        <p style="font-size:13px;color:#666;">
          If the button doesn't work, copy and paste this URL into your browser:<br/>
          <code>${esc(passwordResetUrl)}</code>
        </p>
        <p style="font-size:13px;color:#666;margin-top:24px;">
          If you did not expect this invitation, you can safely ignore this email.
        </p>
      </div>
    `;

    const result = await this.sendToRecipient(recipientEmail, subject, bodyHtml);
    return result;
  }

  /**
   * Email a one-time secure disclosure-packet link to an external recipient
   * (e.g. a whistleblower attorney). The link opens once; the packet it serves
   * carries no reporter identity. Reward follow-up rides the anonymous relay:
   * the caller sets `replyTo` to the receipts address so a reply re-enters the
   * receipt/relay path without exposing the reporter.
   */
  async sendSecurePacketEmail(args: {
    recipient: string;
    trackingId: string;
    url: string;
    replyTo?: string;
    dryrun?: boolean;
    intendedRecipient?: string;
  }): Promise<{ sent: boolean; error?: string }> {
    const esc = (s: string) =>
      s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

    const subject = `${args.dryrun ? '[DRYRUN] ' : ''}Secure disclosure packet — ${args.trackingId}`;
    const dryrunNote =
      args.dryrun && args.intendedRecipient
        ? `<p style="font-size:12px;color:#92400e;background:#fef3c7;padding:8px 12px;border-radius:6px;">DRYRUN — in live mode this would be sent to <strong>${esc(args.intendedRecipient)}</strong>.</p>`
        : '';

    const bodyHtml = `
      <div style="font-family:sans-serif;max-width:600px;">
        ${dryrunNote}
        <h2>You have received a secure disclosure packet</h2>
        <p>Vera.Report has prepared a report dossier for your review. Tracking ID:
           <code>${esc(args.trackingId)}</code>.</p>
        <p>The link below is a <strong>one-time</strong> secure link — its dossier can be revealed once.
           Open it to reveal and download the dossier (PDF). The packet contains reviewed disclosure material; its contents may still identify people.</p>
        <p style="margin:20px 0;">
          <a href="${esc(args.url)}"
             style="background:#000;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;">
            Open secure packet
          </a>
        </p>
        <p style="font-size:13px;color:#666;">
          If the button doesn't work, copy and paste this URL into your browser:<br/>
          <code>${esc(args.url)}</code>
        </p>
        ${
          // Only promise the relay when a Reply-To actually routes into it.
          // This paragraph used to render unconditionally while
          // ReplyToAddresses was conditional, so with no receipt domain
          // configured the mail told the recipient they could reach the
          // reporter by replying — and the reply went to the From address,
          // which has no route. Promising a whistleblower reward channel that
          // silently goes nowhere is worse than omitting it.
          args.replyTo
            ? `<p style="font-size:13px;color:#666;margin-top:20px;">
          The reporter may be eligible for a whistleblower reward and can be reached anonymously:
          simply <strong>reply to this email</strong> and Vera relays your message to the reporter,
          without revealing their identity.
        </p>`
            : ''
        }
        <p style="font-size:12px;color:#999;margin-top:24px;">
          If you did not expect this, you can ignore this email; the link expires automatically.
        </p>
      </div>
    `;

    return this.sendToRecipient(args.recipient, subject, bodyHtml, args.replyTo);
  }
}

export const emailNotificationService = new EmailNotificationService();
