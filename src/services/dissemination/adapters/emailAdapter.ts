import { exportPacketArchive } from '../packetEvidence';
/**
 * Tier A email adapter base (VERA-PDR-001 §7.3).
 *
 * Sends the submission packet as a plain-text cover letter (agency intake
 * staff read text, not JSON) with the report-and-evidence ZIP and JSON sidecar
 * attached, via AWS SES v2 raw MIME. Each entity subclass supplies the
 * intake address, cover-letter template, and SLA profile; each gets its
 * own circuit breaker so one agency's outage never affects another (NFR-3).
 *
 * Safety switch: DISSEMINATION_MODE defaults to 'dryrun', which routes
 * mail to DISSEMINATION_DRYRUN_INBOX instead of the real agency address.
 * Set DISSEMINATION_MODE=live to dispatch for real.
 *
 * Dryrun skips the narrative review gate, so it never sends report content in
 * cleartext: unless DISSEMINATION_EMAIL_POLICIES pins a PGP key for the dryrun
 * inbox, the inbox receives a content-free notice (entity, case reference,
 * sizes of what would be sent) with no narrative and no evidence attached.
 * With a pinned key, the full packet is sent encrypted exactly as in live mode.
 */

import crypto from 'node:crypto';
import { DispatchNotSentError } from '../types';
import { encryptForRecipient, recipientRequiresEncryption } from '../recipientEncryption';
import { disseminationPersistence } from '../disseminationPersistence';
import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';
import { CircuitBreaker } from '../../../utils/circuitBreaker';
import { categoryLabel } from '../taxonomy';
import type {
  DisseminationView,
  DispatchResult,
  Packet,
  PreparedSubmission,
  Receipt,
  SubmissionAdapter,
  Tier,
} from '../types';

export interface EmailAdapterConfig {
  entityId: string;
  entityName: string;
  /** Real agency intake address (used only in live mode). */
  intakeAddress: string;
  /** Salutation line for the cover letter. */
  salutation: string;
  /** Entity-specific paragraph(s) inserted after the intro. */
  bodyIntro: string;
  /** Regexes that recognize an entity-native receipt identifier in an inbound ack. */
  receiptPatterns?: { pattern: RegExp; type: Receipt['type'] }[];
  /**
   * Entity-specific extra attachments (e.g. the STIX bundle for CISA).
   * Returning [] attaches nothing; errors here fail prepare(), which the
   * dispatch worker treats as a retryable failure.
   */
  extraAttachments?: (
    view: DisseminationView,
    packet: Packet,
  ) => { filename: string; contentType: string; content: Buffer }[];
}

export function disseminationMode(): 'dryrun' | 'live' {
  return process.env.DISSEMINATION_MODE?.trim().toLowerCase() === 'live' ? 'live' : 'dryrun';
}

/** Hard timeout on the SES send so a hung connection can't stall the single-flight dispatch worker and starve other channels (review finding H3). */
const SEND_TIMEOUT_MS = 30_000;

export class EmailAdapter implements SubmissionAdapter {
  readonly entityId: string;
  readonly tier: Tier = 'A';
  protected readonly config: EmailAdapterConfig;
  protected readonly breaker: CircuitBreaker;
  private sesClient: SESv2Client | null = null;

  constructor(config: EmailAdapterConfig) {
    this.entityId = config.entityId;
    this.config = config;
    this.breaker = new CircuitBreaker({
      name: `dissemination-${config.entityId}`,
      failureThreshold: 5,
      cooldownMs: 30 * 60 * 1000, // 30-minute half-open window per the PDR sketch
    });
  }

  allowsDispatch(): boolean {
    return this.breaker.allowsRequest();
  }

  async prepare(view: DisseminationView, packet: Packet): Promise<PreparedSubmission> {
    const archive = await exportPacketArchive(packet.trackingId, packet.pdf, undefined, packet.sidecar.evidenceManifest.files);
    if (archive.length > 28 * 1024 * 1024) throw new Error('Evidence package is too large for email. Share a secure packet link instead.');
    const mode = disseminationMode();
    const dryrunInbox = process.env.DISSEMINATION_DRYRUN_INBOX?.trim();
    const to = mode === 'live' ? this.config.intakeAddress : dryrunInbox || '';

    const subjectPrefix = mode === 'live' ? '' : '[DRYRUN] ';
    const subject = `${subjectPrefix}Whistleblower report ${view.trackingId} — submitted via Vera.Report`;
    const coverLetter = this.renderCoverLetter(view, packet);
    const attachments = [
      {
        filename: `vera-report-${view.trackingId}.zip`,
        contentType: 'application/zip',
        content: archive,
      },
      {
        filename: `vera-packet-${view.trackingId}.json`,
        contentType: 'application/json',
        content: Buffer.from(JSON.stringify(packet.sidecar, null, 2)),
      },
      ...(this.config.extraAttachments?.(view, packet) ?? []),
    ];

    // Dryrun bypasses narrative review, so report content may only reach the
    // dryrun inbox encrypted to a pinned key. Otherwise send a notice instead.
    if (mode !== 'live' && !(to && recipientRequiresEncryption(to))) {
      return {
        entityId: this.entityId,
        trackingId: view.trackingId,
        mode: 'email',
        email: {
          to,
          subject: `[DRYRUN] Dispatch notice for ${view.trackingId} (no report content)`,
          coverLetter: this.renderDryrunNotice(view, packet, coverLetter, attachments),
          attachments: [],
          contentFree: true,
        },
      };
    }

    return {
      entityId: this.entityId,
      trackingId: view.trackingId,
      mode: 'email',
      email: { to, subject, coverLetter, attachments },
    };
  }

  async dispatch(prep: PreparedSubmission): Promise<DispatchResult> {
    if (!prep.email) throw new DispatchNotSentError(`[${this.entityId}] prepared submission has no email payload`);
    if (!prep.email.to) {
      throw new DispatchNotSentError(
        `[${this.entityId}] no recipient: dryrun mode requires DISSEMINATION_DRYRUN_INBOX to be set`,
      );
    }

    const messageId = await this.breaker.execute(() => this.sendRawEmail(prep.email!, prep.auditTrackingId));

    return {
      outcome: 'sent',
      provisionalReceipt: { type: 'smtp-message-id', value: messageId },
      detail: `SES message ${messageId} to ${prep.email.to} (${disseminationMode()} mode)`,
    };
  }

  parseReceipt(raw: unknown): Receipt | null {
    if (typeof raw !== 'string' || !raw.trim()) return null;
    for (const { pattern, type } of this.config.receiptPatterns ?? []) {
      const match = raw.match(pattern);
      if (match) {
        return { type, value: match[1] ?? match[0], receivedAt: new Date() };
      }
    }
    return null;
  }

  // ── Cover letter ──────────────────────────────────────────────────

  protected renderCoverLetter(view: DisseminationView, packet: Packet): string {
    const categories = view.categories.map((c) => categoryLabel(c)).join('; ') || 'Uncategorized';
    const files = view.evidence.files;
    const manifestLines =
      files.length === 0
        ? ['  (no evidence files attached)']
        : files.map((f, i) => `  ${i + 1}. ${f.name}${f.cid ? ` — IPFS CID ${f.cid}` : ''}`);

    return [
      this.config.salutation,
      '',
      this.config.bodyIntro,
      '',
      `Tracking ID: ${view.trackingId}`,
      `Concern categories: ${categories}`,
      view.urgency ? `Urgency: ${view.urgency}` : null,
      view.dateOfIncident ? `Date of incident: ${view.dateOfIncident}` : null,
      view.location ? `Location: ${view.location}` : null,
      '',
      'A full dossier (PDF) and a machine-readable packet (JSON) are attached.',
      '',
      'Evidence manifest (encrypted originals pinned to IPFS; digests below):',
      ...manifestLines,
      view.evidence.evidenceHash ? `Evidence digest (SHA-256): ${view.evidence.evidenceHash}` : null,
      `Packet digest (SHA-256): ${packet.packetHash}`,
      '',
      'Evidence decryption keys are not included.',
      'The attached ZIP includes the report PDF and readable evidence files. Extract it to open the attachments.',
      '',
      view.zkProof
        ? `Existence proof: this report is anchored to the Midnight blockchain ` +
          `(proof hash ${view.zkProof.proofHash}${view.zkProof.txHash ? `, tx ${view.zkProof.txHash}` : ''}), ` +
          `establishing tamper-evident existence at its stated submission time.`
        : null,
      '',
      'Transmittal statement: Vera.Report transmits reporter-authored content on the',
      "reporter's instruction and with the reporter's explicit consent; it does not",
      'independently verify the truth of the allegations.',
      '',
      'Vera.Report — anonymous whistleblowing infrastructure',
      'https://vera.report',
    ]
      .filter((line): line is string => line !== null)
      .join('\n');
  }

  /**
   * Content-free dryrun notice: what live mode would send, by size only. It
   * must never include the narrative, evidence names, categories, location or
   * any other reporter-authored field.
   */
  protected renderDryrunNotice(
    view: DisseminationView,
    packet: Packet,
    coverLetter: string,
    attachments: { filename: string; contentType: string; content: Buffer }[],
  ): string {
    return [
      'DRYRUN dispatch notice. This message contains no report content.',
      '',
      'Dissemination runs in dryrun mode and the dryrun inbox has no pinned PGP key',
      'in DISSEMINATION_EMAIL_POLICIES, so the narrative and evidence were withheld.',
      '',
      `Entity: ${this.config.entityName} (${this.entityId})`,
      `Case reference: ${view.trackingId}`,
      'Channel: email (Tier A)',
      `Live recipient: ${this.config.intakeAddress}`,
      '',
      'Live mode would send:',
      `  Cover letter: ${Buffer.byteLength(coverLetter, 'utf8')} bytes`,
      ...attachments.map(a => `  Attachment: ${a.filename} (${a.contentType}, ${a.content.length} bytes)`),
      `  Evidence files in manifest: ${view.evidence.files.length}`,
      `Packet digest (SHA-256): ${packet.packetHash}`,
      '',
      'To receive the encrypted packet in dryrun, pin a PGP key for this inbox in',
      'DISSEMINATION_EMAIL_POLICIES.',
    ].join('\n');
  }

  // ── SES raw MIME ──────────────────────────────────────────────────

  private initialise(): SESv2Client {
    if (this.sesClient) return this.sesClient;
    const endpointUrl = process.env.AWS_ENDPOINT_URL?.trim();
    this.sesClient = new SESv2Client({
      // SES has no idempotency key: a lost response must not cause an SDK resend.
      maxAttempts: 1,
      region: process.env.SES_REGION || process.env.AWS_REGION || 'us-east-2',
      ...(endpointUrl && { endpoint: endpointUrl }),
    });
    return this.sesClient;
  }

  private senderAddress(): string {
    const dedicated = process.env.DISSEMINATION_SENDER_EMAIL?.trim();
    const fallback = process.env.SES_SENDER_EMAIL?.trim();
    const sender = dedicated || fallback;
    if (!sender) {
      throw new DispatchNotSentError(
        `[${this.entityId}] no sender configured (set DISSEMINATION_SENDER_EMAIL or SES_SENDER_EMAIL)`,
      );
    }
    return sender;
  }

  /**
   * Per-entity receipt mailbox (Phase 2a): agency replies route to
   * `<entityId>-receipts@<DISSEMINATION_RECEIPT_DOMAIN>`, where SES inbound
   * relays them to the inbound-mail webhook. Absent config = no Reply-To,
   * replies go to the sender address as before.
   */
  replyToAddress(): string | null {
    const domain = process.env.DISSEMINATION_RECEIPT_DOMAIN?.trim();
    if (!domain) return null;
    return `${this.entityId}-receipts@${domain}`;
  }

  private async sendRawEmail(email: NonNullable<PreparedSubmission['email']>, trackingId?: string): Promise<string> {
    const client = this.initialise();
    const raw = await this.buildMime(this.senderAddress(), email, trackingId);

    const result = await client.send(
      new SendEmailCommand({
        FromEmailAddress: this.senderAddress(),
        Destination: { ToAddresses: [email.to] },
        Content: { Raw: { Data: raw } },
      }),
      { abortSignal: AbortSignal.timeout(SEND_TIMEOUT_MS) },
    );

    if (!result.MessageId) throw new Error('SES delivery outcome is unknown: missing message ID');
    return result.MessageId;
  }

  /** Encrypt the complete inner MIME entity, including attachment names. */
  async buildMime(from: string, email: NonNullable<PreparedSubmission['email']>, trackingId?: string): Promise<Uint8Array> {
    const inner = Buffer.from([...this.mixedEntityLines(email), ''].join('\r\n'), 'utf8');
    const live = disseminationMode() === 'live';
    // Outside live mode, report content is only ever sent encrypted.
    if (!live && !email.contentFree && !recipientRequiresEncryption(email.to)) {
      throw new DispatchNotSentError('Dryrun report content requires a pinned PGP key for the dryrun inbox; no email was sent');
    }
    const encrypted = await encryptForRecipient(email.to, inner, live, async exception => {
      if (!trackingId) throw new DispatchNotSentError('A live plaintext exception requires report audit context');
      try {
        await disseminationPersistence.appendAudit({
          trackingId, entityId: this.entityId, actor: 'system',
          event: 'email_plaintext_exception_attempted', detail: exception,
        });
      } catch (err: unknown) {
        // The audit write precedes the SES call, so nothing was sent.
        throw new DispatchNotSentError(err instanceof Error ? err.message : String(err));
      }
    });
    if (encrypted === null) {
      return Buffer.from([...this.topHeaders(from, email), inner.toString('utf8')].join('\r\n'), 'utf8');
    }
    const boundary = `vera-pgp-${crypto.randomBytes(12).toString('hex')}`;
    // The tracking token and attachment filenames stay inside the ciphertext.
    return Buffer.from([
      ...this.topHeaders(from, { ...email, subject: 'Confidential report via Vera.Report' }),
      `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${boundary}"`,
      '', `--${boundary}`, 'Content-Type: application/pgp-encrypted', '', 'Version: 1', '',
      `--${boundary}`, 'Content-Type: application/octet-stream; name="encrypted.asc"',
      'Content-Disposition: inline; filename="encrypted.asc"', '', encrypted.replace(/\r?\n/g, '\r\n'),
      `--${boundary}--`, '',
    ].join('\r\n'), 'utf8');
  }

  /** RFC 5322 top-level headers, ending with the mixed Content-Type. */
  private topHeaders(from: string, email: NonNullable<PreparedSubmission['email']>): string[] {
    const replyTo = this.replyToAddress();
    return [
      `From: ${from}`,
      `To: ${email.to}`,
      ...(replyTo ? [`Reply-To: ${replyTo}`] : []),
      `Subject: ${email.subject}`,
      'MIME-Version: 1.0',
    ];
  }

  /** The multipart/mixed entity: its Content-Type header plus the body. */
  private mixedEntityLines(email: NonNullable<PreparedSubmission['email']>): string[] {
    const boundary = `vera-${crypto.randomBytes(12).toString('hex')}`;
    const lines: string[] = [
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      quotedPrintable(email.coverLetter),
      '',
    ];

    for (const attachment of email.attachments) {
      lines.push(
        `--${boundary}`,
        `Content-Type: ${attachment.contentType}; name="${attachment.filename}"`,
        'Content-Transfer-Encoding: base64',
        `Content-Disposition: attachment; filename="${attachment.filename}"`,
        '',
        chunkBase64(attachment.content.toString('base64')),
        '',
      );
    }

    lines.push(`--${boundary}--`);
    return lines;
  }
}

/** Encode text as quoted-printable (RFC 2045) for the MIME body. */
function quotedPrintable(text: string): string {
  return text.split(/\r\n|\r|\n/).map(line => {
    const chunks: string[] = [];
    let current = '';
    for (const byte of Buffer.from(line, 'utf8')) {
      const token = byte >= 33 && byte <= 126 && byte !== 61
        ? String.fromCharCode(byte) : `=${byte.toString(16).toUpperCase().padStart(2, '0')}`;
      if (current.length + token.length > 75) { chunks.push(current + '='); current = ''; }
      current += token;
    }
    chunks.push(current);
    return chunks.join('\r\n');
  }).join('\r\n');
}

/** Wrap base64 at 76 chars per RFC 2045. */
function chunkBase64(b64: string): string {
  const chunks: string[] = [];
  for (let i = 0; i < b64.length; i += 76) {
    chunks.push(b64.slice(i, i + 76));
  }
  return chunks.join('\r\n');
}
