import { logger } from '../../utils/logger';
import { SECURE_LINK_ENTITY_ID } from './secureLink';
/**
 * Inbound receipt mail ingest (Phase 2a, VERA-PDR-001 FR-6).
 *
 * Agencies reply to per-entity receipt mailboxes
 * (`<entityId>-receipts@<receipt domain>`). SES inbound stores the raw
 * message in S3 and a relay Lambda posts a digest of it to the
 * dissemination webhook, which lands here. Ingest attempts a fully
 * automatic match:
 *
 *   recipient mailbox → entityId
 *   tracking ID quoted in subject/body → report
 *   adapter.parseReceipt() → entity-native receipt (incident ID, control
 *   number, …)
 *
 * When all three succeed the receipt is recorded and the SLA ack clock
 * stops. Anything else is kept in the `dissemination_inbound` review
 * queue — agency correspondence is never silently dropped (NFR-3).
 */

import crypto from 'node:crypto';
import { disseminationPersistence } from './disseminationPersistence';
import { receiptTracker } from './receiptTracker';
import { getAdapter } from './adapters/registry';
import { getEntity } from './taxonomy';
import type { InboundMailDoc } from './types';

const TRACKING_ID_RE = /VRA-[A-F0-9]{16}/i;

export interface InboundMailPayload {
  authentication?: { spf?: string; dkim?: string; dmarc?: string };
  recipient: string;
  from: string;
  subject: string;
  body: string;
  s3Key?: string;
  messageId?: string;
  receivedAt?: string | Date;
}

/** Map a receipt mailbox address to its entity: `cisa-receipts@…` → `cisa`. */
export function resolveEntityFromRecipient(recipient: string): string | null {
  const local = recipient.trim().toLowerCase().split('@')[0];
  const match = local.match(/^(.+)-receipts$/);
  if (!match) return null;
  const entityId = match[1];
  return getEntity(entityId) || entityId === SECURE_LINK_ENTITY_ID ? entityId : null;
}

export function extractTrackingId(...texts: (string | undefined)[]): string | null {
  for (const text of texts) {
    const match = text?.match(TRACKING_ID_RE);
    if (match) return match[0].toUpperCase();
  }
  return null;
}

class InboundMailService {
  /**
   * Ingest one inbound message. Idempotent on the SES message ID
   * (redeliveries update nothing).
   */
  async ingest(payload: InboundMailPayload): Promise<{
    inboundId: string;
    autoParsed: boolean;
    trackingId?: string;
    entityId?: string;
  }> {
    const receivedAt = payload.receivedAt ? new Date(payload.receivedAt) : new Date();
    const entityId = resolveEntityFromRecipient(payload.recipient) ?? undefined;
    const reference = `${payload.subject} ${payload.body}`.match(/CASE-[a-f0-9]{24}/i)?.[0];
    const trackingId = reference && entityId
      ? await disseminationPersistence.resolveRecipientCase(reference.toLowerCase().replace('case-', 'CASE-'), entityId)
      : extractTrackingId(payload.subject, payload.body) ?? undefined;

    // Deterministic ID from the SES message ID makes redelivery a no-op.
    const inboundId = payload.messageId
      ? crypto.createHash('sha256').update(payload.messageId).digest('hex').slice(0, 32)
      : crypto.randomUUID();

    const doc: InboundMailDoc = {
      inboundId,
      authentication: payload.authentication,
      recipient: payload.recipient,
      from: payload.from,
      subject: payload.subject,
      body: payload.body.slice(0, 10_000),
      s3Key: payload.s3Key,
      messageId: payload.messageId,
      trackingId,
      entityId,
      status: 'pending_review',
      autoParsed: false,
      receivedAt,
      createdAt: new Date(),
    };

    const existing = await disseminationPersistence.getInboundMail(inboundId);
    if (existing && existing.status !== 'pending_review') return { inboundId, autoParsed: existing.autoParsed, trackingId: existing.trackingId, entityId: existing.entityId };
    await disseminationPersistence.insertInboundMail(doc);
    const autoParsed = await this.tryAutoRecord(existing ?? doc);
    doc.autoParsed = autoParsed;
    if (autoParsed) {
      doc.status = 'resolved';
      doc.resolvedBy = 'system';
      doc.resolvedAt = new Date();
    }

    if (autoParsed) await disseminationPersistence.patchInboundMail(inboundId, { autoParsed: true, status: 'resolved', resolvedBy: 'system', resolvedAt: doc.resolvedAt });
    if (!autoParsed) {
      logger.warn(
        `[DISSEMINATION] Inbound mail queued for review (${payload.recipient}, ` +
          `tracking ${trackingId ?? 'unknown'}, entity ${entityId ?? 'unknown'})`,
      );
    }
    return { inboundId, autoParsed, trackingId, entityId };
  }

  /** Full-auto path: entity + tracking ID + recognizable receipt pattern. */
  private async tryAutoRecord(doc: InboundMailDoc): Promise<boolean> {
    if (!doc.entityId || !doc.trackingId || !doc.messageId) return false;
    if (doc.authentication?.spf !== 'PASS' || doc.authentication?.dkim !== 'PASS' || doc.authentication?.dmarc !== 'PASS') return false;
    // No configured trusted sender means manual review, never pattern-only trust.
    let configured: Record<string, string[]>;
    try { configured = JSON.parse(process.env.DISSEMINATION_RECEIPT_SENDERS || '{}'); } catch { return false; }
    if (doc.from.includes(',')) return false;
    const address = doc.from.trim().match(/^(?:[^<>]*<)?([^<>\s,]+@[^<>\s,]+)>?$/)?.[1]?.toLowerCase();
    const allowed = configured[doc.entityId];
    if (!address || !Array.isArray(allowed) || !allowed.some(value => typeof value === 'string' && value.toLowerCase() === address)) return false;

    const adapter = getAdapter(doc.entityId);
    if (!adapter) return false;

    const parsed = adapter.parseReceipt(`${doc.subject}\n${doc.body}`);
    if (!parsed) return false;

    const submissions = await disseminationPersistence.getSubmissionsForReport(doc.trackingId);
    const sub = submissions.find((s) => s.entityId === doc.entityId);
    if (!sub) return false;

    await receiptTracker.recordReceipt(sub, parsed, 'inbound-mail', 'ack', `inbound:${doc.inboundId}`);
    return true;
  }

  /**
   * Admin resolution of a queued message: attach it to a submission as a
   * receipt. The admin supplies the (possibly corrected) tracking ID and
   * entity when ingest couldn't infer them.
   */
  async resolve(
    inboundId: string,
    actor: string,
    opts: { trackingId: string; entityId: string; kind?: 'receipt' | 'ack' | 'feedback'; value?: string },
  ): Promise<{ ok: boolean; error?: string }> {
    const mail = await disseminationPersistence.getInboundMail(inboundId);
    if (!mail) return { ok: false, error: 'inbound_not_found' };
    if (mail.status !== 'pending_review') return { ok: false, error: `already_${mail.status}` };

    const submissions = await disseminationPersistence.getSubmissionsForReport(opts.trackingId);
    const sub = submissions.find((s) => s.entityId === opts.entityId);
    if (!sub) return { ok: false, error: 'submission_not_found' };

    const adapter = getAdapter(opts.entityId);
    const raw = opts.value ?? `${mail.subject}\n${mail.body}`;
    const receipt =
      adapter?.parseReceipt(raw) ??
      receiptTracker.buildManualReceipt(opts.value ?? mail.subject, `inbound mail from ${mail.from}`);
    await receiptTracker.recordReceipt(sub, receipt, actor, opts.kind ?? 'ack', `inbound:${inboundId}`);

    await disseminationPersistence.patchInboundMail(inboundId, {
      status: 'resolved',
      trackingId: opts.trackingId,
      entityId: opts.entityId,
      resolvedBy: actor,
      resolvedAt: new Date(),
    });
    return { ok: true };
  }

  /** Dismiss noise (spam, out-of-office, unrelated mail). */
  async dismiss(inboundId: string, actor: string): Promise<{ ok: boolean; error?: string }> {
    const mail = await disseminationPersistence.getInboundMail(inboundId);
    if (!mail) return { ok: false, error: 'inbound_not_found' };
    if (mail.status !== 'pending_review') return { ok: false, error: `already_${mail.status}` };

    await disseminationPersistence.patchInboundMail(inboundId, {
      status: 'dismissed',
      resolvedBy: actor,
      resolvedAt: new Date(),
    });
    return { ok: true };
  }
}

export const inboundMailService = new InboundMailService();
