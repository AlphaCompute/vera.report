import { snapshotPacketEvidence } from './packetEvidence';
import { logger } from '../../utils/logger';
import { recipientCaseReference } from './recipientCapability';
/**
 * Secure-packet sender (reporter-reward flow).
 *
 * One place that mints a one-time secure-packet link, routes it (dryrun → test
 * inbox / live → recipient), sends it, and audits it. Shared by two callers:
 *   - the admin-triggered endpoint (#505), origin default; and
 *   - the automatic send on report submission (`autoSendSecurePackets`),
 *     origin 'auto'.
 *
 * Firewall + safety invariants (see the reporter-reward plan):
 *   - Consent-gated: nothing leaves unless the reporter agreed to legal
 *     review (`legalReviewConsented`), never on agency-dispatch consent alone.
 *   - Dryrun by default: real recipients are only emailed when
 *     DISSEMINATION_MODE=live; otherwise everything routes to the test inbox.
 *   - Server-side recipient allowlist: the auto path resolves a recipient *id*
 *     to an address from DISSEMINATION_RECIPIENT_EMAILS — a tampered submission
 *     cannot redirect a packet to an arbitrary inbox.
 *   - Redacted narrative, fail-closed: the auto path scrubs the narrative before
 *     any link is sent; if redaction is unavailable it sends nothing.
 */

import crypto from 'node:crypto';
import { disseminationService } from './disseminationService';
import { disseminationPersistence } from './disseminationPersistence';
import { issueRecipientCapability } from './recipientCapability';
import { secureLinkUrl, SECURE_LINK_ENTITY_ID } from './secureLink';
import { redactionService } from './redactionService';
import { emailNotificationService } from '../emailNotification';
import { reportPersistenceService } from '../reportPersistence';
import type { ReportRecord } from '../reportPersistence';
import { encryptContactValue } from '../reportFieldCrypto';
import { isValidRecipientId, getRewardRecipient } from './rewardRecipients';
import { legalReviewConsented } from '../../utils/intakeConsent';
import { normalizeRecipientEmail } from '../../utils/recipientEmail';

/** Current dispatch mode — 'live' only when explicitly set, else 'dryrun'. */
export function disseminationMode(): 'live' | 'dryrun' {
  return (process.env.DISSEMINATION_MODE || '').trim().toLowerCase() === 'live' ? 'live' : 'dryrun';
}

/**
 * Resolve a reward-recipient id to a send address from the server-side env map
 * DISSEMINATION_RECIPIENT_EMAILS ({"<id>":"<email>"}). Returns null for an
 * unknown id, an unset/malformed map, or a missing/invalid address. The id must
 * be in the curated allowlist (lib/rewardRecipients) — the client only ever
 * sends the id, never the address.
 */
export function resolveRecipientEmail(id: string): string | null {
  if (!isValidRecipientId(id)) return null;
  const raw = process.env.DISSEMINATION_RECIPIENT_EMAILS;
  if (!raw) return null;
  try {
    const map = JSON.parse(raw) as Record<string, unknown>;
    const email = map?.[id];
    return normalizeRecipientEmail(email);
  } catch {
    return null;
  }
}

export interface SendSecurePacketResult {
  sent: boolean;
  url?: string;
  sentTo?: string;
  mode?: 'live' | 'dryrun';
  error?: string;
}

/**
 * Mint + send a single one-time secure-packet link. `recipientEmail` is the LIVE
 * target address (ignored in dryrun, which routes to DISSEMINATION_DRYRUN_INBOX);
 * `recipientLabel` is the human name used in the email/audit when it differs from
 * the raw address. Consent is enforced here so both callers are covered.
 */
export async function sendSecurePacket(args: {
  trackingId: string;
  recipientEmail: string;
  actor: string;
  origin?: 'auto';
  recipientLabel?: string;
}): Promise<SendSecurePacketResult> {
  const loaded = await disseminationService.buildView(args.trackingId);
  if (!loaded) return { sent: false, error: 'report_not_found' };

  const consent = disseminationService.consentFromReport(loaded.report);
  if (!consent?.legalReview) return { sent: false, error: 'reporter_consent_missing' };

  if (['dismissed', 'rejected'].includes(loaded.report.status)) return { sent: false, error: 'report_not_eligible' };
  if (args.origin === 'auto') {
    if (loaded.report.processingStatus !== 'completed' || loaded.report.verification?.isLegitimate !== true) {
      return { sent: false, error: 'report_not_eligible' };
    }
  } else {
    const disposition = await disseminationPersistence.getDisposition(args.trackingId);
    if (!(disposition?.narrativeOverride?.narrative?.trim() || disposition?.narrativeReviewedAt) || !loaded.narrativeReadable) {
      return { sent: false, error: 'narrative_review_required' };
    }
  }

  const mode = disseminationMode();
  const recipientEmail = normalizeRecipientEmail(args.recipientEmail);
  if (mode === 'live' && !recipientEmail) {
    return { sent: false, error: 'recipient_email_missing' };
  }
  const dryrunInbox = process.env.DISSEMINATION_DRYRUN_INBOX;
  if (mode === 'dryrun' && !dryrunInbox?.trim()) return { sent: false, error: 'dryrun_inbox_not_configured' };
  const sentTo = mode === 'live' ? recipientEmail : normalizeRecipientEmail(dryrunInbox);
  if (!sentTo) return { sent: false, error: 'dryrun_inbox_invalid' };

  let evidenceDigest: string | undefined;
  if (args.origin !== 'auto') {
    try { evidenceDigest = await snapshotPacketEvidence(args.trackingId); }
    catch (error) {
      if (error instanceof Error && error.message === 'packet_evidence_size_unsupported') return { sent: false, error: error.message };
      throw error;
    }
  }
  const { url, token } = secureLinkUrl(args.trackingId, SECURE_LINK_ENTITY_ID, args.origin, evidenceDigest);
  await issueRecipientCapability(token, 'securelink');

  // Reply-To routes recipient replies back into the receipt/relay path so the
  // reporter can be reached anonymously. Gated on DISSEMINATION_RELAY_ENABLED,
  // NOT merely on the receipt domain: that domain also drives agency-receipt
  // tracking, so keying the reward-reply promise off it alone would resurrect
  // "reply to reach the reporter" on secure-packet mail the moment the domain
  // is set for any reason — while the inbound relay may not be deployed. The
  // promise (and the Reply-To) appear only when the relay is explicitly enabled.
  const relayEnabled = process.env.DISSEMINATION_RELAY_ENABLED === 'true';
  const receiptDomain = process.env.DISSEMINATION_RECEIPT_DOMAIN;
  const replyTo =
    relayEnabled && receiptDomain ? `${SECURE_LINK_ENTITY_ID}-receipts@${receiptDomain}` : undefined;

  const caseReference = recipientCaseReference(args.trackingId, SECURE_LINK_ENTITY_ID);
  await disseminationPersistence.registerRecipientCase(caseReference, SECURE_LINK_ENTITY_ID, args.trackingId);
  const result = await emailNotificationService.sendSecurePacketEmail({
    recipient: sentTo,
    trackingId: caseReference,
    url,
    replyTo,
    dryrun: mode !== 'live',
    intendedRecipient: args.recipientLabel || recipientEmail || undefined,
  });
  if (!result.sent) return { sent: false, error: result.error || 'send_failed', mode };

  await disseminationPersistence.appendAudit({
    trackingId: args.trackingId,
    entityId: SECURE_LINK_ENTITY_ID,
    event: 'secure_packet_emailed',
    actor: args.actor,
    detail: {
      tokenDigest: crypto.createHash('sha256').update(token).digest('hex').slice(0, 16),
      mode,
      origin: args.origin || 'admin',
      recipient: args.recipientLabel || recipientEmail || sentTo,
      sentTo,
    },
  });

  return { sent: true, url, sentTo, mode };
}

/** Mint an admin link without sending mail; retain the same consent/review gates. */
export async function generateSecurePacket(args: { trackingId: string; actor: string }): Promise<{ url?: string; error?: string }> {
  const loaded = await disseminationService.buildView(args.trackingId);
  if (!loaded) return { error: 'report_not_found' };
  if (!disseminationService.consentFromReport(loaded.report)?.legalReview) return { error: 'reporter_consent_missing' };
  if (['dismissed', 'rejected'].includes(loaded.report.status)) return { error: 'report_not_eligible' };
  const disposition = await disseminationPersistence.getDisposition(args.trackingId);
  if (!(disposition?.narrativeOverride?.narrative?.trim() || disposition?.narrativeReviewedAt) || !loaded.narrativeReadable) {
    return { error: 'narrative_review_required' };
  }
  let evidenceDigest: string | undefined;
  try { evidenceDigest = await snapshotPacketEvidence(args.trackingId); }
  catch (error) {
    if (error instanceof Error && error.message === 'packet_evidence_size_unsupported') return { error: error.message };
    throw error;
  }
  const { url, token } = secureLinkUrl(args.trackingId, SECURE_LINK_ENTITY_ID, undefined, evidenceDigest);
  await issueRecipientCapability(token, 'securelink');
  await disseminationPersistence.registerRecipientCase(recipientCaseReference(args.trackingId, SECURE_LINK_ENTITY_ID), SECURE_LINK_ENTITY_ID, args.trackingId);
  // Do not return a bearer capability when its audit record cannot be persisted.
  await disseminationPersistence.appendAudit({
    trackingId: args.trackingId, entityId: SECURE_LINK_ENTITY_ID,
    event: 'secure_packet_generated', actor: args.actor,
    detail: { tokenDigest: crypto.createHash('sha256').update(token).digest('hex').slice(0, 16), origin: 'admin' },
  });
  return { url };
}

/**
 * Automatic send on report submission: for each recipient the reporter chose,
 * email a one-time secure-packet link once background processing has completed.
 * Gated and fail-closed — never throws into the caller (processSubmission).
 */
export async function autoSendSecurePackets(
  report: ReportRecord,
  plaintextNarrative: string | undefined,
): Promise<void> {
  const recipients = report.disseminationRecipients ?? [];
  if (recipients.length === 0) return;
  if (!legalReviewConsented(report.consent)) return;

  // Never auto-forward a report the AI flagged as illegitimate.
  if (['rejected', 'dismissed'].includes(report.status) || report.processingStatus !== 'completed' || report.verification?.isLegitimate !== true) {
    await auditSkip(report.trackingId, 'report_rejected');
    return;
  }

  // Redacted narrative, fail-closed: scrub before anything is sent; if the
  // redaction service is unavailable, send nothing (the admin path is the
  // fallback) rather than risk raw self-identifying text leaving.
  let redacted: string;
  try {
    const proposal = await redactionService.propose(plaintextNarrative || '');
    redacted = proposal.redacted;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn(`[SECURE_PACKET] Auto-send skipped for ${report.trackingId} — redaction unavailable: ${msg}`);
    await auditSkip(report.trackingId, 'redaction_unavailable');
    return;
  }

  // Freeze the scrubbed narrative (encrypted at rest); the reveal route serves
  // this copy for origin:'auto' links.
  try {
    await reportPersistenceService.patch(report.trackingId, {
      encryptedDisseminationNarrative: encryptContactValue(redacted),
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`[SECURE_PACKET] Failed to persist dissemination narrative for ${report.trackingId}: ${msg}`);
    await auditSkip(report.trackingId, 'narrative_persist_failed');
    return;
  }

  const mode = disseminationMode();
  for (const id of recipients) {
    const email = resolveRecipientEmail(id);
    const recipient = getRewardRecipient(id);
    const label = recipient ? `${recipient.name}, ${recipient.org}` : id;

    // Live send needs a configured address; dryrun routes to the test inbox.
    if (mode === 'live' && !email) {
      await auditSkip(report.trackingId, 'recipient_not_configured', id);
      continue;
    }

    try {
      const res = await sendSecurePacket({
        trackingId: report.trackingId,
        recipientEmail: email || '',
        actor: 'auto-submit',
        origin: 'auto',
        recipientLabel: label,
      });
      if (!res.sent) {
        await auditSkip(report.trackingId, res.error || 'send_failed', id);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`[SECURE_PACKET] Auto-send error for ${report.trackingId} → ${id}: ${msg}`);
      await auditSkip(report.trackingId, 'send_error', id);
    }
  }
}

async function auditSkip(trackingId: string, reason: string, recipientId?: string): Promise<void> {
  try {
    await disseminationPersistence.appendAudit({
      trackingId,
      entityId: SECURE_LINK_ENTITY_ID,
      event: 'secure_packet_autosend_skipped',
      actor: 'auto-submit',
      detail: { reason, ...(recipientId ? { recipientId } : {}) },
    });
  } catch {
    /* audit is best-effort */
  }
}
