import { exportPacketArchive, snapshotPacketEvidence } from '../services/dissemination/packetEvidence';
import { reserveUpload, withUploadBudget } from '../middleware/uploadBudget';
import { reviewedNarrativeMatches } from '../services/dissemination/narrativeReview';
import { verifyWebhookSignature, webhookEventKey } from '../middleware/webhookIntegrity';
import { recipientCaseReference } from '../services/dissemination/recipientCapability';
/**
 * Dissemination API Router (VERA-PDR-001 §11) — admin surface for the
 * capture → route → dispatch pipeline.
 *
 * Admin-facing routes are gated by requireInternalSecret — admins reach
 * them through the Next.js proxy, which enforces Auth0 admin role (defense
 * in depth, same pattern as the evidence routes). The token-scoped escrow
 * download is the only public route here; the receipt webhook + inbound
 * mailboxes arrive with the inbound-SES slice.
 */

import crypto from 'node:crypto';
import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import { requireInternalSecret } from '../middleware/internalSecret';
import { disseminationService } from '../services/dissemination/disseminationService';
import { dispatchWorker } from '../services/dissemination/dispatchWorker';
import { disseminationPersistence } from '../services/dissemination/disseminationPersistence';
import { reportPersistenceService } from '../services/reportPersistence';
import { getEntity, isCategorySlug, isJurisdiction, isOrgType } from '../services/dissemination/taxonomy';
import { relayService } from '../services/dissemination/relayService';
import { auditAnchorService } from '../services/dissemination/auditAnchor';
import { counselService } from '../services/dissemination/counselService';
import { verifyWorkspaceToken, workspaceUrl, workspaceAssignmentKey } from '../services/dissemination/counselWorkspace';
import { receiptTracker } from '../services/dissemination/receiptTracker';
import { inboundMailService } from '../services/dissemination/inboundMail';
import { getAdapter } from '../services/dissemination/adapters/registry';
import { verifySecureLinkToken } from '../services/dissemination/secureLink';
import { decryptContactValue } from '../services/reportFieldCrypto';
import { packetSubmitterFor, submitterDisclosureUnchanged } from '../services/submitterDisclosure';

import { issueRecipientCapability, recipientCapabilityActive } from '../services/dissemination/recipientCapability';
import { recipientEvidence, sendRecipientEvidence } from '../services/dissemination/evidenceAccess';
import { escrowBinding } from '../services/dissemination/escrowRelease';
import { channelConsented } from '../services/dissemination/consentScope';
import { legalReviewConsented } from '../utils/intakeConsent';
import { normalizeRecipientEmail } from '../utils/recipientEmail';

const router = Router();

const adminLimiter = rateLimit({
  keyGenerator: requestRateLimitKey,
  store: sharedRateLimitStore('dissemination.admin'),
  windowMs: 60 * 1000,
  max: 60,
  message: { success: false, error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const TRACKING_ID_RE = /^VRA-[A-F0-9]{16}$/i;

function validTrackingId(req: Request, res: Response): string | null {
  const trackingId = req.params.trackingId as string;
  if (!trackingId || !TRACKING_ID_RE.test(trackingId)) {
    res.status(400).json({ success: false, error: 'Invalid tracking ID format' });
    return null;
  }
  return trackingId;
}

/**
 * Self-contained landing/status page for the one-time secure-packet link.
 * No external assets (CSP-safe), no reporter identity. The `ready` state
 * renders a POST form whose submit consumes the link and returns the packet;
 * a bare GET never consumes it, so email link-scanners cannot burn the link.
 */
function renderSecureLinkPage(opts: {
  state: 'ready' | 'used' | 'invalid' | 'stale' | 'error';
  trackingId?: string;
  actionBase?: string;
}): string {
  const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const tid = opts.trackingId
    ? `<p>Tracking ID: <code>${esc(opts.trackingId)}</code></p>`
    : '';
  const shell = (title: string, body: string) =>
    `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<meta name="robots" content="noindex, nofollow"><title>${esc(title)}</title><style>` +
    `:root{color-scheme:light dark}` +
    `body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;` +
    `background:#0f1115;color:#e7e9ee;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}` +
    `.card{max-width:520px;width:100%;background:#171a21;border:1px solid #262b36;border-radius:14px;padding:32px}` +
    `h1{font-size:20px;margin:0 0 10px}p{line-height:1.55;color:#aeb4c0;font-size:14px}` +
    `code{background:#0f1115;padding:2px 6px;border-radius:5px;color:#cfd4de;word-break:break-all}` +
    `button{margin-top:20px;background:#3b82f6;color:#fff;border:0;border-radius:9px;padding:13px 22px;` +
    `font-size:15px;font-weight:600;cursor:pointer}button:hover{background:#2f6fe0}` +
    `.muted{font-size:12px;color:#727a89;margin-top:22px}</style></head><body><div class="card">${body}</div></body></html>`;

  switch (opts.state) {
    case 'ready':
      return shell(
        'Secure disclosure packet',
        `<h1>You have received a secure disclosure packet</h1>${tid}` +
          `<p>This is a one-time secure link from Vera.Report. It can be opened <strong>once</strong>. ` +
          `Download the ZIP below, then extract it to open report.pdf and all attached evidence.</p>` +
          `<form method="POST" action="${esc(opts.actionBase || '')}/reveal"><button type="submit">Reveal packet</button></form>` +
          `<p class="muted">The packet contains reviewed disclosure material; its contents may still identify people. For questions or follow-up, ` +
          `contact the person or organization that shared this link. This download link does not provide a messaging channel to the submitter.</p>`,
      );
    case 'used':
      return shell(
        'Link already used',
        `<h1>This link has already been opened</h1>${tid}` +
          `<p>A one-time secure packet link can be revealed only once. If you need access again, ` +
          `ask your Vera.Report contact to issue a fresh link.</p>`,
      );
    case 'invalid':
      return shell(
        'Link invalid or expired',
        `<h1>This link is invalid or has expired</h1>` +
          `<p>The secure packet link could not be verified — it may have expired. ` +
          `Ask your Vera.Report contact to issue a fresh link.</p>`,
      );
    case 'stale':
      return shell(
        'Link out of date',
        `<h1>This link is out of date</h1>` +
          `<p>The report's files changed after this link was issued, so it can no longer be opened. ` +
          `Ask your Vera.Report contact to issue a fresh link.</p>`,
      );
    default:
      return shell(
        'Something went wrong',
        `<h1>Something went wrong</h1>` +
          `<p>The packet could not be prepared right now. Please try again shortly, or contact Vera.Report.</p>`,
      );
  }
}

router.post('/:trackingId/plan', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const plan = await disseminationService.plan(trackingId);
    if (!plan) return res.status(404).json({ success: false, error: 'Report not found' });
    res.json({ success: true, plan });
  } catch (error: any) {
    req.logError?.('Dissemination plan error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to generate dissemination plan' });
  }
});

router.post('/:trackingId/approve', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { entityIds, approvedBy } = req.body ?? {};
    if (!Array.isArray(entityIds) || entityIds.length === 0 || !entityIds.every((e) => typeof e === 'string')) {
      return res.status(400).json({ success: false, error: 'entityIds must be a non-empty string array' });
    }
    if (typeof approvedBy !== 'string' || !approvedBy) {
      return res.status(400).json({ success: false, error: 'approvedBy is required' });
    }

    const result = await disseminationService.approve(trackingId, entityIds, approvedBy);
    if ('error' in result) {
      const status = result.error === 'report_not_found' ? 404 : 409;
      return res.status(status).json({ success: false, error: result.error });
    }

    // Fast path toward the NFR-6 target (approve → dispatch < 60s).
    dispatchWorker.tick().catch(() => {});

    res.json({ success: true, disposition: result.disposition, refused: result.refused });
  } catch (error: any) {
    req.logError?.('Dissemination approve error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to approve dissemination plan' });
  }
});

router.post('/:trackingId/withdraw', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { entityId, actor } = req.body ?? {};
    if (typeof entityId !== 'string' || !entityId || typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'entityId and actor are required' });
    }

    const result = await disseminationService.withdraw(trackingId, entityId, actor);
    if (!result.ok) return res.status(409).json({ success: false, error: result.error });
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Dissemination withdraw error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to withdraw channel' });
  }
});

router.get('/:trackingId/status', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const [channels, disposition, audit, report] = await Promise.all([
      disseminationService.status(trackingId),
      disseminationPersistence.getDisposition(trackingId),
      disseminationPersistence.getAuditForReport(trackingId),
      reportPersistenceService.get(trackingId),
    ]);
    const consent = report ? disseminationService.consentFromReport(report) : null;
    res.json({ success: true, channels, disposition, audit, consent });
  } catch (error: any) {
    req.logError?.('Dissemination status error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to get dissemination status' });
  }
});

router.post('/:trackingId/receipts', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { entityId, value, actor, kind, note } = req.body ?? {};
    if (typeof entityId !== 'string' || !entityId || typeof value !== 'string' || !value) {
      return res.status(400).json({ success: false, error: 'entityId and value are required' });
    }
    if (typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'actor is required' });
    }
    const validKinds = ['receipt', 'ack', 'feedback'];
    const receiptKind = validKinds.includes(kind) ? kind : 'receipt';

    const result = await disseminationService.recordManualReceipt(
      trackingId, entityId, value, actor, receiptKind, typeof note === 'string' ? note : undefined,
    );
    if (!result.ok) return res.status(404).json({ success: false, error: result.error });
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Dissemination receipt error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to record receipt' });
  }
});

router.post('/:trackingId/retry', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { entityId, actor } = req.body ?? {};
    if (typeof entityId !== 'string' || !entityId || typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'entityId and actor are required' });
    }

    const result = await disseminationService.retry(trackingId, entityId, actor);
    if (!result.ok) return res.status(400).json({ success: false, error: result.error });
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Retry error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to retry submission' });
  }
});

router.get('/:trackingId/companion/:entityId', requireInternalSecret, adminLimiter, reserveUpload, withUploadBudget(async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;
    const entityId = String(req.params.entityId);

    const { PORTAL_PROFILES } = await import('../services/dissemination/tcrModel');
    if (!PORTAL_PROFILES[entityId]) {
      return res.status(404).json({ success: false, error: 'No filing form for this entity' });
    }

    const loaded = await disseminationService.buildView(trackingId);
    if (!loaded) {
      return res.status(404).json({ success: false, error: 'Report not found' });
    }
    // The filing form carries decrypted evidence for this entity; it needs the
    // same channel consent as dispatch (#926), checked again before sending
    // because rendering and evidence export await remote work.
    const companionAllowed = async (report: typeof loaded.report) => {
      const approval = await disseminationPersistence.getDisposition(trackingId);
      return channelConsented(disseminationService.consentFromReport(report), entityId) &&
        (!approval || channelConsented(approval.consentSnapshot, entityId)) &&
        !['rejected', 'dismissed'].includes(report.status);
    };
    if (!await companionAllowed(loaded.report)) {
      return res.status(403).json({ success: false, error: 'reporter_consent_missing' });
    }

    const { renderCompanionPdf } = await import('../services/dissemination/companionPdf');
    const pdf = await renderCompanionPdf(loaded.view, entityId);
    const archive = await exportPacketArchive(trackingId, pdf, undefined, loaded.view.evidence?.files);
    const current = await disseminationService.buildView(trackingId);
    if (!current || !await companionAllowed(current.report)) {
      return res.status(403).json({ success: false, error: 'reporter_consent_missing' });
    }

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="vera-filing-${recipientCaseReference(trackingId, entityId)}-${entityId}.zip"`,
    );
    res.send(archive);
  } catch (error: any) {
    req.logError?.('Dissemination companion error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to render filing form' });
  }
}));

router.get('/rules', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const rules = await disseminationPersistence.listAllRules();
    res.json({ success: true, rules });
  } catch (error: any) {
    req.logError?.('Rules list error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to list routing rules' });
  }
});

router.post('/rules', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const { ruleId, match, route, active, actor } = req.body ?? {};

    if (typeof ruleId !== 'string' || !/^[a-z0-9][a-z0-9-]{1,63}$/.test(ruleId)) {
      return res.status(400).json({ success: false, error: 'ruleId is required (lowercase letters, digits, hyphens; max 64 chars)' });
    }
    if (typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'actor is required' });
    }

    const m = match ?? {};
    const categories = Array.isArray(m.categories) ? m.categories : undefined;
    if (categories && !categories.every((c: unknown) => typeof c === 'string' && isCategorySlug(c))) {
      return res.status(400).json({ success: false, error: 'match.categories contains unknown category slugs' });
    }
    const severity = Array.isArray(m.severity) ? m.severity : undefined;
    const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];
    if (severity && !severity.every((s: unknown) => typeof s === 'string' && VALID_SEVERITIES.includes(s))) {
      return res.status(400).json({ success: false, error: 'match.severity contains unknown severity levels' });
    }
    const jurisdiction = Array.isArray(m.jurisdiction) ? m.jurisdiction : undefined;
    if (jurisdiction && !jurisdiction.every((j: unknown) => typeof j === 'string' && isJurisdiction(j))) {
      return res.status(400).json({ success: false, error: 'match.jurisdiction contains unknown jurisdictions' });
    }
    const orgType = Array.isArray(m.orgType) ? m.orgType : undefined;
    if (orgType && !orgType.every((o: unknown) => typeof o === 'string' && isOrgType(o))) {
      return res.status(400).json({ success: false, error: 'match.orgType contains unknown org types' });
    }

    if (!Array.isArray(route) || route.length === 0) {
      return res.status(400).json({ success: false, error: 'route must be a non-empty array of {entityId}' });
    }
    const targets: { entityId: string; tier: 'A' | 'B' | 'C' }[] = [];
    for (const target of route) {
      const entity = typeof target?.entityId === 'string' ? getEntity(target.entityId) : null;
      if (!entity) {
        return res.status(400).json({ success: false, error: `Unknown route entity: ${target?.entityId}` });
      }
      targets.push({ entityId: entity.entityId, tier: entity.tier });
    }

    const rule = await disseminationPersistence.upsertRoutingRule({
      ruleId,
      match: {
        ...(categories?.length ? { categories } : {}),
        ...(severity?.length ? { severity } : {}),
        ...(jurisdiction?.length ? { jurisdiction } : {}),
        ...(orgType?.length ? { orgType } : {}),
      },
      route: targets,
      active: active !== false,
    });

    await disseminationPersistence.appendAudit({
      trackingId: 'GLOBAL',
      event: 'routing_rule_changed',
      actor,
      detail: { ruleId: rule.ruleId, version: rule.version, active: rule.active },
    });

    res.json({ success: true, rule });
  } catch (error: any) {
    req.logError?.('Rules upsert error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to save routing rule' });
  }
});

router.get('/alerts', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const subs = await disseminationPersistence.listAttentionSubmissions();
    res.json({
      success: true,
      alerts: subs.map((sub) => ({
        trackingId: sub.trackingId,
        entityId: sub.entityId,
        entityName: getEntity(sub.entityId)?.name ?? sub.entityId,
        tier: sub.tier,
        state: sub.state,
        kind: sub.state === 'failed' ? 'dead_letter' : sub.sla?.ackBreached ? 'ack_sla_breached' : 'feedback_sla_breached',
        attempts: sub.attempts,
        lastError: sub.lastError,
        dispatchedAt: sub.dispatchedAt,
        sla: sub.sla,
        updatedAt: sub.updatedAt,
      })),
    });
  } catch (error: any) {
    req.logError?.('Alerts list error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to list alerts' });
  }
});

router.post('/:trackingId/escrow-release', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { entityId, actor } = req.body ?? {};
    if (typeof entityId !== 'string' || !entityId || typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'entityId and actor are required' });
    }

    // Escrow release is consent-gated (§10): the reporter must have agreed
    // to this channel, and the channel must actually have been filed.
    const loaded = await disseminationService.buildView(trackingId);
    if (!loaded) return res.status(404).json({ success: false, error: 'Report not found' });
    const consent = disseminationService.consentFromReport(loaded.report);
    if (!channelConsented(consent, entityId)) {
      return res.status(403).json({ success: false, error: 'reporter_consent_missing' });
    }

    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub) return res.status(404).json({ success: false, error: 'submission_not_found' });
    const releasable = ['dispatched', 'receipted', 'acknowledged', 'feedback_received'];
    if (!releasable.includes(sub.state)) {
      return res.status(400).json({ success: false, error: `cannot_release_in_state_${sub.state}` });
    }

    const { escrowUrl } = await import('../services/dissemination/escrowRelease');
    const { url, token } = escrowUrl(trackingId, entityId, escrowBinding(sub));
    await issueRecipientCapability(token, 'escrow');

    await disseminationPersistence.appendAudit({
      trackingId,
      entityId,
      event: 'escrow_released',
      actor,
      detail: { tokenDigest: crypto.createHash('sha256').update(token).digest('hex').slice(0, 16) },
    });

    res.json({ success: true, url });
  } catch (error: any) {
    req.logError?.('Escrow release error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to release escrow' });
  }
});

router.get('/escrow/:token', adminLimiter, async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  try {
    if (!await recipientCapabilityActive(String(req.params.token))) return res.status(401).json({ success: false, error: 'Invalid or expired recipient grant' });
    const { verifyEscrowToken } = await import('../services/dissemination/escrowRelease');
    const scope = verifyEscrowToken(String(req.params.token));
    if (!scope) return res.status(401).json({ success: false, error: 'Invalid or expired escrow link' });
    const { trackingId, entityId } = scope;
    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find(s => s.entityId === entityId);
    if (!sub || scope.binding !== escrowBinding(sub) ||
        !['dispatched', 'receipted', 'acknowledged', 'feedback_received'].includes(sub.state)) {
      return res.status(403).json({ success: false, error: 'Evidence release is no longer active' });
    }
    const loaded = await disseminationService.buildView(trackingId);
    const disposition = await disseminationPersistence.getDisposition(trackingId);
    const consent = loaded && disseminationService.consentFromReport(loaded.report);
    const allowed = (c: typeof consent) => channelConsented(c, entityId);
    if (['dismissed', 'rejected'].includes(loaded?.report.status ?? '') || !allowed(consent) || !allowed(disposition?.consentSnapshot ?? null) ||
        !disposition?.channels.some(c => c.entityId === entityId && !['withdrawn', 'failed', 'closed', 'suppressed'].includes(c.state))) {
      return res.status(403).json({ success: false, error: 'Report sharing is not authorized' });
    }
    if (sub.counsel) {
      const partner = await disseminationPersistence.getCounselPartner(sub.counsel.counselId);
      if (!partner?.active || !partner.channels.includes(entityId)) {
        return res.status(403).json({ success: false, error: 'Counsel assignment is no longer active' });
      }
    }
    if (!(disposition.narrativeOverride?.narrative?.trim() || disposition.narrativeReviewedAt) ||
        loaded?.narrativeReadable === false) {
      return res.status(409).json({ success: false, error: 'Reviewed report content is required' });
    }
    if (typeof req.query.file === 'string') {
      await disseminationPersistence.appendAudit({
        trackingId, entityId, event: 'escrow_accessed', actor: `escrow-token:${entityId}`,
        detail: { evidenceIndex: /^(0|[1-9]\d*)$/.test(req.query.file) ? Number(req.query.file) : undefined },
      });
      await sendRecipientEvidence(trackingId, req.query.file, res, async () => {
        if (!await recipientCapabilityActive(String(req.params.token))) return false;
        const latestSub = (await disseminationPersistence.getSubmissionsForReport(trackingId)).find(s => s.entityId === entityId);
        if (!latestSub || scope.exp <= Date.now() || scope.binding !== escrowBinding(latestSub) || !['dispatched', 'receipted', 'acknowledged', 'feedback_received'].includes(latestSub.state)) return false;
        if (latestSub.counsel) {
          const partner = await disseminationPersistence.getCounselPartner(latestSub.counsel.counselId);
          if (!partner?.active || !partner.channels.includes(entityId)) return false;
        }
        const currentDisposition = await disseminationPersistence.getDisposition(trackingId);
        const current = await disseminationService.buildView(trackingId);
        return !!current && !['dismissed', 'rejected'].includes(current.report.status) &&
          !!allowed(disseminationService.consentFromReport(current.report)) && !!allowed(currentDisposition?.consentSnapshot ?? null) &&
          !!currentDisposition?.channels.some(c => c.entityId === entityId && !['withdrawn', 'failed', 'closed', 'suppressed'].includes(c.state)) &&
          !!(currentDisposition.narrativeOverride?.narrative?.trim() || currentDisposition.narrativeReviewedAt) && current.narrativeReadable !== false;
      }, String(req.params.token));
      return;
    }
    const files = await recipientEvidence(trackingId);
    res.json({ success: true, escrow: {
      caseReference: recipientCaseReference(trackingId, entityId), entityName: getEntity(entityId)?.name ?? entityId,
      expiresAt: new Date(scope.exp).toISOString(),
      files: files.map(file => ({ name: file.name,
        download: `${req.baseUrl}/escrow/${req.params.token}?file=${file.index}` })),
      notice: 'Evidence is decrypted server-side. This link expires and access is logged.',
    } });
  } catch (error: any) {
    req.logError?.('Escrow access error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to access escrow' });
  }
});

// ── One-time secure disclosure-packet links (reporter-reward flow) ──
// A single-use, emailed, scanner-safe link serving the consent-scoped dossier
// packet to an external recipient. The email POST mints + sends the link; the
// GET renders a landing page and never consumes; the reveal POST consumes the
// jti atomically (fail-closed) and streams the dossier PDF. Reward follow-up
// rides the anonymous relay via the email Reply-To, not this link.

router.post('/:trackingId/secure-packet-generate', adminLimiter, requireInternalSecret, async (req: Request, res: Response) => {
  const trackingId = validTrackingId(req, res);
  if (!trackingId) return;
  if (typeof req.body?.actor !== 'string' || !req.body.actor.trim()) {
    return res.status(400).json({ success: false, error: 'actor is required' });
  }
  try {
    const { generateSecurePacket } = await import('../services/dissemination/securePacketSender');
    const result = await generateSecurePacket({ trackingId, actor: req.body.actor });
    if (!result.url) {
      const status = result.error === 'report_not_found' ? 404 :
        result.error === 'narrative_review_required' ? 409 : 403;
      return res.status(status).json({ success: false, error: result.error });
    }
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ success: true, url: result.url });
  } catch {
    return res.status(503).json({ success: false, error: 'Unable to generate secure packet link' });
  }
});

router.post('/:trackingId/secure-packet-email', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { actor } = req.body ?? {};
    const recipientEmail = normalizeRecipientEmail(req.body?.recipientEmail);
    if (
      !recipientEmail ||
      typeof actor !== 'string' || !actor
    ) {
      return res.status(400).json({ success: false, error: 'recipientEmail (valid) and actor are required' });
    }

    // Delegate to the shared sender: consent gate, dryrun/live routing, mint,
    // send, and audit all live there (also used by the automatic on-submit path).
    const { sendSecurePacket } = await import('../services/dissemination/securePacketSender');
    const result = await sendSecurePacket({ trackingId, recipientEmail, actor });
    if (!result.sent) {
      const status =
        result.error === 'report_not_found' ? 404 :
        result.error === 'reporter_consent_missing' ? 403 :
        result.error === 'narrative_review_required' ? 409 :
        result.error === 'dryrun_inbox_not_configured' || result.error === 'dryrun_inbox_invalid' ? 500 :
        502;
      return res.status(status).json({ success: false, error: result.error || 'Failed to email secure packet' });
    }

    res.json({ success: true, url: result.url, sentTo: result.sentTo, mode: result.mode });
  } catch (error: any) {
    req.logError?.('Secure packet email error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to email secure packet' });
  }
});

router.get('/secure-packet/:token', adminLimiter, async (req: Request, res: Response) => {
  try {
    if (!await recipientCapabilityActive(String(req.params.token))) return res.status(401).type('html').send(renderSecureLinkPage({ state: 'invalid' }));
    const scope = verifySecureLinkToken(String(req.params.token));
    if (!scope) {
      return res.status(401).type('html').send(renderSecureLinkPage({ state: 'invalid' }));
    }
    if (await disseminationPersistence.isSecureLinkConsumed(scope.jti)) {
      return res.status(410).type('html').send(renderSecureLinkPage({ state: 'used', trackingId: recipientCaseReference(scope.trackingId, scope.entityId) }));
    }
    return res.type('html').send(
      renderSecureLinkPage({
        state: 'ready',
        trackingId: recipientCaseReference(scope.trackingId, scope.entityId),
        actionBase: `${req.baseUrl}/secure-packet/${encodeURIComponent(String(req.params.token))}`,
      }),
    );
  } catch (error: any) {
    req.logError?.('Secure packet landing error', 'error', { stack: error.stack });
    res.status(500).type('html').send(renderSecureLinkPage({ state: 'error' }));
  }
});

// Admission precedes single-use consumption, so a busy response preserves the link.
router.post('/secure-packet/:token/reveal', adminLimiter, reserveUpload, withUploadBudget(async (req: Request, res: Response) => {
  try {
    if (!await recipientCapabilityActive(String(req.params.token))) return res.status(401).json({ success: false, error: 'Invalid or expired recipient grant' });
    const scope = verifySecureLinkToken(String(req.params.token)); // nosemgrep: ajinabraham.njsscan.xss.xss_node.express_xss -- token is HMAC-verified; HTML only carries a hex HMAC case reference and renderSecureLinkPage escapes all fields
    if (!scope) {
      return res.status(401).type('html').send(renderSecureLinkPage({ state: 'invalid' }));
    }
    const { trackingId, entityId, jti } = scope;

    // Refuse before burning the link: a link whose consent or report status
    // does not allow disclosure must not be consumed (#926).
    const loaded = await disseminationService.buildView(trackingId);
    if (!loaded) {
      return res.status(404).type('html').send(renderSecureLinkPage({ state: 'error' }));
    }
    if (!legalReviewConsented(loaded.report.consent) || ['rejected', 'dismissed'].includes(loaded.report.status)) {
      return res.status(403).type('html').send(renderSecureLinkPage({ state: 'error' }));
    }

    // A link is bound to the evidence set it was issued for. Refuse a stale link
    // before consuming it: the outcome is deterministic, so burning it helps no one.
    if (scope.evidenceDigest) {
      let current: string | null;
      try { current = await snapshotPacketEvidence(trackingId); }
      catch (err: any) {
        if (err?.message !== 'packet_evidence_changed') throw err;
        current = null;
      }
      if (current !== scope.evidenceDigest) {
        return res.status(409).type('html').send(renderSecureLinkPage({ state: 'stale' }));
      }
    }

    // A missing/reverted narrative review is retryable after review; preserve
    // the capability just as for missing consent or changed evidence (#625).
    if (scope.origin !== 'auto') {
      const disposition = await disseminationPersistence.getDisposition(trackingId);
      if (!reviewedNarrativeMatches(loaded.view, disposition) || !loaded.narrativeReadable) {
        return res.status(409).type('html').send(renderSecureLinkPage({ state: 'error' }));
      }
    }

    // Atomic single-use burn. Fail-closed: consumeSecureLink THROWS if the
    // store is unavailable — we refuse rather than serve an unguarded packet.
    let firstUse: boolean;
    try {
      firstUse = await disseminationPersistence.consumeSecureLink({ jti, trackingId, entityId });
    } catch (err: any) {
      req.logError?.('Secure packet consume failed (fail-closed)', 'error', { stack: err?.stack });
      return res.status(503).type('html').send(renderSecureLinkPage({ state: 'error' }));
    }
    if (!firstUse) {
      return res.status(410).type('html').send(renderSecureLinkPage({ state: 'used', trackingId: recipientCaseReference(trackingId, entityId) }));
    }

    // Auto-origin links (sent automatically on submission) serve the
    // redaction-scrubbed narrative frozen at send time, never the raw
    // self-identifying text. Fail-closed if the scrubbed copy is absent.
    if (scope.origin === 'auto') {
      const enc = loaded.report.encryptedDisseminationNarrative;
      if (!enc) {
        req.logError?.('Secure packet auto-reveal missing scrubbed narrative', 'error', { trackingId });
        return res.status(503).type('html').send(renderSecureLinkPage({ state: 'error' }));
      }
      try {
        loaded.view.narrative = decryptContactValue(enc);
      } catch (err: any) {
        req.logError?.('Secure packet auto-reveal narrative decrypt failed', 'error', { trackingId, stack: err?.stack });
        return res.status(503).type('html').send(renderSecureLinkPage({ state: 'error' }));
      }
    }

    const { packetGenerator } = await import('../services/dissemination/packetGenerator');
    const packet = await packetGenerator.generate(loaded.view, entityId, await packetSubmitterFor(loaded.report));

    const archive = await exportPacketArchive(trackingId, packet.pdf, scope.evidenceDigest, loaded.view.evidence?.files);

    // Audit only a packet that was actually built, and before any bytes leave.
    await disseminationPersistence.appendAudit({
      trackingId,
      entityId,
      event: 'secure_packet_revealed',
      actor: `secure-link:${jti.slice(0, 8)}`,
      detail: { packetHash: packet.packetHash },
    });

    // Rendering and durable auditing can await remote work. Revalidate access
    // immediately before sending bytes; a revoked grant must not use the snapshot.
    const current = await disseminationService.buildView(trackingId);
    if (!await recipientCapabilityActive(String(req.params.token))) return res.status(403).json({ success: false, error: 'Recipient grant revoked' });
    if (current && !submitterDisclosureUnchanged(loaded.report, current.report)) {
      return res.status(403).type('html').send(renderSecureLinkPage({ state: 'error' }));
    }
    if (!current || !legalReviewConsented(current.report.consent) || ['rejected', 'dismissed'].includes(current.report.status)) {
      return res.status(403).type('html').send(renderSecureLinkPage({ state: 'error' }));
    }
    if (scope.origin !== 'auto') {
      const currentDisposition = await disseminationPersistence.getDisposition(trackingId);
      if (loaded.view.narrative !== current.view.narrative ||
          !reviewedNarrativeMatches(current.view, currentDisposition) || !current.narrativeReadable) {
        return res.status(409).type('html').send(renderSecureLinkPage({ state: 'error' }));
      }
    }
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', `attachment; filename="vera-report-${recipientCaseReference(trackingId, entityId)}.zip"`);
    return res.send(archive);
  } catch (error: any) {
    if (error?.message === 'packet_evidence_changed') {
      // Evidence changed between the pre-check and export (a race, not a fault).
      req.logError?.('Secure packet evidence changed during reveal', 'warning', { stack: error.stack });
      return res.status(409).type('html').send(renderSecureLinkPage({ state: 'stale' }));
    }
    req.logError?.('Secure packet reveal error', 'error', { stack: error.stack });
    res.status(500).type('html').send(renderSecureLinkPage({ state: 'error' }));
  }
}));

router.get('/anchors', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const anchors = await disseminationPersistence.listAuditAnchors();
    res.json({
      success: true,
      anchors: anchors.map((a) => ({
        anchorId: a.anchorId,
        root: a.root,
        commitmentVersion: a.commitmentVersion,
        batchRoot: a.batchRoot,
        prevRoot: a.prevRoot,
        eventCount: a.eventCount,
        firstEventAt: a.firstEventAt,
        lastEventAt: a.lastEventAt,
        proofHash: a.proofHash,
        txHash: a.txHash,
        network: a.txHash ? a.network : 'local',
        anchoredAt: a.anchoredAt,
      })),
    });
  } catch (error: any) {
    req.logError?.('Anchor list error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to list audit anchors' });
  }
});

router.get('/anchors/history', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  const { head, tail, limit = '100' } = req.query;
  if (typeof head !== 'string' || !/^[a-f0-9]{64}$/.test(head) || typeof tail !== 'string' ||
      (tail !== 'genesis' && !/^[a-f0-9]{64}$/.test(tail)) || typeof limit !== 'string' ||
      !/^[1-9][0-9]*$/.test(limit) || Number(limit) > 100) {
    return res.status(400).json({ success: false, error: 'Invalid audit history request' });
  }
  try {
    const history = await auditAnchorService.exportHistory(head, tail === 'genesis' ? null : tail, Number(limit));
    return res.json({ success: true, ...history, trust: 'caller-supplied endpoints' });
  } catch {
    return res.status(500).json({ success: false, error: 'Audit history unavailable' });
  }
});

router.get('/:trackingId/audit-proofs', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const events = await disseminationPersistence.getAuditForReport(trackingId);
    const proofs = await Promise.all(
      events.map(async (event) => {
        const proof = await auditAnchorService.proveEvent(event);
        return {
          eventId: event.eventId,
          event: event.event,
          at: event.at,
          anchored: proof.anchored,
          tampered: proof.tampered ?? false,
          root: proof.root,
          commitmentVersion: proof.commitmentVersion,
          batchRoot: proof.batchRoot,
          eventCount: proof.eventCount,
          prevRoot: proof.prevRoot,
          txHash: proof.txHash,
          network: proof.network,
          proof: proof.proof,
        };
      }),
    );
    res.json({ success: true, proofs });
  } catch (error: any) {
    req.logError?.('Audit proof error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to build audit proofs' });
  }
});

router.post('/:trackingId/redact', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { mode, narrative, notes, actor } = req.body ?? {};
    if (typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'actor is required' });
    }

    const { redactionService } = await import('../services/dissemination/redactionService');

    if (mode === 'propose') {
      const loaded = await disseminationService.buildView(trackingId);
      if (!loaded) return res.status(404).json({ success: false, error: 'Report not found' });
      const proposal = await redactionService.propose(loaded.view.narrative);
      return res.json({ success: true, proposal, original: loaded.view.narrative });
    }

    if (mode === 'accept') {
      if (typeof narrative !== 'string') {
        return res.status(400).json({ success: false, error: 'narrative is required' });
      }
      const result = await redactionService.accept(
        trackingId,
        narrative,
        Array.isArray(notes) ? notes.filter((n: unknown) => typeof n === 'string') : [],
        actor,
      );
      if (!result.ok) return res.status(400).json({ success: false, error: result.error });
      return res.json({ success: true });
    }

    if (mode === 'clear') {
      const result = await redactionService.clear(trackingId, actor);
      if (!result.ok) return res.status(400).json({ success: false, error: result.error });
      return res.json({ success: true });
    }

    if (mode === 'mark-clean') {
      const r = await redactionService.markReviewedClean(trackingId, actor);
      if (!r.ok) return res.status(400).json({ success: false, error: r.error });
      return res.json({ success: true });
    }

    res.status(400).json({ success: false, error: 'mode must be propose, accept, clear, or mark-clean' });
  } catch (error: any) {
    req.logError?.('Redaction error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: error.message?.includes('Redaction unavailable')
      ? error.message
      : 'Redaction failed' });
  }
});

router.get('/:trackingId/relay', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const thread = await relayService.getThread(trackingId);
    res.json({ success: true, thread });
  } catch (error: any) {
    req.logError?.('Relay thread error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to load relay thread' });
  }
});

router.post('/:trackingId/relay', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { body, actor, entityId } = req.body ?? {};
    if (typeof body !== 'string' || !body.trim() || typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'body and actor are required' });
    }

    const result = await relayService.postToReporter(
      trackingId,
      body,
      actor,
      typeof entityId === 'string' && entityId ? entityId : undefined,
    );
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Relay post error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to relay message' });
  }
});


router.get('/counsel', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const partners = await counselService.listPartners(req.query.active === 'true');
    res.json({ success: true, partners });
  } catch (error: any) {
    req.logError?.('Counsel list error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to list counsel partners' });
  }
});

router.post('/counsel', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const { counselId, name, channels, contactHandle, engagementModel, active } = req.body ?? {};
    if (typeof name !== 'string' || typeof contactHandle !== 'string') {
      return res.status(400).json({ success: false, error: 'name and contactHandle are required' });
    }
    const result = await counselService.upsertPartner({
      counselId: typeof counselId === 'string' && counselId ? counselId : undefined,
      name,
      contactHandle,
      channels: Array.isArray(channels) ? channels.filter((c: unknown) => typeof c === 'string') : [],
      engagementModel,
      active: typeof active === 'boolean' ? active : undefined,
    });
    if (result.error) {
      return res.status(400).json({ success: false, error: result.error });
    }
    res.json({ success: true, partner: result.partner });
  } catch (error: any) {
    req.logError?.('Counsel upsert error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to save counsel partner' });
  }
});

router.post('/:trackingId/counsel/assign', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { entityId, actor, counselId } = req.body ?? {};
    if (typeof entityId !== 'string' || !entityId || typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'entityId and actor are required' });
    }

    const result = await counselService.assign(
      trackingId,
      entityId,
      actor,
      typeof counselId === 'string' && counselId ? counselId : undefined,
    );
    if (result.error || !result.assignment) {
      return res.status(409).json({ success: false, error: result.error ?? 'assignment_unavailable' });
    }

    // The scoped link the admin shares with counsel: packet + filing form,
    // no Auth0 account; identity only with explicit consent; expires automatically.
    let workspace: string | null = null;
    try {
      workspace = workspaceUrl(trackingId, entityId, result.assignment!);
      await issueRecipientCapability(workspace.split('/').pop()!, 'workspace');
    } catch {
      workspace = null;
      // Issuance failed — assignment stands, but do not return an unusable link.
    }
    res.json({ success: true, assignment: result.assignment, workspaceUrl: workspace });
  } catch (error: any) {
    req.logError?.('Counsel assign error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to assign counsel' });
  }
});

router.post('/:trackingId/counsel/attest', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const trackingId = validTrackingId(req, res);
    if (!trackingId) return;

    const { entityId, value, actor } = req.body ?? {};
    if (
      typeof entityId !== 'string' || !entityId ||
      typeof value !== 'string' || !value.trim() ||
      typeof actor !== 'string' || !actor
    ) {
      return res.status(400).json({ success: false, error: 'entityId, value, and actor are required' });
    }

    const result = await counselService.attest(trackingId, entityId, value, actor);
    if (!result.ok) {
      return res.status(409).json({ success: false, error: result.error });
    }
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Counsel attest error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to record attestation' });
  }
});

router.get('/counsel-workspace/:token', adminLimiter, (req, res, next) => {
  // Individual file requests already enter the transfer budget on their internal
  // evidence route; reserving it here too would deadlock that loopback request.
  if (req.query.doc === 'dossier' || req.query.doc === 'form') reserveUpload(req, res, next);
  else next();
}, withUploadBudget(async (req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  try {
    if (!await recipientCapabilityActive(String(req.params.token))) return res.status(401).json({ success: false, error: 'Invalid or expired recipient grant' });
    const scope = verifyWorkspaceToken(String(req.params.token));
    if (!scope) {
      return res.status(401).json({ success: false, error: 'Invalid or expired workspace link' });
    }
    const { trackingId, entityId } = scope;

    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub?.counsel || scope.assignmentKey !== workspaceAssignmentKey(sub.counsel) ||
        ['withdrawn', 'failed', 'closed', 'suppressed'].includes(sub.state)) {
      return res.status(404).json({ success: false, error: 'No counsel matter for this link' });
    }
    const partner = await disseminationPersistence.getCounselPartner(sub.counsel.counselId);
    if (!partner?.active || !partner.channels.includes(entityId)) {
      return res.status(403).json({ success: false, error: 'Counsel assignment is no longer active' });
    }
    const disposition = await disseminationPersistence.getDisposition(trackingId);
    const loaded = await disseminationService.buildView(trackingId);
    if (!loaded) return res.status(404).json({ success: false, error: 'Report not found' });
    const consent = disseminationService.consentFromReport(loaded.report);
    const allowed = (c: typeof consent) => channelConsented(c, entityId);
    if (['dismissed', 'rejected'].includes(loaded?.report.status ?? '') || !allowed(consent) || !allowed(disposition?.consentSnapshot ?? null) ||
        !disposition?.channels.some(c => c.entityId === entityId && !['withdrawn', 'failed', 'closed', 'suppressed'].includes(c.state))) {
      return res.status(403).json({ success: false, error: 'Report sharing is not authorized' });
    }
    if (!reviewedNarrativeMatches(loaded.view, disposition) ||
        loaded.narrativeReadable === false ||
        (!loaded.view.narrative.trim() && !loaded.view.evidence?.files.some(file => !!file.cid))) {
      return res.status(409).json({ success: false, error: 'Readable, reviewed report content is required' });
    }

    if (typeof req.query.file === 'string') {
      await disseminationPersistence.appendAudit({
        trackingId, entityId, event: 'escrow_accessed', actor: `counsel-token:${sub.counsel.counselId}`,
        detail: { evidenceIndex: /^(0|[1-9]\d*)$/.test(req.query.file) ? Number(req.query.file) : undefined },
      });
      await sendRecipientEvidence(trackingId, req.query.file, res, async () => {
        if (!await recipientCapabilityActive(String(req.params.token))) return false;
        const latestSub = (await disseminationPersistence.getSubmissionsForReport(trackingId)).find(s => s.entityId === entityId);
        if (!latestSub || scope.exp <= Date.now() || !latestSub.counsel || scope.assignmentKey !== workspaceAssignmentKey(latestSub.counsel) || ['withdrawn', 'failed', 'closed', 'suppressed'].includes(latestSub.state)) return false;
        if (latestSub.counsel) {
          const partner = await disseminationPersistence.getCounselPartner(latestSub.counsel.counselId);
          if (!partner?.active || !partner.channels.includes(entityId)) return false;
        }
        const currentDisposition = await disseminationPersistence.getDisposition(trackingId);
        const current = await disseminationService.buildView(trackingId);
        return !!current && !['dismissed', 'rejected'].includes(current.report.status) &&
          !!allowed(disseminationService.consentFromReport(current.report)) && !!allowed(currentDisposition?.consentSnapshot ?? null) &&
          !!currentDisposition?.channels.some(c => c.entityId === entityId && !['withdrawn', 'failed', 'closed', 'suppressed'].includes(c.state)) &&
          !!(currentDisposition.narrativeOverride?.narrative?.trim() || currentDisposition.narrativeReviewedAt) && current.narrativeReadable !== false;
      }, String(req.params.token));
      return;
    }
    const doc = typeof req.query.doc === 'string' ? req.query.doc : null;

    if (doc === 'dossier' || doc === 'form') {
      await disseminationPersistence.appendAudit({
        trackingId, entityId, event: 'escrow_accessed', actor: `counsel-token:${sub.counsel.counselId}`,
        detail: { document: doc, phase: 'attempted' },
      });
      let pdf: Buffer;
      if (doc === 'dossier') {
        const { packetGenerator } = await import('../services/dissemination/packetGenerator');
        const packet = await packetGenerator.generate(loaded.view, entityId, await packetSubmitterFor(loaded.report));
        pdf = packet.pdf;
      } else {
        const { PORTAL_PROFILES } = await import('../services/dissemination/tcrModel');
        if (!PORTAL_PROFILES[entityId]) {
          return res.status(404).json({ success: false, error: 'No filing form for this entity' });
        }
        const { renderCompanionPdf } = await import('../services/dissemination/companionPdf');
        pdf = await renderCompanionPdf(loaded.view, entityId);
      }
      const archive = await exportPacketArchive(trackingId, pdf, undefined, loaded.view.evidence?.files);
      // Revalidate after rendering/auditing: those awaits may overlap a
      // withdrawal, reassignment, reviewer change or identity revocation.
      const latestSub = (await disseminationPersistence.getSubmissionsForReport(trackingId)).find(s => s.entityId === entityId);
      const latestPartner = latestSub?.counsel && await disseminationPersistence.getCounselPartner(latestSub.counsel.counselId);
      const latestDisposition = await disseminationPersistence.getDisposition(trackingId);
      const current = await disseminationService.buildView(trackingId);
      const closed = (state: string) => ['withdrawn', 'failed', 'closed', 'suppressed'].includes(state);
      if (!latestSub?.counsel || scope.assignmentKey !== workspaceAssignmentKey(latestSub.counsel) || closed(latestSub.state) ||
          !latestPartner?.active || !latestPartner.channels.includes(entityId) ||
          !current || !submitterDisclosureUnchanged(loaded.report, current.report) ||
          ['dismissed', 'rejected'].includes(current.report.status) ||
          !allowed(disseminationService.consentFromReport(current.report)) || !allowed(latestDisposition?.consentSnapshot ?? null) ||
          !latestDisposition?.channels.some(c => c.entityId === entityId && !closed(c.state)) ||
          loaded.view.narrative !== current.view.narrative ||
          !reviewedNarrativeMatches(current.view, latestDisposition) ||
          current.narrativeReadable === false) {
        return res.status(403).json({ success: false, error: 'Report sharing authorization changed. Reload the workspace.' });
      }
      if (!await recipientCapabilityActive(String(req.params.token))) return res.status(403).json({ success: false, error: 'Recipient grant revoked' });
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="vera-${doc}-${recipientCaseReference(trackingId, entityId)}.zip"`);
      return res.send(archive);
    }

    const { PORTAL_PROFILES } = await import('../services/dissemination/tcrModel');
    const files = await recipientEvidence(trackingId);
    res.json({
      success: true,
      matter: {
        matterCode: sub.counsel.matterCode,
        counselName: sub.counsel.counselName,
        entityId,
        entityName: getEntity(entityId)?.name ?? entityId,
        state: sub.state,
        files: files.map(file => ({ name: file.name,
          download: `${req.baseUrl}/counsel-workspace/${req.params.token}?file=${file.index}` })),
        documents: [
          { doc: 'dossier', description: 'Reviewed report dossier (includes explicitly consented contact details)' },
          ...(PORTAL_PROFILES[entityId]
            ? [{ doc: 'form', description: 'Pre-filled filing form for counsel completion' }]
            : []),
        ],
        instructions:
          'Use any explicitly consented contact details in the dossier for follow-up. Anonymous reports provide no direct contact. ' +
          'The engagement and signature process remains with counsel. ' +
          'After filing, return the confirmation number to the Vera admin for attestation.',
      },
    });
  } catch (error: any) {
    req.logError?.('Counsel workspace error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to load counsel workspace' });
  }
}));


router.post('/receipts/webhook', adminLimiter, async (req: Request, res: Response) => {
  try {
    if (!verifyWebhookSignature(req, res)) return;

    const { trackingId, entityId, raw, kind } = req.body ?? {};
    if (
      typeof trackingId !== 'string' || !TRACKING_ID_RE.test(trackingId) ||
      typeof entityId !== 'string' || !entityId ||
      typeof raw !== 'string' || !raw
    ) {
      return res.status(400).json({ success: false, error: 'trackingId, entityId, and raw are required' });
    }

    const adapter = getAdapter(entityId);
    const parsed = adapter?.parseReceipt(raw) ?? null;
    if (!parsed) {
      // Unrecognized ack — record verbatim so nothing is silently dropped.
      console.warn(`[DISSEMINATION:${entityId}] Webhook receipt did not match known patterns`);
    }

    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const sub = submissions.find((s) => s.entityId === entityId);
    if (!sub) {
      return res.status(404).json({ success: false, error: 'Submission not found' });
    }

    const validKinds = ['receipt', 'ack', 'feedback'];
    const receiptKind = validKinds.includes(kind) ? kind : 'ack';
    const receipt = parsed ?? receiptTracker.buildManualReceipt(raw.slice(0, 500), 'unparsed webhook payload');
    await receiptTracker.recordReceipt(sub, receipt, 'webhook', receiptKind, webhookEventKey(req));

    res.json({ success: true, parsed: parsed !== null });
  } catch (error: any) {
    req.logError?.('Dissemination webhook error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to process receipt webhook' });
  }
});

router.post('/inbound/webhook', adminLimiter, async (req: Request, res: Response) => {
  try {
    if (!verifyWebhookSignature(req, res)) return;

    const { recipient, from, subject, body, s3Key, messageId, receivedAt, authentication } = req.body ?? {};
    if (typeof recipient !== 'string' || !recipient || typeof body !== 'string') {
      return res.status(400).json({ success: false, error: 'recipient and body are required' });
    }

    const result = await inboundMailService.ingest({
      recipient,
      authentication,
      from: typeof from === 'string' ? from : 'unknown',
      subject: typeof subject === 'string' ? subject : '(no subject)',
      body,
      s3Key: typeof s3Key === 'string' ? s3Key : undefined,
      messageId: typeof messageId === 'string' ? messageId : undefined,
      receivedAt: typeof receivedAt === 'string' ? receivedAt : undefined,
    });

    res.json({ success: true, ...result });
  } catch (error: any) {
    req.logError?.('Dissemination inbound webhook error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to process inbound mail' });
  }
});

router.get('/inbound', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const statusParam = req.query.status;
    const valid = ['pending_review', 'resolved', 'dismissed'];
    const status =
      typeof statusParam === 'string' && valid.includes(statusParam)
        ? (statusParam as 'pending_review' | 'resolved' | 'dismissed')
        : undefined;

    const mail = await disseminationPersistence.listInboundMail(status ?? 'pending_review');
    res.json({ success: true, mail });
  } catch (error: any) {
    req.logError?.('Dissemination inbound list error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to list inbound mail' });
  }
});

router.post('/inbound/:inboundId/resolve', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const inboundId = String(req.params.inboundId);
    const { trackingId, entityId, actor, kind, value } = req.body ?? {};
    if (typeof trackingId !== 'string' || !TRACKING_ID_RE.test(trackingId)) {
      return res.status(400).json({ success: false, error: 'Valid trackingId is required' });
    }
    if (typeof entityId !== 'string' || !entityId || typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'entityId and actor are required' });
    }

    const validKinds = ['receipt', 'ack', 'feedback'];
    const result = await inboundMailService.resolve(inboundId, actor, {
      trackingId,
      entityId,
      kind: validKinds.includes(kind) ? kind : 'ack',
      value: typeof value === 'string' && value ? value : undefined,
    });
    if (!result.ok) {
      return res.status(409).json({ success: false, error: result.error });
    }
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Dissemination inbound resolve error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to resolve inbound mail' });
  }
});

router.post('/inbound/:inboundId/dismiss', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const inboundId = String(req.params.inboundId);
    const { actor } = req.body ?? {};
    if (typeof actor !== 'string' || !actor) {
      return res.status(400).json({ success: false, error: 'actor is required' });
    }

    const result = await inboundMailService.dismiss(inboundId, actor);
    if (!result.ok) {
      return res.status(409).json({ success: false, error: result.error });
    }
    res.json({ success: true });
  } catch (error: any) {
    req.logError?.('Dissemination inbound dismiss error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to dismiss inbound mail' });
  }
});


router.get('/analytics', requireInternalSecret, adminLimiter, async (req: Request, res: Response) => {
  try {
    const { computeAnalytics } = await import('../services/dissemination/analytics');
    const analytics = await computeAnalytics();
    res.json({ success: true, analytics });
  } catch (error: any) {
    req.logError?.('Analytics error', 'error', { stack: error.stack });
    res.status(500).json({ success: false, error: 'Failed to compute analytics' });
  }
});

export default router;
