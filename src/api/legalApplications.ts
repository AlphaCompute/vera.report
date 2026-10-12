import express, { Router } from 'express';
import type { Request, RequestHandler } from 'express';
import rateLimit from 'express-rate-limit';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import { LEGAL_APPLICATION_CLIENT_HEADER, LEGAL_APPLICATION_ID, LEGAL_APPLICATION_INTAKE_CLOSED, LegalApplicationIntakeClosedError } from '../utils/legalApplications';
import type { LegalOrganizationPreparationSource } from '../utils/legalOnboarding';
import { LEGAL_PROVIDER_ORGANIZATION_ID } from '../utils/legalOnboarding';
import type { LegalApplicationSource } from '../services/legalApplications';
import { parseApplicationSubmission } from '../utils/legalApplicationEnrollment';
import { InvalidFirmKeyBindingError } from '../utils/legalApplicationKey';
import { failureReason } from '../utils/failureReason';

/** Responses stay generic; the log names the route and a log-safe reason only. */
const logUnavailable = (route: string, error: unknown) => console.warn('Legal application service unavailable', route, failureReason(error));

/** The browser proxy authenticates staff/Slack; every backend route requires the
 * dedicated internal secret. Applications contain firm information, never cases. */
export function createLegalApplicationsRouter(source: () => Promise<LegalApplicationSource>, guard: RequestHandler, onboarding?: () => Promise<LegalOrganizationPreparationSource>,
  provisioningEnabled: () => Promise<boolean> = async () => false, scope: 'frontend' | 'worker' = 'frontend') {
  const router = Router();
  router.use(guard, express.json({ limit: '192kb', strict: true }));
  router.use((req, res, next) => {
    const action = req.path.toLowerCase().replace(/\/$/, '');
    const allowed = scope === 'worker' ? ['/get', '/decide', '/combined-approval'] : ['/submit', '/list', '/decide', '/status'];
    if (!allowed.includes(action)) { res.sendStatus(404); return; }
    next();
  });
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!req.is('application/json') || !req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      res.status(400).json({ error: 'Invalid request' }); return;
    }
    next();
  });
  // Only the guarded frontend proxy reaches this route, so its client key is trusted;
  // without one, every applicant would share the proxy's address-based quota.
  const keyGenerator = (req: Request) => {
    const client = req.headers[LEGAL_APPLICATION_CLIENT_HEADER];
    return typeof client === 'string' && /^[a-f0-9]{64}$/.test(client) ? `application:${client}` : requestRateLimitKey(req);
  };
  const submitLimiter = rateLimit({ windowMs: 60 * 60_000, max: 20, standardHeaders: true, legacyHeaders: false, keyGenerator, store: sharedRateLimitStore(`legalApplications.${scope}.submit`) });
  router.post('/submit', submitLimiter, async (req, res) => {
    const input = parseApplicationSubmission(req.body);
    if (!input || Object.keys(req.query).length) return res.status(400).json({ error: 'Invalid application' });
    try { await (await source()).submit(input); return res.status(202).json({ success: true }); }
    catch (error) {
      if (error instanceof InvalidFirmKeyBindingError) return res.status(400).json({ error: 'Invalid application key', code: 'invalid-application-key' });
      if (error instanceof LegalApplicationIntakeClosedError) {
        // One public answer for both caps: a per-domain refusal would tell an
        // unauthenticated caller that some firm at that domain has applied.
        res.setHeader('Retry-After', '3600');
        return res.status(429).json({ error: LEGAL_APPLICATION_INTAKE_CLOSED['applications-closed'], code: 'applications-closed' });
      }
      logUnavailable('submit', error);
      return res.status(503).json({ error: 'Application service unavailable' });
    }
  });
  router.post('/get', async (req, res) => {
    const { id, ...rest } = req.body;
    if (Object.keys(rest).length || Object.keys(req.query).length || typeof id !== 'string' || !LEGAL_APPLICATION_ID.test(id)) return res.sendStatus(400);
    try { return res.json({ success: true, application: await (await source()).get(id) }); }
    catch (error) { logUnavailable('get', error); return res.sendStatus(503); }
  });
  router.post('/status', rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false, keyGenerator, store: sharedRateLimitStore(`legalApplications.${scope}.status`) }), async (req, res) => {
    const { id, ...rest } = req.body;
    if (Object.keys(rest).length || Object.keys(req.query).length || typeof id !== 'string' || !LEGAL_APPLICATION_ID.test(id)) return res.sendStatus(400);
    try { return res.json({ success: true, ...await (await source()).applicationStatus(id) }); }
    catch (error) { logUnavailable('status', error); return res.sendStatus(503); }
  });
  router.post('/combined-approval', async (req, res) => {
    const { id, digest, approval, ...rest } = req.body;
    if (Object.keys(rest).length || Object.keys(req.query).length || typeof id !== 'string' || !LEGAL_APPLICATION_ID.test(id) ||
        typeof digest !== 'string' || !LEGAL_APPLICATION_ID.test(digest) || typeof approval !== 'string') return res.sendStatus(400);
    try { const success = await (await source()).saveCombinedApproval(id, digest, approval); return res.status(success ? 200 : 409).json({ success }); }
    catch (error) { logUnavailable('combined-approval', error); return res.sendStatus(503); }
  });
  router.post('/list', async (req, res) => {
    const { before, ...rest } = req.body || {};
    if (Object.keys(rest).length || Object.keys(req.query).length || (before !== undefined &&
        (typeof before !== 'string' || !LEGAL_APPLICATION_ID.test(before)))) return res.status(400).json({ error: 'Invalid request' });
    try { return res.json({ success: true, ...await (await source()).list(before), provisioningEnabled: await provisioningEnabled() }); }
    catch (error) { logUnavailable('list', error); return res.status(503).json({ error: 'Application service unavailable' }); }
  });
  router.post('/decide', async (req, res) => {
    const { id, status, actor, providerOrganizationId, reviewDigest, confirmedKeyId, ...rest } = req.body || {};
    if (Object.keys(rest).length || Object.keys(req.query).length || typeof id !== 'string' || !LEGAL_APPLICATION_ID.test(id) ||
      !['approved', 'denied'].includes(status) || typeof actor !== 'string' || !actor.trim() || actor.length > 254 ||
      /[\u0000-\u001f\u007f]/.test(actor) || (reviewDigest !== undefined && (typeof reviewDigest !== 'string' || !LEGAL_APPLICATION_ID.test(reviewDigest))) ||
      (confirmedKeyId !== undefined && (typeof confirmedKeyId !== 'string' || !LEGAL_APPLICATION_ID.test(confirmedKeyId))) || (providerOrganizationId !== undefined &&
        (status !== 'approved' || typeof providerOrganizationId !== 'string' || !LEGAL_PROVIDER_ORGANIZATION_ID.test(providerOrganizationId)))) return res.status(400).json({ error: 'Invalid request' });
    try {
      if (providerOrganizationId !== undefined && await provisioningEnabled()) return res.status(409).json({ error: 'Automatic organization setup is enabled. Refresh before approving.' });
      const service = await source();
      const approved = providerOrganizationId !== undefined
        ? onboarding && await service.approveAndPrepare(id, providerOrganizationId, actor, await onboarding())
        : await service.decide(id, status, actor, Date.now(), reviewDigest, confirmedKeyId);
      const decision = await service.decision(id);
      if (!approved) return res.status(409).json({ error: 'Application already decided or unavailable', ...(decision ? { decision } : {}) });
      return res.json({ success: true, ...(decision ? { decision } : {}) });
    } catch (error) { logUnavailable('decide', error); return res.status(503).json({ error: 'Application service unavailable' }); }
  });
  return router;
}
