import express, { Router } from 'express';
import { timingSafeEqual } from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import type { ApplicationIdentityProvider, LegalSignInTarget } from '../services/legalApplicationAuth0';
import { confidentialBodyErrors } from '../middleware/confidentialRequestGuard';

type Target = LegalSignInTarget & { organizationId: string; pending: boolean };
export type LegalEntryStore = {
  legalSignInTarget(email: string, providerOrganizationId?: string): Promise<Target | null>;
  consumeLegalSignInApproval(organizationId: string, email: string, subject: string): Promise<void>;
};
/** Auth0 Actions only. Never expose this credential to the SPA, reuse the admin
 * secret, log the body, or forward its response through the public status API. */
export function createLegalEntryRouter(options: { secret?: string; connectionId?: string;
  source: () => Promise<{ store: LegalEntryStore; provider: ApplicationIdentityProvider | null; clientId?: string }> }) {
  const router = Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    const secret = options.secret;
    const supplied = req.headers.authorization;
    if (!secret || secret.length < 32 || !options.connectionId) return res.sendStatus(503);
    const expected = `Bearer ${secret}`;
    if (typeof supplied !== 'string' || Buffer.byteLength(supplied) !== Buffer.byteLength(expected) ||
        !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) return res.sendStatus(401);
    next();
  });
  router.use(rateLimit({ windowMs: 60_000, max: 120, standardHeaders: true, legacyHeaders: false, store: sharedRateLimitStore('legalEntry') }));
  router.post('/', express.json({ limit: '2kb', strict: true }), async (req, res) => {
    const body = req.body;
    if (!req.is('application/json') || Object.keys(req.query).length || !body || typeof body !== 'object' || Array.isArray(body) ||
        Object.keys(body).some(key => !['operation', 'email', 'clientId', 'connectionId', 'organization', 'subject'].includes(key)) ||
        !['lookup', 'complete'].includes(body.operation) || typeof body.clientId !== 'string' || body.connectionId !== options.connectionId ||
        typeof body.email !== 'string' || body.email.length > 254 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$/.test(body.email) ||
        (body.organization !== undefined && !/^org_[A-Za-z0-9]{1,64}$/.test(body.organization)) ||
        (body.operation === 'complete' ? typeof body.subject !== 'string' || !/^[A-Za-z0-9_-]+\|[^\s\u0000-\u001f]{1,200}$/.test(body.subject) : body.subject !== undefined)) return res.sendStatus(400);
    try {
      const { store, provider, clientId } = await options.source();
      if (!clientId || body.clientId !== clientId) return res.sendStatus(403);
      if (!provider?.existingMember || !provider.completeSignIn) return res.sendStatus(503);
      const target = await store.legalSignInTarget(body.email, body.organization);
      if (!target) return res.sendStatus(403);
      // A consumed approval must not recreate membership or roles after removal.
      const deadline = AbortSignal.timeout(15_000);
      const existing = target.pending ? null : await provider.existingMember(target, deadline);
      if (!target.pending && !existing) return res.sendStatus(403);
      if (body.operation === 'complete') {
        if (existing && existing !== body.subject) return res.sendStatus(403);
        // Independently re-read Auth0: the subject, connection and verified email
        // must match even though the request came from an authenticated Action.
        if (await provider.completeSignIn(target, body.subject, deadline, target.pending) !== body.subject) return res.sendStatus(403);
        const current = await store.legalSignInTarget(body.email, target.providerOrganizationId);
        if (!current || current.organizationId !== target.organizationId) return res.sendStatus(403);
        await store.consumeLegalSignInApproval(target.organizationId, body.email, body.subject);
      }
      return res.json({ approved: true, organization: target.providerOrganizationId });
    } catch { return res.sendStatus(403); }
  });
  router.use(confidentialBodyErrors);
  return router;
}
