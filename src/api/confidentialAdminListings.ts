import { Router } from 'express';
import type { RequestHandler } from 'express';
import { requireInternalSecret } from '../middleware/internalSecret';
import {
  CONFIDENTIAL_LISTING_PAGE_DEFAULT, CONFIDENTIAL_LISTING_PAGE_MAX, listConfidentialAdminListings,
} from '../services/confidentialAdminListings';
import type { ConfidentialListingSource } from '../services/confidentialAdminListings';

/** POST /api/admin/confidential/listings with JSON body `{ limit?, after? }`.
 * Reached only through the Next admin proxy (Auth0 admin role, audit-logged);
 * the header secret is defense in depth, as for every other admin route. The
 * confidential-only task uses its own CONFIDENTIAL_ADMIN_SECRET instead of the
 * legacy INTERNAL_API_SECRET.
 * The page cursor (`after`, a case ID) travels in the body, never the URL, so it
 * cannot reach a load balancer, CDN or WAF request log; a query string is refused.
 * The response contains the approved summary, reference, cursor and separate
 * administrator visibility flag. No private case content is read or logged. */
export function createConfidentialAdminListingRouter(source: () => Promise<ConfidentialListingSource>,
  guard: RequestHandler = requireInternalSecret) {
  const router = Router();
  router.post('/listings', guard, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const body: unknown = req.body;
    const fields = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null;
    const { limit: rawLimit, after: rawAfter, ...rest } = fields ?? {};
    const limit = rawLimit === undefined ? CONFIDENTIAL_LISTING_PAGE_DEFAULT : rawLimit;
    const after = rawAfter === undefined || rawAfter === null ? null : rawAfter;
    if (!fields || !req.is('application/json') || Object.keys(req.query).length || Object.keys(rest).length ||
        typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > CONFIDENTIAL_LISTING_PAGE_MAX ||
        (after !== null && (typeof after !== 'string' || !/^[a-f0-9]{64}$/.test(after)))) {
      res.status(400).json({ success: false, error: 'Invalid request' });
      return;
    }
    try {
      const page = await listConfidentialAdminListings(await source(), { limit, after: after as string | null });
      res.json({ success: true, listings: page.listings, next: page.next });
    } catch {
      res.status(503).json({ success: false, error: 'Confidential listings temporarily unavailable' });
    }
  });
  router.post('/listings/moderation', guard, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const body = req.body;
    if (!req.is('application/json') || Object.keys(req.query).length || !body || typeof body !== 'object' || Array.isArray(body) ||
        Object.keys(body).sort().join(',') !== 'actor,caseId,hidden' || typeof body.caseId !== 'string' ||
        !/^[a-f0-9]{64}$/.test(body.caseId) || typeof body.hidden !== 'boolean' || typeof body.actor !== 'string' ||
        !body.actor.trim() || body.actor.length > 254 || /[\r\n]/.test(body.actor)) {
      res.status(400).json({ success: false, error: 'Invalid request' }); return;
    }
    try {
      const store = await source();
      if (!store.moderateListing) throw new Error('Unavailable');
      const changed = await store.moderateListing(body.caseId, body.hidden, body.actor, Date.now());
      res.status(changed ? 200 : 404).json({ success: changed });
    } catch { res.status(503).json({ success: false, error: 'Moderation unavailable' }); }
  });
  return router;
}
