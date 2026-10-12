import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';

/** Public, unauthenticated delivery of the signed release withdrawal list for
 * participant devices. The bytes are signed offline; browsers verify them
 * against the key pinned in their build. Nothing here is private. */
export function createConfidentialReleaseWithdrawalsRouter(source: () => string | null) {
  const router = Router();
  const limiter = rateLimit({ keyGenerator: requestRateLimitKey, store: sharedRateLimitStore('confidentialReleaseWithdrawals'), windowMs: 60_000, max: 120,
    standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests, please try again later.' } });
  router.get('/release-withdrawals', limiter, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const wire = source();
    if (!wire) { res.status(404).json({ error: 'Not published' }); return; }
    res.type('application/json').send(wire);
  });
  return router;
}
