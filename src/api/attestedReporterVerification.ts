import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import { REPORTER_CODE_PATTERN } from '../services/reporterAccess';
import type { AttestedReporterVerification } from '../services/attestedReporterVerification';

export function createAttestedReporterVerificationRouter(service?: Pick<AttestedReporterVerification, 'read'>) {
  const router = Router();
  const limiter = rateLimit({ keyGenerator: requestRateLimitKey, store: sharedRateLimitStore('attestedReporterVerification'), windowMs: 60_000, max: 10, standardHeaders: true, legacyHeaders: false,
    message: { success: false, error: 'Verification temporarily unavailable' } });
  router.post('/status/access/verification', limiter, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Referrer-Policy', 'no-referrer');
    if (!service) { res.status(404).json({ success: false, error: 'Not found' }); return; }
    const code = req.get('X-Reporter-Credential');
    if (!code || !REPORTER_CODE_PATTERN.test(code) || Object.keys(req.query).length ||
        (req.body !== undefined && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) || Object.keys(req.body).length))) {
      res.status(400).json({ success: false, error: 'Reporter credential required' }); return;
    }
    const controller = new AbortController();
    const abort = () => controller.abort();
    req.once('aborted', abort); res.once('close', abort);
    try {
      const verification = await service.read(code, controller.signal);
      if (!res.destroyed && !res.headersSent) res.status(verification ? 200 : 404).json(verification ? { success: true, verification } : { success: false, error: 'Not found' });
    } catch {
      if (!res.destroyed && !res.headersSent) res.status(503).json({ success: false, error: 'Verification temporarily unavailable' });
    } finally { req.removeListener('aborted', abort); res.removeListener('close', abort); }
  });
  return router;
}
