import crypto from 'node:crypto';
import { Request, Response, NextFunction } from 'express';

/** Compare fixed-length digests without a secret-dependent early mismatch.
 * Hashing still takes time proportional to the supplied header length. */
export function internalSecretMatches(provided: string, expected: string): boolean {
  const digest = (value: string) => crypto.createHash('sha256').update(value, 'utf8').digest();
  return crypto.timingSafeEqual(digest(provided), digest(expected));
}

/** CloudFront adds `X-Origin-Verify` to every request it forwards, and the ALB WAF
 * refuses any request without it, so its presence means the caller came in from the
 * public internet. The Next proxy reaches these routes over the internal load
 * balancer and never forwards inbound headers. The ALB sends all of `/api/*` to this
 * server (and path matching differs in case between the two), so without this check
 * the shared secret alone would open admin routes to anyone on the internet. */
export function arrivedFromPublicEdge(req: Request): boolean {
  return req.headers['x-origin-verify'] !== undefined;
}

/**
 * Express middleware: gates a route on the `x-internal-secret` header
 * matching `INTERNAL_API_SECRET`. Comparison is constant-time.
 *
 * Used as defense in depth on Express routes that the Next.js admin proxy
 * is allowed to reach (which itself enforces Auth0 admin role). Without
 * this middleware, anything inside the VPC can hit the backend directly
 * — bypassing the proxy and its admin check entirely.
 *
 * Requests that arrived through the public edge are refused with 404 even when
 * the secret matches.
 *
 * If `INTERNAL_API_SECRET` is unset, every request is rejected with 500
 * and a clear server-side log: fail closed, never open.
 */
export function requireHeaderSecret(variable: 'INTERNAL_API_SECRET' | 'CONFIDENTIAL_ADMIN_SECRET' | 'LEGAL_APPROVAL_BACKEND_SECRET',
  env: NodeJS.ProcessEnv = process.env) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (arrivedFromPublicEdge(req)) {
      res.status(404).json({ success: false, error: 'Not found' });
      return;
    }

    const expected = env[variable];
    if (!expected) {
      console.error(`[INTERNAL_SECRET] ${variable} not configured — refusing request`);
      res.status(500).json({ success: false, error: 'Internal configuration error' });
      return;
    }

    const provided = req.headers['x-internal-secret'];
    if (typeof provided !== 'string' || provided.length === 0) {
      res.status(401).json({ success: false, error: 'Unauthorized' });
      return;
    }

    if (!internalSecretMatches(provided, expected)) {
      res.status(401).json({ success: false, error: 'Unauthorized' });
      return;
    }

    next();
  };
}

/** The legacy API's gate (`INTERNAL_API_SECRET`). The confidential-only process
 * uses `requireHeaderSecret('CONFIDENTIAL_ADMIN_SECRET')` and never sees this one. */
export const requireInternalSecret = requireHeaderSecret('INTERNAL_API_SECRET');
