import type { ErrorRequestHandler, Request, RequestHandler } from 'express';

/** Request admission for the unauthenticated confidential-case routes
 * (`/api/confidential/*`). These routes carry no ambient credential (the browser
 * sends them with `credentials: 'omit'` and every private operation is
 * authenticated inside the attested channel), so this is defense in depth:
 *
 * - Browser requests from a foreign origin are refused before any body is read,
 *   so a hostile page cannot spend a reporter's quota or drive the enclave from
 *   the reporter's address.
 * - Only the one content type each route accepts is admitted. A non-simple type
 *   forces a CORS preflight, which the API answers without an allow header.
 * - Errors are fixed strings. Nothing here reads, echoes or logs a body, header
 *   value or path parameter.
 */
const PRODUCTION_DEFAULT_ORIGINS = ['https://vera.report', 'https://whistleblower.vera.report'];
const DEVELOPMENT_DEFAULT_ORIGINS = [...PRODUCTION_DEFAULT_ORIGINS, 'http://localhost:3000'];

/** The frontend origins allowed to call the API (shared with the CORS policy).
 * Set CORS_ALLOWED_ORIGINS to the frontend origins served by your environment. The built-in fallback never admits a plain-HTTP
 * localhost origin under NODE_ENV=production, and a production allowlist keeps
 * only https:// entries even when configured. */
export function configuredFrontendOrigins(env: NodeJS.ProcessEnv = process.env): string[] {
  const production = env.NODE_ENV === 'production';
  const configured = env.CORS_ALLOWED_ORIGINS?.split(',').map(origin => origin.trim()).filter(Boolean) ?? [];
  const raw = configured.length > 0 ? configured : production ? PRODUCTION_DEFAULT_ORIGINS : DEVELOPMENT_DEFAULT_ORIGINS;
  return production ? raw.filter(origin => origin.startsWith('https://')) : [...raw];
}

/** Case-insensitive, like Express routing: `/API/Confidential/...` reaches the same router. */
export function isConfidentialApiPath(path: string): boolean {
  return /^\/api\/confidential(?:\/|$)/i.test(path);
}

/** Run a global middleware (the 10 MB body parsers) everywhere except the
 * confidential routes, which parse their own bodies under much tighter limits. */
export function exceptConfidentialApi(middleware: RequestHandler): RequestHandler {
  return (req, res, next) => isConfidentialApiPath(req.path) || /^\/api\/auth0\/legal-entry\/?$/i.test(req.path) ||
    /^\/api\/internal\/legal-approval(?:\/|$)/i.test(req.path) ? next() : middleware(req, res, next);
}

function sameOriginOrAllowed(req: Request, allowed: readonly string[]): boolean {
  const origin = req.get('origin');
  const site = req.get('sec-fetch-site');
  if (origin !== undefined) return origin !== 'null' && allowed.includes(origin);
  // No Origin header: server-to-server and old browsers. A browser that reports
  // a cross-site fetch without Origin is still refused.
  return site !== 'cross-site';
}

export function confidentialRequestGuard(contentType: string, allowed: readonly string[] = configuredFrontendOrigins()): RequestHandler {
  const origins = [...allowed];
  return (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!sameOriginOrAllowed(req, origins)) { res.status(403).json({ error: 'Request not allowed' }); return; }
    if (!req.is(contentType)) { res.status(415).json({ error: 'Unsupported content type' }); return; }
    next();
  };
}

/** Body-parser failures (oversized, malformed, wrong charset) become fixed
 * replies here, so no parser message quoting the raw body reaches a log or client. */
export const confidentialBodyErrors: ErrorRequestHandler = (error, _req, res, next) => {
  if (res.headersSent) { next(error); return; }
  res.setHeader('Cache-Control', 'no-store');
  const type = (error as { type?: unknown } | null)?.type;
  if (type === 'entity.too.large') { res.status(413).json({ error: 'Request too large' }); return; }
  res.status(400).json({ error: 'Invalid request' });
};
