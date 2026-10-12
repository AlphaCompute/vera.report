/**
 * Response headers for the private participant screens: /report, /status and the
 * /legal portal (docs/security/README.md#trust-boundaries: "strict CSP,
 * no third-party scripts on private screens, no private SSR output").
 *
 * CommonJS so next.config.js and pages/_document.tsx share one definition.
 *
 * - Every private page (/report, /status and all of /legal) is server-rendered;
 *   pages/_document.tsx sets its nonce CSP from lib/confidential/strictPageHeaders.ts
 *   (connect-src limited to 'self' and the configured identity tenants) plus PRIVATE_PAGE_HEADERS below.
 * - next.config.js adds PRIVATE_PAGE_HEADERS (without a CSP) to every /legal
 *   response as well, so a response that skips _document still gets them. It
 *   must not add a second, nonce-less CSP: browsers enforce every policy sent.
 */

/** Pages that set these headers. Kept narrow on purpose. */
const PRIVATE_PAGE = /^\/(?:report|status|legal)(?=\/|$)/;

function isPrivatePagePath(pathname) {
  return privatePageFamily(pathname) !== null;
}

/** 'report' | 'status' | 'legal' for a private page path or URL, else null. */
function privatePageFamily(pathOrUrl) {
  if (typeof pathOrUrl !== 'string') return null;
  let path = pathOrUrl;
  try { path = new URL(pathOrUrl, 'http://local.invalid').pathname; } catch { return null; }
  const match = PRIVATE_PAGE.exec(path);
  return match ? match[0].replace(/\//g, '') : null;
}

/** A client-side (soft) navigation keeps the current document and therefore its
 * response headers. Entering a private page family from any other page must
 * load a new document so that family's CSP and headers apply. */
function requiresDocumentNavigation(currentPath, targetUrl) {
  // Only router-local paths are eligible; never turn a scheme or foreign URL
  // into a document navigation through this helper.
  if (typeof targetUrl !== 'string' || !targetUrl.startsWith('/') || targetUrl.startsWith('//') || /[\\\r\n]/.test(targetUrl)) return false;
  const target = privatePageFamily(targetUrl);
  return target !== null && target !== privatePageFamily(currentPath);
}

/** Headers other than the CSP, identical for every private page. */
const PRIVATE_PAGE_HEADERS = Object.freeze({
  'Cache-Control': 'private, no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'X-Robots-Tag': 'noindex, nofollow',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()',
});

/** next.config.js `headers()` entries for the /legal portal. The per-request
 * nonce CSP comes from pages/_document.tsx. `dev` is accepted for callers. */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function legalPortalHeaderRules(dev) {
  const headers = Object.entries(PRIVATE_PAGE_HEADERS).map(([key, value]) => ({ key, value }));
  return ['/legal', '/legal/:path*'].map(source => ({ source, headers }));
}

module.exports = {
  PRIVATE_PAGE_HEADERS, isPrivatePagePath, legalPortalHeaderRules, privatePageFamily, requiresDocumentNavigation,
};
