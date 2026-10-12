/** Pages that hold participant or firm key material: the reporter pages, and
 * every legal-portal page (which decrypts the firm's private key in the
 * browser). They get a same-origin and nonce script policy, are never cached and never
 * leak their URL in a Referer. Each listed page must be server-rendered
 * (`getServerSideProps`); a statically optimized page is served from the build
 * output without running `_document`, so it would get none of these headers. */
export const STRICT_PAGE_PATTERN = /^\/(?:report|status|legal)(?:[/?#]|$)/;
const LEGAL_PAGE_PATTERN = /^\/legal(?:[/?#]|$)/;
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function isStrictPage(url: string | undefined): boolean {
  return STRICT_PAGE_PATTERN.test(url || '');
}

/** The legal portal exchanges its PKCE code with the identity provider from
 * the browser, so only those two token endpoints join `connect-src`. A value
 * that is not a bare hostname is dropped rather than written into the header. */
export function legalIdentityOrigins(domains: (string | undefined)[]): string[] {
  return [...new Set(domains.filter((domain): domain is string => !!domain && domain.length <= 253 && HOSTNAME.test(domain)))].map(domain => `https://${domain}`);
}

export function strictPageHeaders(url: string | undefined, nonce: string, development: boolean,
  identityDomains: (string | undefined)[] = []): Record<string, string> {
  const dev = development ? " 'unsafe-eval'" : '';
  const connect = [...new Set(["'self'", ...(LEGAL_PAGE_PATTERN.test(url || '') ? legalIdentityOrigins(identityDomains) : [])])].join(' ');
  return {
    'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'${dev}; style-src 'self' 'unsafe-inline'; ` +
      `img-src 'self' data: blob:; font-src 'self'; connect-src ${connect}; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` +
      (development ? '' : '; upgrade-insecure-requests'),
    'Cache-Control': 'private, no-store',
    'Referrer-Policy': 'no-referrer',
  };
}
