import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { isStrictPage, legalIdentityOrigins, strictPageHeaders } from '../../../lib/confidential/strictPageHeaders';

const root = resolve(__dirname, '../../..');
const pagesUnder = (dir: string): string[] => readdirSync(dir).flatMap(name => {
  const path = join(dir, name);
  return statSync(path).isDirectory() ? pagesUnder(path) : /\.tsx?$/.test(name) ? [path] : [];
});
const legalPages = pagesUnder(resolve(root, 'pages/legal'));

test.each(['/report', '/status', '/status?code=1', '/legal', '/legal?code=x&state=y', '/legal/keys', '/legal/administration',
  '/legal/enroll', '/legal/cases/abc', '/legal/cases/abc?x=1'])('%s is a strict key page', url => {
  expect(isStrictPage(url)).toBe(true);
});
test.each([undefined, '', '/', '/reports', '/legally', '/statuses', '/admin', '/api/legal', '/_next/static/x.js'])('%s is not a strict key page', url => {
  expect(isStrictPage(url)).toBe(false);
});

test('legal pages get a same-origin and nonce CSP, no-store and no-referrer', () => {
  for (const url of ['/legal', '/legal/keys', '/legal/administration', '/legal/cases/abc']) {
    const headers = strictPageHeaders(url, 'NONCE', false, ['identity.example', 'onboarding.example']);
    const csp = headers['Content-Security-Policy'];
    expect(csp).toContain("script-src 'self' 'nonce-NONCE';");
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("connect-src 'self' https://identity.example https://onboarding.example;");
    expect(headers['Cache-Control']).toBe('private, no-store');
    expect(headers['Referrer-Policy']).toBe('no-referrer');
  }
});

test('reporter pages never gain identity-provider origins', () => {
  const csp = strictPageHeaders('/report', 'N', false, ['identity.example'])['Content-Security-Policy'];
  expect(csp).toContain("connect-src 'self';");
});

test('only bare hostnames reach connect-src', () => {
  expect(legalIdentityOrigins(['identity.example', undefined, '', 'evil.example; script-src *', 'https://x.example', 'identity.example']))
    .toEqual(['https://identity.example']);
});

test('development allows eval only for the dev server', () => {
  expect(strictPageHeaders('/legal', 'N', true)['Content-Security-Policy']).toContain("'nonce-N' 'unsafe-eval'");
});

test('_document applies the shared strict headers', () => {
  const document = readFileSync(resolve(root, 'pages/_document.tsx'), 'utf8');
  expect(document).toMatch(/isStrictPage\(ctx\.req\.url\)/);
  expect(document).toMatch(/strictPageHeaders\(/);
  expect(document).toMatch(/<NextScript nonce=\{this\.props\.nonce\}/);
});

// A statically optimized page is served from build output without running
// `_document.getInitialProps`, so it would ship with none of the headers.
test.each(['pages/report.tsx', 'pages/status.tsx', ...legalPages.map(path => relative(root, path))])('%s is server-rendered', path => {
  expect(readFileSync(resolve(root, path), 'utf8')).toMatch(/export const getServerSideProps\b/);
});

test('every legal page is covered by the strict-page pattern', () => {
  expect(legalPages.length).toBeGreaterThanOrEqual(5);
  for (const path of legalPages) {
    const route = '/' + relative(resolve(root, 'pages'), path).split(sep).join('/').replace(/\.tsx?$/, '').replace(/\/index$/, '').replace(/\[([^\]]+)\]/g, 'x');
    expect(isStrictPage(route)).toBe(true);
  }
});

// With the mode off, functional legal pages render only the disabled notice.
// Their default export must decide on `confidentialCasesEnabled()` before any
// hook (sign-in completion, invitation consumption, cross-tab lock) can run.
test.each(['pages/legal/keys.tsx', 'pages/legal/administration.tsx', 'pages/legal/enroll.tsx'])('%s is gated on the confidential mode', path => {
  const source = readFileSync(resolve(root, path), 'utf8');
  const body = source.split(/export default function \w+\(\) \{/)[1].split(/\r?\n}\r?\n/)[0];
  expect(body.trim()).toMatch(/^return confidentialCasesEnabled\(\) \? <\w+ \/> : <LegalPortalDisabled title="[^"]+" \/>;$/);
});

test('gate-rendered legal pages show the disabled notice when the mode is off', () => {
  const portal = readFileSync(resolve(root, 'components/vera/confidential/LegalPortal.tsx'), 'utf8');
  expect(portal).toMatch(/if \(!confidentialCasesEnabled\(\)\) \{ setGate\(\{ state: "disabled" \}\); return; \}/);
  for (const path of ['pages/legal/index.tsx', 'pages/legal/report.tsx']) {
    expect(readFileSync(resolve(root, path), 'utf8')).toMatch(/<LegalGate\b/);
  }
});


test('organization approval never opens outbound firm connections in key-holding pages', () => {
  for (const route of ['/status', '/report', '/legal', '/legal/administration']) {
    const policy = strictPageHeaders(route, 'N', false, [])['Content-Security-Policy'];
    expect(policy).toContain("connect-src 'self';");
    expect(policy).not.toContain('counsel.example');
  }
});
