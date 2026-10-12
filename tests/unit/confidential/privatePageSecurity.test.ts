/**
 * Regression tests for the private participant pages (/report, /status, /legal):
 * response headers and CSP, case IDs kept out of URLs, sign-in return paths,
 * evidence download names and on-screen error text.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import {
  PRIVATE_PAGE_HEADERS, isPrivatePagePath, legalPortalHeaderRules, requiresDocumentNavigation,
} from '../../../lib/privatePageHeaders';
import { strictPageHeaders } from '../../../lib/confidential/strictPageHeaders';
import { caseIdFromFragment, LEGAL_CASE_PATH } from '../../../lib/confidential/legalCaseLink';
import { safeReturnPath } from '../../../lib/confidential/legalAuth';
import { OPAQUE_DOWNLOAD_TYPE, safeDownloadName } from '../../../lib/confidential/safeDownload';
import { userFacingMessage } from '../../../lib/confidential/userFacingError';
import { chooseEvidenceSink, memorySink, safeFileName } from '../../../lib/confidential/evidenceTransfer';

const ROOT = path.resolve(__dirname, '../../..');
const CASE_ID = 'c3'.repeat(32);
const directives = (csp: string) => new Map(csp.split(';').map(part => part.trim().split(/\s+/)).map(([name, ...values]) => [name, values]));

describe('private page CSP', () => {
  test('production policy: same-origin scripts, no framing, plugins, base or foreign forms', () => {
    const csp = directives(strictPageHeaders('/report', 'AAAAAAAAAAAAAAAAAAAAAAAA', false)['Content-Security-Policy']);
    expect(csp.get('script-src')).toEqual(["'self'", "'nonce-AAAAAAAAAAAAAAAAAAAAAAAA'"]);
    expect(csp.get('default-src')).toEqual(["'self'"]);
    expect(csp.get('connect-src')).toEqual(["'self'"]);
    expect(csp.get('object-src')).toEqual(["'none'"]);
    expect(csp.get('frame-src')).toEqual(["'none'"]);
    expect(csp.get('frame-ancestors')).toEqual(["'none'"]);
    expect(csp.get('base-uri')).toEqual(["'none'"]);
    expect(csp.get('form-action')).toEqual(["'self'"]);
    expect(csp.has('upgrade-insecure-requests')).toBe(true);
    for (const [, values] of csp) {
      expect(values).not.toContain("'unsafe-eval'");
      expect(values.filter(value => /^https?:\/\//.test(value))).toEqual([]);
    }
    expect(csp.get('script-src')).not.toContain("'unsafe-inline'");
  });

  test('approved organization keys do not require outbound firm connections', () => {
    const csp = directives(strictPageHeaders('/status', 'N', false, ['identity.example'])['Content-Security-Policy']);
    expect(csp.get('connect-src')).toEqual(["'self'"]);
    expect(csp.get('script-src')).toEqual(["'self'", "'nonce-N'"]);
  });

  test('development relaxations never reach a production policy', () => {
    const dev = directives(strictPageHeaders('/report', 'N', true)['Content-Security-Policy']);
    expect(dev.get('script-src')).toEqual(["'self'", "'nonce-N'", "'unsafe-eval'"]);
    expect(dev.has('upgrade-insecure-requests')).toBe(false);
  });

  test('the /legal portal gets the private headers, after the site-wide rule, and no second CSP', () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const config = require('../../../next.config.js');
    return config.headers().then((rules: { source: string; headers: { key: string; value: string }[] }[]) => {
      const global = rules.findIndex(rule => rule.source === '/:path*');
      for (const source of ['/legal', '/legal/:path*']) {
        const index = rules.findIndex(rule => rule.source === source);
        expect(index).toBeGreaterThan(global);
        const headers = Object.fromEntries(rules[index].headers.map(header => [header.key, header.value]));
        expect(headers).toMatchObject(PRIVATE_PAGE_HEADERS);
        // The nonce CSP is per request (pages/_document.tsx); a static nonce-less
        // policy here would also be enforced and block the page's scripts.
        expect(headers['Content-Security-Policy']).toBeUndefined();
      }
      expect(legalPortalHeaderRules(false)[0].headers.find(header => header.key === 'Content-Security-Policy')).toBeUndefined();
    });
  });

  test('the per-request pages set the same headers, with outbound connect only on /status', () => {
    const document = readFileSync(path.join(ROOT, 'pages/_document.tsx'), 'utf8');
    expect(document).toMatch(/strictPageHeaders\(ctx\.req\.url, nonce/);
    expect(document).toMatch(/Object\.entries\(PRIVATE_PAGE_HEADERS\)\) ctx\.res\.setHeader/);
    expect(PRIVATE_PAGE_HEADERS).toMatchObject({
      'Cache-Control': 'private, no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex, nofollow',
    });
    for (const page of ['/report', '/status', '/legal', '/legal/report', '/legal/enroll?x=1']) expect(isPrivatePagePath(page)).toBe(true);
    for (const page of ['/', '/legality', '/reports', '/admin']) expect(isPrivatePagePath(page)).toBe(false);
  });
});

test('entering a private page family always loads a new document with its own headers', () => {
  expect(requiresDocumentNavigation('/', '/report')).toBe(true);
  expect(requiresDocumentNavigation('/', `/legal/report#${CASE_ID}`)).toBe(true);
  expect(requiresDocumentNavigation('/report', '/status')).toBe(true);
  expect(requiresDocumentNavigation('/status', '/legal')).toBe(true);
  expect(requiresDocumentNavigation('/legal', `/legal/report#${CASE_ID}`)).toBe(false);
  expect(requiresDocumentNavigation('/legal/report', '/legal/keys')).toBe(false);
  expect(requiresDocumentNavigation('/status', '/')).toBe(false);
  expect(requiresDocumentNavigation('/', '/legality')).toBe(false);
  for (const target of ['javascript:/legal/.test(alert(1))', '//evil.example/legal', '/\\evil.example/legal']) {
    expect(requiresDocumentNavigation('/', target)).toBe(false);
  }
  const app = readFileSync(path.join(ROOT, 'pages/_app.tsx'), 'utf8');
  expect(app).toMatch(/throw cancelled/);
  expect(app).toMatch(/router\.events\.on\('routeChangeStart', enterPrivateDocument\)/);
  expect(app).toMatch(/requiresDocumentNavigation\(window\.location\.pathname, url\)\) \{\s*const allowed = window\.dispatchEvent/);
  expect(app).toMatch(/cancelable: true, detail: \{ url \}/);
  expect(app).toMatch(/if \(allowed\) window\.location\.assign\(url\)/);
});

describe('legal case links keep the case ID out of requests', () => {
  test('an inbound fragment stays out of the HTTP request', () => {
    const href = `/legal/report#${CASE_ID}`;
    expect(href).toBe(`${LEGAL_CASE_PATH}#${CASE_ID}`);
    const url = new URL(href, 'https://vera.report');
    expect(url.pathname + url.search).not.toContain(CASE_ID);
    expect(caseIdFromFragment(url.hash)).toBe(CASE_ID);
    expect(caseIdFromFragment('#not-a-case')).toBeNull();
    expect(caseIdFromFragment(`#${CASE_ID}&x=1`)).toBeNull();
  });

  test('no page or component links to a case by path', () => {
    for (const file of ['pages/legal/index.tsx', 'pages/legal/report.tsx',
      'components/vera/confidential/LegalPortal.tsx', 'components/vera/confidential/LegalReportView.tsx']) {
      expect(readFileSync(path.join(ROOT, file), 'utf8')).not.toMatch(/\/legal\/cases\/\$\{/);
    }
    expect(readFileSync(path.join(ROOT, 'pages/legal/report.tsx'), 'utf8')).toMatch(/components\/vera\/confidential\/LegalReportView/);
    expect(existsSync(path.join(ROOT, 'pages/legal/cases'))).toBe(false);
  });

  test('sign-in returns only to /legal paths, keeping a case fragment', () => {
    expect(safeReturnPath(`/legal/report#${CASE_ID}`)).toBe(`/legal/report#${CASE_ID}`);
    expect(safeReturnPath('/legal/keys')).toBe('/legal/keys');
    for (const hostile of ['https://evil.example/legal', '//evil.example', '/legal//evil.example', '/legal/case#x',
      '/legal?next=https://evil.example', '/legalx', '/admin', null, 42]) {
      expect(safeReturnPath(hostile)).toBe('/legal');
    }
  });
});

describe('evidence downloads', () => {
  test('are always opaque octet streams', () => { expect(OPAQUE_DOWNLOAD_TYPE).toBe('application/octet-stream'); });

  test.each([
    ['report.pdf', 'report.pdf'],
    ['../../etc/passwd', 'passwd'],
    ['..\\..\\boot.ini', 'boot.ini'],
    ['.bashrc', 'bashrc'],
    ['invoice.pdf. ', 'invoice.pdf'],
    ['CON', '_CON'],
    ['lpt1.txt', '_lpt1.txt'],
    ['photo‮gnp.exe', 'photo_gnp.exe'],
    ['a"b<c>d|e?.txt', 'a_b_c_d_e_.txt'],
    ['', 'download'],
    ['///', 'download'],
    [undefined, 'download'],
  ])('%j is saved as %j', (input, expected) => { expect(safeDownloadName(input)).toBe(expected); });

  test('long names keep their extension within the limit', () => {
    const name = safeDownloadName(`${'x'.repeat(300)}.pdf`);
    expect(name.length).toBeLessThanOrEqual(120);
    expect(name.endsWith('.pdf')).toBe(true);
  });

  test('the legal portal routes every download through the sanitizer', () => {
    const portal = readFileSync(path.join(ROOT, 'components/vera/confidential/LegalPortal.tsx'), 'utf8');
    expect(portal).toMatch(/link\.download = safeDownloadName\(filename\)/);
    expect(portal).toMatch(/type = OPAQUE_DOWNLOAD_TYPE/);
  });
});

describe('chunked evidence downloads (EvidenceDownloadButton, OwnerFiles)', () => {
  const hostile = ['.bashrc', '..', 'report.pdf.exe.', 'invoice.pdf ', 'CON', 'NUL.txt', '../../etc/passwd', 'photo\u202Egnp.exe'];
  const g = globalThis as Record<string, unknown>;
  let saved: Record<string, unknown>;
  beforeEach(() => { saved = { document: g.document, showSaveFilePicker: g.showSaveFilePicker }; });
  afterEach(() => { for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete g[key]; else g[key] = value; } });

  test.each(hostile)('safeFileName(%j) matches the hardened sanitizer', input => {
    expect(safeFileName(input)).toBe(safeDownloadName(input));
  });

  test.each(hostile)('the in-memory download of %j uses the hardened name and an opaque type', async input => {
    const link: Record<string, unknown> = { click: jest.fn(), remove: jest.fn() };
    g.document = { createElement: () => link, body: { appendChild: jest.fn() } };
    const createObjectURL = jest.spyOn(URL, 'createObjectURL').mockReturnValue('blob:x');
    jest.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    jest.useFakeTimers();
    try {
      const sink = memorySink(input);
      await sink.write(new Uint8Array([1, 2, 3]));
      await sink.close();
      expect(link.download).toBe(safeDownloadName(input));
      expect((createObjectURL.mock.calls[0][0] as Blob).type).toBe(OPAQUE_DOWNLOAD_TYPE);
    } finally { jest.runOnlyPendingTimers(); jest.useRealTimers(); jest.restoreAllMocks(); }
  });

  test.each(hostile)('the save dialog suggests the hardened name for %j', async input => {
    const picker = jest.fn(async (_options: { suggestedName: string }) => ({
      createWritable: async () => ({ write: async () => undefined, close: async () => undefined, abort: async () => undefined }),
    }));
    g.showSaveFilePicker = picker;
    expect(await chooseEvidenceSink(input)).not.toBeNull();
    expect(picker).toHaveBeenCalledWith({ suggestedName: safeDownloadName(input) });
    const suggested = picker.mock.calls[0][0].suggestedName;
    expect(suggested).not.toMatch(/^\.|[. ]$|[\\/]/);
    expect(suggested).not.toMatch(/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i);
  });
});

describe('on-screen error text', () => {
  test('keeps deliberate guidance', () => {
    for (const message of ['This organization workspace backup is invalid',
      'Use a unique passphrase of at least 16 characters. Save it separately from this browser.',
      'Some VERA device data could not be cleared. Lock this workspace, then clear this site’s data in your browser settings.']) {
      expect(userFacingMessage(new Error(message), 'fallback')).toBe(message);
    }
  });

  test.each([
    ['a key ID', 'Error decrypting: key 7f3a9c0d1e2b4a5f6c7d8e9f0a1b2c3d not found'],
    ['an armored block', '-----BEGIN PGP MESSAGE----- wcBMA'],
    ['a URL', 'Failed to fetch https://firm.example/api/status'],
    ['JSON', 'Unexpected token { in {"caseId":"x"}'],
    ['a stack', 'Error\n    at decrypt (openpgp.mjs:1:1)'],
    ['a recovery code', `VERA-OWNER-1.${CASE_ID}`],
    ['lowercase library text', 'misformed armored text'],
    ['an empty message', ''],
  ])('replaces %s with the fallback', (_name, message) => {
    expect(userFacingMessage(new Error(message), 'Please try again.')).toBe('Please try again.');
  });

  test('non-errors use the fallback', () => {
    expect(userFacingMessage('This looks fine', 'fallback')).toBe('fallback');
    expect(userFacingMessage(undefined, 'fallback')).toBe('fallback');
  });
});

test('fields that hold recovery codes or invitation links are never spell-checked or autocompleted', () => {
  const status = readFileSync(path.join(ROOT, 'pages/status.tsx'), 'utf8');
  const field = status.slice(status.indexOf('id="report-id"'), status.indexOf('id="report-id"') + 1200);
  for (const attribute of ['autoComplete="off"', 'spellCheck={false}', 'autoCorrect="off"']) {
    expect(field).toContain(attribute);
  }
  // Recovery codes are upper case; capitalizing them does not involve a suggestion dictionary.
  expect(field).toMatch(/autoCapitalize="(none|characters)"/);
  const administration = readFileSync(path.join(ROOT, 'pages/legal/administration.tsx'), 'utf8');
  const link = administration.match(/<textarea id="invitation-link"[^>]*>/)?.[0] ?? '';
  for (const attribute of ['readOnly', 'spellCheck={false}', 'autoComplete="off"', 'value={result.link}']) expect(link).toContain(attribute);
});

// Fragment-only switches reuse the page component; private state must not follow.
test('case switches remount the case view rather than retaining another case draft', () => {
  const page = readFileSync(path.join(ROOT, 'pages/legal/report.tsx'), 'utf8');
  expect(page).toContain('<CaseView key={caseId} session={session} caseId={caseId} />');
  expect(page).toContain('<LegalGate key={caseId}');
  // The fragment hook also follows Next's pushState hash changes.
  expect(readFileSync(path.join(ROOT, 'lib/confidential/legalCaseLink.ts'), 'utf8')).toContain("'hashChangeComplete'");
});
