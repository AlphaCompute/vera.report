/** Redaction and storage-privacy guards for confidential cases: log redaction
 * of recovery codes, OpenPGP material and bearer tokens; MongoDB driver logging
 * pinned off for the confidential database; case IDs kept out of legal-portal
 * URLs; the reporter-page content security policy. */
import { MongoClient } from 'mongodb';
import { logger, redactCapabilities } from '../../../src/utils/logger';
import { confidentialMongoClientOptions } from '../../../src/services/confidentialCaseStore';
import { caseIdFromFragment } from '../../../lib/confidential/legalCaseLink';
import { privateRequest } from '../../../src/utils/requestPrivacy';
import { strictPageHeaders } from '../../../lib/confidential/strictPageHeaders';

const CASE_ID = 'c3'.repeat(32);
const OWNER_CODE = `VERA-OWNER-1.${CASE_ID}.${'b'.repeat(40)}.${'S'.repeat(43)}`;
const FIRM_CODE = 'VERA-FIRM-1.abcDEF_123-xyz~';
const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhdXRoMHxsYXd5ZXIifQ.c2lnbmF0dXJlLXNlbnRpbmVs';
const ARMOR = '-----BEGIN PGP MESSAGE-----\n\nwcFMA-SENTINEL\n=abcd\n-----END PGP MESSAGE-----';

test('recovery codes, OpenPGP blocks and bearer tokens never survive log redaction', () => {
  const line = redactCapabilities(`restore ${OWNER_CODE} firm ${FIRM_CODE} token ${JWT} body ${ARMOR} done`);
  for (const secret of [OWNER_CODE, 'SSSS', FIRM_CODE, JWT, 'wcFMA-SENTINEL', 'BEGIN PGP']) expect(line).not.toContain(secret);
  expect(line).toContain('[RECOVERY-REDACTED]');
  expect(line).toContain('[TOKEN-REDACTED]');
  expect(line).toContain('[PGP-REDACTED]');
  expect(line).toMatch(/done$/);
  // A truncated armor block (no END line) is still removed.
  expect(redactCapabilities('x -----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret-material')).toBe('x [PGP-REDACTED]');
});

test('the application logger applies redaction to messages and sensitive fields in both formats', () => {
  const saved = { LOG_LEVEL: process.env.LOG_LEVEL, LOG_FORMAT: process.env.LOG_FORMAT };
  const spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  try {
    process.env.LOG_LEVEL = 'debug';
    for (const format of ['text', 'json']) {
      process.env.LOG_FORMAT = format;
      logger.error(`failed ${OWNER_CODE}`, { recoveryCode: 'plain-recovery', stateKey: 'plain-state-key', accessToken: 'plain-token',
        ciphertext: 'plain-ciphertext', proof: 'plain-proof', passphrase: 'plain-passphrase', nested: { note: JWT } });
    }
    const output = JSON.stringify(spy.mock.calls);
    for (const secret of [OWNER_CODE, 'plain-recovery', 'plain-state-key', 'plain-token', 'plain-ciphertext', 'plain-proof',
      'plain-passphrase', JWT]) expect(output).not.toContain(secret);
  } finally {
    spy.mockRestore();
    for (const [key, value] of Object.entries(saved)) if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
});

test('the confidential MongoDB client ignores driver logging requested through the environment', () => {
  const saved = { ...process.env };
  Object.assign(process.env, { MONGODB_LOG_ALL: 'debug', MONGODB_LOG_COMMAND: 'debug', MONGODB_LOG_PATH: 'stdout' });
  try {
    const legacyStyle = new MongoClient('mongodb://127.0.0.1:1/x');
    const confidential = new MongoClient('mongodb://127.0.0.1:1/x', confidentialMongoClientOptions());
    // Control: the environment alone does enable command logging for a default client.
    expect((legacyStyle as unknown as { mongoLogger?: { componentSeverities: Record<string, string> } })
      .mongoLogger?.componentSeverities.command).toBe('debug');
    expect((confidential as unknown as { mongoLogger?: unknown }).mongoLogger).toBeUndefined();
    expect(confidential.options.monitorCommands).toBe(false);
    expect(confidentialMongoClientOptions('/ca.pem')).toMatchObject({ tlsCAFile: '/ca.pem', writeConcern: { w: 'majority', j: true } });
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
  }
});

test('inbound legacy fragments never reach the request path or query', () => {
  const href = `/legal/report#${CASE_ID}`;
  expect(href).toBe(`/legal/report#${CASE_ID}`);
  const url = new URL(href, 'https://vera.example');
  // What a browser sends in the request line: path and query only.
  expect(`${url.pathname}${url.search}`).toBe('/legal/report');
  expect(privateRequest(url.pathname)).toBe(true);
  expect(caseIdFromFragment(url.hash)).toBe(CASE_ID);
  expect(caseIdFromFragment('#not-a-case')).toBeNull();
});

test('private pages never connect to a legal organization website', () => {
  const csp = (url: string, dev = false) => strictPageHeaders(url, 'n0nce', dev, [])['Content-Security-Policy'];
  const status = csp('/status');
  expect(status).toContain("connect-src 'self';");
  expect(status).not.toContain('.well-known');
  expect(status).not.toMatch(/https:\/\/\*/);
  expect(status).not.toContain('unsafe-eval');
  for (const url of ['/report', '/report?step=1']) expect(csp(url)).toContain("connect-src 'self';");
  expect(csp('/status?x=1', true)).toContain("'nonce-n0nce' 'unsafe-eval'");
});

test('short recovery codes never survive log redaction, grouped or not', () => {
  const grouped = Array.from({ length: 14 }, (_, index) => `${'7K3M9QXA'.slice(index % 5, index % 5 + 4)}`).join('-');
  const bare = grouped.replace(/-/g, '');
  const line = redactCapabilities(`restore ${grouped} and ${bare} done`);
  expect(line).not.toContain(grouped);
  expect(line).not.toContain(bare);
  expect(line).toBe('restore [RECOVERY-REDACTED] and [RECOVERY-REDACTED] done');
  expect(redactCapabilities('this that with from word more text here some else')).toBe('this that with from word more text here some else');
});
