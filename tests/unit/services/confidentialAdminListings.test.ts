import { projectConfidentialListings } from '../../../lib/confidentialAdminListings';
const mockSession = jest.fn();
jest.mock('@/lib/auth0', () => ({ auth0: {
  getSession: (...args: unknown[]) => mockSession(...args), withApiAuthRequired: (handler: unknown) => handler,
} }));
// Provider checks are covered by currentAdminAuthorization.test.ts.
jest.mock('@/lib/currentAdminAuthorization', () => ({
  currentAdminAuthorization: async (user: Record<string, any>) => ({
    userId: user.sub, email: user.email, name: user.name, roles: user['https://vera.app/roles'] ?? [],
  }),
}));

import { createHash, webcrypto } from 'node:crypto';
import { createMessage, sign } from '../../../enclave/src/confidential/pgp';
import express from 'express';
import request from 'supertest';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import {
  listConfidentialAdminListings, verifyConfidentialListing,
} from '../../../src/services/confidentialAdminListings';
import type { ConfidentialListingRow } from '../../../src/services/confidentialAdminListings';
import { createConfidentialAdminListingRouter } from '../../../src/api/confidentialAdminListings';
import { CONFIDENTIAL_ADMIN_VISIBLE_FIELDS } from '../../../src/utils/intakeConsent';
import listingsProxy from '../../../pages/api/admin/confidential/listings';
import moderationProxy from '../../../pages/api/admin/confidential/listings/moderation';

type Owner = Awaited<ReturnType<typeof createCaseOwner>>;
const hex = (n: number) => n.toString(16).padStart(64, '0');
const SECRET = 'synthetic-confidential-listing-secret';

async function signed(owner: Owner, statement: OwnerStatement) {
  const wire = await signOwnerStatement(statement, owner.privateKey);
  return { wire, ...await verifyOwnerStatement(wire, owner.trust) };
}
async function listingRow(owner: Owner, summary = 'Public summary', revision = 1): Promise<ConfidentialListingRow> {
  const listing = await signed(owner, { kind: 'listing', caseId: owner.trust.caseId, revision, summary });
  return { caseId: owner.trust.caseId, ownerPublicKey: owner.trust.ownerPublicKey.armor(),
    ownerFingerprint: owner.trust.ownerFingerprint, listingDigest: listing.digest, listingWire: listing.wire };
}

let owner: Owner, other: Owner, row: ConfidentialListingRow;
beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [owner, other] = await Promise.all([createCaseOwner(), createCaseOwner()]);
  row = await listingRow(owner, 'Accounting irregularities at a regional supplier');
}, 60_000);

test('browser projection retains only well-typed public facts and drops malformed rows', () => {
  const valid = { caseId: hex(1), summary: 'Summary', publishedAt: 1_790_000_000_000, hasAttachments: false };
  expect(projectConfidentialListings({ listings: [{ ...valid, contact: 'private@example.org', category: 'fraud' }], next: null }))
    .toEqual({ listings: [valid], next: null });
  for (const invalid of [{ publishedAt: null }, { publishedAt: 'today' }, { publishedAt: -1 }, { publishedAt: 1.5 },
    { hasAttachments: 'false' }, { hasAttachments: null }]) {
    expect(projectConfidentialListings({ listings: [{ ...valid, ...invalid }] }).listings).toEqual([]);
  }
});

describe('host verification of owner-signed listings', () => {
  it('accepts an enclave-signed listing and returns exactly caseId + summary', async () => {
    const listing = await verifyConfidentialListing(row);
    expect(listing).toEqual({ caseId: owner.trust.caseId, summary: 'Accounting irregularities at a regional supplier' });
    // Unpublished optional fields are omitted, never serialized as empty values.
    expect(Object.keys(listing!).sort()).toEqual(['caseId', 'summary']);
  });

  it('projects only authenticated optional submission facts and rejects tampering', async () => {
    for (const hasAttachments of [false, true]) {
      const statement = { kind: 'listing' as const, caseId: owner.trust.caseId, revision: 1, summary: 'Summary',
        publishedAt: 1_790_000_000_000, hasAttachments };
      const listing = await signed(owner, statement);
      const withFacts = { ...row, listingWire: listing.wire, listingDigest: listing.digest };
      const expected = { caseId: owner.trust.caseId, summary: 'Summary', publishedAt: statement.publishedAt, hasAttachments };
      expect(await verifyConfidentialListing(withFacts)).toEqual(expected);
      expect((await listConfidentialAdminListings({ listListingWires: async () => [withFacts] })).listings).toEqual([expected]);
      const changed = JSON.parse(listing.wire);
      changed.statement.hasAttachments = !hasAttachments;
      expect(await verifyConfidentialListing({ ...withFacts, listingWire: JSON.stringify(changed) })).toBeNull();
    }
  });

  it.each([{ publishedAt: '2026-09-28' }, { publishedAt: -1 }, { publishedAt: 1.5 }, { publishedAt: 8_640_000_000_000_001 }, { publishedAt: null }, { hasAttachments: 'yes' }, { hasAttachments: 1 }, { hasAttachments: null }, { category: 'financial-fraud' }, { region: 'europe' }, { category: 'fraud' }, { region: 'us-west' }, { region: 'Springfield, IL' }, { category: null },
    { location: 'Portland' }, { region: 'europe', location: 'Portland' }])('rejects owner-signed unknown listing fields or values: %j', async extra => {
    const unsigned = { protocol: 'vera-owner-authorization/v1', ownerFingerprint: owner.trust.ownerFingerprint,
      statement: { kind: 'listing', caseId: owner.trust.caseId, revision: 1, summary: 'Public summary', ...extra } };
    const payload = JSON.stringify(unsigned);
    const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(payload) }),
      signingKeys: owner.privateKey, detached: true, format: 'armored' });
    const listingWire = JSON.stringify({ ...unsigned, signature });
    await expect(verifyOwnerStatement(listingWire, owner.trust)).rejects.toThrow();
    await expect(verifyConfidentialListing({ ...row, listingWire,
      listingDigest: createHash('sha256').update(payload).digest('hex') })).resolves.toBeNull();
  });

  it('rejects altered summaries, wrong keys, digest mismatches and non-listing statements', async () => {
    const wire = JSON.parse(row.listingWire!);
    const altered = JSON.stringify({ ...wire, statement: { ...wire.statement, summary: 'Forged summary' } });
    const extraField = JSON.stringify({ ...wire, statement: { ...wire.statement, category: 'financial-fraud' } });
    const otherRow = await listingRow(other);
    const manifest = await signed(owner, { kind: 'manifest', caseId: owner.trust.caseId, revision: 1, objects: [] });
    const cases: ConfidentialListingRow[] = [
      { ...row, listingWire: altered },
      { ...row, listingWire: extraField },
      { ...row, listingWire: JSON.stringify({ ...wire, statement: { ...wire.statement, region: 'europe' } }) },
      { ...row, listingDigest: hex(9) },
      { ...row, listingWire: null },
      { ...row, listingWire: 'not json' },
      // Another owner's valid listing presented under this case.
      { ...row, listingWire: otherRow.listingWire, listingDigest: otherRow.listingDigest },
      // This listing presented with a different owner key.
      { ...row, ownerPublicKey: other.trust.ownerPublicKey.armor(), ownerFingerprint: other.trust.ownerFingerprint },
      { ...row, ownerPublicKey: owner.trust.ownerPublicKey.armor(), ownerFingerprint: other.trust.ownerFingerprint },
      { ...row, caseId: hex(1) },
      // A valid signed statement that is not a listing.
      { ...row, listingWire: manifest.wire, listingDigest: manifest.digest },
      { ...row, ownerPublicKey: owner.privateKey.armor() },
    ];
    for (const item of cases) expect(await verifyConfidentialListing(item)).toBeNull();
  });

  it('pages by cursor, omits unverifiable rows and never serializes other fields', async () => {
    const rows = [row, { ...row, caseId: hex(2) }, await listingRow(other, 'Second summary')];
    const calls: [number, string | null][] = [];
    const source = { async listListingWires(limit: number, after: string | null) {
      calls.push([limit, after]);
      return rows.map(item => ({ ...item, checkpoints: ['SECRET-CHECKPOINT'], statements: { x: 'SECRET-GRANT' } }));
    } };
    const page = await listConfidentialAdminListings(source, { limit: 3, after: hex(0) });
    expect(calls).toEqual([[3, hex(0)]]);
    expect(page.listings).toEqual([
      { caseId: owner.trust.caseId, summary: 'Accounting irregularities at a regional supplier' },
      { caseId: other.trust.caseId, summary: 'Second summary' },
    ]);
    expect(page.next).toBe(other.trust.caseId);
    expect(JSON.stringify(page)).not.toMatch(/SECRET|BEGIN PGP|signature|revision/);
    expect((await listConfidentialAdminListings(source, { limit: 5 })).next).toBeNull();
    await expect(listConfidentialAdminListings(source, { limit: 101 })).rejects.toThrow();
    await expect(listConfidentialAdminListings(source, { after: 'VERA-OWNER-1.x' })).rejects.toThrow();
  });
});

describe('Express admin listing route', () => {
  const app = express();
  let rows: ConfidentialListingRow[] = [];
  const listListingWires = jest.fn(async () => rows);
  const moderateListing = jest.fn(async () => true);
  app.use(express.json());
  app.use('/api/admin/confidential', createConfidentialAdminListingRouter(async () => ({ listListingWires, moderateListing })));
  const list = (body: unknown = {}) => request(app).post('/api/admin/confidential/listings').send(body as object);
  beforeEach(() => { process.env.INTERNAL_API_SECRET = SECRET; rows = [row]; listListingWires.mockClear(); });

  it('requires the internal secret', async () => {
    await list().expect(401);
    expect(listListingWires).not.toHaveBeenCalled();
  });

  it('moderation refuses unauthenticated or expanded requests and handles unavailable audits safely', async () => {
    const post = (body: object) => request(app).post('/api/admin/confidential/listings/moderation').send(body);
    const body = { caseId: hex(7), hidden: true, actor: 'admin@example.test' };
    await post(body).expect(401);
    expect(moderateListing).not.toHaveBeenCalled();
    await post({ ...body, narrative: 'private' }).set('x-internal-secret', SECRET).expect(400);
    expect(moderateListing).not.toHaveBeenCalled();
    await post(body).set('x-internal-secret', SECRET).expect(200);
    expect(moderateListing).toHaveBeenLastCalledWith(hex(7), true, 'admin@example.test', expect.any(Number));
    moderateListing.mockRejectedValueOnce(new Error('private database detail'));
    const response = await post(body).set('x-internal-secret', SECRET).expect(503);
    expect(JSON.stringify(response.body)).not.toContain('private database detail');
  });

  it('returns exactly [{caseId, summary}] and a cursor', async () => {
    const response = await list({ limit: 1 }).set('x-internal-secret', SECRET).expect(200);
    expect(response.body).toEqual({ success: true, listings: [{ caseId: owner.trust.caseId,
      summary: 'Accounting irregularities at a regional supplier' }], next: owner.trust.caseId });
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it.each([{ limit: 0 }, { limit: 101 }, { limit: '1' }, { limit: 1.5 }, { after: 'VERA-OWNER-1.abc' }, { after: 'XYZ' },
    { caseId: 'abc' }, [1]])('rejects invalid body %j', async body => {
    await list(body).set('x-internal-secret', SECRET).expect(400);
    expect(listListingWires).not.toHaveBeenCalled();
  });

  it('keeps the case-ID cursor out of URLs: the cursor rides in the body and GET or a query string is refused', async () => {
    const cursor = owner.trust.caseId;
    await list({ after: cursor }).set('x-internal-secret', SECRET).expect(200);
    expect(listListingWires).toHaveBeenCalledTimes(1);
    listListingWires.mockClear();
    await request(app).get(`/api/admin/confidential/listings?after=${cursor}`).set('x-internal-secret', SECRET).expect(404);
    await request(app).post(`/api/admin/confidential/listings?after=${cursor}`).send({}).set('x-internal-secret', SECRET).expect(400);
    await request(app).post('/api/admin/confidential/listings').type('form').send(`after=${cursor}`).set('x-internal-secret', SECRET).expect(400);
    expect(listListingWires).not.toHaveBeenCalled();
  });

  it('fails closed without leaking store errors', async () => {
    listListingWires.mockRejectedValueOnce(new Error('mongo detail with ' + owner.trust.caseId));
    const response = await list().set('x-internal-secret', SECRET).expect(503);
    expect(JSON.stringify(response.body)).not.toContain(owner.trust.caseId);
  });
});

describe('Next admin proxy', () => {
  let saved: NodeJS.ProcessEnv;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;
  const res = () => ({ status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), setHeader: jest.fn() });
  const session = (roles: string[]) => ({ user: { sub: 'auth0|admin', email: 'qa@example.org', email_verified: true,
    org_id: 'org_test', 'https://vera.app/roles': roles } });
  beforeEach(() => {
    saved = { ...process.env };
    Object.assign(process.env, { INTERNAL_API_SECRET: SECRET, BACKEND_URL: 'http://synthetic.invalid',
      ADMIN_ALLOWED_DOMAINS: '@example.org', TENANT_ORG_ID: 'org_test' });
    mockSession.mockResolvedValue(session(['admin']));
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(async (url) => String(url).endsWith('/audit-log')
      ? Response.json({ success: true })
      : Response.json({ success: true, next: hex(7), listings: [
        { caseId: hex(7), summary: 'Visible summary', narrative: 'PRIVATE', checkpoints: ['PRIVATE'] },
        { caseId: hex(8), summary: 'Described summary', category: 'crypto', region: 'north-america' },
        { caseId: hex(9), summary: 'Odd values dropped', category: 'Portland', region: 'us-west' },
        { caseId: 'not-a-case', summary: 'dropped' }], requests: ['PRIVATE'], messages: ['PRIVATE'] }));
  });
  afterEach(() => { process.env = saved; jest.restoreAllMocks(); });

  it('moderation requires admin and derives its audited actor from the session', async () => {
    const req = { method: 'POST', query: {}, body: { caseId: hex(7), hidden: true }, headers: { 'content-type': 'application/json' }, socket: {} };
    mockSession.mockResolvedValue(session(['employee']));
    const denied = res();
    await moderationProxy(req as any, denied as any);
    expect(denied.status).toHaveBeenCalledWith(403);
    expect(fetchSpy).not.toHaveBeenCalled();
    mockSession.mockResolvedValue(session(['admin']));
    const forged = res();
    await moderationProxy({ ...req, body: { ...req.body, actor: 'forged' } } as any, forged as any);
    expect(forged.status).toHaveBeenCalledWith(400);
    expect(fetchSpy).not.toHaveBeenCalled();
    const accepted = res();
    await moderationProxy(req as any, accepted as any);
    expect(accepted.status).toHaveBeenCalledWith(200);
    expect(fetchSpy.mock.calls[0][0]).toBe('http://synthetic.invalid/api/admin/confidential/listings/moderation');
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).toEqual({ ...req.body, actor: 'qa@example.org' });
    expect(accepted.json).toHaveBeenCalledWith({ success: true });
  });

  it('re-projects to caseId + summary, forwards the cursor and audit-logs without case data', async () => {
    const response = res();
    await listingsProxy({ method: 'POST', query: {}, body: { after: hex(3), limit: 25 }, headers: {}, socket: {} } as any, response as any);
    expect(response.status).toHaveBeenCalledWith(200);
    const body = response.json.mock.calls[0][0];
    expect(body).toEqual({ success: true, listings: [{ caseId: hex(7), summary: 'Visible summary' },
      { caseId: hex(8), summary: 'Described summary' },
      { caseId: hex(9), summary: 'Odd values dropped' }], next: hex(7) });
    // The case-ID cursor is forwarded in the body, never in the backend URL.
    expect(String(fetchSpy.mock.calls[0][0])).toBe('http://synthetic.invalid/api/admin/confidential/listings');
    expect(fetchSpy.mock.calls[0][1]?.method).toBe('POST');
    expect(JSON.parse(String(fetchSpy.mock.calls[0][1]?.body))).toEqual({ limit: 25, after: hex(3) });
    const audit = fetchSpy.mock.calls.find(([url]) => String(url).endsWith('/audit-log'));
    expect(audit).toBeDefined();
    const entry = JSON.parse(String(audit![1]!.body));
    expect(entry.action).toBe('confidential_listing_view');
    expect(JSON.stringify(entry)).not.toMatch(new RegExp(`${hex(3)}|${hex(7)}|Visible summary`));
  });

  it('denies employees and invalid cursors before reaching the backend', async () => {
    mockSession.mockResolvedValue(session(['employee']));
    const denied = res();
    await listingsProxy({ method: 'POST', query: {}, body: {}, headers: {}, socket: {} } as any, denied as any);
    expect(denied.status).toHaveBeenCalledWith(403);
    mockSession.mockResolvedValue(session(['admin']));
    const invalid = res();
    await listingsProxy({ method: 'POST', query: {}, body: { after: 'VERA-OWNER-1.secret' }, headers: {}, socket: {} } as any, invalid as any);
    expect(invalid.status).toHaveBeenCalledWith(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('refuses a case-ID cursor in the URL (GET or query string) before reaching the backend', async () => {
    for (const req of [{ method: 'GET', query: { after: hex(3) }, body: undefined },
      { method: 'POST', query: { after: hex(3) }, body: {} }, { method: 'POST', query: {}, body: `after=${hex(3)}` },
      { method: 'POST', query: {}, body: { limit: '25' } }]) {
      const response = res();
      await listingsProxy({ ...req, headers: {}, socket: {} } as any, response as any);
      expect(response.status).toHaveBeenCalledWith(req.method === 'GET' ? 405 : 400);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
