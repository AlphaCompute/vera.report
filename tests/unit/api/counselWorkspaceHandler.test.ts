import { unzipSync } from 'fflate';
import * as packetEvidence from '../../../src/services/dissemination/packetEvidence';
import { issueRecipientCapability } from '../../../src/services/dissemination/recipientCapability';
jest.mock('express-rate-limit', () => {
    const actual = jest.requireActual<typeof import('express-rate-limit')>('express-rate-limit');
    return { __esModule: true, ...actual, default: () => (_req: unknown, _res: unknown, next: () => void) => next() };
});
import { makeSecureLinkToken } from '../../../src/services/dissemination/secureLink';
jest.mock('../../../src/services/dissemination/companionPdf', () => ({ renderCompanionPdf: jest.fn().mockResolvedValue(Buffer.from('%PDF-reviewed-form')) }));
import express, { type Request } from 'express';
import { proxyRecipientRateLimitHeaders, requestRateLimitKey } from '../../../src/utils/proxyRateLimit';
import request from 'supertest';
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { sendAlert: jest.fn().mockResolvedValue(undefined) } }));
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: { uploadEncryptedFile: jest.fn() } }));
jest.mock('../../../src/services/dissemination/packetGenerator', () => ({ packetGenerator: { packetVersion: 1, generate: jest.fn().mockResolvedValue({ pdf: Buffer.from('%PDF-reviewed-packet') }) } }));
import router from '../../../src/api/dissemination';
import { disseminationPersistence as persistence } from '../../../src/services/dissemination/disseminationPersistence';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { makeWorkspaceToken, workspaceAssignmentKey } from '../../../src/services/dissemination/counselWorkspace';
import { counselService } from '../../../src/services/dissemination/counselService';
import { escrowBinding, makeEscrowToken } from '../../../src/services/dissemination/escrowRelease';
import { packetGenerator } from '../../../src/services/dissemination/packetGenerator';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { encryptSubmitterDisclosure } from '../../../src/services/submitterDisclosure';
let issueTestGrant = true;
const app = express().use(express.json()).use('/api/dissemination', async (req, _res, next) => {
  const token = req.path.split('/')[2];
  const kind = req.path.startsWith('/counsel-workspace/') ? 'workspace' : req.path.startsWith('/escrow/') ? 'escrow' : 'securelink';
  if (issueTestGrant && token) await issueRecipientCapability(token, kind).catch(() => {});
  next();
}, router);
const trackingId = 'VRA-0000000000000001';
const assignment = { counselId: 'firm-a', counselName: 'Firm A', contactHandle: 'handle', matterCode: 'M-123456' };
const consent = { psst: { granted: false }, agency: true, capturedAt: new Date(), textVersion: 'v1' };
// Secure legal packets need the reporter's legal-review consent, not agency consent (#926).
const legalConsent = { psst: { granted: false }, agency: false, legalReview: true, capturedAt: new Date(), textVersion: 'v4-legal-review' };
const useLegalReview = () => { loaded.report.consent = legalConsent; };
let sub: any; let disposition: any; let partner: any; let loaded: any;
let buildViewSpy: jest.SpyInstance;
const env = { ...process.env };
const originalFetch = global.fetch;
function token(id = trackingId, entity = 'eeoc', days = 30) { return makeWorkspaceToken(id, entity, workspaceAssignmentKey(assignment), days); }
function get(t = token(), doc = '') { return request(app).get(`/api/dissemination/counsel-workspace/${t}${doc ? '?doc=' + doc : ''}`); }
beforeEach(() => {
  jest.spyOn(packetEvidence, 'snapshotPacketEvidence').mockResolvedValue('a'.repeat(64));
  jest.spyOn(packetEvidence, 'loadPacketEvidence').mockResolvedValue([{name: 'evidence-1.csv', mimetype: 'text/csv', content: Buffer.from('synthetic')}]);
  jest.spyOn(packetEvidence, 'exportPacketArchive').mockImplementation(async (id, pdf, digest) => {
    const files = await packetEvidence.loadPacketEvidence(id, digest ?? await packetEvidence.snapshotPacketEvidence(id));
    return packetEvidence.renderPacketArchive(pdf, files);
  });
  issueTestGrant = true;
  process.env.DISSEMINATION_WEBHOOK_SECRET = 'test-only-secret';
  sub = { submissionId: 'submission-a', entityId: 'eeoc', state: 'dispatched', counsel: { ...assignment } };
  partner = { active: true, channels: ['eeoc'] };
  disposition = { channels: [{ entityId: 'eeoc', state: 'dispatched' }], consentSnapshot: consent, narrativeReviewedAt: new Date() };
  loaded = { narrativeReadable: true, report: { consent }, view: { trackingId, narrative: 'Reviewed narrative' } };
  jest.spyOn(persistence, 'getSubmissionsForReport').mockImplementation(async id => id === trackingId ? [sub] : []);
  jest.spyOn(persistence, 'getCounselPartner').mockImplementation(async () => partner);
  jest.spyOn(persistence, 'getDisposition').mockImplementation(async () => disposition);
  buildViewSpy = jest.spyOn(disseminationService, 'buildView').mockImplementation(async () => loaded);
  jest.mocked(packetGenerator.generate).mockClear();
  process.env.INTERNAL_API_SECRET = 'internal-evidence-secret';
  jest.spyOn(persistence, 'appendAudit').mockResolvedValue(undefined as never);
  jest.spyOn(reportPersistenceService, 'listEvidenceByTrackingIds').mockResolvedValue([
    { fileKey: `${trackingId}/Jane-private.pdf`, originalCID: 'encrypted-cid', encryptionKey: 'secret-key' } as any,
  ]);
  global.fetch = jest.fn().mockImplementation(async () => new Response('decrypted evidence bytes'));
});
afterEach(() => { jest.restoreAllMocks(); global.fetch = originalFetch; });
afterAll(() => { process.env = env; });
it('serves a reviewed authorized dossier with no-store', async () => {
  const res = await get(token(), 'dossier');
  expect(res.status).toBe(200); expect(res.headers['cache-control']).toBe('no-store');
  expect(packetGenerator.generate).toHaveBeenCalledWith(loaded.view, 'eeoc', { mode: 'anonymous' });
});

it('bounds all packet exports together and preserves one-time links while capacity is busy', async () => {
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  let started!: () => void;
  const ready = new Promise<void>(resolve => { started = resolve; });
  jest.mocked(packetGenerator.generate).mockImplementationOnce(async () => {
    started();
    await pending;
    return { pdf: Buffer.from('%PDF-delayed'), packetHash: 'synthetic' } as any;
  });
  const consume = jest.spyOn(persistence, 'consumeSecureLink');
  const first = get(token(), 'dossier').then(response => response);
  await ready;
  try {
    const blocked = await get(token(), 'form');
    expect(blocked.status).toBe(503);
    expect(blocked.headers['retry-after']).toBe('30');
    expect((await request(app).get(`/api/dissemination/${trackingId}/companion/eeoc`)
      .set('x-internal-secret', 'internal-evidence-secret')).status).toBe(503);
    expect((await request(app).post('/api/dissemination/secure-packet/synthetic/reveal')).status).toBe(503);
    expect(consume).not.toHaveBeenCalled();
    expect(packetGenerator.generate).toHaveBeenCalledTimes(1);
    expect((await get()).status).toBe(200);
  } finally { release(); }
  expect((await first).status).toBe(200);
  expect((await get(token(), 'dossier')).status).toBe(200);
});

it('releases packet capacity after rendering fails', async () => {
  jest.mocked(packetGenerator.generate).mockRejectedValueOnce(new Error('synthetic renderer failure'));
  expect((await get(token(), 'dossier')).status).toBe(500);
  expect((await get(token(), 'dossier')).status).toBe(200);
});

it.each(['dossier', 'form'])('refuses a %s prepared from a superseded narrative', async doc => {
  const entityId = doc === 'form' ? 'sec-tcr' : 'eeoc';
  sub.entityId = entityId;
  partner.channels = [entityId];
  disposition.channels[0].entityId = entityId;
  const before = loaded;
  const after = { ...loaded, view: { ...loaded.view, narrative: '[REPORTER] observed the incident.' } };
  buildViewSpy.mockResolvedValueOnce(before).mockResolvedValue(after);
  disposition.narrativeOverride = { narrative: after.view.narrative };
  jest.spyOn(persistence, 'getDisposition')
    .mockResolvedValueOnce({ ...disposition, narrativeOverride: undefined })
    .mockResolvedValue(disposition);
  const res = await get(token(trackingId, entityId), doc);
  expect(res.status).toBe(403);
  expect(res.headers['content-type']).not.toContain('application/zip');
});
it.each(['other-case', 'other-channel', 'tampered', 'expired'])('denies %s links', async kind => {
  const t = kind === 'other-case' ? token('VRA-0000000000000002') : kind === 'other-channel' ? token(trackingId, 'sec-tcr') : kind === 'expired' ? token(trackingId, 'eeoc', -1) : token() + 'x';
  expect((await get(t, 'dossier')).status).toBeGreaterThanOrEqual(400);
  expect(packetGenerator.generate).not.toHaveBeenCalled();
});
it.each(['different-partner', 'same-partner-new-matter', 'withdrawn', 'inactive', 'wrong-channel', 'consent-revoked', 'unreviewed', 'empty'])('denies %s before packet generation or manifest', async kind => {
  if (kind === 'different-partner') sub.counsel.counselId = 'firm-b';
  if (kind === 'same-partner-new-matter') sub.counsel.matterCode = 'M-654321';
  if (kind === 'withdrawn') sub.state = 'withdrawn';
  if (kind === 'inactive') partner.active = false;
  if (kind === 'wrong-channel') partner.channels = ['sec-tcr'];
  if (kind === 'consent-revoked') loaded.report.consent = { ...consent, agency: false };
  if (kind === 'unreviewed') delete disposition.narrativeReviewedAt;
  if (kind === 'empty') loaded.view.narrative = '';
  expect((await get(token(), 'dossier')).status).toBeGreaterThanOrEqual(400);
  expect((await get()).status).toBeGreaterThanOrEqual(400);
  expect(packetGenerator.generate).not.toHaveBeenCalled();
});
it('rejects a real narrative decryption failure rather than producing an empty dossier', async () => {
  buildViewSpy.mockRestore();
  jest.spyOn(reportPersistenceService, 'get').mockResolvedValue({ trackingId, consent, encryptedDescription: 'invalid-ciphertext' } as any);
  jest.spyOn(reportPersistenceService, 'listEvidenceByTrackingIds').mockResolvedValue([]);
  expect((await get(token(), 'dossier')).status).toBe(409);
  expect(packetGenerator.generate).not.toHaveBeenCalled();
});

it('reissues an assignment-bound link on an authenticated retry without reassigning', async () => {
  process.env.INTERNAL_API_SECRET = 'test-internal';
  jest.spyOn(counselService, 'assign').mockResolvedValue({ assignment });
  const res = await request(app).post(`/api/dissemination/${trackingId}/counsel/assign`)
    .set('x-internal-secret', 'test-internal').send({ entityId: 'eeoc', actor: 'admin', counselId: 'firm-a' });
  expect(res.status).toBe(200);
  expect(res.body.assignment).toEqual(assignment);
  const refreshed = res.body.workspaceUrl.split('/').pop();
  expect((await get(refreshed, 'dossier')).status).toBe(200);
});
it('does not turn an assignment retry into a different counsel assignment', async () => {
  process.env.INTERNAL_API_SECRET = 'test-internal';
  jest.spyOn(counselService, 'assign').mockResolvedValue({ error: 'counsel_already_assigned' });
  const res = await request(app).post(`/api/dissemination/${trackingId}/counsel/assign`)
    .set('x-internal-secret', 'test-internal').send({ entityId: 'eeoc', actor: 'admin', counselId: 'firm-b' });
  expect(res.status).toBe(409);
});

it('allows a previously accepted, explicitly reviewed files-only report with retrievable evidence', async () => {
  loaded.view.narrative = '';
  loaded.view.evidence = { files: [{ name: 'evidence-1.pdf', cid: 'QmEvidence' }] };
  expect((await get(token(), 'dossier')).status).toBe(200);
});
it('does not hide unreadable narrative behind an evidence manifest', async () => {
  loaded.narrativeReadable = false;
  loaded.view.narrative = '';
  loaded.view.evidence = { files: [{ name: 'evidence-1.pdf', cid: 'QmEvidence' }] };
  expect((await get(token(), 'dossier')).status).toBe(409);
  expect(packetGenerator.generate).not.toHaveBeenCalled();
});

for (const surface of ['counsel', 'escrow']) {
  describe(`${surface} evidence downloads`, () => {
    function url() {
      return surface === 'counsel' ? `/api/dissemination/counsel-workspace/${token()}`
        : `/api/dissemination/escrow/${makeEscrowToken(trackingId, 'eeoc', escrowBinding(sub))}`;
    }
    it('downloads the persisted file bytes with a safe name and no key disclosure', async () => {
      const manifest = await request(app).get(url());
      expect(manifest.status).toBe(200);
      const files = surface === 'counsel' ? manifest.body.matter.files : manifest.body.escrow.files;
      expect(files[0].name).toBe('evidence-1.pdf');
      expect(JSON.stringify(files)).not.toMatch(/Jane|private|secret-key|encrypted-cid/);
      const download = await request(app).get(files[0].download);
      expect(download.status).toBe(200);
      expect(download.body).toEqual(Buffer.from('decrypted evidence bytes'));
      expect(download.headers['content-disposition']).toBe('attachment; filename="evidence-1.pdf"');
      expect(download.headers['cache-control']).toBe('no-store');
      expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/Jane-private.pdf'), expect.objectContaining({
        headers: expect.objectContaining({ 'x-internal-secret': 'internal-evidence-secret' }),
      }));
      const [upstream, options] = jest.mocked(global.fetch).mock.calls[0];
      const path = new URL(String(upstream)).pathname;
      const headers = options!.headers as Record<string, string>;
      const capability = decodeURIComponent(files[0].download.split('?')[0].split('/').pop());
      expect(headers['x-vera-rate-id']).toBe(proxyRecipientRateLimitHeaders(capability, 'GET', path)['x-vera-rate-id']);
      expect(requestRateLimitKey({ headers, method: 'GET', originalUrl: path,
        ip: '127.0.0.1', socket: { remoteAddress: '127.0.0.1' } } as Request)).toBe(`web:${headers['x-vera-rate-id']}`);
      expect(Object.keys(headers).sort()).toEqual(['x-internal-secret', 'x-vera-rate-id', 'x-vera-rate-signature', 'x-vera-rate-time']);
    });
    it.each(['consent', 'withdrawn', 'reassigned'])('rejects %s changes after the link was issued', async change => {
      const link = url();
      if (change === 'consent') loaded.report.consent = { ...consent, agency: false };
      if (change === 'withdrawn') sub.state = 'withdrawn';
      if (change === 'reassigned') sub.counsel.counselId = 'firm-b';
      expect((await request(app).get(link + '?file=0')).status).toBeGreaterThanOrEqual(400);
      expect(global.fetch).not.toHaveBeenCalled();
    });
    it('rejects caller filenames and out-of-range indexes without accessing decryption', async () => {
      expect((await request(app).get(url() + '?file=Jane-private.pdf')).status).toBe(400);
      expect((await request(app).get(url() + '?file=999')).status).toBe(404);
      expect(global.fetch).not.toHaveBeenCalled();
    });
  });
}

it.each(['dossier', 'form'])('refuses %s release before generation when audit fails', async doc => {
  jest.mocked(persistence.appendAudit).mockRejectedValue(new Error('audit unavailable'));
  const response = await get(token(), doc);
  expect(response.status).toBe(500);
  expect(packetGenerator.generate).not.toHaveBeenCalled();
  expect(response.headers['content-type']).not.toContain('application/zip');
});
it('does not disclose the reporter credential in recipient filenames', async () => {
  const response = await get(token(), 'dossier');
  expect(response.headers['content-disposition']).not.toContain(trackingId);
  expect(response.headers['content-disposition']).toContain('CASE-');
});

it('audits an authorized filing form before releasing bytes', async () => {
  sub.entityId = 'sec-tcr'; partner.channels = ['sec-tcr'];
  disposition.channels = [{ entityId: 'sec-tcr', state: 'dispatched' }];
  const response = await get(token(trackingId, 'sec-tcr'), 'form');
  expect(response.status).toBe(200);
  expect(persistence.appendAudit).toHaveBeenCalledWith(expect.objectContaining({
    trackingId, entityId: 'sec-tcr', detail: { document: 'form', phase: 'attempted' },
  }));
  expect(response.headers['content-disposition']).not.toContain(trackingId);
});

for (const terminal of ['closed', 'suppressed'] as const) {
  it(`denies counsel and escrow when the disposition channel is ${terminal}`, async () => {
    disposition.channels[0].state = terminal;
    expect((await get(token(), 'dossier')).status).toBe(403);
    expect((await request(app).get(`/api/dissemination/escrow/${makeEscrowToken(trackingId, 'eeoc', escrowBinding(sub))}?file=0`)).status).toBe(403);
    expect(global.fetch).not.toHaveBeenCalled();
    expect(packetGenerator.generate).not.toHaveBeenCalled();
  });
  it(`denies a ${terminal} counsel submission even with a stale active disposition`, async () => {
    sub.state = terminal;
    expect((await get(token(), 'dossier')).status).toBe(404);
  });
}
it('denies counsel bytes after human dismissal', async () => {
  loaded.report.status = 'dismissed';
  expect((await get(token(), 'dossier')).status).toBe(403);
  expect(packetGenerator.generate).not.toHaveBeenCalled();
});

it.each(['unreviewed', 'unreadable'])('refuses a previously minted manual secure link when %s', async condition => {
  useLegalReview();
  if (condition === 'unreviewed') delete disposition.narrativeReviewedAt;
  else loaded.narrativeReadable = false;
  loaded.report.status = 'verified';
  jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  const response = await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId)}/reveal`);
  expect(response.status).toBe(409);
  expect(packetGenerator.generate).not.toHaveBeenCalled();
});


it.each(['consent', 'dismissed', 'review'])('rechecks secure-link %s after packet rendering before disclosure', async revoked => {
  useLegalReview();
  jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  jest.mocked(packetGenerator.generate).mockImplementationOnce(async () => {
    if (revoked === 'consent') loaded.report.consent = { ...legalConsent, legalReview: false };
    if (revoked === 'dismissed') loaded.report.status = 'dismissed';
    if (revoked === 'review') delete disposition.narrativeReviewedAt;
    return { pdf: Buffer.from('%PDF-private-not-authorized') } as any;
  });
  const response = await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId)}/reveal`);
  expect(response.status).toBe(revoked === 'review' ? 409 : 403);
  expect(response.headers['content-type']).not.toContain('application/zip');
  expect(response.text).not.toContain('private-not-authorized');
});
it('allows an accountless one-use recipient download with current consent and review', async () => {
  useLegalReview();
  jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  const response = await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId)}/reveal`);
  expect(response.status).toBe(200);
  expect(response.headers['content-type']).toContain('application/zip');
});

it.each(['secure-link', 'counsel'])('refuses a rendered %s packet after submitter disclosure consent changes', async surface => {
  if (surface === 'secure-link') useLegalReview();
  loaded.report.trackingId = trackingId;
  loaded.report.submitter = await encryptSubmitterDisclosure({ mode: 'identified', details: {
    name: 'Alex Example', contactMethod: 'email', contactValue: 'alex@example.invalid',
  } }, trackingId);
  const initial = structuredClone(loaded);
  const revoked = { ...initial, report: { ...initial.report, submitter: { mode: 'anonymous' } } };
  buildViewSpy.mockResolvedValueOnce(initial).mockResolvedValue(revoked);
  jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  const response = surface === 'counsel' ? await get(token(), 'dossier')
    : await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId)}/reveal`);
  expect(packetGenerator.generate).toHaveBeenCalled();
  expect(response.status).toBe(403);
  expect(response.headers['content-type']).not.toContain('application/zip');
});

it.each(['withdrawn', 'reassigned', 'partner-inactive', 'consent', 'review'])('denies a dossier when %s changes during rendering', async change => {
  jest.mocked(packetGenerator.generate).mockImplementationOnce(async () => {
    if (change === 'withdrawn') sub.state = 'withdrawn';
    if (change === 'reassigned') sub.counsel = { ...assignment, counselId: 'other-firm' };
    if (change === 'partner-inactive') partner.active = false;
    if (change === 'consent') loaded = { ...loaded, report: { ...loaded.report, consent: { ...consent, agency: false } } };
    if (change === 'review') disposition = { ...disposition, narrativeReviewedAt: undefined };
    return { pdf: Buffer.from('%PDF-sensitive-dossier') } as any;
  });
  const response = await get(token(), 'dossier');
  expect(response.status).toBe(403);
  expect(response.headers['content-type']).not.toContain('application/zip');
});

it('rejects a cryptographically valid but never-issued grant', async () => {
  issueTestGrant = false;
  expect((await get(token(), 'dossier')).status).toBe(401);
});
for (const surface of ['counsel', 'escrow']) {
  it.each(['consent', 'assignment', 'state', 'expiry'])('rechecks '+surface+' evidence after fetch: %s', async change => {
    const t = surface === 'counsel' ? token() : makeEscrowToken(trackingId, 'eeoc', escrowBinding(sub));
    global.fetch = jest.fn().mockImplementation(async () => {
      if (change === 'consent') loaded.report.consent = { ...consent, agency: false };
      if (change === 'assignment') sub.counsel.matterCode = 'changed';
      if (change === 'state') sub.state = 'withdrawn';
      if (change === 'expiry') jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 60 * 24 * 3600_000);
      return new Response('private-evidence-canary');
    });
    const path = surface === 'counsel' ? 'counsel-workspace' : 'escrow';
    const result = await request(app).get(`/api/dissemination/${path}/${t}?file=0`);
    expect(result.status).toBe(403);
    expect(result.text).not.toContain('private-evidence-canary');
  });
}

const evidenceDigest = 'a'.repeat(64);
it('exports report and attachment bytes in a no-store one-time ZIP', async () => {
  useLegalReview();
  jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  jest.spyOn(packetEvidence, 'loadPacketEvidence').mockResolvedValue([{ name: 'evidence-1.csv', mimetype: 'text/csv', content: Buffer.from('synthetic') }]);
  jest.spyOn(packetEvidence, 'snapshotPacketEvidence').mockResolvedValue(evidenceDigest);
  const response = await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId, undefined, undefined, evidenceDigest)}/reveal`).buffer(true).parse((res, done) => { const chunks: Buffer[] = []; res.on('data', chunk => chunks.push(Buffer.from(chunk))); res.on('end', () => done(null, Buffer.concat(chunks))); });
  expect(response.status).toBe(200);
  expect(response.headers['content-type']).toContain('application/zip');
  expect(response.headers['cache-control']).toBe('no-store');
  const entries = unzipSync(response.body);
  expect(Buffer.from(entries['evidence/evidence-1.csv']).toString()).toBe('synthetic');
  expect(Object.keys(entries)).toContain('report.pdf');
});
it('includes attachments for previously issued links as well', async () => {
  useLegalReview();
  jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  const load = jest.spyOn(packetEvidence, 'loadPacketEvidence');
  const response = await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId)}/reveal`);
  expect(response.status).toBe(200);
  expect(response.headers['content-type']).toContain('application/zip');
  expect(load).toHaveBeenCalled();
});
it('refuses the evidence archive when consent is revoked during preparation', async () => {
  useLegalReview();
  jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  jest.spyOn(packetEvidence, 'loadPacketEvidence').mockImplementation(async () => {
    loaded.report.consent = { ...legalConsent, legalReview: false };
    return [{ name: 'evidence-1.csv', mimetype: 'text/csv', content: Buffer.from('private-file') }];
  });
  jest.spyOn(packetEvidence, 'snapshotPacketEvidence').mockResolvedValue(evidenceDigest);
  const response = await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId, undefined, undefined, evidenceDigest)}/reveal`).buffer(true).parse((res, done) => { const chunks: Buffer[] = []; res.on('data', chunk => chunks.push(Buffer.from(chunk))); res.on('end', () => done(null, Buffer.concat(chunks))); });
  expect(response.status).toBe(403);
  expect(response.body.toString()).not.toContain('private-file');
});

it('refuses the agency filing form and evidence export without that channel consent (#926)', async () => {
  const companion = () => request(app).get(`/api/dissemination/${trackingId}/companion/sec-tcr`).set('x-internal-secret', 'internal-evidence-secret');
  loaded = { ...loaded, report: { consent: { ...consent, textVersion: 'v3-legal-review-default' } } };
  const refused = await companion();
  expect(refused.status).toBe(403);
  expect(refused.body.error).toBe('reporter_consent_missing');
  expect(packetEvidence.exportPacketArchive).not.toHaveBeenCalled();
  loaded = { ...loaded, report: { consent } };
  expect((await companion()).status).toBe(200);
});

it('does not burn a secure link when consent does not allow disclosure (#926)', async () => {
  loaded.report.consent = { ...legalConsent, legalReview: false };
  const consume = jest.spyOn(persistence, 'consumeSecureLink').mockResolvedValue(true);
  const response = await request(app).post(`/api/dissemination/secure-packet/${makeSecureLinkToken(trackingId)}/reveal`);
  expect(response.status).toBe(403);
  expect(consume).not.toHaveBeenCalled();
  expect(packetGenerator.generate).not.toHaveBeenCalled();
});
