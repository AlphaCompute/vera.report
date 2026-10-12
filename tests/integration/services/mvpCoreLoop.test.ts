import { unzipSync } from 'fflate';
/** Connected local acceptance: real HTTP routes, MongoDB and evidence crypto.
 * Only external proof, AI, IPFS transport and delivery workers are doubled.
 * The Next submit handler is mounted directly, without an Auth0 login session.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
const delivery = require('../../../scripts/delivery/evidence.cjs');
const metadataFixtures = require('../../../scripts/delivery/metadata-fixtures.cjs');
import {tiffFixture} from '../../helpers/tiffFixture';
import { createServer, type Server } from 'node:http';
import { spawn, type ChildProcess } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { MongoMemoryServer } from 'mongodb-memory-server';
import express from 'express';
import request from 'supertest';

const mockObjects = new Map<string, Buffer>();
jest.mock('../../../src/services/reportScoring', () => ({ verifyReport: async () => ({ isLegitimate: true, credibilityScore: 80, category: 'other', organizationType: 'company', spamIndicators: [], contentAnalysis: 'Synthetic test', riskLevel: 'low' }) }));
// The scoring transport is supplied above; allow the durable worker to use it.
// Missing real provider configuration is covered by reportScoringRecovery.
jest.mock('../../../src/services/shroudClient', () => ({ isShroudConfigured: () => true }));
jest.mock('../../../src/services/veniceAI', () => ({ veniceAIService: { isConfigured: () => false } }));
jest.mock('../../../src/services/submissionNotificationWorker', () => ({ notifySubmission: async () => {} }));
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { sendAlert: jest.fn(), notifyNewReport: jest.fn(), sendSecurePacketEmail: jest.fn() } }));
jest.mock('../../../src/services/dissemination/dispatchWorker', () => ({ dispatchWorker: { tick: async () => {} } }));
jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: {
  readCiphertext: async (cid: string) => {
    const data = mockObjects.get(cid);
    if (!data) throw new Error('Synthetic object missing');
    return data;
  },
  uploadEncryptedFile: async (bytes: Buffer, _name: string, _report: string, key: string) => {
    const crypto = require('node:crypto');
    const salt = crypto.randomBytes(16); const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', crypto.scryptSync(key, salt, 32), iv);
    const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
    const cid = crypto.createHash('sha256').update(ciphertext).digest('hex');
    mockObjects.set(cid, ciphertext);
    return { originalCID: cid, iv: iv.toString('base64'), authTag: cipher.getAuthTag().toString('base64'), salt: salt.toString('base64') };
  },
} }));
jest.mock('axios', () => ({ __esModule: true, default: { get: async (url: string) => {
  const data = mockObjects.get(url.split('/').pop()!);
  if (!data) throw new Error('Synthetic object missing');
  return { data };
} } }));
import intake from '../../../src/api/whistleblower';
import { proxyRateLimitHeaders } from '../../../src/utils/proxyRateLimit';
import legal from '../../../src/api/dissemination';
import submitProxy from '../../../pages/api/whistleblower/submit';
import { reportPersistenceService as reports } from '../../../src/services/reportPersistence';
import { disseminationPersistence as persistence } from '../../../src/services/dissemination/disseminationPersistence';
import { submissionAttemptStore } from '../../../src/services/submissionAttempt';

const narrative = 'Synthetic workplace retaliation report with documentary evidence.';
const evidence = Buffer.from('date,event\n2026-01-01,synthetic-test\n');

describe('MVP connected report-to-legal loop', () => {
  let mongo: MongoMemoryServer; let server: Server; let app: express.Express;
  let taggedFiles:Array<{name:string,mime:string,bytes:Buffer}>=[];
  const savedEnv = { ...process.env };
  const secret = 'synthetic-internal-secret-with-at-least-32-characters';
  let key = crypto.randomBytes(32).toString('hex');
  let browser: any; let recordingContext: any; let next: ChildProcess | undefined;
  const recordedVideos:Array<{video:any,name:string}>=[];
  let capturedBody: Buffer | undefined; let capturedType: string | undefined;
  const post = (url: string, body: object) => request(app).post(url).set('x-internal-secret', secret).send(body);
  const submit = () => capturedBody
    ? request(app).post('/next-submit').set('x-idempotency-key', key).set('content-type', capturedType!).send(capturedBody)
    : request(app).post('/next-submit').set('x-idempotency-key', key)
    .field('description', narrative).field('evidenceType', 'other').field('wantsReward', 'false').field('consentLegalReview', 'true')
    .attach('files', evidence, { filename: 'proof.csv', contentType: 'text/csv' })
    .attach('files',taggedFiles[0].bytes,{filename:taggedFiles[0].name,contentType:taggedFiles[0].mime})
    .attach('files',taggedFiles[1].bytes,{filename:taggedFiles[1].name,contentType:taggedFiles[1].mime})
    .attach('files',taggedFiles[2].bytes,{filename:taggedFiles[2].name,contentType:taggedFiles[2].mime})
    .attach('files',taggedFiles[3].bytes,{filename:taggedFiles[3].name,contentType:taggedFiles[3].mime});
  beforeAll(async () => {
    if(process.env.MVP_EVIDENCE_DIR)fs.mkdirSync(process.env.MVP_EVIDENCE_DIR,{recursive:true});
    taggedFiles=await metadataFixtures.create(tiffFixture());
    delivery.setWebFiles([{name:"proof.csv",mime:"text/csv",bytes:evidence},...taggedFiles]);
    mongo = await MongoMemoryServer.create();
    Object.assign(process.env, { MONGODB_URI: mongo.getUri(), MONGODB_DB_NAME: 'mvp_connected',
      WEBHOOK_URL: 'https://synthetic.invalid/webhook', WEBHOOK_SECRET: 'synthetic-webhook-secret',
      FRONTEND_TRUST_PROXY_HOPS: '0',
      INTERNAL_API_SECRET: secret, DISSEMINATION_WEBHOOK_SECRET: 'synthetic-workspace-secret',
      DISSEMINATION_MODE: 'dry-run', REWARD_ENCRYPTION_KEY: 'synthetic-reward-key' });
    app = express();
    app.use((req: any, _res, next) => { req.logError = (...args: any[]) => process.stderr.write(JSON.stringify(args) + '\n'); next(); });
    // Preserve the raw multipart stream exactly as the Next handler receives it.
    app.post('/next-submit', (req, res) => submitProxy(req as any, res as any));
    app.use('/api/whistleblower/submit', (req, _res, next) => {
      if (process.env.MVP_BROWSER_ACCEPTANCE === 'true' && !capturedBody) {
        // Observe the bytes actually received by Express. Chromium's protocol
        // postData omits uploaded file bytes, so it cannot be used for replay.
        const chunks: Buffer[] = [];
        // A data listener would start flowing before the async rate limiter
        // reaches multer. Observe emitted chunks without changing stream mode.
        const emit = req.emit;
        req.emit = function (event: string | symbol, ...args: any[]) {
          if (event === 'data') chunks.push(Buffer.from(args[0]));
          if (event === 'end') {
            capturedBody = Buffer.concat(chunks);
            capturedType = String(req.headers['content-type']);
            key = String(req.headers['x-idempotency-key']);
          }
          return emit.call(this, event, ...args);
        };
      }
      next();
    });
    app.use(express.json()); app.use('/api/whistleblower', intake); app.use('/api/dissemination', legal);
    app.use((error: Error, _req: any, res: any, _next: any) => { process.stderr.write(error.stack + '\n'); res.status(500).json({ error: error.message }); });
    server = app.listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
    const port = (server.address() as any).port;
    process.env.BACKEND_URL = `http://127.0.0.1:${port}`; process.env.PORT = String(port);
  });
  afterAll(async () => {
    await recordingContext?.close();
    for(const item of recordedVideos)fs.renameSync(await item.video.path(),path.join(process.env.MVP_EVIDENCE_DIR!,item.name));
    await browser?.close();
    delivery.write(process.env.MVP_EVIDENCE_DIR);
    if (next && next.exitCode === null) {
      next.kill('SIGTERM');
      await new Promise<void>(resolve => next!.once('exit', () => resolve()));
    }
    await reports.close(); await persistence.disconnect(); await submissionAttemptStore.close();
    if (server) await new Promise<void>(resolve => server.close(() => resolve()));
    await mongo?.stop(); process.env = savedEnv;
  });

  it('persists, recovers a receipt, decrypts evidence for counsel, records filing and revokes access', async () => {
    let accepted: { status: number; body: any };
    if (process.env.MVP_BROWSER_ACCEPTANCE === 'true') {
      // Opt-in: npm ci --prefix qa, npm run build, then set this flag for Jest.
      // Browser submission is not intercepted: Next forwards it to this real backend.
      const portProbe = createServer();
      await new Promise<void>(resolve => portProbe.listen(0, '127.0.0.1', resolve));
      const frontPort = (portProbe.address() as any).port;
      await new Promise<void>(resolve => portProbe.close(() => resolve()));
      next = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '-p', String(frontPort)], {
        cwd: process.cwd(), env: { ...process.env, NODE_ENV: 'production' }, stdio: ['ignore', 'ignore', 'pipe'],
      });
      next.stderr?.on('data', bytes => process.stderr.write(bytes));
      const front = `http://127.0.0.1:${frontPort}`;
      let ready = false;
      for (let i = 0; i < 200; i++) {
        try { if ((await fetch(front + '/report')).ok) { ready = true; break; } } catch {}
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      expect(ready).toBe(true);
      const { chromium } = createRequire(path.resolve('qa/package.json'))('@playwright/test');
      browser = await chromium.launch({ headless: true,
        ...(process.env.MVP_DISABLE_WEBGL === 'true' ? { args: ['--disable-webgl'] } : {}),
      });
      recordingContext = await browser.newContext(process.env.MVP_EVIDENCE_DIR ? {recordVideo:{dir:process.env.MVP_EVIDENCE_DIR,size:{width:1280,height:800}},viewport:{width:1280,height:800}} : {});
      const page = await recordingContext.newPage();
      // Vera's messages also exist as screen-reader copies (a live region outside
      // <main> and an sr-only span per message); match only the on-screen text.
      const shown = (text: string, exact = false) =>
        page.locator('main').getByText(text, { exact }).and(page.locator(':not(.sr-only)'));
      if(process.env.MVP_EVIDENCE_DIR)recordedVideos.push({video:page.video(),name:'web-intake.webm'});
      if(process.env.MVP_EVIDENCE_DIR) { fs.mkdirSync(process.env.MVP_EVIDENCE_DIR,{recursive:true}); fs.writeFileSync(path.join(process.env.MVP_EVIDENCE_DIR,'local-preview.json'),JSON.stringify({front,backend:process.env.BACKEND_URL})); }
      page.on('pageerror', (error: Error) => process.stderr.write(`Browser runtime error: ${error.message}\n`));
      page.setDefaultTimeout(20000);
      await page.addInitScript(() => {
        (window as any).__allowReceiptCopy = false;
        Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
          writeText: async (text: string) => {
            if (!(window as any).__allowReceiptCopy) throw new Error('Synthetic clipboard denial');
            (window as any).__copiedReceipt = text;
          },
        } });
        document.execCommand = () => false;
      });
      await page.goto(front + '/');
      // The privacy guard cancels the soft transition and replaces the document.
      // Observe that response rather than awaiting a promise in the old context.
      const reportDocument = page.waitForResponse(response => response.url() === front + '/report' &&
        response.request().isNavigationRequest());
      await page.evaluate(() => { void (window as any).next.router.push('/report').catch(() => undefined); });
      const reportResponse = await reportDocument;
      expect(reportResponse.headers()['content-security-policy']).toContain("script-src 'self' 'nonce-");
      await page.waitForURL(front + '/report');
      try {
        await page.getByRole('textbox', { name: 'Email', exact: true }).fill('synthetic-reporter@example.com');
      await page.getByRole('button', { name: 'Continue', exact: true }).click();
      } catch (error) {
        // This is a synthetic local page, before any reporter data is entered.
        process.stderr.write(`Initial report page: ${(await page.locator('body').innerText()).slice(0, 2000)}\n`);
        throw error;
      }
      await page.getByRole('button', { name: 'Cyber Security', exact: true }).click();
      await page.getByPlaceholder('Describe what happened').fill(narrative);
      await page.getByPlaceholder('Describe what happened').press('Enter');
      await shown('VERA removes supported file metadata on its servers').waitFor({ state: 'visible' });
      await shown('faces, voices, visible text, watermarks and other details inside a file can still identify you').waitFor({ state: 'visible' });
      await shown('Review and sanitize sensitive files on your device before uploading.').waitFor({ state: 'visible' });
      await page.locator('input[type=file]').setInputFiles([{ name: 'proof.csv', mimeType: 'text/csv', buffer: evidence },...taggedFiles.map(f=>({name:f.name,mimeType:f.mime,buffer:f.bytes}))]);
      await page.getByRole('button', { name: /continue/i }).click();
      await page.getByRole('button', { name: 'Low', exact: true }).click();
      await page.getByRole('button', { name: 'Ready to submit', exact: true }).click();
      // A second click during the presentation delay must not queue a stale
      // confirm transition that can race with the accepted receipt.
      await page.getByRole('button', { name: /United States/i }).evaluate(async (button: HTMLButtonElement) => {
        button.click();
        await new Promise(resolve => setTimeout(resolve, 150));
        button.click();
      });
      await shown('Review your report, then choose Submit when you are ready.', true).waitFor();
      expect(await shown('By submitting, you allow VERA administrators to share your report and evidence with trusted legal reviewers after review. Your report will not be sent automatically.', true).count()).toBe(1);
      const intakeStarted=performance.now();
      const responsePromise = page.waitForResponse((r: any) => r.url().endsWith('/api/whistleblower/submit'));
      await page.getByRole('button', { name: /Submit Report/i }).click();
      const response = await responsePromise;
      delivery.measure('intake_acknowledgment',performance.now()-intakeStarted,'web');
      expect(capturedBody?.includes(evidence)).toBe(true);
      accepted = { status: response.status(), body: await response.json() };
      if (accepted.status !== 200) process.stderr.write(JSON.stringify(accepted) + '\n');
      expect(accepted).toMatchObject({ status: 200, body: { success: true, trackingId: expect.any(String) } });
      try {
        await page.getByText(accepted.body.trackingId, { exact: true }).first().waitFor({ timeout: 45000 });
      } catch (error) {
        // This browser uses synthetic local report data and no Auth0 session.
        // Preserve the original assertion failure even if a closed page prevents capture.
        const diagnosticDir = path.resolve('test-results/mvp-receipt-failure');
        fs.mkdirSync(diagnosticDir, { recursive: true });
        const captures = await Promise.allSettled([
          page.screenshot({ path: path.join(diagnosticDir, 'page.png'), fullPage: true, timeout: 5000 }),
          page.locator('body').innerText({ timeout: 5000 }).then((body: string) => {
            fs.writeFileSync(path.join(diagnosticDir, 'page.json'), JSON.stringify({
              scope: 'Synthetic local intake; external services are doubled; no Auth0 login',
              url: page.url(),
              expectedTrackingId: accepted.body.trackingId,
              body: body.slice(0, 20000),
            }, null, 2));
          }),
        ]);
        for (const capture of captures) {
          if (capture.status === 'rejected') process.stderr.write(`Receipt diagnostic capture failed: ${String(capture.reason)}\n`);
        }
        throw error;
      }
      const modal = page.getByRole('alertdialog');
      await page.getByRole('button', { name: 'Copy submission ID', exact: true }).waitFor();
      await page.getByRole('link', { name: 'Back to Home' }).click();
      await modal.waitFor();
      expect(await modal.innerText()).toContain('Without it, you won’t be able to check your report’s status.');
      await modal.getByRole('button', { name: 'Copy ID and stay', exact: true }).click();
      await modal.getByRole('alert').waitFor();
      expect(await modal.isVisible()).toBe(true);
      await page.keyboard.press('Escape');
      await modal.waitFor({state:'hidden'});
      expect(new URL(page.url()).pathname).toBe('/report');
      // Same-document hash navigation needs no prompt. Leaving the document
      // through browser Back uses the native unsaved-receipt protection.
      await page.locator('a[href="#main-content"]').focus();
      await page.keyboard.press('Enter');
      await page.waitForURL(front + '/report#main-content');
      expect(await modal.isVisible()).toBe(false);
      await page.evaluate(() => history.back());
      await page.waitForURL(front + '/report');
      const backPrompt = page.waitForEvent('dialog');
      await page.evaluate(() => { setTimeout(() => history.back(), 0); });
      const dialog = await backPrompt;
      expect(dialog.type()).toBe('beforeunload');
      await dialog.dismiss();
      expect(new URL(page.url()).pathname).toBe('/report');
      expect(await page.getByRole('button', { name: 'Copy submission ID', exact: true }).isVisible()).toBe(true);
      // Router-driven navigation is guarded even without an anchor click.
      await page.evaluate(() => (window as any).next.router.push('/status').catch(() => {}));
      await modal.waitFor();
      await modal.getByRole('button', {name:'Stay on this page'}).click();
      expect(await page.evaluate(() => {
        const event = new Event('beforeunload', {cancelable:true});
        window.dispatchEvent(event); return event.defaultPrevented;
      })).toBe(true);
      await page.setViewportSize({width:390,height:844});
      await page.getByRole('link', {name:'Back to Home'}).click();
      await modal.waitFor();
      const bounds = await modal.boundingBox();
      expect(bounds.x).toBeGreaterThanOrEqual(0);
      expect(bounds.x + bounds.width).toBeLessThanOrEqual(391);
      if (process.env.MVP_EVIDENCE_DIR) await page.screenshot({path:path.join(process.env.MVP_EVIDENCE_DIR,'receipt-warning-mobile.png')});
      await page.evaluate(() => { (window as any).__allowReceiptCopy = true; });
      await modal.getByRole('button', {name:'Copy ID and stay',exact:true}).click();
      await modal.waitFor({state:'hidden'});
      expect(await page.evaluate(() => (window as any).__copiedReceipt)).toBe(accepted.body.trackingId);
      expect(new URL(page.url()).pathname).toBe('/report');
      expect(await page.evaluate(() => {
        const event = new Event('beforeunload', {cancelable:true});
        window.dispatchEvent(event); return event.defaultPrevented;
      })).toBe(false);
      await page.getByRole('link', {name:'Back to Home'}).click();
      await page.waitForURL(front + '/', {waitUntil:'domcontentloaded'});
      // Reuse the accepted synthetic response to exercise explicit departure
      // without creating a second report or changing the persistence assertions.
      let releaseReceipt!: () => void;
      let submissionStarted!: () => void;
      const receiptGate = new Promise<void>(resolve => { releaseReceipt = resolve; });
      const started = new Promise<void>(resolve => { submissionStarted = resolve; });
      await page.route('**/api/whistleblower/submit', async (route: any) => {
        submissionStarted();
        await receiptGate;
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(accepted.body) });
      });
      await page.goto(front + '/report');
      await page.getByRole('textbox', { name: 'Email', exact: true }).fill('synthetic-reporter@example.com');
      await page.getByRole('button', { name: 'Continue', exact: true }).click();
      await page.getByRole('button', { name: 'Cyber Security', exact: true }).click();
      await page.getByPlaceholder('Describe what happened').fill(narrative);
      await page.getByPlaceholder('Describe what happened').press('Enter');
      await page.locator('input[type=file]').setInputFiles({name:'proof.csv',mimeType:'text/csv',buffer:evidence});
      await page.getByRole('button', { name: /continue/i }).click();
      await page.getByRole('button', { name: 'Low', exact: true }).click();
      await page.getByRole('button', { name: 'Ready to submit', exact: true }).click();
      // A second click during the presentation delay must not queue a stale
      // confirm transition that can race with the accepted receipt.
      await page.getByRole('button', { name: /United States/i }).evaluate(async (button: HTMLButtonElement) => {
        button.click();
        await new Promise(resolve => setTimeout(resolve, 150));
        button.click();
      });
      await shown('Review your report, then choose Submit when you are ready.', true).waitFor();
      expect(await shown('By submitting, you allow VERA administrators to share your report and evidence with trusted legal reviewers after review. Your report will not be sent automatically.', true).count()).toBe(1);
      await page.getByRole('button', { name: /Submit Report/i }).click();
      await started;
      const receiptButton = page.getByRole('button', { name:'Copy submission ID',exact:true });
      expect(await receiptButton.isVisible()).toBe(false);
      releaseReceipt();
      // A confirmed receipt must bypass the 12–20 second simulated animation.
      await receiptButton.waitFor({ timeout: 5000 });
      await page.getByRole('link', { name:'Back to Home' }).click();
      await modal.waitFor();
      let nativePrompts = 0;
      page.on('dialog', async (dialog: any) => { nativePrompts++; await dialog.dismiss(); });
      await modal.getByRole('button', {name:'Leave without copying',exact:true}).click();
      await page.waitForURL(front + '/', {waitUntil:'domcontentloaded'});
      expect(nativePrompts).toBe(0);

    } else {
      const intakeStarted=performance.now();
      accepted = await submit();
      delivery.measure('intake_acknowledgment',performance.now()-intakeStarted,'web-http');
    }
    expect(accepted.status).toBe(200);
    const reporterCode = accepted.body.trackingId;
    expect(reporterCode).toMatch(/^VRC-[A-F0-9]{64}$/);
    const trackingId = (await reports.getForReporter(reporterCode))!.trackingId;
    expect((await request(app).get(`/api/whistleblower/status/${trackingId}`)).status).toBe(404);
    for (let i = 0; i < 100 && (await reports.get(trackingId))?.processingStatus === 'processing'; i++) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    expect((await reports.get(trackingId))?.processingStatus).toBe('completed');
    const storedRecord = await reports.get(trackingId);
    expect(storedRecord?.encryptedDescription).toBeUndefined(); // intake writes the envelope now, not the legacy field
    expect(JSON.stringify(storedRecord?.encryptedNarrative)).not.toContain(narrative); // narrative never at rest in plaintext
    expect(mockObjects.size).toBe(5);
    expect([...mockObjects.values()][0].includes(evidence)).toBe(false);

    // Close and reopen every workflow database connection; no receipt in a JS Map.
    await reports.close(); await persistence.disconnect(); await submissionAttemptStore.close();
    await mongo.stop({ doCleanup: false }); await mongo.start();
    process.env.MONGODB_URI = mongo.getUri();
    const recoveryStarted=performance.now();
    const recovered = await submit();
    delivery.measure('receipt_recovery_after_database_restart',performance.now()-recoveryStarted,'web');
    expect(recovered.status).toBe(200); expect(recovered.body.trackingId).toBe(reporterCode);
    // Proving moved off the request path in #277, so the receipt — original or
    // recovered — never depends on it. The guarantee under test is unchanged:
    // a restart recovers the same receipt without duplicating intake work.
    expect(mockObjects.size).toBe(5);
    expect((await request(app).get('/api/whistleblower/admin/reports')).status).toBe(401);
    expect((await request(app).get('/api/whistleblower/admin/reports').set('x-internal-secret', secret)).status).toBe(200);
    // Ordinary intake must reach legal handoff without a test-only consent patch.
    expect(storedRecord?.consent).toMatchObject({ agency: false, legalReview: true, psst: { granted: false }, press: false, textVersion: 'v4-legal-review' });
    expect(storedRecord?.disseminationRecipients ?? []).toEqual([]);
    const unreviewed = await post(`/api/dissemination/${trackingId}/secure-packet-generate`, { actor: 'synthetic-admin' });
    expect(unreviewed.status).toBe(409);
    expect(unreviewed.body.error).toBe('narrative_review_required');
    expect((await post(`/api/dissemination/${trackingId}/redact`, { mode: 'mark-clean', actor: 'synthetic-admin' })).status).toBe(200);
    expect(await persistence.getSubmissionsForReport(trackingId)).toEqual([]);
    // Issued before the legacy evidence row below is added, so its evidence snapshot goes stale.
    const staleLink = await post(`/api/dissemination/${trackingId}/secure-packet-generate`, { actor: 'synthetic-admin' });
    expect(staleLink.status).toBe(200);
    // Legal-review consent never authorizes a government agency channel (#926).
    const refused = await post(`/api/dissemination/${trackingId}/approve`, { entityIds: ['eeoc'], approvedBy: 'synthetic-admin' });
    expect({ status: refused.status, body: refused.body }).toMatchObject({ status: 409, body: { error: 'no_channels_approved: eeoc(reporter_consent_missing)' } });
    // Counsel matters on agency channels need consent captured by the agency question.
    await reports.patch(trackingId, { consent: { psst: { granted: false }, agency: true, press: false, capturedAt: new Date(), textVersion: 'v2' } });
    const approved = await post(`/api/dissemination/${trackingId}/approve`, { entityIds: ['eeoc'], approvedBy: 'synthetic-admin' });
    expect({ status: approved.status, body: approved.body }).toMatchObject({ status: 200, body: { success: true } });
    expect((await post(`/api/dissemination/${trackingId}/redact`, { mode: 'mark-clean', actor: 'synthetic-admin' })).status).toBe(200);
    const partner = await post('/api/dissemination/counsel', { name: 'Synthetic Counsel', contactHandle: 'synthetic@example.invalid', channels: ['eeoc'] });
    expect(partner.status).toBe(200);
    const assignment = await post(`/api/dissemination/${trackingId}/counsel/assign`, { entityId: 'eeoc', actor: 'synthetic-admin', counselId: partner.body.partner.counselId });
    expect({ status: assignment.status, body: assignment.body }).toMatchObject({ status: 200, body: { success: true } });
    const token = assignment.body.workspaceUrl.split('/').pop();
    const workspacePath = `/api/dissemination/counsel-workspace/${token}`;
    const workspace = await request(app).get(workspacePath);
    expect(workspace.status).toBe(200);
    expect(JSON.stringify(workspace.body)).not.toContain(trackingId);
    expect(token).toMatch(/^v3\./);
    const decryptStarted=performance.now();
    const file = await request(app).get(workspace.body.matter.files[0].download);
    delivery.measure('authorized_evidence_decryption',performance.now()-decryptStarted,'legal');
    expect(file.status).toBe(200); expect(file.body).toEqual(evidence);
    const metadataChecks=[];
    expect(workspace.body.matter.files).toHaveLength(5);
    for(let index=0;index<taggedFiles.length;index++) {
      const downloaded=await request(app).get(workspace.body.matter.files[index+1].download);
      expect(downloaded.status).toBe(200);
      metadataChecks.push(await metadataFixtures.verify(taggedFiles[index],downloaded.body,process.env.MVP_EVIDENCE_DIR));
    }
    if(process.env.MVP_EVIDENCE_DIR) {
      fs.writeFileSync(path.join(process.env.MVP_EVIDENCE_DIR,'metadata-checks.json'),JSON.stringify({processing:'server-side intake before encrypted storage; authorized decrypted downloads',scope:'Synthetic sentinels and visible-content checks, not complete anonymity assurance',files:metadataChecks},null,2));
      if(recordingContext) {
        const page=await recordingContext.newPage();recordedVideos.push({video:page.video(),name:'metadata-verification.webm'});
        await page.setContent('<html><body style="font:22px system-ui;padding:40px;color:#173039"><h1>Metadata verification</h1><p>Synthetic files passed through the real intake and encrypted storage. These checks inspect authorized decrypted downloads.</p><p>Processing occurs on the server. Removing metadata does not remove identifying faces, voices, visible text or context.</p><main></main></body></html>');
        for(const item of metadataChecks) {
          await page.evaluate((entry:any)=>{const row=document.createElement('p');row.textContent=entry.file+': identifying metadata present before → removed after; visible content preserved. '+entry.verifiedBy;document.querySelector('main')!.appendChild(row);},item);
          await page.waitForTimeout(1500);
        }
      }
    }

    // Legacy names can contain literal percent signs and quotes. The HTTP
    // router must decode once, return the decrypted bytes and use safe headers.
    const originalParams = await reports.getEvidenceParams(`${trackingId}/evidence-1.csv`);
    expect(originalParams).not.toBeNull();
    const legacyName = '2-proof%".csv';
    const { _id, fileKey, ...legacyParams } = originalParams as typeof originalParams & { _id?: unknown; fileKey?: string };
    await reports.saveEvidenceParams(`${trackingId}/${legacyName}`, legacyParams);
    const legacyFile = await request(app)
      .get(`/api/whistleblower/evidence/${trackingId}/${encodeURIComponent(legacyName)}`)
      .set('x-internal-secret', secret);
    expect(legacyFile.status).toBe(200);
    expect(legacyFile.text).toBe(evidence.toString());
    expect(legacyFile.headers['cache-control']).toBe('no-store');
    expect(legacyFile.headers['content-disposition']).toBe('attachment; filename="2-proof%_.csv"');
    expect(legacyFile.headers['x-content-type-options']).toBe('nosniff');
    const dossier = await request(app).get(workspacePath + '?doc=dossier').buffer(true).parse((res, done) => { const chunks: Buffer[] = []; res.on('data', chunk => chunks.push(Buffer.from(chunk))); res.on('end', () => done(null, Buffer.concat(chunks))); });
    expect(dossier.status).toBe(200);
    expect(dossier.headers['content-type']).toContain('application/zip');
    const exported = unzipSync(dossier.body);
    expect(Buffer.from(exported['report.pdf']).subarray(0,4).toString()).toBe('%PDF');
    const exportedFiles = (await request(app).get(workspacePath)).body.matter.files;
    expect(Object.keys(exported).filter(name => name.startsWith('evidence/'))).toHaveLength(exportedFiles.length);
    for (const file of exportedFiles) {
      const original = await request(app).get(file.download);
      expect(Buffer.from(exported[`evidence/${file.name}`])).toEqual(original.body);
    }
    expect(dossier.headers['content-disposition']).not.toContain(trackingId);
    expect(await persistence.getAuditForReport(trackingId)).toContainEqual(expect.objectContaining({
      event: 'escrow_accessed', detail: expect.objectContaining({ document: 'dossier' }),
    }));
    const filed = await post(`/api/dissemination/${trackingId}/counsel/attest`, { entityId: 'eeoc', value: 'SYNTHETIC-FILED-123', actor: 'synthetic-admin' });
    expect(filed.status).toBe(200);
    await persistence.disconnect(); await reports.close();
    const status = await request(app).get('/api/whistleblower/status/access').set('X-Reporter-Credential', reporterCode);
    expect(status.status).toBe(200);
    expect(status.body.dissemination).toContainEqual(expect.objectContaining({ entityId: 'eeoc', state: 'acknowledged', receipted: true }));
    expect(status.body.relay).toContainEqual(expect.objectContaining({ direction: 'to-reporter', body: expect.stringContaining(assignment.body.assignment.matterCode) }));
    // Revoking agency consent closes the counsel workspace and its evidence.
    const agencyRecord = (await reports.get(trackingId))!;
    await reports.patch(trackingId, { consent: { ...agencyRecord.consent!, agency: false } });
    expect((await request(app).get(workspacePath)).status).toBeGreaterThanOrEqual(400);
    expect((await request(app).get(workspace.body.matter.files[0].download)).status).toBeGreaterThanOrEqual(400);
    // With no remaining consent, no secure legal packet can be generated (#926);
    // restore the reporter's own intake (legal-review) consent for the packet.
    expect((await post(`/api/dissemination/${trackingId}/secure-packet-generate`, {actor:'synthetic-admin'})).status).toBe(403);
    await reports.patch(trackingId, { consent: storedRecord!.consent });
    const earlierLink = await post(`/api/dissemination/${trackingId}/secure-packet-generate`, {actor:'synthetic-admin'});
    expect(earlierLink.status).toBe(200);
    const generated = await post(`/api/dissemination/${trackingId}/secure-packet-generate`, {actor:'synthetic-admin'});
    expect(generated.status).toBe(200);
    const packetToken = generated.body.url.split('/').pop();
    const packetPath = `/api/dissemination/secure-packet/${packetToken}`;
    expect((await request(app).get(packetPath)).status).toBe(200);
    expect((await request(app).get(packetPath)).status).toBe(200); // mail scanner must not consume
    if (recordingContext) {
      const page=await recordingContext.newPage();
      if(process.env.MVP_EVIDENCE_DIR)recordedVideos.push({video:page.video(),name:'legal-packet.webm'});
      await page.goto(process.env.BACKEND_URL+packetPath);
      await page.getByRole('button').first().click();
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(1500);
    } else expect((await request(app).post(packetPath+'/reveal')).status).toBe(200);
    expect((await request(app).post(packetPath+'/reveal')).status).toBeGreaterThanOrEqual(400);
    // #625 reissue policy (docs/LOCAL-SHROUD-LEGAL-ACCEPTANCE.md): generating a
    // replacement never revokes an earlier unconsumed link, which still opens once.
    const earlierPath = `/api/dissemination/secure-packet/${earlierLink.body.url.split('/').pop()}`;
    expect((await request(app).post(earlierPath+'/reveal')).status).toBe(200);
    expect((await request(app).post(earlierPath+'/reveal')).status).toBeGreaterThanOrEqual(400);
    // Every link is bound to the evidence set it was issued for: once evidence changes,
    // an older link is refused rather than disclosing files that were never reviewed with it.
    const stalePath = `/api/dissemination/secure-packet/${staleLink.body.url.split('/').pop()}`;
    expect((await request(app).post(stalePath+'/reveal')).status).toBeGreaterThanOrEqual(400);
  }, 180000);
  it('rejects unsupported and malformed uploads rather than recording successful sanitization',async()=>{
    const outcomes=[];
    for(const specimen of [{name:'unsupported.exe',mime:'application/octet-stream',bytes:Buffer.from('synthetic invalid executable')},{name:'malformed.png',mime:'image/png',bytes:Buffer.from('synthetic malformed image')}]) {
      const storedBefore=mockObjects.size;
      const response=await request(app).post('/api/whistleblower/submit')

        .set('x-idempotency-key',crypto.randomBytes(32).toString('hex'))
        .field('description',narrative).field('evidenceType','other').field('wantsReward','false')
        .attach('files',specimen.bytes,{filename:specimen.name,contentType:specimen.mime});
      expect(response.status).toBeGreaterThanOrEqual(400);expect(response.body.success).not.toBe(true);expect(response.body.trackingId).toBeUndefined();
      expect(mockObjects.size).toBe(storedBefore);
      outcomes.push({file:specimen.name,status:response.status,accepted:false,originalFileStored:false});
    }
    if(process.env.MVP_EVIDENCE_DIR)fs.writeFileSync(path.join(process.env.MVP_EVIDENCE_DIR,'rejected-fixtures.json'),JSON.stringify(outcomes,null,2));
  });

  it('measures bounded local intake concurrency without claiming real proof or Shroud performance',async()=>{
    const samples:any[]=[];
    for(const concurrency of [1,2,4]){
      const started=performance.now();
      const results=await Promise.all(Array.from({length:concurrency},async(_,index)=>{
        const single=performance.now();
        // Model distinct web reporters through the same signed quota boundary
        // as Next. Keep both the per-client quota and upload admission enabled.
        const address=`192.0.2.${concurrency * 10 + index}`;
        const quotaHeaders=proxyRateLimitHeaders({
          headers: {},
          socket: { remoteAddress: address },
        }, 'POST', '/api/whistleblower/submit');
        const response=await request(app).post('/api/whistleblower/submit')
          .set(quotaHeaders)
          .set('x-idempotency-key',crypto.randomBytes(32).toString('hex')).field('description',narrative).field('evidenceType','cyber-security').field('jurisdiction','us').field('wantsReward','false')
          .attach('files',evidence,{filename:'synthetic.csv',contentType:'text/csv'});
        return{status:response.status,milliseconds:performance.now()-single,error:response.body?.error};
      }));
      samples.push({concurrency,totalMilliseconds:performance.now()-started,failures:results.filter(r=>r.status!==200).length,samples:results});
      if(process.env.MVP_EVIDENCE_DIR)fs.writeFileSync(path.join(process.env.MVP_EVIDENCE_DIR,'concurrency.json'),JSON.stringify(samples,null,2));
      // The single-upload budget intentionally sheds concurrent excess.
      // Record all rejected attempts rather than hiding them or disabling admission.
      expect(results.filter(r=>r.status===200).length).toBeGreaterThan(0);
      for(const result of results) {
        expect([200,503]).toContain(result.status);
        if(result.status===503)expect(result.error).toBe('upload_capacity_busy');
      }
    }
  },120000);

});
