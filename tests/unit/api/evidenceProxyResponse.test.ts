import { Writable } from 'node:stream';
import type { NextApiRequest, NextApiResponse } from 'next';
jest.mock('@/lib/authMiddleware', () => ({ withRoleAuth: (_role: string, handler: Function) => (req: unknown, res: unknown) => handler(req, res, { userId: 'admin', email: 'admin@example.test' }) }));
jest.mock('@/lib/auditClient', () => ({ logAuditEventRequired: jest.fn().mockResolvedValue(undefined) }));
import handler from '../../../pages/api/whistleblower/evidence/[trackingId]/[filename]';
const originalFetch = global.fetch;
const env = { ...process.env };
const req = { method: 'GET', query: { trackingId: 'VRA-ABCD1234ABCD1234', filename: 'evidence.json' }, headers: {}, socket: {} } as unknown as NextApiRequest;
function response() {
  const chunks: Buffer[] = [];
  return Object.assign(new Writable({ write(chunk, _enc, cb) { chunks.push(Buffer.from(chunk)); cb(); } }), { chunks, status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), send: jest.fn().mockReturnThis(), setHeader: jest.fn() }) as unknown as NextApiResponse;
}
beforeEach(() => { process.env.INTERNAL_API_SECRET = 'synthetic'; });
afterEach(() => { global.fetch = originalFetch; process.env = { ...env }; });
it('does not turn a non-JSON upstream error into a successful evidence response', async () => {
  global.fetch = jest.fn().mockResolvedValue(new Response('<h1>Gateway unavailable</h1>', { status: 503, headers: { 'content-type': 'text/html' } }));
  const res = response(); await handler(req, res);
  expect(res.status).toHaveBeenCalledWith(503);
  expect(res.send).not.toHaveBeenCalled();
  expect(res.json).toHaveBeenCalledWith({ success: false, error: 'Evidence unavailable' });
});
it('preserves successful JSON evidence bytes and prevents caching', async () => {
  const bytes = '{\n  "amount": 1e3, "entries": [1, 2]\n}\n';
  global.fetch = jest.fn().mockResolvedValue(new Response(bytes, { status: 200, headers: { 'content-type': 'application/json', 'content-disposition': 'inline; filename="evidence.json"' } }));
  const res = response(); await handler(req, res);
  expect(res.status).toHaveBeenCalledWith(200);
  expect(Buffer.concat((res as any).chunks)).toEqual(Buffer.from(bytes));
  expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
  expect(res.setHeader).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff');
});
it('does not interpret untrusted HTML evidence on the administrator origin', async () => {
  global.fetch = jest.fn().mockResolvedValue(new Response('<script>window.example = true</script>', { status: 200, headers: { 'content-type': 'text/html', 'content-disposition': 'inline' } }));
  const res = response(); await handler(req, res);
  expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/octet-stream');
  expect(res.setHeader).toHaveBeenCalledWith('Content-Disposition', 'attachment; filename="evidence.json"');
  // Even if a browser rendered it, the download is a sandboxed, script-less document.
  expect(res.setHeader).toHaveBeenCalledWith('Content-Security-Policy', "sandbox; default-src 'none'; frame-ancestors 'none'");
  expect(res.setHeader).toHaveBeenCalledWith('Cross-Origin-Resource-Policy', 'same-origin');
});
it('keeps the browser viewer for inline image and PDF evidence but forbids framing', async () => {
  global.fetch = jest.fn().mockResolvedValue(new Response('%PDF-1.7', { status: 200, headers: { 'content-type': 'application/pdf' } }));
  const res = response(); await handler({ ...req, query: { ...req.query, filename: 'scan.pdf' } } as unknown as NextApiRequest, res);
  expect(res.setHeader).toHaveBeenCalledWith('Content-Disposition', 'inline; filename="scan.pdf"');
  expect(res.setHeader).toHaveBeenCalledWith('Content-Security-Policy', "frame-ancestors 'none'");
  expect(res.setHeader).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff');
});
