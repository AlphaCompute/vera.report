import type { NextApiRequest, NextApiResponse } from 'next';
jest.mock('../../../pages/api/admin/confidential/listings', () => ({ confidentialListingBackend: () => ({ url: 'https://backend.example', secret: 'never-forward-this-admin-secret' }) }));
import handler from '../../../pages/api/auth0/legal-entry';
const auth = 'Bearer ' + 'synthetic'.repeat(8);
const originalMode = process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
function response() {
  const res = { setHeader: jest.fn(), status: jest.fn(), end: jest.fn(), json: jest.fn() };
  res.status.mockReturnValue(res); return res;
}
beforeEach(() => { process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '1'; });
afterEach(() => {
  jest.restoreAllMocks();
  if (originalMode === undefined) delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
  else process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = originalMode;
});
test.each(['lookup', 'complete'])('legacy mode refuses %s before forwarding an Action credential or applicant data', async operation => {
  process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0';
  const fetcher = jest.spyOn(global, 'fetch').mockResolvedValue(Response.json({ approved: true, organization: 'org_approved' }));
  const res = response();
  await handler({ method: 'POST', query: {}, headers: { authorization: auth },
    body: { operation, email: 'approved@firm.example', subject: 'email|synthetic' } } as unknown as NextApiRequest,
  res as unknown as NextApiResponse);
  expect(res.status).toHaveBeenCalledWith(503);
  expect(res.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
  expect(fetcher).not.toHaveBeenCalled();
  expect(res.json).not.toHaveBeenCalled();
  expect(res.end).toHaveBeenCalled();
});
test('the fixed proxy forwards only the Action credential and projects only the routing result', async () => {
  const fetcher = jest.spyOn(global, 'fetch').mockResolvedValue(new Response(JSON.stringify({ approved: true, organization: 'org_approved', privateField: 'omit' })));
  const res = response();
  const body = { operation: 'lookup', email: 'approved@firm.example' };
  await handler({ method: 'POST', query: {}, headers: { authorization: auth, 'x-internal-secret': 'attacker' }, body } as unknown as NextApiRequest, res as unknown as NextApiResponse);
  expect(fetcher).toHaveBeenCalledWith('https://backend.example/api/auth0/legal-entry', expect.objectContaining({ redirect: 'error',
    headers: { 'Content-Type': 'application/json', Authorization: auth }, body: JSON.stringify(body) }));
  expect(JSON.stringify(fetcher.mock.calls)).not.toContain('never-forward-this-admin-secret');
  expect(res.json).toHaveBeenCalledWith({ approved: true, organization: 'org_approved' });
});
test.each([{ method: 'GET', query: {}, headers: {} }, { method: 'POST', query: { url: 'foreign' }, headers: { authorization: auth } },
  { method: 'POST', query: {}, headers: {} }])('rejects unsupported requests before forwarding', async input => {
  const fetcher = jest.spyOn(global, 'fetch'); const res = response();
  await handler(input as unknown as NextApiRequest, res as unknown as NextApiResponse);
  expect(fetcher).not.toHaveBeenCalled(); expect(res.end).toHaveBeenCalled();
});
