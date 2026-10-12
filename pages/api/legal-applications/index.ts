import type { NextApiRequest, NextApiResponse } from 'next';
import { parseApplicationSubmission } from '@/src/utils/legalApplicationEnrollment';
import { legalApplicationRequest } from '@/lib/legalApplicationProxy';
import { proxyClientQuotaKey } from '@/src/utils/proxyRateLimit';
import { LEGAL_APPLICATION_CLIENT_HEADER } from '@/src/utils/legalApplications';
export const config = { api: { bodyParser: { sizeLimit: '80kb' } } };
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).end(); }
  if (String(req.headers['content-type'] || '').split(';')[0] !== 'application/json' || Object.keys(req.query).length) return res.status(400).json({ error: 'Invalid request' });
  const input = parseApplicationSubmission(req.body);
  if (!input) return res.status(400).json({ error: 'Complete all fields using your firm email domain.' });
  // Every submission reaches the backend from this server, so forward the trusted
  // client's daily-rotated quota key; otherwise all applicants share one quota.
  let client: string;
  try { client = proxyClientQuotaKey(req); } catch { return res.status(503).json({ error: 'Applications unavailable' }); }
  const result = await legalApplicationRequest('submit', input, { [LEGAL_APPLICATION_CLIENT_HEADER]: client });
  return res.status(result.status).json(result.data);
}
