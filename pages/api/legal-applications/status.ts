import type { NextApiRequest, NextApiResponse } from 'next';
import { legalApplicationRequest } from '@/lib/legalApplicationProxy';
import { LEGAL_APPLICATION_ID, LEGAL_APPLICATION_CLIENT_HEADER } from '@/src/utils/legalApplications';
import { proxyClientQuotaKey } from '@/src/utils/proxyRateLimit';
export const config = { api: { bodyParser: { sizeLimit: '1kb' } } };
/** Unpredictable application ID returns only progress, never the applicant,
 * approval certificate, sign-in token, or any key material. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).end(); }
  if (String(req.headers['content-type'] || '').split(';')[0] !== 'application/json' || Object.keys(req.query).length ||
      !req.body || Object.keys(req.body).join(',') !== 'id' || typeof req.body.id !== 'string' || !LEGAL_APPLICATION_ID.test(req.body.id)) return res.status(400).end();
  let client: string;
  try { client = proxyClientQuotaKey(req); } catch { return res.status(503).end(); }
  const result = await legalApplicationRequest('status', { id: req.body.id }, { [LEGAL_APPLICATION_CLIENT_HEADER]: client });
  return res.status(result.status).json(result.data);
}
