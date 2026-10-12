import type { NextApiRequest, NextApiResponse } from 'next';
import { confidentialListingBackend } from '../admin/confidential/listings';
import { confidentialCasesEnabled } from '@/lib/confidential/config';

export const config = { api: { bodyParser: { sizeLimit: '2kb' } } };
/** Fixed server-to-server route. The backend checks the dedicated Action secret;
 * the frontend never receives or substitutes the internal administrator secret. */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Cache-Control', 'no-store');
  if (!confidentialCasesEnabled()) return res.status(503).end();
  if (req.method !== 'POST' || Object.keys(req.query).length) return res.status(405).end();
  const credential = req.headers.authorization;
  if (typeof credential !== 'string' || credential.length > 256 || !/^Bearer [A-Za-z0-9_-]{32,200}$/.test(credential)) return res.status(401).end();
  const backend = confidentialListingBackend();
  if (!backend) return res.status(503).end();
  try {
    const upstream = await fetch(`${backend.url}/api/auth0/legal-entry`, { method: 'POST', redirect: 'error',
      headers: { 'Content-Type': 'application/json', Authorization: credential },
      body: JSON.stringify(req.body), signal: AbortSignal.timeout(17_000) });
    if (!upstream.ok) { void upstream.body?.cancel(); return res.status([400, 401, 403, 429].includes(upstream.status) ? upstream.status : 503).end(); }
    const value = await upstream.json();
    if (value?.approved !== true || typeof value.organization !== 'string' || !/^org_[A-Za-z0-9]{1,64}$/.test(value.organization)) return res.status(503).end();
    return res.json({ approved: true, organization: value.organization });
  } catch { return res.status(503).end(); }
}
