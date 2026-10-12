import type { NextApiRequest, NextApiResponse } from 'next';
import { verifySlackApplicationDecision, updateSlackApplicationDecision } from '@/src/services/legalApplicationSlack';
import { projectLegalApplicationDecision } from '@/src/utils/legalApplications';
import { legalApplicationRequest } from '@/lib/legalApplicationProxy';
export const config = { api: { bodyParser: false } };
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).end(); }
  if (String(req.headers['content-type'] || '').split(';')[0] !== 'application/x-www-form-urlencoded' || Object.keys(req.query).length) return res.status(400).end();
  const chunks: Buffer[] = []; let length = 0;
  try {
    for await (const chunk of req) { const bytes = Buffer.from(chunk); length += bytes.length; if (length > 32_768) return res.status(413).end(); chunks.push(bytes); }
  } catch { return res.status(400).end(); }
  const decision = verifySlackApplicationDecision(Buffer.concat(chunks), req.headers['x-slack-request-timestamp'], req.headers['x-slack-signature']);
  if (!decision) return res.status(403).end();
  // Combined approvals require the isolated worker's authenticated Slack
  // connection and signed journal. This web process never acts as that signer.
  if (decision.reviewDigest) return res.status(409).json({ error: 'Use the configured combined approval worker.' });
  // Acknowledge the verified interaction within Slack's three-second deadline.
  // This self-hosted Node handler still awaits bounded work after ending the
  // response; it is not a durable queue. A process interruption requires staff
  // to check the application via the authenticated admin API and retry (the
  // durable decision is immutable).
  res.status(200).end();
  const { responseUrl, ...input } = decision;
  let outcome = null;
  try {
    const result = await legalApplicationRequest('decide', input);
    if ((result.status === 200 || result.status === 409) && 'decision' in result.data) {
      const recorded = projectLegalApplicationDecision(result.data.decision);
      if (recorded?.id === input.id) outcome = recorded;
    }
  } catch { /* Never log signed payloads or response URLs. */ }
  await updateSlackApplicationDecision(responseUrl, outcome);
}
