/**
 * SES inbound → dissemination webhook relay (VERA-PDR-001 Phase 2a).
 *
 * Wired as the Lambda action on the SES receipt rule for the dissemination
 * receipt domain (after the S3 action). For each inbound message it loads
 * the raw MIME from S3, extracts the text body, and POSTs a digest to
 * POST /api/dissemination/inbound/webhook, HMAC-signed with the shared
 * webhook secret. The backend does all matching/parsing — this function
 * deliberately stays dumb so agency-specific logic lives in one place.
 *
 * Runtime: nodejs20.x, no dependencies.
 *
 * Environment:
 *   WEBHOOK_URL     e.g. https://vera.report/api/dissemination/inbound/webhook
 *   WEBHOOK_SECRET  DISSEMINATION_WEBHOOK_SECRET shared with the backend
 *   MAIL_BUCKET     S3 bucket the SES receipt rule writes raw mail to
 *   MAIL_PREFIX     key prefix of the S3 action (default "dissemination/")
 */

import crypto from 'node:crypto';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';

const s3 = new S3Client({});

const MAX_BODY_CHARS = 10_000;

export async function handler(event) {
  const results = [];
  for (const record of event.Records ?? []) {
    const mail = record.ses?.mail;
    if (!mail) continue;
    try {
      results.push(await relay(mail, record.ses.receipt));
    } catch (err) {
      // Throwing makes SES retry the whole batch; the webhook is idempotent
      // on messageId, so retries are safe and preferable to dropped mail.
      console.error(`Relay failed for ${mail.messageId}:`, err);
      throw err;
    }
  }
  return { relayed: results.length };
}

async function relay(mail, receipt) {
  const s3Key = `${process.env.MAIL_PREFIX ?? 'dissemination/'}${mail.messageId}`;
  const raw = await loadRawMessage(s3Key);

  const payload = {
    authentication: { spf: receipt?.spfVerdict?.status, dkim: receipt?.dkimVerdict?.status, dmarc: receipt?.dmarcVerdict?.status },
    recipient: mail.destination?.[0] ?? '',
    from: mail.commonHeaders?.from?.[0] ?? mail.source ?? 'unknown',
    subject: mail.commonHeaders?.subject ?? '(no subject)',
    body: extractTextBody(raw).slice(0, MAX_BODY_CHARS),
    s3Key,
    messageId: mail.messageId,
    receivedAt: mail.timestamp,
  };

  const body = JSON.stringify(payload);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = crypto
    .createHmac('sha256', process.env.WEBHOOK_SECRET)
    .update(`${timestamp}.${new URL(process.env.WEBHOOK_URL).pathname}.`).update(body)
    .digest('hex');

  const res = await fetch(process.env.WEBHOOK_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-vera-signature': signature,
      'x-vera-timestamp': timestamp,
    },
    body,
  });
  if (!res.ok) {
    throw new Error(`Webhook returned ${res.status}: ${await res.text()}`);
  }
  return mail.messageId;
}

async function loadRawMessage(key) {
  const res = await s3.send(
    new GetObjectCommand({ Bucket: process.env.MAIL_BUCKET, Key: key }),
  );
  return await res.Body.transformToString('utf8');
}

/**
 * Minimal MIME text extraction: prefer the first text/plain part; fall
 * back to the whole body with headers stripped. Good enough for agency
 * auto-acks, which are overwhelmingly plain text — anything exotic still
 * reaches the review queue with its S3 key for manual inspection.
 */
const MAX_MIME_PARTS = 256;
export const TRUNCATED_MIME_BODY =
  '[Message exceeded the MIME part limit; no text/plain part found in the scanned parts. See the S3 key for the original.]';

export function extractTextBody(raw) {
  const headerEnd = raw.indexOf('\r\n\r\n');
  const headers = headerEnd === -1 ? '' : raw.slice(0, headerEnd);
  const body = headerEnd === -1 ? raw : raw.slice(headerEnd + 4);

  const boundaryMatch = headers.match(/boundary="?([^";\r\n]+)"?/i);
  if (!boundaryMatch) return decodePart(headers, body);

  // The boundary comes from the inbound message, so a one-character value
  // against a multi-megabyte body expands into millions of array entries.
  // Cap the split; no legitimate report packet approaches this many parts.
  const parts = body.split(`--${boundaryMatch[1]}`, MAX_MIME_PARTS + 1);
  const truncated = parts.length > MAX_MIME_PARTS;
  for (const part of parts.slice(0, MAX_MIME_PARTS)) {
    const partHeaderEnd = part.indexOf('\r\n\r\n');
    if (partHeaderEnd === -1) continue;
    const partHeaders = part.slice(0, partHeaderEnd);
    if (/content-type:\s*text\/plain/i.test(partHeaders)) {
      return decodePart(partHeaders, part.slice(partHeaderEnd + 4));
    }
  }
  // Throwing would only make SES retry and then discard the event, so the
  // message would never reach review. Relay a placeholder instead of raw MIME;
  // reviewers open the original through its S3 key.
  if (truncated) return TRUNCATED_MIME_BODY;
  return decodePart(headers, body);
}

function decodePart(headers, content) {
  const trimmed = content.trim();
  if (/content-transfer-encoding:\s*base64/i.test(headers)) {
    try {
      return Buffer.from(trimmed.replace(/\s+/g, ''), 'base64').toString('utf8');
    } catch {
      return trimmed;
    }
  }
  if (/content-transfer-encoding:\s*quoted-printable/i.test(headers)) {
    return trimmed
      .replace(/=\r\n/g, '')
      .replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
  return trimmed;
}
