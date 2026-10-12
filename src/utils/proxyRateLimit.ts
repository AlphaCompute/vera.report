import { createHmac, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import type { IncomingHttpHeaders } from 'node:http';
import { ipKeyGenerator } from 'express-rate-limit';
import type { Request } from 'express';
import { adminPollingKey } from './adminPollingQuota';

type ProxyRequest = { headers: IncomingHttpHeaders; socket: { remoteAddress?: string } };
const ID_HEADER = 'x-vera-rate-id';
const TIME_HEADER = 'x-vera-rate-time';
const SIGNATURE_HEADER = 'x-vera-rate-signature';
const MAX_AGE_MS = 60_000;

function mac(secret: string, values: string[]): string {
  return createHmac('sha256', secret).update(JSON.stringify(values)).digest('hex');
}

/** Trust only the configured, ingress-enforced number of proxy hops, from the right. */
function clientAddress(req: ProxyRequest): string {
  const raw = process.env.FRONTEND_TRUST_PROXY_HOPS || '0';
  if (!/^[0-9]$/.test(raw)) throw new Error('Invalid FRONTEND_TRUST_PROXY_HOPS');
  const hops = Number(raw);
  const forwarded = req.headers['x-forwarded-for'];
  const chain = typeof forwarded === 'string' ? forwarded.split(',').map(ip => ip.trim()) : [];
  const address = hops === 0 ? req.socket.remoteAddress : chain[chain.length - hops];
  if (!address || !isIP(address)) throw new Error('Trusted client address unavailable');
  // Keep IPv6 subnet handling consistent with the backend's direct-client limits.
  return ipKeyGenerator(address);
}

/** Daily-rotated quota key for the trusted client; never expose the raw address. */
export function proxyClientQuotaKey(req: ProxyRequest): string {
  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret) throw new Error('INTERNAL_API_SECRET is required for proxy quotas');
  return mac(secret, ['vera:rate-client:v1', String(Math.floor(Date.now() / 86_400_000)), clientAddress(req)]);
}

/** Server-only quota identity: no raw IP or reusable internal credential crosses this boundary. */
export function proxyRateLimitHeaders(req: ProxyRequest, method: string, path: string): Record<string, string> {
  const id = proxyClientQuotaKey(req);
  return signedQuotaHeaders(id, method, path);
}

/** Call only after server-side administrator authorization; ignores caller-supplied identity headers.
 * This selects an ordinary transfer quota, not the privileged admin polling budget. */
export function proxyAdminRateLimitHeaders(userId: string, method: string, path: string): Record<string, string> {
  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret || !userId) throw new Error('Verified administrator and internal secret required');
  const id = mac(secret, ['vera:rate-admin:v1', String(Math.floor(Date.now() / 86_400_000)), userId]);
  return signedQuotaHeaders(id, method, path);
}

/** Call only after capability, assignment and consent verification. The capability never leaves this process. */
export function proxyRecipientRateLimitHeaders(capability: string, method: string, path: string): Record<string, string> {
  const secret = process.env.INTERNAL_API_SECRET;
  if (!secret || !capability) throw new Error('Verified recipient capability and internal secret required');
  const id = mac(secret, ['vera:rate-recipient:v1', String(Math.floor(Date.now() / 86_400_000)), capability]);
  return signedQuotaHeaders(id, method, path);
}

function signedQuotaHeaders(id: string, method: string, path: string): Record<string, string> {
  const time = String(Date.now());
  return {
    [ID_HEADER]: id,
    [TIME_HEADER]: time,
    [SIGNATURE_HEADER]: mac(process.env.INTERNAL_API_SECRET!, ['vera:rate-request:v1', method.toUpperCase(), path, time, id]),
  };
}

/** A quota signature grants no report access or internal-route authorization. */
export function requestRateLimitKey(req: Request): string {
  const adminKey = adminPollingKey(req);
  if (adminKey) return adminKey;
  const secret = process.env.INTERNAL_API_SECRET;
  const id = req.headers[ID_HEADER], time = req.headers[TIME_HEADER], signature = req.headers[SIGNATURE_HEADER];
  if (secret && typeof id === 'string' && /^[a-f0-9]{64}$/.test(id) &&
      typeof time === 'string' && /^[0-9]{13}$/.test(time) && Math.abs(Date.now() - Number(time)) <= MAX_AGE_MS &&
      typeof signature === 'string' && /^[a-f0-9]{64}$/.test(signature)) {
    const expected = mac(secret, ['vera:rate-request:v1', req.method.toUpperCase(), req.originalUrl, time, id]);
    if (timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'))) return `web:${id}`;
  }
  // Missing, expired or forged claims never select a caller-controlled quota.
  return `ip:${ipKeyGenerator(req.ip || req.socket.remoteAddress || 'unknown')}`;
}
