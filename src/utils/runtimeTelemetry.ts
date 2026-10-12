import { privateRequest } from './requestPrivacy';
import { json, type RequestHandler } from 'express';

const groups = ['whistleblower', 'dissemination', 'inheritance', 'vault', 'monitoring', 'analytics'];
export function operationName(path: string, route?: unknown): string {
  const group = groups.find(value => path.startsWith(`/api/${value}/`) || path === `/api/${value}`) || 'other';
  // Express route patterns are developer-owned; never use originalUrl, query,
  // headers, request bodies or actual route parameter values in telemetry.
  return `${group}:${typeof route === 'string' && route.length <= 160 ? route : 'unmatched'}`;
}

export function emitTelemetry(event: Record<string, string | number>): void {
  console.log(JSON.stringify({ veraTelemetry: 1, ...event }));
}

export const runtimeTelemetry: RequestHandler = (req, res, next) => {
  if (privateRequest(req.path)) { next(); return; }
  const start = performance.now();
  const initialPath = req.path;
  res.once('finish', () => {
    emitTelemetry({
      source: 'backend', operation: operationName(initialPath, req.route?.path),
      method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(req.method) ? req.method : 'OTHER',
      durationMs: Math.round(performance.now() - start),
      statusClass: Math.floor(res.statusCode / 100),
    });
  });
  next();
};

const kinds = new Set(['exception', 'rejection', 'request_failure', 'page_load', 'lcp']);
const pages = new Set(['/', '/report', '/status', '/admin', '/monitoring']);
export function parseClientMetric(body: unknown): Record<string, string | number> | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const data = body as Record<string, unknown>;
  if (typeof data.kind !== 'string' || !kinds.has(data.kind)) return null;
  if (typeof data.page !== 'string' || !pages.has(data.page)) return null;
  if (typeof data.value !== 'number' || !Number.isFinite(data.value) || data.value < 0 || data.value > 300000) return null;
  // Reconstruct an allowlisted record. Client-supplied messages/stacks/URLs and
  // arbitrary keys never reach logs, including malicious telemetry submissions.
  return { source: 'browser', operation: data.page, kind: data.kind, value: Math.round(data.value) };
}

const parseJson = json({ limit: '1kb' });
export const parseClientTelemetry: RequestHandler = (req, res, next) => {
  parseJson(req, res, (error?: { status?: number }) => {
    if (error) {
      // JSON parser errors may contain raw input excerpts. Keep them away
      // from global error logging and never serialize the Error object.
      res.setHeader('Cache-Control', 'no-store');
      res.status(error.status === 413 ? 413 : 400).json({ error: 'Invalid metric payload' });
      return;
    }
    next();
  });
};

export const clientTelemetry: RequestHandler = (req, res) => {
  const event = parseClientMetric(req.body);
  res.setHeader('Cache-Control', 'no-store');
  if (!event) { res.status(400).json({ error: 'Invalid metric' }); return; }
  emitTelemetry(event);
  res.status(204).end();
};
