import { legacyPrivateFailure, privateRequest, telemetryPath } from '../utils/requestPrivacy';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { adminPollingKey } from '../utils/adminPollingQuota';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import rateLimit, { type AugmentedRequest } from 'express-rate-limit';
import helmet from 'helmet';
import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

// Rate limiting configurations for different endpoint types
// A named limiter counts in the shared store so every API task enforces one budget.
export const createRateLimiter = (windowMs: number, max: number, message?: string, storeName?: string) => {
  return rateLimit({
    keyGenerator: requestRateLimitKey,
    ...(storeName ? { store: sharedRateLimitStore(storeName) } : {}),
    windowMs,
    max,
    handler: (req, res) => {
      const resetTime = (req as AugmentedRequest).rateLimit?.resetTime?.getTime();
      const retryAfter = Math.max(1, Math.ceil(((resetTime ?? Date.now() + windowMs) - Date.now()) / 1000));
      res.setHeader('Retry-After', retryAfter);
      res.status(429).json({
        error: message || 'Too many requests from this IP, please try again later.',
        retryAfter,
      });
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// Different rate limits for different operations
export const rateLimiters = {
  // General API requests - 100 requests per 15 minutes
  general: createRateLimiter(15 * 60 * 1000, 100, undefined, 'general'),
  // Dashboard reads plus audit writes: normally 10–16/minute per user.
  adminPolling: createRateLimiter(60 * 1000, 60, 'Too many admin requests, please try again later.', 'adminPolling'),

  // Authentication/login - 5 attempts per 15 minutes
  auth: createRateLimiter(15 * 60 * 1000, 5, 'Too many authentication attempts', 'auth'),

  // Message sending - 20 messages per minute
  messaging: createRateLimiter(60 * 1000, 20, 'Too many messages sent', 'messaging'),

  // File uploads - 10 uploads per hour
  upload: createRateLimiter(60 * 60 * 1000, 10, 'Too many file uploads', 'upload'),

  // Vault operations - 50 operations per hour
  vault: createRateLimiter(60 * 60 * 1000, 50, 'Too many vault operations', 'vault'),

  // Monitoring endpoints - 100 requests per minute (for dashboard)
  monitoring: createRateLimiter(60 * 1000, 100, undefined, 'monitoring'),

  // Public browser telemetry collector - tighter than dashboard monitoring so
  // a single IP cannot flood the BrowserErrors metric (still untrusted).
  clientTelemetry: createRateLimiter(60 * 1000, 20, 'Too many telemetry requests', 'clientTelemetry'),
};

/** These mounted endpoints have their own bounded quotas (channel600/min,
 * staging60/hour, evidence chunks 1200/hour). The general100/15min budget would otherwise make a single
 * maximum-size ranged read impossible. Unknown methods/paths stay protected. */
export function usesConfidentialRouteQuota(req: Pick<Request, 'method' | 'path'>): boolean {
  return process.env.CONFIDENTIAL_CASES_ENABLED === 'true' && req.method === 'POST' &&
    ['/api/confidential/channel/open', '/api/confidential/channel/call', '/api/confidential/objects',
      '/api/confidential/chunks'].includes(req.path);
}
export const apiRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  if (usesConfidentialRouteQuota(req)) { next(); return; }
  return (adminPollingKey(req) ? rateLimiters.adminPolling : rateLimiters.general)(req, res, next);
};

// Security headers with Helmet
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "https:"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Validation error handler
export const handleValidationErrors = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array().map(err => ({
        field: err.type === 'field' ? (err as any).path : err.type,
        message: err.msg
      }))
    });
  }
  next();
};

// Preserve evidence text exactly. Field types/lengths belong to route validators;
// HTML escaping belongs to output rendering, never to stored report content.
export const validateRequestBody = (req: Request, res: Response, next: NextFunction) => {
  const pending: Array<{ value: unknown; depth: number }> = [{ value: req.body, depth: 0 }];
  while (pending.length) {
    const { value, depth } = pending.pop()!;
    if (typeof value !== 'object' || value === null) continue;
    if (depth > 32) {
      return res.status(400).json({ success: false, error: 'Request body nesting exceeds maximum depth' });
    }
    for (const [key, child] of Object.entries(value)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        return res.status(400).json({ success: false, error: 'Invalid request body field' });
      }
      if (typeof child === 'object' && child !== null) pending.push({ value: child, depth: depth + 1 });
    }
  }
  next();
};

// Error handling middleware
export const securityErrorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  const requestId = (req as any).requestId as string | undefined;

  // Log security-related errors
  const sensitive = privateRequest(req.originalUrl || req.path);
  const legacy = sensitive ? legacyPrivateFailure(req.originalUrl || req.path, err.status) : null;
  if (legacy) console.error('[SECURITY ERROR] Private request failed', legacy);
  if (!sensitive) console.error('[SECURITY ERROR]', {
    timestamp: new Date().toISOString(),
    requestId,
    method: req.method,
    path: telemetryPath(req.originalUrl || req.path),
    error: err.message
  });

  // Don't expose internal error details in production
  const isDevelopment = !sensitive && process.env.NODE_ENV === 'development';

  res.status(err.status || 500).json({
    success: false,
    error: isDevelopment ? err.message : 'Internal server error',
    ...(isDevelopment && { stack: err.stack }),
    ...(requestId && { requestId })
  });
};

// IP whitelist for admin operations (if needed)
export const ipWhitelist = (allowedIPs: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const clientIP = req.ip || req.connection.remoteAddress || '';

    if (allowedIPs.length > 0 && !allowedIPs.includes(clientIP)) {
      return res.status(403).json({
        success: false,
        error: 'Access denied: IP not whitelisted'
      });
    }

    next();
  };
};

// Request timeout middleware.
// When applied per-route after the global middleware, it clears the
// previous (shorter) timer and replaces it with the new one.
export const requestTimeout = (timeoutMs: number = 30000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Clear any existing timeout set by a prior (global) middleware
    const prev = (res as any).__requestTimeout;
    if (prev) clearTimeout(prev);

    const timeout = setTimeout(() => {
      if (!res.headersSent) {
        res.status(408).json({
          success: false,
          error: 'Request timeout'
        });
      }
    }, timeoutMs);

    (res as any).__requestTimeout = timeout;
    res.on('finish', () => clearTimeout(timeout));
    res.on('close', () => clearTimeout(timeout));

    next();
  };
};
