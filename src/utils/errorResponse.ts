import { privateRequest } from './requestPrivacy';
import { Response } from 'express';
import crypto from 'node:crypto';

export interface ApiError {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    requestId?: string;
  };
}

export interface ApiSuccess<T = any> {
  success: true;
  data: T;
  timestamp: string;
  requestId?: string;
}

export class ErrorResponseUtil {
  /**
   * Send a standardized error response
   */
  static sendError(
    res: Response, 
    statusCode: number, 
    errorCode: string, 
    message: string, 
    details?: any,
    requestId?: string
  ): void {
    const response: ApiError = {
      success: false,
      error: {
        code: errorCode,
        message,
        details,
        timestamp: new Date().toISOString(),
        requestId
      }
    };

    console.error(`❌ [API_ERROR] ${statusCode} ${errorCode}: ${message}`, {
      details,
      requestId,
      timestamp: response.error.timestamp
    });

    res.status(statusCode).json(response);
  }

  /**
   * Send a standardized success response
   */
  static sendSuccess<T>(
    res: Response, 
    data: T, 
    statusCode: number = 200,
    requestId?: string
  ): void {
    const response: ApiSuccess<T> = {
      success: true,
      data,
      timestamp: new Date().toISOString(),
      requestId
    };

    res.status(statusCode).json(response);
  }

  /**
   * Handle common validation errors
   */
  static sendValidationError(
    res: Response, 
    message: string = 'Validation failed',
    details?: any,
    requestId?: string
  ): void {
    this.sendError(res, 400, 'VALIDATION_ERROR', message, details, requestId);
  }

  /**
   * Handle authentication errors
   */
  static sendAuthError(
    res: Response, 
    message: string = 'Authentication failed',
    requestId?: string
  ): void {
    this.sendError(res, 401, 'AUTH_ERROR', message, undefined, requestId);
  }

  /**
   * Handle not found errors
   */
  static sendNotFoundError(
    res: Response, 
    resource: string = 'Resource',
    requestId?: string
  ): void {
    this.sendError(res, 404, 'NOT_FOUND', `${resource} not found`, undefined, requestId);
  }

  /**
   * Handle rate limit errors
   */
  static sendRateLimitError(
    res: Response, 
    message: string = 'Rate limit exceeded',
    requestId?: string
  ): void {
    this.sendError(res, 429, 'RATE_LIMIT', message, undefined, requestId);
  }

  /**
   * Handle internal server errors
   */
  static sendInternalError(
    res: Response, 
    message: string = 'Internal server error',
    error?: Error,
    requestId?: string
  ): void {
    const details = process.env.NODE_ENV === 'development' ? {
      stack: error?.stack,
      name: error?.name
    } : undefined;

    this.sendError(res, 500, 'INTERNAL_ERROR', message, details, requestId);
  }
}

/**
 * Middleware to add request ID to all requests.
 * Uses incoming X-Request-ID header if present (from clients or load balancers),
 * otherwise generates a new one.
 */
export function addRequestId(req: any, res: any, next: any): void {
  const incoming = req.headers['x-request-id'];
  req.requestId = !privateRequest(req.originalUrl || req.url || '') && typeof incoming === 'string' && incoming.length > 0 && incoming.length <= 128 && /^[a-zA-Z0-9_-]+$/.test(incoming)
    ? incoming
    : `req_${Date.now()}_${crypto.randomBytes(5).toString('hex')}`;
  res.setHeader('X-Request-ID', req.requestId);
  next();
}

export default ErrorResponseUtil;