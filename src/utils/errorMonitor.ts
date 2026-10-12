import { legacyPrivateFailure, privateRequest, telemetryPath } from './requestPrivacy';
import { logger } from './logger';
interface ErrorEvent {
  id: string;
  type: 'error' | 'warning' | 'critical';
  message: string;
  stack?: string;
  context?: any;
  timestamp: Date;
  userId?: string;
  endpoint?: string;
  requestId?: string;
}

interface ErrorStats {
  total: number;
  byType: Record<string, number>;
  byEndpoint: Record<string, number>;
  recent: ErrorEvent[];
  criticalCount: number;
}

/**
 * Simple error monitoring and alerting system
 */
export class ErrorMonitor {
  private errors: ErrorEvent[] = [];
  private closing = false;
  private readonly notifications = new Set<Promise<void>>();
  private closePromise?: Promise<void>;
  private readonly maxErrors = 1000;
  private alertThresholds = {
    criticalCount: 5, // Alert after 5 critical errors in the window
    errorRatio: 0.1, // Alert if more than 10% of requests in the window logged an error
    minRequests: 20, // The ratio is only meaningful with at least this many requests in the window
    burstErrorsPerMinute: 10, // Alert on this many errors in the last minute, whatever the traffic
    timeWindow: 300000 // 5 minutes
  };
  private static readonly BURST_WINDOW = 60 * 1000;
  // Requests counted per second, oldest first; at most timeWindow / 1000 buckets.
  private requestBuckets: Array<{ second: number; count: number }> = [];

  /**
   * Log an error event
   */
  logError(
    message: string,
    type: 'error' | 'warning' | 'critical' = 'error',
    context?: any
  ): string {
    const errorId = `err_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    
    const event: ErrorEvent = {
      id: errorId,
      type,
      message,
      stack: context?.stack,
      context: this.sanitizeContext(context),
      timestamp: new Date(),
      userId: context?.userId,
      endpoint: context?.endpoint,
      requestId: context?.requestId
    };

    this.errors.push(event);
    
    // Keep only the most recent errors
    if (this.errors.length > this.maxErrors) {
      this.errors = this.errors.slice(-this.maxErrors);
    }

    // Log to console with appropriate level
    this.logToConsole(event);

    // Check for alert conditions
    this.checkAlertConditions();

    return errorId;
  }

  /**
   * Log error to console with proper formatting
   */
  private logToConsole(event: ErrorEvent): void {
    const emoji = {
      error: '❌',
      warning: '⚠️',
      critical: '🚨'
    }[event.type];

    const reqTag = event.requestId ? ` [${event.requestId}]` : '';
    const logLine = `${emoji} [${event.type.toUpperCase()}]${reqTag} ${event.message}`;
    
    if (event.type === 'critical') {
      console.error(logLine, event.context);
    } else if (event.type === 'warning') {
      console.warn(logLine, event.context);
    } else {
      console.error(logLine, event.context);
    }
  }

  /**
   * Sanitize context to remove sensitive data
   */
  private sanitizeContext(context: any): any {
    if (!context) return context;

    const sanitized = { ...context };
    
    // Remove sensitive fields
    const sensitiveFields = [
      'password', 'token', 'secret', 'key', 'auth', 'credential',
      'mnemonic', 'privateKey', 'seed'
    ];

    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }

    return sanitized;
  }

  /**
   * Check if alerts should be triggered
   */
  private checkAlertConditions(): void {
    const recentErrors = this.getRecentErrors();
    const criticalErrors = recentErrors.filter(e => e.type === 'critical');

    // Alert on critical error threshold
    if (criticalErrors.length >= this.alertThresholds.criticalCount) {
      this.triggerAlert('CRITICAL_ERROR_THRESHOLD', {
        count: criticalErrors.length,
        timeWindow: this.alertThresholds.timeWindow / 1000,
      });
    }

    // Alert on high error rate: a real error ratio once traffic gives a usable
    // sample, plus an absolute burst guard for when there is little traffic.
    const now = Date.now();
    const requests = this.recentRequestCount(now);
    const errorRatio = requests > 0 ? recentErrors.length / requests : 0;
    const ratioBreached = requests >= this.alertThresholds.minRequests
      && errorRatio > this.alertThresholds.errorRatio;
    const burstCutoff = now - ErrorMonitor.BURST_WINDOW;
    const lastMinuteErrors = recentErrors.filter(e => e.timestamp.getTime() > burstCutoff).length;
    const burstBreached = lastMinuteErrors >= this.alertThresholds.burstErrorsPerMinute;
    if (ratioBreached || burstBreached) {
      this.triggerAlert('HIGH_ERROR_RATE', {
        reason: ratioBreached ? 'ratio' : 'burst',
        errorRatio: errorRatio.toFixed(3),
        requests,
        lastMinuteErrors,
        timeWindow: this.alertThresholds.timeWindow / 1000,
        totalErrors: recentErrors.length
      });
    }
  }

  /**
   * Count one request toward the error-ratio denominator. Only a per-second
   * counter is kept, no request data.
   */
  recordRequest(now: number = Date.now()): void {
    const second = Math.floor(now / 1000);
    const last = this.requestBuckets[this.requestBuckets.length - 1];
    if (last && last.second === second) {
      last.count++;
      return;
    }
    this.requestBuckets.push({ second, count: 1 });
    this.pruneRequestBuckets(now);
  }

  private pruneRequestBuckets(now: number): void {
    const cutoff = now - this.alertThresholds.timeWindow;
    let drop = 0;
    while (drop < this.requestBuckets.length && (this.requestBuckets[drop].second + 1) * 1000 <= cutoff) drop++;
    if (drop > 0) this.requestBuckets.splice(0, drop);
  }

  private recentRequestCount(now: number): number {
    this.pruneRequestBuckets(now);
    let total = 0;
    for (const bucket of this.requestBuckets) total += bucket.count;
    return total;
  }

  /**
   * Get errors from the last time window
   */
  private getRecentErrors(): ErrorEvent[] {
    const cutoff = new Date(Date.now() - this.alertThresholds.timeWindow);
    return this.errors.filter(error => error.timestamp > cutoff);
  }

  /**
   * Trigger an alert (can be extended to send notifications)
   */
  private lastAlertAt: Record<string, number> = {};
  private static readonly ALERT_COOLDOWN = 60 * 1000; // 1 minute between same alert type

  private triggerAlert(alertType: string, data: any): void {
    if (this.closing) return;
    const now = Date.now();
    if (now - (this.lastAlertAt[alertType] || 0) < ErrorMonitor.ALERT_COOLDOWN) return;
    this.lastAlertAt[alertType] = now;

    console.error(`🚨 [ALERT] ${alertType}`, data);
    this.trackNotification(import('../services/submissionWebhook').then(({ notifyOperationalEvent }) =>
      notifyOperationalEvent('operations.error_threshold')));
    this.trackNotification(import('../services/emailNotification').then(({ emailNotificationService }) =>
      emailNotificationService.notifyErrorThreshold(data.count || data.totalErrors || 0)));
  }

  private trackNotification(operation: Promise<unknown>): void {
    const pending = operation.then(() => {}, () => {
      // Provider error text may contain request data; never reflect it here.
      logger.warn('[ERROR_MONITOR] Alert notification failed');
    }).finally(() => this.notifications.delete(pending));
    this.notifications.add(pending);
  }

  /** Stop admission and drain accepted attempts. Delivery remains best effort. */
  close(): Promise<void> {
    this.closing = true;
    return this.closePromise ??= Promise.all(this.notifications).then(() => {});
  }

  /**
   * Get error statistics
   */
  getStats(): ErrorStats {
    const recentErrors = this.getRecentErrors();
    const byType: Record<string, number> = {};
    const byEndpoint: Record<string, number> = {};

    for (const error of recentErrors) {
      byType[error.type] = (byType[error.type] || 0) + 1;
      if (error.endpoint) {
        byEndpoint[error.endpoint] = (byEndpoint[error.endpoint] || 0) + 1;
      }
    }

    return {
      total: recentErrors.length,
      byType,
      byEndpoint,
      recent: recentErrors.slice(-10), // Last 10 errors
      criticalCount: recentErrors.filter(e => e.type === 'critical').length
    };
  }

  /**
   * Get specific error by ID
   */
  getError(errorId: string): ErrorEvent | null {
    return this.errors.find(error => error.id === errorId) || null;
  }

  /**
   * Clear old errors
   */
  clearOldErrors(maxAge: number = 24 * 60 * 60 * 1000): number {
    const cutoff = new Date(Date.now() - maxAge);
    const before = this.errors.length;
    this.errors = this.errors.filter(error => error.timestamp > cutoff);
    const removed = before - this.errors.length;
    
    if (removed > 0) {
      logger.info(`🧹 [ERROR_MONITOR] Cleaned up ${removed} old error records`);
    }
    
    return removed;
  }

  /**
   * Express middleware for automatic error logging
   */
  middleware() {
    return (req: any, res: any, next: any) => {
      // Load balancer probes would dilute the error ratio, so they are not counted.
      if ((req.originalUrl || req.url || '').split('?')[0] !== '/health') this.recordRequest();

      // Add error logging to request object
      req.logError = (message: string, type: 'error' | 'warning' | 'critical' = 'error', context?: any) => {
        const sensitive = privateRequest(req.originalUrl || req.url || '');
        // Confidential/legal requests retain no per-request diagnostics. Legacy
        // failures retain only fixed route-family counts for operational alerts.
        if (sensitive) {
          const legacy = legacyPrivateFailure(req.originalUrl || req.url || '', res.statusCode);
          if (legacy) {
            const method = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(req.method)
              ? req.method : 'UNKNOWN';
            this.logError('Private request failed', type, {
              endpoint: `${method} /${legacy.routeFamily}/[redacted]`
            });
          }
          return 'private-request';
        }
        return this.logError(message, type, {
          ...context,
          userId: req.userId || req.user?.id,
          endpoint: `${req.method} ${telemetryPath(req.originalUrl || req.url || '')}`,
          requestId: req.requestId
        });
      };

      next();
    };
  }
}

// Global error monitor instance
export const errorMonitor = new ErrorMonitor();

// Housekeeping must not keep a process alive after its work finishes.
setInterval(() => {
  errorMonitor.clearOldErrors();
}, 60 * 60 * 1000).unref();

export default ErrorMonitor;