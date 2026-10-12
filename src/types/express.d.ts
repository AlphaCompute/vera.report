declare namespace Express {
  interface Request {
    requestId?: string;
    logError?: (
      message: string,
      type?: 'error' | 'warning' | 'critical',
      context?: Record<string, unknown>
    ) => string;
  }
}
