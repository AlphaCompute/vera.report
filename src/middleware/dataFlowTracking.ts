import { privateRequest, telemetryPath } from '../utils/requestPrivacy';
import { logger } from '../utils/logger';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

export interface DataFlowAudit {
  flowId: string;
  endpoint: string;
  method: string;
  timestamp: number;
  dataType: 'vault' | 'user' | 'asset' | 'inheritance' | 'message' | 'system';
  destination: 'mongodb' | 'ipfs' | 'memory';
  status: 'start' | 'success' | 'failure' | 'error';
  metadata: {
    responseTime?: number;
    errorDetails?: string;
    dataSize?: number;
    [key: string]: any;
  };
}

interface RequestWithFlow extends Request {
  flowId?: string;
  flowStartTime?: number;
}

const dataFlowLogs: DataFlowAudit[] = [];
const MAX_LOG_SIZE = 10000; // Keep last 10k entries
// telemetryPath already caps paths at 200; this keeps every retained string bounded.
const MAX_FIELD_LENGTH = 200;
const MAX_METHOD_LENGTH = 16;

function generateFlowId(): string {
  return uuidv4();
}

function logDataFlow(audit: DataFlowAudit): void {
  dataFlowLogs.push(audit);

  // Keep logs within size limit
  if (dataFlowLogs.length > MAX_LOG_SIZE) {
    dataFlowLogs.splice(0, dataFlowLogs.length - MAX_LOG_SIZE);
  }

  // Log to console in development
  if (process.env.NODE_ENV === 'development') {
    logger.info(`[DATA_FLOW] ${audit.status.toUpperCase()}:`, {
      flowId: audit.flowId,
      endpoint: audit.endpoint,
      dataType: audit.dataType,
      destination: audit.destination,
      responseTime: audit.metadata.responseTime
    });
  }
}

export function trackDataFlow(req: RequestWithFlow, res: Response, next: NextFunction): void {
  // Even redacted per-request timestamps permit correlation with source visits.
  // Private participant traffic must not create a flow record at all.
  if (privateRequest(req.originalUrl || req.path)) { next(); return; }
  const flowId = generateFlowId();
  const startTime = Date.now();

  req.flowId = flowId;
  req.flowStartTime = startTime;

  // Determine data type based on endpoint
  const dataType = determineDataType(req.path);

  // Determine destination based on endpoint
  const destination = determineDestination(req.path);

  // Flow records carry no acting identity. This middleware runs before any
  // authentication, and this process has no per-user principal on the tracked
  // routes (Auth0 is verified by the Next proxy, which forwards only the shared
  // internal secret), so any identity here would be client-chosen (#1113).
  const sensitive = privateRequest(req.originalUrl || req.path);
  const endpoint = telemetryPath(req.originalUrl || req.path).slice(0, MAX_FIELD_LENGTH);
  const method = String(req.method).slice(0, MAX_METHOD_LENGTH);

  // Log start of flow
  const startAudit: DataFlowAudit = {
    flowId,
    endpoint,
    method,
    timestamp: startTime,
    dataType,
    destination,
    status: 'start',
    metadata: {
      ...(!sensitive && { dataSize: req.headers['content-length'] ? parseInt(req.headers['content-length']) : 0 })
    }
  };

  logDataFlow(startAudit);

  // Override res.end to capture completion
  const originalEnd = res.end.bind(res);
  res.end = function(chunk?: any, encoding?: any): Response {
    const endTime = Date.now();
    const responseTime = endTime - startTime;

    // Determine final status
    const status = res.statusCode >= 400 ? 'error' : 'success';

    // Log end of flow
    const endAudit: DataFlowAudit = {
      flowId,
      endpoint,
      method,
      timestamp: endTime,
      dataType,
      destination,
      status,
      metadata: {
        responseTime,
        statusCode: res.statusCode,
        errorDetails: status === 'error' ? `HTTP ${res.statusCode}` : undefined,
        ...(!sensitive && { responseSize: chunk ? Buffer.byteLength(chunk) : 0 })
      }
    };

    logDataFlow(endAudit);

    // Call original end method
    return originalEnd(chunk, encoding);
  };

  next();
}

function determineDataType(path: string): DataFlowAudit['dataType'] {
  if (path.includes('/vault')) return 'vault';
  if (path.includes('/inheritance')) return 'inheritance';
  if (path.includes('/user') || path.includes('/auth')) return 'user';
  if (path.includes('/message') || path.includes('/send')) return 'message';
  if (path.includes('/asset') || path.includes('/upload')) return 'asset';
  return 'system';
}

function determineDestination(path: string): DataFlowAudit['destination'] {
  if (path.includes('/upload') || path.includes('/ipfs')) return 'ipfs';
  if (path.includes('/stats') || path.includes('/analytics')) return 'memory';
  return 'mongodb'; // Default for most data operations
}

export function getDataFlowLogs(filters?: {
  dataType?: DataFlowAudit['dataType'];
  destination?: DataFlowAudit['destination'];
  status?: DataFlowAudit['status'];
  timeRange?: { start: number; end: number };
}): DataFlowAudit[] {
  let filtered = dataFlowLogs;

  if (filters) {
    if (filters.dataType) {
      filtered = filtered.filter(log => log.dataType === filters.dataType);
    }
    if (filters.destination) {
      filtered = filtered.filter(log => log.destination === filters.destination);
    }
    if (filters.status) {
      filtered = filtered.filter(log => log.status === filters.status);
    }
    if (filters.timeRange) {
      filtered = filtered.filter(log =>
        log.timestamp >= filters.timeRange!.start &&
        log.timestamp <= filters.timeRange!.end
      );
    }
  }

  return filtered.sort((a, b) => b.timestamp - a.timestamp);
}

export function getDataFlowMetrics() {
  const totalFlows = dataFlowLogs.length;
  const successCount = dataFlowLogs.filter(log => log.status === 'success').length;
  const errorCount = dataFlowLogs.filter(log => log.status === 'error').length;
  const successRate = totalFlows > 0 ? (successCount / totalFlows) * 100 : 0;

  const avgResponseTime = dataFlowLogs
    .filter(log => log.metadata.responseTime)
    .reduce((sum, log, _, arr) => sum + (log.metadata.responseTime! / arr.length), 0);

  const dataTypeBreakdown = dataFlowLogs.reduce((acc, log) => {
    acc[log.dataType] = (acc[log.dataType] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const destinationBreakdown = dataFlowLogs.reduce((acc, log) => {
    acc[log.destination] = (acc[log.destination] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return {
    totalFlows,
    successCount,
    errorCount,
    successRate,
    avgResponseTime,
    dataTypeBreakdown,
    destinationBreakdown,
    lastUpdated: Date.now()
  };
}

export function clearDataFlowLogs(): void {
  dataFlowLogs.length = 0;
}
