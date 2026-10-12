import { adminPollingHeaders } from '@/src/utils/adminPollingQuota';
import { ADMIN_ACTIONS } from '@/src/services/adminAuditActions';
import type { AdminAction, AuditSeverity, AdminAuditEntry, AuditLogFilters } from '@/src/services/adminAuditLog';

type AuditLogInput = Omit<AdminAuditEntry, 'auditId' | 'timestamp' | 'severity'> & {
  severity?: AuditSeverity;
};

type AuditQueryResult = {
  entries: AdminAuditEntry[];
  total: number;
  page: number;
  limit: number;
};

const backendUrl = (): string => process.env.BACKEND_URL || 'http://localhost:3001';
const internalSecret = (): string => process.env.INTERNAL_API_SECRET || '';

/**
 * Fire-and-forget audit log write via Express backend.
 * Never throws — catches and logs errors.
 */
export function logAuditEvent(entry: AuditLogInput): void {
  const url = `${backendUrl()}/api/admin/audit-log`;
  const secret = internalSecret();

  if (!secret) {
    console.error('[AUDIT_CLIENT] INTERNAL_API_SECRET not set — audit log will not be persisted');
    return;
  }

  let quotaHeaders: Record<string, string>;
  try {
    quotaHeaders = adminPollingHeaders(entry.adminUserId, 'POST', '/api/admin/audit-log');
  } catch {
    console.error('[AUDIT_CLIENT] Admin polling identity unavailable — audit log will not be persisted');
    return;
  }
  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-internal-secret': secret,
      ...quotaHeaders,
    },
    body: JSON.stringify(entry),
    signal: AbortSignal.timeout(5000),
  })
    .then(async (response) => {
      // A rejected write resolves the promise, so this cannot be left to .catch:
      // that only sees transport failures, and a 400 would vanish silently.
      if (!response.ok) {
        console.error(`[AUDIT_CLIENT] Audit log REJECTED (${response.status}) for action '${entry.action}' — not persisted`);
        return;
      }
      const body = await response.json().catch(() => null);
      if (body?.success !== true) {
        console.error(`[AUDIT_CLIENT] Audit log NOT ACKNOWLEDGED for action '${entry.action}' — not persisted`);
      }
    })
    .catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[AUDIT_CLIENT] Failed to send audit log: ${msg}`);
    });
}

/**
 * Query audit logs via Express backend.
 */
export async function queryAuditLogs(
  filters: AuditLogFilters = {},
): Promise<AuditQueryResult> {
  const secret = internalSecret();
  if (!secret) {
    throw new Error('INTERNAL_API_SECRET not configured');
  }

  const params = new URLSearchParams();
  if (filters.adminEmail) params.set('adminEmail', filters.adminEmail);
  if (filters.action) params.set('action', filters.action);
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.resourceId) params.set('resourceId', filters.resourceId);
  if (filters.startDate) params.set('startDate', filters.startDate.toISOString());
  if (filters.endDate) params.set('endDate', filters.endDate.toISOString());
  if (filters.page) params.set('page', String(filters.page));
  if (filters.limit) params.set('limit', String(filters.limit));

  const url = `${backendUrl()}/api/admin/audit-logs?${params.toString()}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: { 'x-internal-secret': secret },
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Audit logs query failed (${response.status}): ${text}`);
  }

  const body = await response.json();
  return body.data as AuditQueryResult;
}

export type { AdminAction, AuditSeverity };
export { ADMIN_ACTIONS };

/** Required audit receipt for report mutations and sensitive reads. */
export async function logAuditEventRequired(entry: AuditLogInput): Promise<void> {
  const secret = internalSecret();
  if (!secret) throw new Error('Audit storage not configured');
  const response = await fetch(`${backendUrl()}/api/admin/audit-log`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-internal-secret': secret, ...adminPollingHeaders(entry.adminUserId, 'POST', '/api/admin/audit-log') },
    body: JSON.stringify(entry),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error('Audit persistence failed');
  const body = await response.json();
  if (body?.success !== true) throw new Error('Audit persistence was not acknowledged');
}
