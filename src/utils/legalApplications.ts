import { LEGAL_TEXT_CONTROL } from './legalOnboarding';
import { parseApplicationKey } from './legalApplicationEnrollment';
import type { ApplicationKey } from './legalApplicationEnrollment';
/** Firm application data is deliberately staff-readable. Never submit a case here. */
export type LegalApplicationInput = {
  displayName: string; domain: string; email: string; lawyerName: string; jurisdiction: string; registrationNumber: string;
};
export type LegalApplicationView = LegalApplicationInput & {
  enrollment?: ApplicationKey;
  keyReviewStatus?: 'pending' | 'approved' | 'denied';
  keyReviewedBy?: string; keyReviewedAt?: number;
  id: string; createdAt: number; status: 'pending' | 'approved' | 'denied'; decidedAt?: number; decidedBy?: string;
  provisioningStatus?: 'queued' | 'retrying' | 'ready';
  providerOrganizationId?: string; organizationId?: string; provisionedAt?: number;
  provisioningError?: LegalProvisioningErrorCode;
};
export const LEGAL_PROVISIONING_ERRORS = ['provider_unavailable', 'provider_configuration', 'provider_binding', 'roster_conflict', 'invalid_application', 'lookup_limit'] as const;
export type LegalProvisioningErrorCode = typeof LEGAL_PROVISIONING_ERRORS[number];
/** Log-only source of a failure: a fixed tag or an Auth0 HTTP status. Never persisted. */
export type LegalProvisioningDetail = 'lock_wait' | 'fetch' | 'timeout' | 'token_response' | 'listing_shape' |
  'membership_pending' | 'organization_deleted' | `auth0_status_${number}`;
/** Fixed diagnostics only: never retain provider bodies, credentials or contact data. */
export class LegalProvisioningError extends Error {
  constructor(readonly code: LegalProvisioningErrorCode, readonly detail?: LegalProvisioningDetail) {
    super(`Legal provisioning unavailable: ${code}`);
  }
}
/** Intake refuses new applications while too many await review, tenant-wide or
 * for one domain. These public codes never reveal a count or another applicant. */
export const LEGAL_APPLICATION_INTAKE_CLOSED = {
  'applications-closed': 'Applications are temporarily closed. Try again later.',
  'domain-applications-pending': 'Your firm already has applications awaiting review. Try again after one is decided.',
} as const;
export type LegalApplicationIntakeClosedCode = keyof typeof LEGAL_APPLICATION_INTAKE_CLOSED;
export const legalApplicationIntakeClosedCode = (value: unknown): LegalApplicationIntakeClosedCode | null =>
  typeof value === 'string' && Object.prototype.hasOwnProperty.call(LEGAL_APPLICATION_INTAKE_CLOSED, value) ? value as LegalApplicationIntakeClosedCode : null;
export class LegalApplicationIntakeClosedError extends Error {
  constructor(readonly code: LegalApplicationIntakeClosedCode) {
    super(`Legal application intake closed: ${code}`); this.name = 'LegalApplicationIntakeClosedError';
  }
}
export const LEGAL_APPLICATION_ID = /^[a-f0-9]{64}$/;
/** Opaque per-client quota key set by the authenticated frontend proxy. */
export const LEGAL_APPLICATION_CLIENT_HEADER = 'x-vera-application-client';
export function parseLegalApplication(value: unknown): LegalApplicationInput | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  const fields = ['displayName', 'domain', 'email', 'lawyerName', 'jurisdiction', 'registrationNumber'];
  if (Object.keys(row).sort().join(',') !== fields.sort().join(',')) return null;
  const limits: Record<string, number> = { displayName: 160, domain: 253, email: 254, lawyerName: 160, jurisdiction: 120, registrationNumber: 120 };
  if (fields.some(key => typeof row[key] !== 'string' || !(row[key] as string).trim() ||
    (row[key] as string).length > limits[key] || LEGAL_TEXT_CONTROL.test(row[key] as string))) return null;
  const result = Object.fromEntries(fields.map(key => [key, (row[key] as string).trim()])) as LegalApplicationInput;
  if (result.displayName.length < 2) return null;
  result.domain = result.domain.toLowerCase();
  result.email = result.email.toLowerCase();
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(result.domain) ||
      !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$/.test(result.email) ||
      result.email.split('@')[1] !== result.domain) return null;
  return result;
}
export function projectLegalApplication(value: unknown): LegalApplicationView | null {
  if (!value || typeof value !== 'object') return null;
  const row = value as Record<string, unknown>;
  const input = parseLegalApplication(Object.fromEntries(['displayName', 'domain', 'email', 'lawyerName', 'jurisdiction', 'registrationNumber'].map(key => [key, row[key]])));
  if (!input || typeof row.id !== 'string' || !LEGAL_APPLICATION_ID.test(row.id) ||
      !Number.isSafeInteger(row.createdAt) || !['pending', 'approved', 'denied'].includes(row.status as string)) return null;
  if (row.enrollment !== undefined && (!parseApplicationKey(row.enrollment) || parseApplicationKey(row.enrollment)!.organizationId !== row.id)) return null;
  return { ...input, id: row.id, createdAt: row.createdAt as number, status: row.status as LegalApplicationView['status'],
    ...(parseApplicationKey(row.enrollment) ? { enrollment: parseApplicationKey(row.enrollment)! } : {}),
    ...(['pending', 'approved', 'denied'].includes(row.keyReviewStatus as string) ? { keyReviewStatus: row.keyReviewStatus as LegalApplicationView['keyReviewStatus'] } : {}),
    ...(typeof row.keyReviewedBy === 'string' && /^slack:T[A-Z0-9]+:U[A-Z0-9]+$/.test(row.keyReviewedBy) ? { keyReviewedBy: row.keyReviewedBy } : {}),
    ...(Number.isSafeInteger(row.keyReviewedAt) ? { keyReviewedAt: row.keyReviewedAt as number } : {}),
    ...(Number.isSafeInteger(row.decidedAt) ? { decidedAt: row.decidedAt as number } : {}),
    ...(typeof row.decidedBy === 'string' ? { decidedBy: row.decidedBy.slice(0, 254) } : {}),
    ...(row.status === 'approved' ? {
      provisioningStatus: (['queued', 'retrying', 'ready'].includes(row.provisioningStatus as string)
        ? row.provisioningStatus : 'queued') as LegalApplicationView['provisioningStatus'],
      ...(typeof row.providerOrganizationId === 'string' && /^org_[A-Za-z0-9]+$/.test(row.providerOrganizationId)
        ? { providerOrganizationId: row.providerOrganizationId } : {}),
      ...(typeof row.organizationId === 'string' && LEGAL_APPLICATION_ID.test(row.organizationId) ? { organizationId: row.organizationId } : {}),
      ...(Number.isSafeInteger(row.provisionedAt) ? { provisionedAt: row.provisionedAt as number } : {}),
      ...(LEGAL_PROVISIONING_ERRORS.includes(row.provisioningError as LegalProvisioningErrorCode)
        ? { provisioningError: row.provisioningError as LegalProvisioningErrorCode } : {}),
    } : {}) };
}

/** Bounded durable decision, safe to show in a staff-only Slack response. */
export type LegalApplicationDecision = { id: string; status: 'approved' | 'denied'; decidedBy: string; decidedAt: number; displayName?: string };
export function projectLegalApplicationDecision(value: unknown): LegalApplicationDecision | null {
  if (!value || typeof value !== 'object') return null;
  const row = value as Record<string, unknown>;
  if (typeof row.id !== 'string' || !LEGAL_APPLICATION_ID.test(row.id) ||
      (row.status !== 'approved' && row.status !== 'denied') || typeof row.decidedBy !== 'string' ||
      !row.decidedBy || row.decidedBy.length > 254 || LEGAL_TEXT_CONTROL.test(row.decidedBy) ||
      !Number.isSafeInteger(row.decidedAt) || (row.decidedAt as number) <= 0) return null;
  return { id: row.id, status: row.status, decidedBy: row.decidedBy, decidedAt: row.decidedAt as number,
    ...(typeof row.displayName === 'string' && row.displayName.length > 0 && row.displayName.length <= 160 && !LEGAL_TEXT_CONTROL.test(row.displayName)
      ? { displayName: row.displayName } : {}) };
}
