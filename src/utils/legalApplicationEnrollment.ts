import { parseLegalApplication } from './legalApplications';
import type { LegalApplicationInput, LegalApplicationView } from './legalApplications';

export type ApplicationKey = { organizationId: string; recipientKeyId: string; bindingDocument: string };
export type KeyedApplication = LegalApplicationInput & { enrollment: ApplicationKey };
const ID = /^[a-f0-9]{64}$/;
/** Backend counterpart of enclave/confidential/applicationOrganization.ts.
 * The standalone backend and measured enclave have separate build roots. */
export async function applicationOrganizationId(recipientKeyId: string): Promise<string> {
  if (typeof recipientKeyId !== 'string' || !ID.test(recipientKeyId)) throw new Error('Invalid application key');
  const bytes = new TextEncoder().encode(`vera-application-organization/v1:${recipientKeyId}`);
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('');
}
export function parseApplicationKey(value: unknown): ApplicationKey | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (Object.keys(row).sort().join(',') !== 'bindingDocument,organizationId,recipientKeyId' ||
      typeof row.organizationId !== 'string' || !ID.test(row.organizationId) ||
      typeof row.recipientKeyId !== 'string' || !ID.test(row.recipientKeyId) ||
      typeof row.bindingDocument !== 'string' || !row.bindingDocument || row.bindingDocument.length > 65536) return null;
  return { organizationId: row.organizationId, recipientKeyId: row.recipientKeyId, bindingDocument: row.bindingDocument };
}
export function parseApplicationSubmission(value: unknown): LegalApplicationInput | KeyedApplication | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const { enrollment, ...fields } = value as Record<string, unknown>;
  const application = parseLegalApplication(fields);
  if (!application) return null;
  if (!Object.prototype.hasOwnProperty.call(value, 'enrollment')) return application;
  const key = parseApplicationKey(enrollment);
  return key ? { ...application, enrollment: key } : null;
}
/** Every reviewed field and the complete self-signed public-key/profile document
 * are pinned in the Slack button. A database edit invalidates the approval. */
export async function applicationReviewDigest(application: LegalApplicationView): Promise<string> {
  const { displayName, domain, email, lawyerName, jurisdiction, registrationNumber } = application;
  const input = parseLegalApplication({ displayName, domain, email, lawyerName, jurisdiction, registrationNumber });
  const enrollment = parseApplicationKey(application.enrollment);
  if (!input || !enrollment || enrollment.organizationId !== application.id) throw new Error('Invalid combined application');
  const bytes = new TextEncoder().encode(JSON.stringify({ id: application.id, ...input, enrollment }));
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('');
}
