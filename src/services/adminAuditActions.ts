/**
 * Audit action vocabulary, kept free of any service or database dependency.
 *
 * This lives apart from adminAuditLog.ts deliberately. Tests mock that module
 * to avoid MongoDB, and a jest.mock replaces the whole module object — so an
 * action list exported from there vanishes under test while the route that
 * validates against it keeps running. The vocabulary is data, not behaviour,
 * so it belongs somewhere nothing needs to mock.
 */

export type AdminAction =
  | 'evidence_access'
  | 'contact_info_decrypt'
  | 'narrative_decrypt'
  | 'report_status_change'
  | 'report_note_add'
  | 'report_notes_view'
  | 'report_analyze'
  | 'report_list_view'
  | 'stats_view'
  | 'confidential_listing_view'
  | 'legal_application_decide'
  | 'legal_onboarding_view'
  | 'legal_organization_create'
  | 'legal_organization_revoke'
  | 'legal_invitation_revoke'
  | 'legal_member_remove'
  | 'user_invited'
  | 'user_role_changed'
  | 'user_deleted'
  | 'role_change_blocked';

export type AuditSeverity = 'critical' | 'important' | 'info';

export const SEVERITY_MAP: Record<AdminAction, AuditSeverity> = {
  evidence_access: 'critical',
  contact_info_decrypt: 'critical',
  narrative_decrypt: 'critical',
  report_status_change: 'critical',
  report_analyze: 'important',
  report_note_add: 'important',
  report_notes_view: 'info',
  report_list_view: 'info',
  stats_view: 'info',
  // Case IDs and owner-approved summaries only; no private case content exists to view.
  confidential_listing_view: 'info',
  // Legal organization roster (no case data). Registration and invitations happen in
  // the enclave under the separate onboarding identity; they are recorded in the
  // confidential onboarding audit trail, not here.
  legal_application_decide: 'important',
  legal_onboarding_view: 'info',
  legal_organization_create: 'important',
  legal_organization_revoke: 'important',
  legal_invitation_revoke: 'important',
  legal_member_remove: 'important',
  user_invited: 'important',
  user_role_changed: 'critical',
  user_deleted: 'critical',
  role_change_blocked: 'important',
};

/**
 * Every AdminAction, derived from SEVERITY_MAP rather than hand-maintained.
 * SEVERITY_MAP is Record<AdminAction, AuditSeverity>, so the compiler rejects a
 * new action that has no severity, which keeps this exhaustive by construction.
 * Three hand-written copies of this list had silently drifted apart before it
 * existed: the write path rejected the four user-management actions outright,
 * and the query path was missing two note actions.
 */
export const ADMIN_ACTIONS = Object.keys(SEVERITY_MAP) as AdminAction[];
