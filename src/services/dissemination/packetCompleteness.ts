/**
 * Internal, nonblocking packet heuristic (ALPHA-098 / #703).
 * These provisional checks are not sourced agency requirements and do not
 * establish legal sufficiency, recipient acceptance or permission to dispatch.
 * New MVP intake requires a narrative (#703). Missing narrative remains advisory
 * for previously accepted packets; checklist ownership and presentation remain open.
 */

import type { DisseminationView, PacketCompleteness, CompletenessItem, CompletenessSeverity } from './types';
import { getEntity } from './taxonomy';

function present(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === 'string') return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

/** Provisional internal subject-organization expectations, not agency rules. */
const SUBJECT_ORG_REQUIRED = new Set<string>([
  'gao-fraudnet', // which federal program / funds
  'epa-oig',      // which EPA program / office
  'sec-tcr',      // the subject entity of the Form TCR
  'cftc-tcr',
  'fincen',
  'doj',
]);

/** CISA is cyber-scoped: a cyber category drives routing and the STIX bundle. */
const CYBER_ENTITIES = new Set<string>(['cisa']);

/**
 * Apply the provisional internal checklist for `entityId`. Non-throwing and
 * side-effect-free. This grade must not gate intake or dispatch. A
 * `recommended` gap never fails `ok`; only a missing `required` item does.
 */
export function checkPacketCompleteness(view: DisseminationView, entityId: string): PacketCompleteness {
  const checklist: CompletenessItem[] = [];
  const add = (key: string, label: string, severity: CompletenessSeverity, ok: boolean) =>
    checklist.push({ key, label, severity, present: ok });

  // Internal expectation, not a dispatch gate for previously accepted files-only reports.
  add('narrative', 'Reporter narrative', 'required', present(view.narrative));
  add('categories', 'At least one concern category', 'required', present(view.categories));

  // Provisional expectation; authoritative recipient checklists remain unconfirmed.
  add(
    'subjectOrganization',
    'Subject organisation named',
    SUBJECT_ORG_REQUIRED.has(entityId) ? 'required' : 'recommended',
    present(view.subjectOrganization),
  );

  // Strongly helps every recipient, but a report can legitimately lack them.
  add('dateOfIncident', 'Date of incident', 'recommended', present(view.dateOfIncident));
  add(
    'evidence',
    'Evidence manifest entries or report digest recorded',
    'recommended',
    present(view.evidence?.files) || present(view.evidence?.evidenceHash),
  );
  add(
    'existenceProof',
    'Verified Midnight existence proof',
    'recommended',
    !!view.zkProof && view.zkProof.verified === true && view.zkProof.proofType === 'compact_circuit' &&
      present(view.zkProof.txHash) && present(view.zkProof.contractAddress),
  );

  // CISA: a cyber category makes routing + the STIX 2.1 bundle meaningful.
  if (CYBER_ENTITIES.has(entityId)) {
    add(
      'cyberCategory',
      'Cyber-security category (CISA routing / STIX)',
      'recommended',
      (view.categories ?? []).includes('cyber-security'),
    );
  }

  const missing = checklist
    .filter((i) => !i.present)
    .sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'required' ? -1 : 1));

  return {
    entityId,
    entityName: getEntity(entityId)?.name ?? entityId,
    ok: !missing.some((i) => i.severity === 'required'),
    missing,
    checklist,
  };
}
