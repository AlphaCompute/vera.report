/**
 * Form TCR data model and portal companions (Phase 2c, VERA-PDR-001 Tier B).
 *
 * Tier B is a document-generation problem plus a human-workflow problem,
 * not an automation problem: SEC (Rule 21F-9), CFTC, and FinCEN all take
 * the same Tip/Complaint/Referral form shape, and FinCEN's rule
 * standardizes on the SEC's TCR — so ONE data model covers all three with
 * per-agency question ordering. IRS Form 211 (mail-only) reuses the same
 * facts with its own field list.
 *
 * The companion is a field-by-field answer sheet in the portal's own
 * question order, so the human filing session is copy-paste. Identity
 * fields are structurally "anonymous via counsel" — the model is built
 * from the DisseminationView, which cannot carry reporter identity.
 */

import { categoryLabel } from './taxonomy';
import type { DisseminationView } from './types';

export interface TcrModel {
  trackingId: string;
  /** Filing posture: Vera reports are always anonymous. */
  anonymousFiling: true;
  attorneyNote: string;
  categories: string[];
  natureOfComplaint: string;
  incidentDate: string;
  location: string;
  subjectOrganization: string;
  narrative: string;
  evidenceSummary: string;
  existenceProof: string;
  priorReporting: string;
}

export interface CompanionField {
  section: string;
  question: string;
  answer: string;
}

export interface PortalProfile {
  entityId: string;
  entityName: string;
  portalUrl: string;
  formName: string;
  /** Guidance shown above the field list in the filing session. */
  filingNotes: string[];
  /** Portal questions in the portal's own order, mapped to model fields. */
  questions: { section: string; question: string; field: keyof TcrModel | 'fixed'; fixed?: string }[];
}

const ATTORNEY_NOTE =
  'Anonymous filing: SEC Rule 21F-9 (and the CFTC equivalent) requires an attorney of ' +
  'record for anonymous submissions. Counsel completes the attorney certification; the ' +
  'reporter signs the hard copy retained by counsel. Vera.Report never holds reporter identity.';

export function buildTcrModel(view: DisseminationView): TcrModel {
  const files = view.evidence.files;
  const evidenceLines =
    files.length === 0
      ? ['No evidence files attached.']
      : files.map((f, i) => `${i + 1}. ${f.name}${f.cid ? ` (IPFS CID ${f.cid})` : ''}`);
  if (view.evidence.evidenceHash) {
    evidenceLines.push(`Evidence digest (SHA-256): ${view.evidence.evidenceHash}`);
  }
  evidenceLines.push(
    'Files are encrypted and pinned to IPFS; decryption is escrowed by Vera.Report and ' +
      'released on request subject to reporter consent — cite the tracking ID.',
  );

  return {
    trackingId: view.trackingId,
    anonymousFiling: true,
    attorneyNote: ATTORNEY_NOTE,
    categories: view.categories.map((c) => categoryLabel(c)),
    natureOfComplaint: view.categories.map((c) => categoryLabel(c)).join('; ') || 'See narrative',
    incidentDate: view.dateOfIncident || 'Not specified — see narrative',
    location: view.location || 'Not specified — see narrative',
    subjectOrganization:
      view.subjectOrganization ?? 'Not separately extracted — identified in the narrative below',
    narrative: view.narrative || '(Narrative withheld — request via Vera.Report citing the tracking ID.)',
    evidenceSummary: evidenceLines.join('\n'),
    existenceProof: view.zkProof
      ? `Midnight blockchain existence proof: proof hash ${view.zkProof.proofHash}` +
        (view.zkProof.txHash ? `, tx ${view.zkProof.txHash}` : '') +
        '. Establishes tamper-evident existence of this report at its stated submission time.'
      : 'No blockchain proof reference available.',
    priorReporting:
      'This matter is submitted via Vera.Report. Per agency guidance, only one method of ' +
      'transmission is used per agency (no duplicate portal/mail filings).',
  };
}

/** Shared TCR question flow (SEC ordering; CFTC/FinCEN reuse with tweaks). */
function tcrQuestions(agency: string): PortalProfile['questions'] {
  return [
    { section: 'Section A — Complainant', question: 'Complainant name / contact', field: 'fixed', fixed: 'ANONYMOUS — filed through attorney of record' },
    { section: 'Section A — Complainant', question: 'Are you submitting anonymously?', field: 'fixed', fixed: 'Yes' },
    { section: 'Section B — Attorney', question: 'Attorney information and certification', field: 'attorneyNote' },
    { section: 'Section C — Tell us about your complaint', question: 'Date of the alleged conduct', field: 'incidentDate' },
    { section: 'Section C — Tell us about your complaint', question: 'Nature of the complaint', field: 'natureOfComplaint' },
    { section: 'Section C — Tell us about your complaint', question: 'Location of the conduct', field: 'location' },
    { section: 'Section D — Subject', question: 'Individual or entity the complaint concerns', field: 'subjectOrganization' },
    { section: 'Section E — Details', question: 'Describe the facts of your complaint', field: 'narrative' },
    { section: 'Section E — Details', question: 'Describe supporting materials / evidence', field: 'evidenceSummary' },
    { section: 'Section E — Details', question: 'Existence / timestamp verification', field: 'existenceProof' },
    { section: 'Section F — Prior action', question: `Have you reported this to ${agency} or another authority before?`, field: 'priorReporting' },
    { section: 'Section G — Declaration', question: 'Declaration under penalty of perjury', field: 'fixed', fixed: 'Executed by counsel per the anonymous-filing rule; reporter-signed original retained by counsel.' },
  ];
}

export const PORTAL_PROFILES: Record<string, PortalProfile> = {
  'sec-tcr': {
    entityId: 'sec-tcr',
    entityName: 'SEC Office of the Whistleblower (Form TCR)',
    portalUrl: 'https://www.sec.gov/tcr',
    formName: 'SEC Form TCR',
    filingNotes: [
      'The SEC portal issues an immediate acknowledgment with a TCR confirmation number — record it as this channel\'s receipt.',
      'Anonymous filing requires an attorney of record (Rule 21F-9); route through the Tier C counsel flow.',
      'Use only ONE method of transmission — do not also mail or fax this TCR.',
    ],
    questions: tcrQuestions('the SEC'),
  },
  'cftc-tcr': {
    entityId: 'cftc-tcr',
    entityName: 'CFTC Whistleblower Office (Form TCR)',
    portalUrl: 'https://www.whistleblower.gov/overview/submitatip',
    formName: 'CFTC Form TCR',
    filingNotes: [
      'The CFTC portal mirrors the SEC TCR structure; the confirmation number is the receipt.',
      'Anonymous filing requires an attorney of record; route through the Tier C counsel flow.',
    ],
    questions: tcrQuestions('the CFTC'),
  },
  fincen: {
    entityId: 'fincen',
    entityName: 'FinCEN Office of the Whistleblower',
    portalUrl: 'https://www.fincen.gov/contact',
    formName: 'FinCEN whistleblower submission (TCR form type)',
    filingNotes: [
      'FinCEN confirms receipt of each submission and sends a reference number — record it as this channel\'s receipt.',
      'FinCEN\'s proposed rule standardizes on the SEC TCR form type; the same answers apply.',
    ],
    questions: tcrQuestions('FinCEN'),
  },
  // ── US registry breadth (PDR completion) ──────────────────────────
  'fbi-ic3': {
    entityId: 'fbi-ic3',
    entityName: 'FBI Internet Crime Complaint Center (IC3)',
    portalUrl: 'https://complaint.ic3.gov/',
    formName: 'IC3 complaint',
    filingNotes: [
      'IC3 asks for complainant contact details and does not offer a formal anonymous track — file as Vera.Report (transmitter on the reporter\'s instruction), not as the victim.',
      'On submission IC3 shows a complaint ID — record it as this channel\'s receipt. IC3 sends no further acknowledgment.',
      'Scope: internet-facilitated crime (BEC, ransomware, fraud, data breaches with a cyber nexus).',
    ],
    questions: [
      { section: 'Complainant', question: 'Complainant name / contact', field: 'fixed', fixed: 'Vera.Report (transmitting on behalf of an anonymous reporter, with consent)' },
      { section: 'Incident', question: 'Describe the incident', field: 'narrative' },
      { section: 'Incident', question: 'When did the incident occur?', field: 'incidentDate' },
      { section: 'Incident', question: 'Where did it occur?', field: 'location' },
      { section: 'Subject', question: 'Subject (person/organization) information', field: 'subjectOrganization' },
      { section: 'Supporting information', question: 'Describe supporting evidence', field: 'evidenceSummary' },
      { section: 'Supporting information', question: 'Existence / timestamp verification', field: 'existenceProof' },
      { section: 'Prior action', question: 'Reported elsewhere?', field: 'priorReporting' },
    ],
  },
  'epa-violation': {
    entityId: 'epa-violation',
    entityName: 'EPA Violation Reporting',
    portalUrl: 'https://echo.epa.gov/report-environmental-violations',
    formName: 'EPA "Report an Environmental Violation" form',
    filingNotes: [
      'The EPA violation form explicitly allows anonymous reporting — leave contact fields blank.',
      'No confirmation number is issued; record the filing date/time as a manual receipt.',
      'For matters implicating EPA employees or programs themselves, prefer the EPA OIG channel (Tier A email).',
    ],
    questions: [
      { section: 'Reporter', question: 'Your contact information (optional)', field: 'fixed', fixed: 'Left blank — anonymous report transmitted by Vera.Report with reporter consent' },
      { section: 'Violation', question: 'Describe the suspected violation', field: 'narrative' },
      { section: 'Violation', question: 'When did you observe it?', field: 'incidentDate' },
      { section: 'Violation', question: 'Location (facility, city, state)', field: 'location' },
      { section: 'Violation', question: 'Who is responsible (company / facility)?', field: 'subjectOrganization' },
      { section: 'Evidence', question: 'Supporting evidence', field: 'evidenceSummary' },
      { section: 'Evidence', question: 'Existence / timestamp verification', field: 'existenceProof' },
    ],
  },
  ftc: {
    entityId: 'ftc',
    entityName: 'Federal Trade Commission',
    portalUrl: 'https://reportfraud.ftc.gov/',
    formName: 'ReportFraud.ftc.gov report',
    filingNotes: [
      'ReportFraud accepts reports without verified identity; skip contact fields where the flow allows.',
      'The flow ends with a report number — record it as this channel\'s receipt.',
      'Scope: unfair or deceptive practices, fraud, privacy/data-security failures, dark patterns (incl. AI/trust-safety claims).',
    ],
    questions: [
      { section: 'What happened', question: 'Describe what happened', field: 'narrative' },
      { section: 'What happened', question: 'When did it start / occur?', field: 'incidentDate' },
      { section: 'Company', question: 'Company or person the report concerns', field: 'subjectOrganization' },
      { section: 'Company', question: 'Where did this happen?', field: 'location' },
      { section: 'Details', question: 'Supporting evidence', field: 'evidenceSummary' },
      { section: 'Details', question: 'Existence / timestamp verification', field: 'existenceProof' },
      { section: 'About you', question: 'Your information', field: 'fixed', fixed: 'Anonymous — transmitted by Vera.Report on the reporter\'s instruction' },
    ],
  },
  doj: {
    entityId: 'doj',
    entityName: 'Department of Justice',
    portalUrl: 'https://www.justice.gov/actioncenter/submit-complaint',
    formName: 'DOJ complaint intake (component-specific)',
    filingNotes: [
      'DOJ intake is component-specific — the submit-complaint hub routes to the right division (Fraud Section, Civil Rights, Antitrust, etc.). Pick the component matching the categories below.',
      'Most DOJ web intakes issue no confirmation number; record the component and filing date as a manual receipt.',
      'False Claims Act qui tam matters cannot be filed via web form — they require counsel and a sealed complaint; route through the Tier C counsel flow instead.',
    ],
    questions: [
      { section: 'Complaint', question: 'Which DOJ component? (choose per category)', field: 'natureOfComplaint' },
      { section: 'Complaint', question: 'Describe the violation', field: 'narrative' },
      { section: 'Complaint', question: 'When did it occur?', field: 'incidentDate' },
      { section: 'Complaint', question: 'Where did it occur?', field: 'location' },
      { section: 'Subject', question: 'Who committed the violation?', field: 'subjectOrganization' },
      { section: 'Evidence', question: 'Supporting evidence', field: 'evidenceSummary' },
      { section: 'Evidence', question: 'Existence / timestamp verification', field: 'existenceProof' },
      { section: 'Contact', question: 'Your contact information', field: 'fixed', fixed: 'Anonymous — transmitted by Vera.Report on the reporter\'s instruction' },
    ],
  },
  // ── EU Directive channels (Phase 4c) ──────────────────────────────
  'eu-olaf': {
    entityId: 'eu-olaf',
    entityName: 'European Anti-Fraud Office (OLAF)',
    portalUrl: 'https://fraud-notification.olaf.europa.eu/',
    formName: 'OLAF Fraud Notification System (anonymous notification)',
    filingNotes: [
      'OLAF\'s notification system is natively anonymous — no attorney of record is required.',
      'On submission the system issues a case reference and credentials for a secure follow-up mailbox; record the case reference as this channel\'s receipt.',
      'Scope: fraud, corruption, or serious misconduct affecting the EU budget or EU institutions. If the conduct is purely national, prefer the member-state external channel.',
    ],
    questions: [
      { section: 'Notification', question: 'Do you wish to remain anonymous?', field: 'fixed', fixed: 'Yes — anonymous notification' },
      { section: 'Notification', question: 'What happened? (describe the alleged fraud or irregularity)', field: 'narrative' },
      { section: 'Notification', question: 'When did the conduct occur?', field: 'incidentDate' },
      { section: 'Notification', question: 'Where did it occur (country / body)?', field: 'location' },
      { section: 'Notification', question: 'Who is involved (persons / organisations)?', field: 'subjectOrganization' },
      { section: 'Supporting documents', question: 'Attach or describe supporting documents', field: 'evidenceSummary' },
      { section: 'Supporting documents', question: 'Existence / timestamp verification', field: 'existenceProof' },
      { section: 'Prior action', question: 'Have you reported this elsewhere?', field: 'priorReporting' },
    ],
  },
  'ec-competition': {
    entityId: 'ec-competition',
    entityName: 'European Commission — Competition Whistleblower Tool',
    portalUrl: 'https://competition-policy.ec.europa.eu/cartels/whistleblower_en',
    formName: 'DG COMP anonymous whistleblower message',
    filingNotes: [
      'The tool is anonymous by design (run via an external intermediary); two-way follow-up is possible through the mailbox the tool creates.',
      'No acknowledgment is guaranteed — record the tool\'s mailbox reference (if issued) as a manual receipt.',
      'Scope: cartels and other antitrust infringements (price fixing, market sharing, abuse of dominance).',
    ],
    questions: [
      { section: 'Message', question: 'Describe the suspected competition infringement', field: 'narrative' },
      { section: 'Message', question: 'Undertakings (companies) involved', field: 'subjectOrganization' },
      { section: 'Message', question: 'When and where did the conduct take place?', field: 'incidentDate' },
      { section: 'Message', question: 'Location / affected markets', field: 'location' },
      { section: 'Evidence', question: 'What evidence can you provide?', field: 'evidenceSummary' },
      { section: 'Evidence', question: 'Existence / timestamp verification', field: 'existenceProof' },
    ],
  },
  'irs-211': {
    entityId: 'irs-211',
    entityName: 'IRS Whistleblower Office (Form 211)',
    portalUrl: 'https://www.irs.gov/pub/irs-pdf/f211.pdf',
    formName: 'IRS Form 211 (Application for Award for Original Information)',
    filingNotes: [
      'Form 211 is MAIL-ONLY: print the completed form and mail to the IRS Whistleblower Office, Ogden, UT 84404.',
      'The IRS does not accept anonymous claims — Form 211 requires claimant identity. Route through counsel (Tier C); counsel handles the identity leg entirely off-platform.',
      'No electronic receipt exists; record the mailing (certified-mail number) as a manual receipt.',
    ],
    questions: [
      { section: 'Section A — Claim', question: 'Name of taxpayer / entity the claim concerns', field: 'subjectOrganization' },
      { section: 'Section A — Claim', question: 'Date(s) of the alleged violation', field: 'incidentDate' },
      { section: 'Section B — Allegations', question: 'Alleged violation of tax law (describe)', field: 'narrative' },
      { section: 'Section B — Allegations', question: 'How did you learn of / obtain this information?', field: 'fixed', fixed: 'Withheld to preserve anonymity at this stage; available through counsel.' },
      { section: 'Section B — Allegations', question: 'Supporting documentation', field: 'evidenceSummary' },
      { section: 'Section B — Allegations', question: 'Existence / timestamp verification', field: 'existenceProof' },
      { section: 'Section C — Claimant', question: 'Claimant identity and signature under penalty of perjury', field: 'fixed', fixed: 'Completed by the reporter with counsel — the identity leg happens outside Vera.Report by design.' },
    ],
  },
};

/** Render the companion answer sheet: portal question order, ready to paste. */
export function renderCompanionFields(view: DisseminationView, entityId: string): CompanionField[] {
  const profile = PORTAL_PROFILES[entityId];
  if (!profile) throw new Error(`No portal profile for entity ${entityId}`);
  const model = buildTcrModel(view);

  return profile.questions.map((q) => ({
    section: q.section,
    question: q.question,
    answer: q.field === 'fixed' ? q.fixed ?? '' : String(model[q.field]),
  }));
}

/** Render the companion as paste-ready plain text for the filing session. */
export function renderCompanionText(view: DisseminationView, entityId: string): string {
  const profile = PORTAL_PROFILES[entityId];
  if (!profile) throw new Error(`No portal profile for entity ${entityId}`);
  const fields = renderCompanionFields(view, entityId);

  const lines: string[] = [
    `${profile.formName} — filing companion for ${view.trackingId}`,
    `Portal: ${profile.portalUrl}`,
    '',
    'FILING NOTES:',
    ...profile.filingNotes.map((n) => `- ${n}`),
    '',
  ];

  let currentSection = '';
  for (const f of fields) {
    if (f.section !== currentSection) {
      currentSection = f.section;
      lines.push(`== ${f.section} ==`, '');
    }
    lines.push(`Q: ${f.question}`, `A: ${f.answer}`, '');
  }

  lines.push(
    '--',
    'Generated by Vera.Report. Contains no reporter identity. Record the portal',
    'confirmation / control number as this channel\'s receipt in the admin panel.',
  );
  return lines.join('\n');
}
