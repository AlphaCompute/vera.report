/**
 * Shared types for the Dissemination Service (VERA-PDR-001 §7–§9).
 */

import type { CategorySlug, PsstTreatment, Tier } from './taxonomy';
import type { PacketSubmitter } from '../submitterDisclosure';

export type { Tier } from './taxonomy';

// ── Consent (FR-8) ──────────────────────────────────────────────────

export interface ConsentSnapshot {
  /** Consent to share with Psst.org partner legal counsel. */
  psst: {
    granted: boolean;
    treatment?: PsstTreatment;
  };
  /** Consent to submit to government agencies on the reporter's behalf. */
  agency: boolean;
  /** Consent to admin-reviewed sharing with trusted legal reviewers (secure packets). */
  legalReview?: boolean;
  /** Consent to prepare a SecureDrop press/media handoff (reporter-elected, opt-in). */
  press?: boolean;
  capturedAt: Date;
  /** Version of the consent language shown to the reporter. */
  textVersion: string;
}

// ── Dissemination view (identity firewall, PDR §10) ─────────────────

/**
 * Identity-free projection of a report. This is the ONLY report shape the
 * dissemination layer may consume. It structurally excludes reporter
 * identifiers: reward contact data, nullifiers, decryption keys, and any
 * session metadata have no place in this type.
 */
export interface DisseminationView {
  trackingId: string;
  categories: CategorySlug[];
  /** Raw category strings for context (legacy slug, AI label). */
  rawCategories: string[];
  narrative: string;
  urgency?: string;
  location?: string;
  dateOfIncident?: string;
  verification?: {
    credibilityScore: number;
    category: string;
  };
  evidence: {
    /** Versioned SHA-256 commitment to the original submission (hex). */
    evidenceHash?: string;
    evidenceHashVersion?: import('../../utils/evidenceCommitment').EvidenceHashVersion;
    /** IPFS CID of the report metadata JSON. */
    ipfsHash?: string;
    files: EvidenceManifestEntry[];
  };
  zkProof?: {
    proofHash: string;
    proofType?: string;
    contractAddress?: string;
    txHash?: string;
    verified: boolean;
  };
  submittedAt?: Date;
  /**
   * Reporter's Psst handling election (hold-encrypted / share-with-counsel
   * / coordinate-disclosure). Not identity — it rides as unencrypted
   * metadata on Psst deposits (Stage 1 and Stage 2).
   */
  psstTreatment?: string;
  /**
   * Governing jurisdiction (Phase 4c): 'us' | 'eu' | 'other'. Absent on
   * pre-4c reports, which route as US-default.
   */
  jurisdiction?: string;
  /**
   * Org-type of the subject organization (Psst taxonomy, FR-2 routing
   * dimension). Proposed by AI triage; 'unknown' or absent when unclear.
   */
  orgType?: string;
  /** The organization the report concerns, extracted by AI triage. Not identity. */
  subjectOrganization?: string;
}

export interface EvidenceManifestEntry {
  name: string;
  /** IPFS CID of the encrypted file. Decryption is escrowed — never in packets. */
  cid?: string;
  mimetype?: string;
  size?: number;
}

// ── Packets (FR-5) ──────────────────────────────────────────────────

export interface Packet {
  trackingId: string;
  entityId: string;
  packetVersion: number;
  /** Rendered PDF dossier. */
  pdf: Buffer;
  /** Machine-readable sidecar. */
  sidecar: PacketSidecar;
  /** SHA-256 of the PDF (hex). */
  packetHash: string;
  /** IPFS CID of the encrypted packet, when pinning succeeded. */
  packetCid?: string;
  /** Key the packet was encrypted under before pinning — retained so the CID stays recoverable for audit. */
  packetKey?: string;
  generatedAt: Date;
  /** Per-recipient completeness grade (ALPHA-098); set by packetGenerator.generate(). */
  completeness?: PacketCompleteness;
}

// ── Packet completeness (ALPHA-098) ─────────────────────────────────

export type CompletenessSeverity = 'required' | 'recommended';

export interface CompletenessItem {
  key: string;
  label: string;
  severity: CompletenessSeverity;
  /** Whether the view carries this item. */
  present: boolean;
}

export interface PacketCompleteness {
  entityId: string;
  entityName: string;
  /** Internal heuristic only: no provisional `required` item missing. Not legal sufficiency or recipient acceptance. */
  ok: boolean;
  /** Absent items, most-severe first. */
  missing: CompletenessItem[];
  /** The full checklist evaluated. */
  checklist: CompletenessItem[];
}

export interface PacketSidecar {
  schema: 'vera-packet/1.0';
  /** Explicitly consented identity for recipients only; absent in legacy packets. */
  submitter?: PacketSubmitter;
  trackingId: string;
  entityId: string;
  packetVersion: number;
  generatedAt: string;
  categories: { slug: string; label: string }[];
  /** Subject organization extracted by AI triage (FR-2). */
  subjectOrganization?: string;
  orgType?: string;
  narrative: string;
  urgency?: string;
  location?: string;
  dateOfIncident?: string;
  /** Governing jurisdiction (us | eu | other) — routing- and requirement-relevant. */
  jurisdiction?: string;
  /** When the reporter submitted, ISO 8601. Mirrors the PDF "Report submitted" line. */
  submittedAt?: string;
  verification?: { credibilityScore: number; category: string };
  evidenceManifest: {
    evidenceHash?: string;
    evidenceHashVersion?: import('../../utils/evidenceCommitment').EvidenceHashVersion;
    ipfsHash?: string;
    files: EvidenceManifestEntry[];
    escrowStatement: string;
  };
  existenceProof?: {
    proofHash: string;
    proofType?: string;
    contractAddress?: string;
    txHash?: string;
    verified: boolean;
    network: string;
  };
  transmittalStatement: string;
}

// ── Adapters (PDR §7.3) ─────────────────────────────────────────────

export interface PreparedSubmission {
  /** Internal report audit key. Never include in outbound content. */
  auditTrackingId?: string;
  entityId: string;
  trackingId: string;
  /** How this prepared submission leaves Vera. */
  mode: 'email' | 'deep-link' | 'api';
  /** Email fields (mode: 'email'). */
  email?: {
    to: string;
    subject: string;
    coverLetter: string;
    attachments: { filename: string; contentType: string; content: Buffer }[];
    /**
     * True only for a dryrun notice that carries no report content (no
     * narrative, no evidence). Any other email is report content and, outside
     * live mode, may only be sent encrypted to a pinned key.
     */
    contentFree?: boolean;
  };
  /** Deep-link handoff fields (mode: 'deep-link'). */
  deepLink?: {
    url: string;
    /** Prefilled metadata the human carries into the partner form. */
    fields: Record<string, string>;
    /** Ready-to-paste deposit body. */
    depositBody: string;
  };
  /** Programmatic deposit fields (mode: 'api' — Psst Stage 2, Phase 4a). */
  api?: {
    /** Client-side PGP ciphertext of the deposit body. */
    encryptedBody: string;
    /** Unencrypted metadata fields posted alongside. */
    fields: Record<string, string>;
  };
}

export interface DispatchResult {
  /** 'sent' — left Vera; 'handoff' — awaiting human action (deep-link). */
  outcome: 'sent' | 'handoff';
  /** Entity-native provisional receipt (e.g. SES message-ID). */
  provisionalReceipt?: { type: ReceiptType; value: string };
  detail?: string;
}

export type ReceiptType =
  | 'smtp-message-id'
  | 'portal-confirmation'
  | 'control-number'
  | 'incident-id'
  | 'manual';

export interface Receipt {
  type: ReceiptType;
  value: string;
  receivedAt: Date;
  note?: string;
}

export interface SubmissionAdapter {
  entityId: string;
  tier: Tier;
  /** Render the entity-specific payload from the packet. */
  prepare(view: DisseminationView, packet: Packet): Promise<PreparedSubmission>;
  /** Send (Tier A) or hand off to a human (deep-link). */
  dispatch(prep: PreparedSubmission): Promise<DispatchResult>;
  /** Parse an inbound acknowledgment into a receipt, if recognizable. */
  parseReceipt(raw: unknown): Receipt | null;
  /** Cooldown-aware admission check (circuit breaker). */
  allowsDispatch(): boolean;
}

// ── Channel lifecycle (PDR §8) ──────────────────────────────────────

export type ChannelState =
  | 'recommended'
  | 'approved'
  | 'packet_ready'
  | 'dispatched'
  | 'receipted'
  | 'acknowledged'
  | 'feedback_received'
  | 'closed'
  | 'suppressed'
  | 'withdrawn'
  | 'deferred'
  | 'failed'
  | 'sla_breached';

// ── Persistence documents (PDR §9) ──────────────────────────────────

export interface DispositionDoc {
  trackingId: string;
  channels: { entityId: string; tier: Tier; state: ChannelState }[];
  consentSnapshot: ConsentSnapshot;
  approvedBy: string;
  /**
   * Admin-accepted redacted narrative (AI redaction pass). When set, it
   * replaces the reporter's raw narrative in every packet and companion
   * generated afterwards — the raw text never leaves the platform.
   */
  narrativeOverride?: {
    narrative: string;
    /** What the redaction changed, for the admin review step. */
    notes: string[];
    setBy: string;
    setAt: Date;
  };
  /** Set when an admin marked the narrative reviewed with no redaction needed (H1 gate). */
  narrativeReviewedAt?: Date;
  narrativeReviewedBy?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface SubmissionDoc {
  /** Fences a worker after a stale queue item is reclaimed. */
  claimToken?: string;
  /** Non-authorizing external reference used to reconcile agency replies. */
  caseReference?: string;
  submissionId: string;
  trackingId: string;
  entityId: string;
  tier: Tier;
  /** sha256(trackingId + entityId + packetVersion) — a retry can never double-file. */
  idempotencyKey: string;
  state: ChannelState;
  packetVersion: number;
  packetHash?: string;
  packetCid?: string;
  /** Key the pinned packet was encrypted under — kept so the CID stays a recoverable audit copy. */
  packetKey?: string;
  /** Deep-link handoff payload for manual channels (Psst Stage-1). */
  handoff?: { url: string; fields: Record<string, string>; depositBody: string };
  /** Counsel assignment for Tier C channels (Phase 3b). */
  counsel?: CounselAssignment;
  attempts: number;
  nextAttemptAt?: Date;
  lastError?: string;
  dispatchedAt?: Date;
  /**
   * Set immediately before the external send and cleared on a clean failure or
   * success. If a reclaimed row still has it set, a prior attempt reached the
   * send but neither completed nor failed cleanly (process crash mid-send) — the
   * agency may already have received it, so the worker must NOT blindly re-send.
   */
  dispatchInFlightAt?: Date;
  /** SLA clocks start at dispatch (PDR §8). */
  sla?: SlaState;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Inbound mail that arrived on a receipt mailbox (SES inbound → Lambda →
 * webhook). Parsed receipts are recorded immediately; anything that can't
 * be matched to a submission lands here for admin review, so no agency
 * correspondence is ever silently dropped.
 */
export interface InboundMailDoc {
  authentication?: { spf?: string; dkim?: string; dmarc?: string };
  inboundId: string;
  /** Receipt mailbox that received the message (e.g. cisa-receipts@…). */
  recipient: string;
  from: string;
  subject: string;
  /** Plain-text body excerpt (truncated by the relay). */
  body: string;
  /** S3 object key of the full raw message, when relayed from SES. */
  s3Key?: string;
  /** SES message ID of the inbound mail. */
  messageId?: string;
  /** Extracted at ingest when the mail quoted a tracking ID. */
  trackingId?: string;
  /** Derived from the receipt mailbox address. */
  entityId?: string;
  status: 'pending_review' | 'resolved' | 'dismissed';
  /** How ingest handled it: matched receipts are recorded automatically. */
  autoParsed: boolean;
  resolvedBy?: string;
  resolvedAt?: Date;
  receivedAt: Date;
  createdAt: Date;
}

export interface ReceiptDoc {
  submissionId: string;
  trackingId: string;
  entityId: string;
  type: ReceiptType;
  value: string;
  note?: string;
  receivedAt: Date;
  createdAt: Date;
}

export interface SlaState {
  /** 7-day acknowledgment target; null when entity has no ack expectation. */
  ackDueAt: Date | null;
  /** 3-month feedback target. */
  feedbackDueAt: Date | null;
  ackReceivedAt?: Date;
  feedbackReceivedAt?: Date;
  ackBreached: boolean;
  feedbackBreached: boolean;
}

export interface RoutingRuleDoc {
  ruleId: string;
  match: {
    categories?: string[];
    /** Org-type dimension (FR-2): rule fires only when AI triage identified one of these org types. */
    orgType?: string | string[];
    severity?: string[];
    /** Jurisdiction dimension (Phase 4c): rule fires only when the report's jurisdiction is listed. */
    jurisdiction?: string[];
  };
  route: { entityId: string; tier: Tier }[];
  version: number;
  effectiveFrom: Date;
  active: boolean;
  createdAt: Date;
}

export interface AuditEventDoc {
  eventId: string;
  trackingId: string;
  entityId?: string;
  event: string;
  /** Actor is an admin email or 'system' — never a reporter identifier. */
  actor: string;
  detail?: Record<string, unknown>;
  at: Date;
}

/**
 * A Merkle batch record. Check network/transaction evidence separately:
 * local fallback records do not establish a Midnight commitment.
 * Inclusion proofs detect edited events against an independently trusted root.
 */
export interface AuditAnchorDoc {
  anchorId: string;
  /** Committed digest: legacy Merkle root, or the versioned history commitment. */
  root: string;
  commitmentVersion?: 2;
  /** Merkle root of the event leaves for versioned history commitments. */
  batchRoot?: string;
  /** Ordered leaves: audit eventId + its canonical hash. */
  leaves: { eventId: string; leafHash: string }[];
  eventCount: number;
  firstEventAt: Date;
  lastEventAt: Date;
  /** Previous committed root; authenticated only by commitmentVersion 2. */
  prevRoot?: string;
  /** Proof artifact digest; may represent a local hash commitment without a transaction. */
  proofHash?: string;
  txHash?: string;
  network: string;
  anchoredAt: Date;
}

export type AuditHistoryEntry = Pick<AuditAnchorDoc, 'root' | 'commitmentVersion' | 'batchRoot' | 'eventCount' | 'prevRoot' | 'proofHash' | 'txHash' | 'network'>;

/** Durable single-batch coordinator; submitting is never reclaimed by elapsed time. */
export interface AuditBatchState {
  _id: 'audit-anchor';
  revision: number;
  /** Last completed root, advanced atomically with batch completion. */
  lastRoot?: string;
  batch?: {
    state: 'ready' | 'submitting' | 'complete';
    attemptId: string;
    anchor: AuditAnchorDoc;
  };
}

// ── Counsel bench (Phase 3, Tier C) ─────────────────────────────────

/**
 * A counsel partner is just a routing target: Psst Legal, panel firms,
 * and "reporter's own attorney" are rows in this collection, not code
 * paths — the partner-not-roadblock principle expressed as a schema.
 * Deactivating a row removes it from assignment.
 */
export interface CounselPartnerDoc {
  counselId: string;
  name: string;
  /** Entity channels this counsel can file (e.g. sec-tcr, eeoc, osc). */
  channels: string[];
  /**
   * Published contact handle the REPORTER uses to reach counsel directly
   * (e.g. a Signal handle). The reporter-to-counsel leg happens entirely
   * off-platform; Vera never carries it.
   */
  contactHandle: string;
  engagementModel: 'psst-legal' | 'panel' | 'reporter-own';
  active: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/** Counsel assignment stamped on a Tier C submission at dispatch. */
export interface CounselAssignment {
  counselId: string;
  counselName: string;
  contactHandle: string;
  /**
   * The join key between reporter and counsel: counsel learns "the person
   * quoting M-XXXX is my client"; Vera never learns who that is.
   */
  matterCode: string;
}

// ── One-time secure-packet links (single-use guard) ────────────────

/**
 * One consumed one-time secure-packet link. Records that a `jti` (the token's
 * unique id) has been burned, so the link cannot be replayed. Identity-free:
 * it holds no reporter data and no recipient contact — only the token id and
 * the report it scoped.
 */
export interface SecureLinkRevealDoc {
  /** Unique token id — the single-use key (unique index). */
  jti: string;
  trackingId: string;
  entityId: string;
  revealedAt: Date;
  detail?: Record<string, unknown>;
}

// ── Relay threads (Phase 3c, two-way anonymous follow-up) ──────────

/**
 * One message in a report's relay thread. The schema structurally cannot
 * carry identity: there is no sender field beyond the role enum, and no
 * free-form metadata. Admin identities live only in the audit log.
 */
export interface RelayMessageDoc {
  messageId: string;
  trackingId: string;
  /** Channel context when the message concerns one entity's follow-up. */
  entityId?: string;
  direction: 'to-reporter' | 'from-reporter';
  body: string;
  createdAt: Date;
}

// ── Routing plan (FR-2) ─────────────────────────────────────────────

export interface RecommendedChannel {
  entityId: string;
  entityName: string;
  tier: Tier;
  /** Whether an adapter can dispatch this channel in the current phase. */
  supported: boolean;
  /** Whether reporter consent covers this channel. */
  consentSatisfied: boolean;
  reason: string;
  notes?: string;
}

export interface DisseminationPlan {
  trackingId: string;
  categories: CategorySlug[];
  channels: RecommendedChannel[];
  consent: ConsentSnapshot | null;
  generatedAt: Date;
}

/** Only throw before any external delivery attempt has begun. */
export class DispatchNotSentError extends Error {}
