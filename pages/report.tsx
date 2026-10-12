import { ConfidentialReleaseIdentity } from '@/components/vera/confidential/ConfidentialReleaseIdentity';
import { CONTACT_LABELS, EMPTY_CONTACTS, contactProblem, suppliedContacts, type ReportContacts } from '@/lib/reportContacts';
import { SecurityDetails } from '@/components/vera/confidential/SecurityDetails';
import type { ReleaseIdentity } from '@/lib/confidential/releaseIdentity';
import { ConfidentialLoading, SecureChannelMark, type SecureChannelState } from '@/components/vera/confidential/SecureChannelMark';
import { OWNER_FAILURE_COPY } from '@/lib/confidential/failureCopy';
import { useReceiptNavigationGuard } from "@/lib/useReceiptNavigationGuard";
import { AlertDialog, AlertDialogContent, AlertDialogTitle, AlertDialogDescription, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { JURISDICTION_CHOICES as JURISDICTIONS, URGENCY_CHOICES as URGENCY_LEVELS } from '@/src/utils/intakeDefinitions';
import { LEGAL_REVIEW_NOTICE } from '@/src/utils/intakeConsent';
import { maxIncidentDate, incidentDateRangeError, formatIncidentRange } from '@/src/utils/reportIntakeRules';
import { copyText } from "@/lib/copyText";
import { EVIDENCE_SIZE_LABEL, evidenceTotalError, EVIDENCE_FILE_ACCEPT, EVIDENCE_FILE_TYPES_LABEL, MAX_EVIDENCE_FILES, evidenceFileError, resolveEvidenceMimeType } from '@/src/utils/evidenceFiles';
import { useState, useRef, useEffect, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import Head from "next/head";
import { toast } from "sonner";
import { motion, AnimatePresence } from "motion/react";
import {
  Copy,
  Download,
  ShieldCheck,
  ChevronLeft,
  Paperclip,
  X,
  Check,
  ExternalLink,
} from "lucide-react";
import { VeraReportLogo } from "@/components/vera/VeraReportLogo";
import { TypewriterText } from "@/components/vera/TypewriterText";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { REPORT_CATEGORIES as CATEGORIES } from "@/lib/reportCategories";
import { createSubmissionAttemptKey } from "@/lib/submissionAttemptKey";
import { readSubmissionReceipt } from "@/lib/reportSubmission";
import { getReportProofSummary, readReportProofStatus, readReceiptNetwork, receiptExplorerUrl, receiptNetworkLabel, type ReportProofStatus } from "@/lib/reportProof";
import { SubmitterDisclosureFields } from '@/components/vera/SubmitterDisclosureFields';
import { EMPTY_SUBMITTER_DISCLOSURE, parseSubmitterElection, type SubmitterDisclosureInput } from '@/src/utils/submitterDisclosure';
import { CONFIDENTIAL_METADATA_NOTICE, CONFIDENTIAL_RELEASE_MANIFEST, CONFIDENTIAL_REVIEW_NOTICE, confidentialCasesEnabled } from '@/lib/confidential/config';
import { SummaryComposer } from '@/components/vera/confidential/SummaryComposer';
import { EMPTY_LISTING_DRAFT, listingDraftProblem, type ListingDraft } from '@/lib/confidential/listingDraft';
import { CONFIDENTIAL_EVIDENCE_LIMIT_TEXT, CONFIDENTIAL_MAX_FILES, checkConfidentialSelection, percent, progressText } from '@/lib/confidential/evidence';
import { ConfidentialReview } from '@/components/vera/confidential/ConfidentialReview';
import { useLockAwareUnloadPrompt, useParticipantLock } from '@/lib/confidential/participantLock';
import { reportDraftAtRisk } from '@/lib/reportDraft';
import { RecoveryReceipt } from '@/components/vera/confidential/RecoveryReceipt';
import { WhoCanSee } from '@/components/vera/confidential/WhoCanSee';
import { RecoveryLeaveDialog } from '@/components/vera/confidential/RecoveryLeaveDialog';
import { keepPreparedSubmission, SAME_REPORT_RETRY_NOTE, submitFailureMessage } from '@/lib/confidential/submitRetry';

/** Next step after a failed confidential submit; the draft stays on this page. */
const CONFIDENTIAL_SUBMIT_NEXT_STEP: Record<string, string> = {
  offline: 'Your report is still here. Reconnect, then choose Submit again.',
  unavailable: 'Your report is still here. Try again in a few minutes; if it keeps failing, keep this page open and try later.',
  clock: 'Your report is still here. Set this device’s date and time to update automatically, then choose Submit again.',
  busy: 'Your report is still here. Wait a minute, then choose Submit again.',
  verification: 'Don’t submit again on this network for now. Keep this page open, then try later from a different network, ' +
    'for example mobile data instead of public Wi-Fi.',
  refused: 'Your report is still here. Try again in a few minutes.',
};

/* ─── Types ─── */
type Step =
  | "intro"
  | "contact"
  | "category"
  | "report"
  | "files"
  | "details"
  | "jurisdiction"
  | "summary"
  | "confirm"
  | "submitting"
  | "submitted";

const LEGACY_ADMIN_DISCLOSURE = 'NOT CONFIDENTIAL FROM VERA ADMINISTRATORS: this reporting flow lets authorized administrators read your report, attachments and any contact details you include.';

interface ChatMessage {
  id: string;
  role: "vera" | "user";
  content: string;
  timestamp: Date;
}

interface Snapshot {
  step: Step;
  msgCount: number;
  formData: FormData;
  files: File[];
  textInput: string;
}

interface FormData extends SubmitterDisclosureInput {
  category: string;
  urgency: string;
  description: string;
  location: string;
  dateOfIncident: string;
  incidentEndDate: string;
  incidentDateMode: "date" | "timeframe";
  contactMethod: string;
  contactValue: string;
  contacts: ReportContacts;
  jurisdiction: string;
  consentPsst: boolean | null;
  psstTreatment: string;
  consentLegalReview: boolean | null;
  consentPress: boolean | null;
  /** Reward-recipient ids the reporter chose to receive a one-time secure link. */
  disseminationRecipients: string[];
}

/* ─── Constants ─── */
// The category taxonomy now lives in @/lib/reportCategories (imported above as
// CATEGORIES), shared with /status so the reporter-facing labels can't drift (#451).

// Governing jurisdiction (Phase 4c) — drives EU Directive routing.
const INITIAL_FORM: FormData = {
  ...EMPTY_SUBMITTER_DISCLOSURE,
  category: "",
  urgency: "",
  description: "",
  location: "",
  dateOfIncident: "",
  incidentEndDate: "",
  incidentDateMode: "timeframe",
  contactMethod: "",
  contactValue: "",
  contacts: { ...EMPTY_CONTACTS },
  jurisdiction: "",
  consentPsst: null,
  psstTreatment: "",
  consentLegalReview: null,
  consentPress: null,
  disseminationRecipients: [],
};

function uid() {
  return Math.random().toString(36).substring(2, 9);
}

function formatTime(d: Date) {
  return d.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function getCategoryLabel(v: string) {
  return CATEGORIES.find((c) => c.value === v)?.label ?? v;
}
function getUrgencyLabel(v: string) {
  return URGENCY_LEVELS.find((u) => u.value === v)?.label ?? v;
}
function getJurisdictionLabel(v: string) {
  return JURISDICTIONS.find((j) => j.value === v)?.label ?? v;
}

/* ─── ink helper: auto-adapts to light/dark via CSS vars ─── */
const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

/* ═══════════════════════════════════════════════════════
   Redesign primitives — Figma "Vera Report" report view.
   Fluid tokens are derived from the 1728px design canvas.
   ═══════════════════════════════════════════════════════ */
const pageVars = {
  "--gutter": "clamp(20px, 3.47vw, 60px)",
  "--col-max": "834px",
  "--col-pad": "20px",
  "--fs-msg": "clamp(1rem, 1.22vw, 1.3125rem)" /* 16 → 21 */,
  "--fs-meta": "clamp(0.8125rem, 0.93vw, 1rem)" /* 13 → 16 */,
  "--fs-label": "clamp(0.6875rem, 0.81vw, 0.875rem)" /* 11 → 14 */,
  "--fs-send": "clamp(0.875rem, 0.98vw, 1.0625rem)" /* 14 → 17 */,
  "--arrow": "clamp(16px, 1.22vw, 21px)",
  "--tick-w": "clamp(24px, 2.32vw, 40px)",
  "--tick-h": "clamp(6px, 0.58vw, 10px)",
  fontFamily: "var(--font-display)",
} as React.CSSProperties;

/** Small uppercase caption used above form fields and chip groups. */
const fieldLabelStyle: React.CSSProperties = {
  fontFamily: "var(--font-display)",
  fontWeight: 600,
  fontSize: "var(--fs-label)",
  letterSpacing: "2px",
  textTransform: "uppercase",
  lineHeight: 1,
  color: "rgba(0,0,0,0.4)",
};

/** Key/value rows inside the zero-knowledge proof panel. */
const proofKeyStyle: React.CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: "var(--fs-label)",
  color: "rgba(0,0,0,0.4)",
};
const proofValueStyle: React.CSSProperties = {
  fontFamily: "var(--font-display)",
  fontSize: "var(--fs-label)",
  color: "#000",
};
const proofMonoStyle: React.CSSProperties = {
  fontSize: "var(--fs-label)",
  color: "rgba(0,0,0,0.6)",
};

type OptionButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  active?: boolean;
};

/** Flat #f2f2f2 chip used for every choice step. */
function OptionButton({
  children,
  className = "",
  active = false,
  ...rest
}: OptionButtonProps) {
  return (
    <button
      type="button"
      {...rest}
      className={`inline-flex items-center gap-[8px] px-[16px] py-[12px] text-left transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-40 ${
        active ? "bg-black" : "bg-[#f2f2f2] hover:bg-[#e6e6e6]"
      } ${className}`}
      style={{
        fontFamily: "var(--font-sans)",
        fontWeight: 500,
        fontSize: "13px",
        lineHeight: "16px",
        color: active ? "#ffffff" : "rgba(0,0,0,0.6)",
      }}
    >
      {children}
    </button>
  );
}

/** Black SEND action pinned to the bottom-right of the composer. */
function SendButton({
  label = "Send",
  className = "",
  inverted = false,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { label?: string; inverted?: boolean }) {
  return (
    <button
      type="button"
      {...rest}
      className={`inline-flex h-[42px] shrink-0 items-center justify-end gap-[8px] pl-[18px] pr-[10px] transition-opacity duration-200 hover:opacity-85 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-30 ${inverted ? "bg-white text-black focus-visible:ring-white focus-visible:ring-offset-black" : "bg-black text-white"} ${className}`}
      style={{
        fontFamily: "var(--font-display)",
        fontWeight: 600,
        fontSize: "var(--fs-send)",
        letterSpacing: "2px",
        textTransform: "uppercase",
      }}
    >
      {label}
      <span
        className="block shrink-0"
        style={{ width: "var(--arrow)", height: "var(--arrow)" }}
        aria-hidden="true"
      >
        <img src="/redesign/arrow-right.svg" alt="" className={`block h-full w-full ${inverted ? "invert" : ""}`} />
      </span>
    </button>
  );
}

/** Quiet "back one step" affordance (not in the mock, kept for usability). */
function BackButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-[4px] uppercase transition-opacity duration-200 hover:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2"
      style={{
        fontFamily: "var(--font-display)",
        fontWeight: 600,
        fontSize: "var(--fs-label)",
        letterSpacing: "1px",
        color: "rgba(0,0,0,0.4)",
      }}
    >
      <ChevronLeft className="size-[14px]" />
      Back
    </button>
  );
}

/** Black tick + CONFIDENTIAL, anchored to the reading column's left edge. */
function ClassificationMark() {
  return (
    <div className="flex flex-col gap-[clamp(12px,1.27vw,22px)]">
      <span
        className="block"
        style={{ width: "var(--tick-w)", height: "var(--tick-h)", backgroundColor: "#000" }}
        aria-hidden="true"
      />
      <span
        className="uppercase"
        style={{
          fontFamily: "var(--font-display)",
          fontWeight: 600,
          fontSize: "var(--fs-meta)",
          letterSpacing: "2px",
          lineHeight: 1,
          color: "#000",
        }}
      >
        Confidential
      </span>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   Component
   ═══════════════════════════════════════════════════════ */
export default function Report() {
  // Preserve unsaved work against automatic idle locks, but honor explicit locks.
  useParticipantLock('/status', false, false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [step, setStep] = useState<Step>("intro");
  const [isTyping, setIsTyping] = useState(false);
  const [typingMessageId, setTypingMessageId] = useState<string | null>(null);
  const [veraAnnouncement, setVeraAnnouncement] = useState("");
  const [textInput, setTextInput] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [reportId, setReportId] = useState("");
  const [proofStatus, setProofStatus] = useState<ReportProofStatus>("unknown");
  const [zkProof, setZkProof] = useState<{
    proofHash: string;
    nullifier?: string;
    publicSignals?: string[];
    verified: boolean;
    txHash?: string;
    proofType?: string;
    contractAddress?: string;
    network?: string;
  } | null>(null);
  const proofSummary = getReportProofSummary(proofStatus, zkProof);
  const proofExplorerUrl = receiptExplorerUrl(zkProof, process.env.NEXT_PUBLIC_BLOCK_EXPLORER_URL, process.env.NEXT_PUBLIC_BLOCK_EXPLORER_NETWORK);
  const [formData, setFormData] = useState<FormData>({ ...INITIAL_FORM });
  const [history, setHistory] = useState<Snapshot[]>([]);
  const [contactError, setContactError] = useState("");
  // Confidential intake: build-time opt-in; no fallback to the legacy plaintext path.
  const confidential = confidentialCasesEnabled();
  const [releaseIdentity, setReleaseIdentity] = useState<ReleaseIdentity | null>(null);
  const [releaseIdentityFailed, setReleaseIdentityFailed] = useState(false);
  const [channelState, setChannelState] = useState<SecureChannelState>('pending');
  const [entryFailure, setEntryFailure] = useState<string | null>(null);
  const entryCheck = useRef<Promise<{ identity: ReleaseIdentity | null; failure: string | null }> | null>(null);
  const [entryAnimationComplete, setEntryAnimationComplete] = useState(false);
  const preparingConfidential = confidential && !entryAnimationComplete;
  // Bumped by "Try again" so a failed check is retried in place, never by a
  // reload that would discard the draft.
  const [releaseIdentityAttempt, setReleaseIdentityAttempt] = useState(0);
  useEffect(() => {
    if (!confidential) return;
    let cancelled = false;
    setChannelState('pending');
    setReleaseIdentityFailed(false);
    // Share the in-flight check across Strict Mode effect replays. Finish the
    // anonymous challenge even after unmount so the enclave session is released.
    entryCheck.current ??= (async () => {
      let identity: ReleaseIdentity | null = null;
      let client: typeof import('@/lib/confidential/client') | undefined;
      try {
        identity = await (await import('@/lib/confidential/releaseIdentity')).releaseIdentity(CONFIDENTIAL_RELEASE_MANIFEST);
        client = await import('@/lib/confidential/client');
        await client.synchronizeTrustedTime(client.fetchRelay(), CONFIDENTIAL_RELEASE_MANIFEST, Date.now());
        return { identity, failure: null };
      } catch (error) {
        const failure = client && client.isReleasePaused(error) && error instanceof Error ? error.message
          : client ? OWNER_FAILURE_COPY[client.channelFailure(error).reason].title
          : 'Unable to load VERA’s security check';
        return { identity, failure };
      }
    })();
    void entryCheck.current.then(({ identity, failure }) => {
      if (cancelled) return;
      entryCheck.current = null;
      setReleaseIdentity(identity);
      setReleaseIdentityFailed(!identity);
      setEntryFailure(failure);
      setChannelState(failure ? 'failed' : 'verified');
    });
    return () => { cancelled = true; };
  }, [confidential, releaseIdentityAttempt]);
  // The public summary stays outside step snapshots so going back never loses it.
  const [listingDraft, setListingDraft] = useState<ListingDraft>(EMPTY_LISTING_DRAFT);
  const [listingError, setListingError] = useState("");
  const [submittingLabel, setSubmittingLabel] = useState("Submitting report…");
  // Why the last confidential submit failed (reason-specific; kept until the next attempt).
  const [confidentialFailure, setConfidentialFailure] = useState<{ reason: string; message: string; sameReport: boolean } | null>(null);
  // Header status mark: only claims "verified" after a real check (never a static trust badge).
  const secureChannelMark = confidential ? (
    <SecureChannelMark releaseIdentity={releaseIdentity ?? (releaseIdentityFailed ? 'failed' : 'loading')}
      connectionState={channelState} />
  ) : null;
  const [confidentialReceipt, setConfidentialReceipt] = useState<{ recoveryCode: string; recoveryPackage: string } | null>(null);

  /* ── Dark mode toggle ── */
  const [isDark] = useState(false); // Light mode primary; theme toggle hidden for now

  const scrollRef = useRef<HTMLDivElement>(null);
  const confidentialHeadingRef = useRef<HTMLHeadingElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const hasInitialized = useRef(false);
  const submissionInFlight = useRef(false);
  // An encrypted submission that did not finish (interrupted upload, or a publish
  // whose reply never arrived). Kept only in memory for this page: Submit retries
  // this same report (same recovery code) while the reviewed content is unchanged,
  // re-encrypting just the chunks the server has not confirmed. `mayHavePublished`
  // records that the publish request may already have reached the service.
  const pendingConfidential = useRef<{ key: string; prepared: import('@/enclave/src/confidential/ownerSubmission').PreparedSubmission;
    state: import('@/lib/confidential/client').ChunkUploadState; mayHavePublished: boolean } | null>(null);
  const uploadAbort = useRef<AbortController | null>(null);
  const filesSnapshot = useRef<File[]>([]);
  const [uploadPaused, setUploadPaused] = useState<string | null>(null);
  const [uploadingFiles, setUploadingFiles] = useState(false);
  const [submittingProgress, setSubmittingProgress] = useState<{ bytesDone: number; bytesTotal: number } | null>(null);
  const stepTransitionPending = useRef(false);
  const veraSequence = useRef<{ activeId: string; remaining: string[]; nextStep?: Step } | null>(null);
  const userTyping = useRef<{ activeId: string; onComplete: (() => void) | null } | null>(null);
  const userFollowUpTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const submissionAttemptKey = useRef<ReturnType<typeof createSubmissionAttemptKey> | null>(null);

  // The submit response precedes background proof generation. Refresh only the
  // receipt's proof fields; keep the reporter credential out of URLs and caches.
  useEffect(() => {
    if (!reportId || (proofStatus !== "pending" && proofStatus !== "unknown")) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const refreshProof = async () => {
      let finished = false;
      try {
        const response = await fetch('/api/whistleblower/status/access', {
          headers: { 'X-Reporter-Credential': reportId },
          cache: 'no-store',
          signal: controller.signal,
        });
        if (!response.ok) return;
        const body: unknown = await response.json();
        if (controller.signal.aborted || !body || typeof body !== 'object') return;
        const data = body as Record<string, unknown>;
        if (data.success !== true) return;
        const status = readReportProofStatus(data.proofStatus);
        if (status === "unknown") return;
        const proof = data.zkProof && typeof data.zkProof === 'object'
          ? data.zkProof as Record<string, unknown> : null;
        setZkProof(proof && typeof proof.proofHash === 'string' ? {
          proofHash: proof.proofHash,
          verified: proof.verified === true,
          txHash: typeof proof.txHash === 'string' ? proof.txHash : undefined,
          proofType: typeof proof.proofType === 'string' ? proof.proofType : undefined,
          contractAddress: typeof proof.contractAddress === 'string' ? proof.contractAddress : undefined,
          network: typeof proof.network === 'string' ? proof.network : undefined,
        } : null);
        setProofStatus(status);
        finished = status === "attached" || status === "failed" || status === "not_applicable";
      } catch {
        // A temporary status lookup failure must not invalidate the saved receipt.
      } finally {
        if (!controller.signal.aborted && !finished) {
          timer = setTimeout(refreshProof, 5000);
        }
      }
    };
    timer = setTimeout(refreshProof, 5000);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [reportId, proofStatus]);

  /* ── Auto-scroll ── */
  const scrollToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      if (scrollRef.current) {
        const confirmation = scrollRef.current.querySelector<HTMLElement>('[aria-labelledby="confirm-title"], [aria-labelledby="summary-step-title"]');
        if (confirmation) {
          const top = confirmation.getBoundingClientRect().top - scrollRef.current.getBoundingClientRect().top + scrollRef.current.scrollTop;
          scrollRef.current.scrollTop = Math.max(0, top - 24);
        } else {
          scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
      }
    });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, isTyping, scrollToBottom]);

  useEffect(() => () => {
    if (userFollowUpTimer.current) clearTimeout(userFollowUpTimer.current);
  }, []);

  /* ── Reveal Vera messages in order; unlock answers when the question finishes. ── */
  const pushVeraMessages = useCallback(
    (texts: string[], nextStep?: Step) => {
      if (texts.length === 0) return;
      stepTransitionPending.current = true;
      setIsTyping(true);
      const id = uid();
      veraSequence.current = { activeId: id, remaining: texts.slice(1), nextStep };
      setTypingMessageId(id);
      setVeraAnnouncement(texts[0]);
      setMessages((prev) => [...prev, { id, role: "vera", content: texts[0], timestamp: new Date() }]);
    },
    []
  );

  /* ── Reveal a user answer, then optionally continue after the typewriter finishes. ── */
  const pushUserMessage = useCallback((text: string, onComplete?: () => void) => {
    const id = uid();
    userTyping.current = { activeId: id, onComplete: onComplete ?? null };
    stepTransitionPending.current = true;
    setIsTyping(true);
    setTypingMessageId(id);
    setMessages((prev) => [...prev, { id, role: "user", content: text, timestamp: new Date() }]);
  }, []);

  const completeTypingMessage = useCallback((messageId: string) => {
    const sequence = veraSequence.current;
    if (sequence) {
      // Ignore stale or duplicate animation callbacks, including Strict Mode effects.
      if (sequence.activeId !== messageId) return;
      if (sequence.remaining.length > 0) {
        const id = uid();
        const [content, ...remaining] = sequence.remaining;
        veraSequence.current = { ...sequence, activeId: id, remaining };
        setTypingMessageId(id);
        setVeraAnnouncement(content);
        setMessages((prev) => [...prev, { id, role: "vera", content, timestamp: new Date() }]);
        return;
      }
      veraSequence.current = null;
      stepTransitionPending.current = false;
      setTypingMessageId(null);
      setIsTyping(false);
      if (sequence.nextStep) setStep(sequence.nextStep);
      return;
    }

    const pendingUser = userTyping.current;
    if (!pendingUser || pendingUser.activeId !== messageId) return;
    const after = pendingUser.onComplete;
    userTyping.current = null;
    setTypingMessageId(null);

    if (after) {
      // Keep the step locked; show "Vera is typing" during the beat before her reply.
      if (userFollowUpTimer.current) clearTimeout(userFollowUpTimer.current);
      userFollowUpTimer.current = setTimeout(() => {
        userFollowUpTimer.current = null;
        after();
      }, 300);
      return;
    }

    stepTransitionPending.current = false;
    setIsTyping(false);
  }, []);

  // Lock before the presentation delay; exiting buttons can still receive clicks.
  const beginStepTransition = () => {
    if (stepTransitionPending.current) return false;
    stepTransitionPending.current = true;
    setIsTyping(true);
    return true;
  };

  /* ── Save snapshot before transitioning ── */
  const saveSnapshot = useCallback(() => {
    setHistory((prev) => [
      ...prev,
      {
        step,
        msgCount: messages.length,
        formData: { ...formData },
        files: [...files],
        textInput,
      },
    ]);
  }, [step, messages.length, formData, files, textInput]);

  /* ── Go back ── */
  const handleGoBack = useCallback(() => {
    if (history.length === 0) return;
    // A paused upload is resumed silently on the next Submit if nothing reviewed changed.
    setUploadPaused(null);
    // The narrative and contacts stay editable on the confidential review. Carry
    // those edits into the earlier snapshots so Back never restores older values.
    const kept = confidential && step === "confirm"
      ? history.map(snapshot => ({
          ...snapshot,
          formData: { ...snapshot.formData, description: formData.description, contacts: { ...formData.contacts } },
          textInput: snapshot.step === "report" ? formData.description : snapshot.textInput,
        }))
      : history;
    const prev = kept[kept.length - 1];
    if (userFollowUpTimer.current) {
      clearTimeout(userFollowUpTimer.current);
      userFollowUpTimer.current = null;
    }
    userTyping.current = null;
    veraSequence.current = null;
    stepTransitionPending.current = false;
    setTypingMessageId(null);
    setIsTyping(false);
    setMessages((msgs) => msgs.slice(0, prev.msgCount));
    setFormData({ ...prev.formData });
    setFiles([...prev.files]);
    setStep(prev.step);
    setHistory(kept.slice(0, -1));
    setTextInput(prev.textInput);
    setContactError("");
    // Let a repeated question be announced again after going back.
    setVeraAnnouncement("");
  }, [history, confidential, step, formData.description, formData.contacts]);

  /* ── Initialize ── */
  useEffect(() => {
    if (hasInitialized.current || preparingConfidential) return;
    hasInitialized.current = true;
    // Confidential intake is only: what happened, files, contact,
    // summary, submit. The legacy routing, consent and rewards questions do
    // nothing for an encrypted report, so they are never asked.
    if (confidential) {
      pushVeraMessages([
        "Welcome to VERA. You can submit a report without an account. Your report and files are encrypted on this device before they are sent. VERA administrators cannot read them, and you decide which legal organizations can.",
        "In your own words, what happened? Include roughly when and where, and who was involved, if you can. Only you and the legal organizations you allow can read this.",
      ], "report");
      return;
    }
    pushVeraMessages(
      [
        "Welcome to VERA. You can submit a report without an account. VERA processes your report and files on its servers for authorized review. Your report will not be automatically sent to outside recipients. Review your narrative and files for details that could identify you.",
        "How would you like to be contacted? Add at least one method. Authorized VERA administrators can read these details for follow-up.",
      ],
      "contact"
    );
  }, [pushVeraMessages, confidential, preparingConfidential]);

  /* ── Focus ── */
  useEffect(() => {
    if ((step === "summary" || step === "confirm") && !isTyping) {
      const timer = setTimeout(() => document.getElementById(step === "confirm" ? "confirm-title" : "summary-step-title")?.focus(), 120);
      return () => clearTimeout(timer);
    }
  }, [step, isTyping]);
  useEffect(() => {
    if (step === "report") {
      setTimeout(() => {
        const el = document.querySelector<HTMLTextAreaElement>('[data-slot="textarea"]');
        el?.focus();
      }, 120);
    }
  }, [step]);

  /* ─────────────────────────────────────────
     Step Handlers
     ───────────────────────────────────────── */

  /* ── Confidential-only prompts ── */
  const CONFIDENTIAL_CONTACT_PROMPT =
    "How would you like to be contacted? Your contact details are encrypted separately from your report. VERA administrators cannot read them, and only you can see them unless you later share them with a specific legal organization.";
  const askForSummary = () => pushVeraMessages([
    CONFIDENTIAL_REVIEW_NOTICE,
    "Write that summary now. The examples and on-device checks below help you leave out anything that could identify you.",
  ], "summary");

  const handleContactsSubmit = () => {
    const problem = contactProblem(formData.contacts);
    if (problem) { setContactError(problem); return; }
    if (!beginStepTransition()) return;
    saveSnapshot(); setContactError('');
    const contacts = Object.entries(suppliedContacts(formData.contacts)).map(([key, value]) => `${CONTACT_LABELS[key as keyof ReportContacts]}: ${value}`).join('\n');
    setFormData(previous => ({ ...previous, contactMethod: 'multiple', contactValue: contacts, ...(previous.submitterMode === 'identified' ? { submitterContactMethod: 'multiple', submitterContactValue: contacts.split('\n').join('; ') } : {}) }));
    pushUserMessage(contacts, () => confidential ? askForSummary() : pushVeraMessages(['What kind of issue are you reporting?'], 'category'));
  };

  // Step 3: Category
  const handleCategorySelect = (value: string) => {
    if (!beginStepTransition()) return;
    saveSnapshot();
    setFormData((prev) => ({ ...prev, category: value }));
    pushUserMessage(getCategoryLabel(value), () =>
      pushVeraMessages(
        ["In your own words — what happened?"],
        "report"
      )
    );
  };

  // Step 4: Report description
  /**
   * Save a nonblank narrative locally and queue the file step with its privacy
   * notice after the answer is displayed. Ignore input during a pending transition.
   */
  const handleReportSubmit = () => {
    const text = textInput.trim();
    if (!text) return;
    if (!beginStepTransition()) return;
    saveSnapshot();
    setFormData((prev) => ({ ...prev, description: text }));
    setTextInput("");
    pushUserMessage(text, () =>
      pushVeraMessages(
        [
          confidential
            ? `If you have supporting files, such as documents, photos or recordings, attach them now. ${CONFIDENTIAL_EVIDENCE_LIMIT_TEXT} Files are encrypted on this device, so VERA can’t remove hidden details such as the location in a photo or the author of a document. Check them before attaching.`
            : "If you have supporting files — images, documents — you can attach them now. VERA removes supported file metadata on its servers, but faces, voices, visible text, watermarks and other details inside a file can still identify you. Review and sanitize sensitive files on your device before uploading.",
        ],
        "files"
      )
    );
  };

  // Step 5: Files
  const handleFilesSkip = () => {
    if (!beginStepTransition()) return;
    saveSnapshot();
    pushUserMessage("Skip", () =>
      confidential ? pushVeraMessages([CONFIDENTIAL_CONTACT_PROMPT], "contact") :
      pushVeraMessages(
        ["Anything else? You can add the report’s sensitivity, location, or timeframe — or go ahead and submit."],
        "details"
      )
    );
  };

  const handleFilesContinue = () => {
    if (!beginStepTransition()) return;
    saveSnapshot();
    pushUserMessage(
      `${files.length} file${files.length > 1 ? "s" : ""} attached`,
      () => confidential ? pushVeraMessages([CONFIDENTIAL_CONTACT_PROMPT], "contact") :
        pushVeraMessages(
          ["Anything else? You can add the report’s sensitivity, location, or timeframe — or go ahead and submit."],
          "details"
        )
    );
  };

  const incidentDateValue = formData.incidentDateMode === "date"
    ? formData.dateOfIncident
    : formatIncidentRange(formData.dateOfIncident, formData.incidentEndDate);

  // Step 6: Details (all optional, handled inline)
  const handleDetailsSubmit = () => {
    // `max` on the picker stops the calendar, not a typed or pasted value, and
    // the intake rejects a future date anyway (#853).
    const timeframeError = incidentDateRangeError(formData.dateOfIncident, formData.incidentDateMode === "date" ? formData.dateOfIncident : formData.incidentEndDate);
    if (timeframeError) {
      toast.error(timeframeError);
      return;
    }
    if (!beginStepTransition()) return;
    saveSnapshot();
    const parts: string[] = [];
    if (formData.urgency)
      parts.push(`Sensitivity: ${getUrgencyLabel(formData.urgency)}`);
    if (formData.location) parts.push(`Location: ${formData.location}`);
    if (formData.dateOfIncident) parts.push(`${formData.incidentDateMode === "date" ? "Date" : "Timeframe"}: ${incidentDateValue}`);

    const answer = parts.length > 0 ? parts.join(" · ") : "Ready to submit";
    pushUserMessage(answer, () =>
      pushVeraMessages(
        [
          "Vera currently accepts reports concerning conduct under United States jurisdiction. Confirm the jurisdiction to continue.",
        ],
        "jurisdiction"
      )
    );
  };

  // Step 6.5: Jurisdiction (Phase 4c — drives EU Directive routing)
  const handleJurisdictionSelect = (value: string) => {
    if (!beginStepTransition()) return;
    saveSnapshot();
    setFormData((prev) => ({ ...prev, jurisdiction: value }));
    setFormData((prev) => ({ ...prev, consentPsst: false, consentLegalReview: true, consentPress: false, disseminationRecipients: [] }));
    pushUserMessage(getJurisdictionLabel(value), () =>
      pushVeraMessages([
        confidential ? CONFIDENTIAL_REVIEW_NOTICE : LEGAL_REVIEW_NOTICE,
        "Review your report, then choose Submit when you are ready."
      ], "confirm")
    );
  };

  // Confidential step 4: the public summary, reviewed on this device.
  const handleSummaryContinue = () => {
    const problem = listingDraftProblem(listingDraft);
    setListingError(problem ?? "");
    if (problem) return;
    if (!beginStepTransition()) return;
    saveSnapshot();
    pushUserMessage("My summary is ready", () =>
      pushVeraMessages(["Review your report, then choose Submit when you are ready."], "confirm"));
  };

  const discardPendingConfidential = () => {
    for (const item of pendingConfidential.current?.prepared.chunkedObjects ?? []) item.dispose();
    pendingConfidential.current = null;
    setUploadPaused(null);
  };

  // Confidential submit: encrypt and sign on this device, then send ciphertext
  // over the verified enclave channel. Any failure keeps the draft; nothing is
  // ever retried through the legacy plaintext endpoint. Evidence uploads in
  // encrypted chunks; an interrupted upload resumes from where it stopped as long
  // as the reviewed report and files are unchanged. A failure after the publish
  // request may have been sent keeps the prepared report too: the service may
  // already hold it, so Submit retries the exact same report (accepted
  // idempotently) instead of creating a second one whose recovery code differs.
  const handleConfidentialConfirm = async () => {
    if (entryCheck.current) return;
    if (!releaseIdentity) { toast.error("The secure release identity is unavailable. Your report has not been sent."); return; }
    const problem = listingDraftProblem(listingDraft);
    if (problem) { toast.error(problem); return; }
    // Snapshot what the person reviewed before any await.
    const summary = listingDraft.summary.trim();
    // Only the optional fields the reporter explicitly chose (validated above).
    const description = formData.description.trim();
    if (!description) { toast.error("Describe what happened before submitting."); return; }
    const contactError = contactProblem(formData.contacts);
    if (contactError) { toast.error(contactError); return; }
    const contact = suppliedContacts(formData.contacts);
    const chosenFiles = [...files];
    // Identifies exactly what was reviewed; the File objects themselves are compared too.
    const key = JSON.stringify({ summary, description, contact });
    const pending = pendingConfidential.current;
    const resuming = !!pending && pending.key === key && pending.prepared.chunkedObjects.length === chosenFiles.length &&
      filesSnapshot.current.length === chosenFiles.length && filesSnapshot.current.every((file, index) => file === chosenFiles[index]);
    if (pending && !resuming) discardPendingConfidential();
    submissionInFlight.current = true;
    setUploadPaused(null);
    setConfidentialFailure(null);
    setEntryFailure(null);
    setChannelState('pending');
    // Submission progress follows the request, not a chat animation. A fast
    // failure returns to review, where messages are unmounted; waiting for a
    // typewriter callback there would leave isTyping locked and hide the draft.
    setMessages(previous => [...previous, { id: uid(), role: "user",
      content: resuming && uploadPaused ? "Resume the upload." : resuming ? "Try again." : "Submit it.", timestamp: new Date() }]);
    setSubmittingLabel(resuming ? "Reconnecting to the secure service…" : "Encrypting your report on this device…");
    setStep("submitting");
    const abort = new AbortController();
    uploadAbort.current = abort;
    let client: typeof import('@/lib/confidential/client') | null = null;
    let chunks: typeof import('@/enclave/src/confidential/caseChunks') | null = null;
    try {
      const [submission, loadedClient, loadedChunks] = await Promise.all([
        import('@/enclave/src/confidential/ownerSubmission'), import('@/lib/confidential/client'),
        import('@/enclave/src/confidential/caseChunks')]);
      client = loadedClient; chunks = loadedChunks;
      const { blobEvidenceSource } = loadedChunks;
      let current = resuming ? pendingConfidential.current! : null;
      if (!current) {
        // Sign the first checkpoint with attested enclave time, so a device clock
        // that runs fast cannot produce a report the service refuses to open.
        await client.synchronizeTrustedTime(client.fetchRelay(), CONFIDENTIAL_RELEASE_MANIFEST, Date.now());
        const prepared = await submission.prepareConfidentialSubmission({
          summary,
          narrative: { description },
          contact,
          identity: null,
          // Read from disk one chunk at a time; a large file is never loaded whole.
          files: chosenFiles.map(file => ({ ...blobEvidenceSource(file), type: resolveEvidenceMimeType(file.type, file.name) })),
        }, CONFIDENTIAL_RELEASE_MANIFEST, client.trustedTime(Date.now()), { onProgress: progress => {
          if (chosenFiles.length) setSubmittingLabel(progressText("Encrypting files on this device", progress));
          setSubmittingProgress(progress);
        } });
        current = { key, prepared, state: client.createChunkUploadState(), mayHavePublished: false };
        filesSnapshot.current = chosenFiles;
        pendingConfidential.current = current;
      }
      setSubmittingLabel(chosenFiles.length ? "Verifying the secure service…" : "Verifying the secure service and sending your encrypted report…");
      setUploadingFiles(chosenFiles.length > 0);
      let announced = -1;
      const attempt = current;
      // Device time here: publishing re-verifies the service and signs with the
      // attested offset learned when the service was verified.
      await client.publishPreparedCase({ relay: client.fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST, now: Date.now(),
        prepared: current.prepared, onPublishSending: () => { attempt.mayHavePublished = true; }, upload: { state: current.state, signal: abort.signal, onProgress: progress => {
          setSubmittingProgress(progress);
          // Announce at most every 5% so screen readers are not flooded.
          const bucket = Math.floor(percent(progress) / 5);
          if (bucket === announced) return;
          announced = bucket;
          setSubmittingLabel(progress.bytesDone >= progress.bytesTotal ? "Files uploaded. Sending your encrypted report…"
            : progressText("Uploading encrypted files", progress));
        } } });
      setConfidentialReceipt({ recoveryCode: current.prepared.recoveryCode, recoveryPackage: current.prepared.recoveryPackage });
      setChannelState('verified');
      discardPendingConfidential();
      setStep("submitted");
    } catch (error) {
      setChannelState('failed');
      const changed = !!chunks && error instanceof chunks.EvidenceChangedError;
      if (client && error instanceof client.ConfidentialUploadInterruptedError && pendingConfidential.current) {
        // Nothing was submitted; the uploaded parts are kept for a resume.
        setUploadPaused(abort.signal.aborted
          ? "Upload paused. Nothing has been submitted yet. Choose Resume upload to continue where it stopped."
          : error.message);
      } else {
        const unavailable = error instanceof Error && error.name === 'ConfidentialUnavailableError';
        const reason = unavailable ? String((error as Error & { reason?: string }).reason ?? 'refused') : null;
        const pending = pendingConfidential.current;
        // Keep the prepared report whenever the service may already hold it; see submitRetry.
        const sameReport = !!pending && keepPreparedSubmission({ mayHavePublished: pending.mayHavePublished,
          evidenceChanged: changed, releasePaused: !!client && client.isReleasePaused(error), reason });
        if (!sameReport) discardPendingConfidential();
        if (unavailable) {
          // The confirm card explains why and what to do; the toast only says it was not confirmed.
          setConfidentialFailure({ reason: reason!, message: error.message, sameReport });
          toast.error(sameReport ? 'We could not confirm your report was received. See the note above the Submit button.'
            : 'Your report was not sent. See the note above the Submit button.');
        } else if (sameReport) {
          setConfidentialFailure({ reason: 'refused', message: 'We could not confirm your report was received.', sameReport });
          toast.error('We could not confirm your report was received. See the note above the Submit button.');
        } else {
          toast.error(changed ? "A file changed after it was encrypted. Choose Submit again to encrypt the current version."
            // Only errors written for the reporter show their own text; see submitFailureMessage.
            : submitFailureMessage(error, (!!chunks && error instanceof chunks.EvidenceTooLargeError)
              || (!!client && client.isReleasePaused(error))));
        }
      }
      setStep("confirm");
    } finally {
      submissionInFlight.current = false;
      uploadAbort.current = null;
      setUploadingFiles(false);
      setSubmittingProgress(null);
      setSubmittingLabel("Submitting report…");
    }
  };

  // Confirm
  const handleConfirm = async () => {
    const contactIssue = contactProblem(formData.contacts);
    if (contactIssue) { toast.error(contactIssue); return; }
    if (submissionInFlight.current) return;
    if (confidential) return handleConfidentialConfirm();
    try { parseSubmitterElection({ ...formData }); }
    catch (error) { toast.error((error as Error).message); return; }
    submissionInFlight.current = true;
    // Animate the answer for polish; start the network submit without waiting.
    pushUserMessage("Submit it.");
    setStep("submitting");

    try {
      const submitData = new FormData();
      submitData.append('description', formData.description || textInput);
      submitData.append('evidenceType', formData.category || 'other');
      submitData.append('urgency', formData.urgency || 'medium');
      if (formData.location) submitData.append('location', formData.location);
      if (formData.dateOfIncident) submitData.append('dateOfIncident', incidentDateValue);
      submitData.append('wantsReward', 'false');
      if (formData.contactMethod) submitData.append('contactMethod', formData.contactMethod);
      if (formData.contactValue) submitData.append('contactValue', formData.contactValue);
      submitData.append('submitterMode', formData.submitterMode);
      if (formData.submitterMode === 'identified') {
        submitData.append('submitterName', formData.submitterName);
        submitData.append('submitterContactMethod', formData.submitterContactMethod);
        submitData.append('submitterContactValue', formData.submitterContactValue);
        submitData.append('submitterConsent', String(formData.submitterConsent));
      }

      // Dissemination taxonomy + consent snapshot (VERA-PDR-001 FR-8)
      if (formData.category) submitData.append('categories', JSON.stringify([formData.category]));
      if (formData.jurisdiction) submitData.append('jurisdiction', formData.jurisdiction);
      submitData.append('consentPsst', String(formData.consentPsst ?? false));
      if (formData.consentPsst && formData.psstTreatment) {
        submitData.append('psstTreatment', formData.psstTreatment);
      }
      submitData.append('consentLegalReview', String(formData.consentLegalReview === true));
      submitData.append('consentPress', String(formData.consentPress ?? false));
      if (formData.disseminationRecipients.length > 0) {
        submitData.append('disseminationRecipients', JSON.stringify(formData.disseminationRecipients));
      }

      // Append actual files
      files.forEach((file) => {
        submitData.append('files', file);
      });

      submissionAttemptKey.current ??= createSubmissionAttemptKey();
      const response = await fetch('/api/whistleblower/submit', {
        method: 'POST',
        headers: { 'X-Idempotency-Key': submissionAttemptKey.current(submitData) },
        body: submitData,
      });

      const result = readSubmissionReceipt(response.ok, await response.json().catch(() => null));

      setReportId(result.trackingId);
      setProofStatus(result.proofStatus);
      setZkProof(result.zkProof ?? null);
      setStep("submitted");
    } catch (error) {
      toast.error(error instanceof Error && !(error instanceof TypeError)
        ? error.message
        : 'We could not confirm your submission. Your report is still here; please try again.');
      setStep("confirm");
    } finally {
      submissionInFlight.current = false;
    }
  };

  // File handling
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(e.target.files || []);
    e.target.value = "";
    if (confidential) {
      const { accepted, problems } = checkConfidentialSelection(files, selected);
      for (const problem of problems) toast.error(problem);
      if (accepted.length) setFiles((prev) => [...prev, ...accepted]);
      return;
    }
    const valid = selected.filter((file) => {
      const error = evidenceFileError(file);
      if (error) toast.error(`${file.name}: ${error}`);
      return error === null;
    });
    if (files.length + valid.length > MAX_EVIDENCE_FILES) {
      toast.error(`You can attach up to ${MAX_EVIDENCE_FILES} evidence files.`);
      return;
    }
    const totalError = evidenceTotalError([...files, ...valid]);
    if (totalError) { toast.error(totalError); return; }
    setFiles((prev) => [...prev, ...valid]);
  };
  const removeFile = (i: number) =>
    setFiles((prev) => prev.filter((_, idx) => idx !== i));

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (step === "report") handleReportSubmit();
    }
  };

  const router = useRouter();
  const [copied, setCopied] = useState(false);
  const copyResetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [receiptSaved, setReceiptSaved] = useState(false);
  const [receiptCopyError, setReceiptCopyError] = useState(false);
  const copyReportId = useCallback(async () => {
    if (!reportId) return false;
    const success = await copyText(reportId);
    if (copyResetTimer.current) clearTimeout(copyResetTimer.current);
    setCopied(success);
    setReceiptCopyError(!success);
    if (success) {
      setReceiptSaved(true);
      copyResetTimer.current = setTimeout(() => setCopied(false), 3000);
    }
    return success;
  }, [reportId]);

  useEffect(() => () => {
    if (copyResetTimer.current) clearTimeout(copyResetTimer.current);
  }, []);

  const downloadReportKey = () => {
    if (!reportId) return;
    const content = `VERA Report ID (access key)\n\n${reportId}\n\nKeep this key safe. Without your Report ID, you cannot check your report's status.\nTreat it as a password: anyone with it can access your report status.\n`;
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "vera-report-key.txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setReceiptSaved(true);
  };

  useEffect(() => {
    if (reportId) void copyReportId();
  }, [reportId, copyReportId]);

  const receiptGuard = useReceiptNavigationGuard(router, (!!reportId || !!confidentialReceipt) && !receiptSaved);
  // Leaving during an encrypted upload loses the unsent parts' place; ask first.
  const uploadInProgress = uploadingFiles || !!uploadPaused;
  useLockAwareUnloadPrompt(uploadInProgress);
  // The unsent draft (narrative, files, summary, contacts) lives only in this tab: ask
  // before a reload, tab close, link or Back throws it away. An explicit Lock
  // still clears the page without waiting on the prompt.
  const draftAtRisk = reportDraftAtRisk(step, {
    description: formData.description, typed: textInput, files: files.length, summary: listingDraft.summary, contacts: formData.contacts,
  });
  const draftGuard = useReceiptNavigationGuard(router, draftAtRisk);
  const [copyingReceipt, setCopyingReceipt] = useState(false);
  const copyAndStay = async () => {
    setCopyingReceipt(true);
    try {
      const success = await copyReportId();
      setReceiptCopyError(!success);
      if (success) receiptGuard.stay();
    } finally { setCopyingReceipt(false); }
  };

  const canGoBack =
    history.length > 0 &&
    !isTyping &&
    !["intro", "submitting", "submitted"].includes(step);

  /* ═══════════════════════════════════════════════════════
     Render
     ═══════════════════════════════════════════════════════ */
  if (preparingConfidential) return (
    <>
      <Head><title>Submit Report - Vera</title></Head>
      <ConfidentialLoading ready={channelState === 'verified'} failed={channelState === 'failed'} onComplete={() => setEntryAnimationComplete(true)} />
    </>
  );

  return (
    <>
      {confidentialReceipt ? (
        <RecoveryLeaveDialog open={receiptGuard.open} recoveryCode={confidentialReceipt.recoveryCode}
          onStay={receiptGuard.stay} onLeave={receiptGuard.leave} />
      ) : (
      <AlertDialog open={receiptGuard.open} onOpenChange={(open) => { if (!open) receiptGuard.stay(); }}>
        <AlertDialogContent>
          <AlertDialogTitle>Save your Report ID before leaving</AlertDialogTitle>
          <AlertDialogDescription>
            You haven’t saved your Report ID. Without it, you won’t be able to check your report’s status.
          </AlertDialogDescription>
          <p className="break-all font-mono select-all">{reportId}</p>
          {receiptCopyError && <p role="alert">Copy failed. Try again or select and save the ID above.</p>}
          <button type="button" className="rounded bg-black px-4 py-3 text-white" disabled={copyingReceipt} onClick={() => void copyAndStay()}>
            {copyingReceipt ? 'Copying…' : 'Copy ID and stay'}
          </button>
          <AlertDialogCancel>Stay on this page</AlertDialogCancel>
          <button type="button" className="rounded border px-4 py-2" onClick={receiptGuard.leave}>Leave without copying</button>
        </AlertDialogContent>
      </AlertDialog>
      )}
      <AlertDialog open={draftGuard.open} onOpenChange={(open) => { if (!open) draftGuard.stay(); }}>
        <AlertDialogContent>
          <AlertDialogTitle className="font-bold text-red-800">Leave without sending your report?</AlertDialogTitle>
          <AlertDialogDescription className="font-bold text-red-800">
            Your report has not been sent. It is kept only on this page, so leaving clears what you wrote and the files you added.
          </AlertDialogDescription>
          <AlertDialogCancel>Stay and keep my report</AlertDialogCancel>
          <button type="button" className="rounded border px-4 py-2" onClick={draftGuard.leave}>Leave and clear my report</button>
        </AlertDialogContent>
      </AlertDialog>
      <Head>
        <title>Submit Report - Vera</title>
      </Head>
      <a
        href="#main-content"
        className="absolute left-[-9999px] focus:left-4 focus:top-4 focus:z-[100] focus:px-4 focus:py-2 focus:bg-background focus:text-foreground focus:ring-2 focus:ring-[var(--ring)] focus:ring-offset-2 focus:rounded-md focus:overflow-visible focus:w-auto focus:h-auto focus:no-underline"
      >
        Skip to main content
      </a>
      <div className="relative flex h-screen flex-col bg-white text-black" style={pageVars}>
        {/* Column rules — the two full-height hairlines from the design */}
        <div
          className="pointer-events-none absolute inset-0 hidden justify-center min-[1240px]:flex"
          aria-hidden="true"
        >
          <div className="h-full w-full max-w-[var(--col-max)] border-x border-[rgba(0,0,0,0.12)]" />
        </div>

        {/* ── Header ── */}
        <header className="relative z-50 shrink-0 pb-[clamp(24px,2.8vw,48px)] pt-[clamp(16px,1.33vw,23px)]">
          <div className="flex items-start justify-between gap-4 px-[var(--gutter)]">
            <Link
              href="/"
              aria-label="Vera Report home"
              className="block text-black transition-opacity duration-300 hover:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2"
            >
              <VeraReportLogo style={{ height: "clamp(30px, 2.6vw, 45px)", width: "auto" }} />
            </Link>
            <span
              className="btn-slide-black inline-flex shrink-0 cursor-pointer items-center gap-[6px] p-[10px] uppercase text-white transition-colors duration-300"
              style={{
                display: "none", // Emergency badge hidden per request
                backgroundColor: "#ff0000",
                fontFamily: "var(--font-display)",
                fontWeight: 600,
                fontSize: "var(--fs-label)",
                letterSpacing: "2px",
                lineHeight: 1,
              }}
            >
              <span
                aria-hidden="true"
                className="shrink-0"
                style={{ width: "1.5em", height: "1.5em", display: "inline-block" }}
              >
                <svg
                  viewBox="0 0 21 21"
                  fill="none"
                  style={{ width: "100%", height: "100%", display: "block" }}
                >
                  <path
                    d="M19.0312 19.6875H1.96869C1.74117 19.6875 1.52998 19.5696 1.41048 19.3761C1.29098 19.1825 1.28008 18.9409 1.38167 18.7377L9.91292 1.67523C10.1353 1.23049 10.8646 1.23049 11.087 1.67523L19.6183 18.7377C19.7202 18.9409 19.7093 19.1825 19.5895 19.3761C19.4696 19.5697 19.2587 19.6875 19.0312 19.6875ZM3.03063 18.375H17.9693L10.4999 3.43601L3.03063 18.375Z"
                    fill="currentColor"
                  />
                  <path
                    d="M10.664 16.2422C11.117 16.2422 11.4843 15.8749 11.4843 15.4219C11.4843 14.9689 11.117 14.6016 10.664 14.6016C10.211 14.6016 9.84369 14.9689 9.84369 15.4219C9.84369 15.8749 10.211 16.2422 10.664 16.2422Z"
                    fill="currentColor"
                  />
                  <path d="M11.3203 8.8594H10.0078V13.4531H11.3203V8.8594Z" fill="currentColor" />
                </svg>
              </span>
              Emergency
            </span>
          </div>

          {/* Column-anchored chrome (desktop): classification + channel status */}
          <div className="pointer-events-none absolute inset-x-0 top-[clamp(16px,1.33vw,23px)] hidden min-[1240px]:block">
            <div className="mx-auto flex w-full max-w-[var(--col-max)] items-start justify-between px-[var(--col-pad)]">
              {secureChannelMark ?? <ClassificationMark />}
            </div>
          </div>

          {/* Same chrome, stacked in flow, once the column can no longer host it */}
          <div className="mx-auto mt-[clamp(20px,2.6vw,32px)] flex w-full max-w-[var(--col-max)] flex-wrap items-end justify-between gap-x-4 gap-y-3 px-[var(--col-pad)] min-[1240px]:hidden">
            {secureChannelMark ?? <ClassificationMark />}
          </div>
        </header>

        {confidential && entryFailure && (
          <div role="alert" className="relative z-10 mx-auto w-full max-w-[var(--col-max)] px-[var(--col-pad)] pb-4 text-sm">
            <p className="font-semibold">{entryFailure}</p>
            <p className="mt-1">You can keep writing here. VERA will check again before sending.</p>
            <button type="button" className="mt-2 underline underline-offset-4 disabled:opacity-50"
              disabled={channelState === 'pending'} onClick={() => setReleaseIdentityAttempt(n => n + 1)}>
              {channelState === 'pending' ? 'Checking enclave…' : 'Check enclave again'}
            </button>
          </div>
        )}

        {process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_VERA_LOCAL_REVIEW === '1' && (
          <p role="note" className="relative z-10 bg-amber-100 px-6 py-2 text-center text-sm font-semibold">Local review · simulated secure service · use test data only</p>
        )}

        {/* One persistent live region, so screen readers announce each new question. */}
        <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{veraAnnouncement}</div>

        {/* ── Chat Area ── */}
        <main id="main-content" ref={scrollRef} className="relative z-10 flex-1 overflow-y-auto min-h-0 scroll-mt-4" tabIndex={-1}>
          <AnimatePresence mode="wait">
            {/* ── Chat view (intro through submitting) ── */}
            {step !== "submitted" && (
              <motion.div
                key="chat-view"
                exit={{ opacity: 0 }}
                transition={{ duration: 0.4 }}
                className="mx-auto w-full max-w-[var(--col-max)] px-[var(--col-pad)] pb-[clamp(24px,2.32vw,40px)] pt-[clamp(28px,3.13vw,54px)]"
              >

                {/* Messages */}
                <div className="space-y-[clamp(20px,1.74vw,30px)]">
                  <AnimatePresence initial={false}>
                    {(step === "confirm" ? [] : messages).map((msg) =>
                      msg.role === "user" ? (
                        <motion.div
                          key={msg.id}
                          initial={{ opacity: 1 }}
                          animate={{ opacity: 1 }}
                          className="flex items-center justify-between gap-[clamp(12px,1.4vw,24px)] py-[clamp(9px,0.75vw,13px)]"
                          style={{
                            borderTop: "1px solid rgba(0,0,0,0.3)",
                            borderBottom: "1px solid rgba(0,0,0,0.3)",
                          }}
                        >
                          <span
                            className="shrink-0"
                            style={{
                              fontFamily: "var(--font-display)",
                              fontSize: "var(--fs-meta)",
                              lineHeight: 1.2,
                              color: "rgba(0,0,0,0.4)",
                            }}
                          >
                            <span className="sr-only">You said at </span>_
                            {formatTime(msg.timestamp)}
                          </span>
                          <p
                            className="whitespace-pre-wrap text-right"
                            style={{
                              fontFamily: "var(--font-display)",
                              fontSize: "var(--fs-msg)",
                              lineHeight: 1.2,
                              color: "rgba(0,0,0,0.4)",
                            }}
                          >
                            <TypewriterText
                              text={msg.content}
                              messageId={msg.id}
                              animate={msg.id === typingMessageId}
                              onComplete={completeTypingMessage}
                            />
                          </p>
                        </motion.div>
                      ) : (
                        <motion.div
                          key={msg.id}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ duration: 0.12 }}
                        >
                          <p
                            className="mb-[10px]"
                            style={{
                              fontFamily: "var(--font-display)",
                              fontSize: "var(--fs-meta)",
                              lineHeight: 1.2,
                              color: "rgba(0,0,0,0.4)",
                            }}
                          >
                            <span className="sr-only">Vera said at </span>_
                            {formatTime(msg.timestamp)}
                          </p>
                          <p
                            className="whitespace-pre-wrap"
                            style={{
                              fontFamily: "var(--font-display)",
                              fontSize: "var(--fs-msg)",
                              lineHeight: 1.4,
                              color: "#000",
                            }}
                          >
                            <TypewriterText
                              text={msg.content}
                              messageId={msg.id}
                              animate={msg.id === typingMessageId}
                              onComplete={completeTypingMessage}
                            />
                          </p>
                        </motion.div>
                      )
                    )}
                  </AnimatePresence>

                  {/* ── Confidential summary ── */}
                  {step === "summary" && !isTyping && (
                    <motion.div
                      key="summary"
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -5 }}
                      transition={{ duration: 0.2 }}
                    >
                      <section aria-labelledby="summary-step-title" className="my-6 border border-black/15 p-5 sm:p-8">
                        <h2 id="summary-step-title" tabIndex={-1} className="mb-5 outline-none" style={{ fontFamily: "var(--font-display)", fontSize: "clamp(1.25rem,1.8vw,1.75rem)", lineHeight: 1.25 }}>
                          Write the summary legal organizations will see
                        </h2>
                        <SummaryComposer value={listingDraft} onChange={draft => { setListingDraft(draft); if (listingError) setListingError(""); }} />
                        {listingError && <p role="alert" className="mt-5 text-sm text-red-800">{listingError}</p>}
                        <div className="mt-8 flex flex-wrap items-center justify-between gap-4">
                          {canGoBack ? <BackButton onClick={handleGoBack} /> : <span />}
                          <SendButton label="Continue" onClick={handleSummaryContinue} />
                        </div>
                      </section>
                    </motion.div>
                  )}

                  {/* ── Confirm ── */}
                  {step === "confirm" && !isTyping && (
                    <motion.div
                      key="confirm"
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -5 }}
                      transition={{ duration: 0.2 }}
                    >
                      <section aria-labelledby="confirm-title" className="min-h-[65vh] py-2 text-black">
                        <h2 id="confirm-title" tabIndex={-1} className="mb-6 outline-none" style={{ fontFamily: "var(--font-display)", fontSize: "clamp(1.25rem,1.8vw,1.75rem)", lineHeight: 1.25 }}>
                          Review your report
                        </h2>
                        {confidential ? <>
                          <ConfidentialReview description={formData.description} files={files}
                            contacts={formData.contacts} draft={listingDraft}
                            onDescriptionChange={description => setFormData(previous => ({ ...previous, description }))}
                            onContactsChange={contacts => setFormData(previous => ({ ...previous, contacts }))}
                            onDraftChange={setListingDraft} />
                          <WhoCanSee className="mb-8" />
                          <p className="mb-3 max-w-[62ch] text-sm">{CONFIDENTIAL_METADATA_NOTICE}</p>
                          {releaseIdentity ? <ConfidentialReleaseIdentity identity={releaseIdentity} />
                            : releaseIdentityFailed ? (
                              <div role="alert" data-testid="release-identity-failed" className="mb-4 max-w-[62ch] text-sm">
                                <p>Submission unavailable. Try reconnecting.</p>
                                <p className="mt-2 text-black/60">Your draft is still on this page.</p>
                                <button type="button" className="mt-3 underline underline-offset-4" onClick={() => setReleaseIdentityAttempt(n => n + 1)}>
                                  Try again
                                </button>
                              </div>
                            ) : <p role="status" className="mb-4 text-sm">Checking VERA’s secure service…</p>}
                        </> : <>
                          <p className="mb-5 bg-red-50 p-3 text-sm font-bold text-red-800">{LEGACY_ADMIN_DISCLOSURE}</p>
                          <SubmitterDisclosureFields contacts={formData.contacts} value={formData} onChange={updates => setFormData(prev => ({ ...prev, ...updates }))} />
                        </>}
                        {confidential && confidentialFailure && (
                          <div role="alert" data-failure={confidentialFailure.reason} className="mt-6 max-w-[62ch] border border-black/30 p-4 text-sm"
                            style={{ borderWidth: confidentialFailure.reason === 'verification' ? 2 : 1 }}>
                            {confidentialFailure.reason === 'verification' && <p className="mb-1 font-semibold">Possible security problem</p>}
                            <p>{confidentialFailure.message}</p>
                            <p className="mt-2 text-black/60">{CONFIDENTIAL_SUBMIT_NEXT_STEP[confidentialFailure.reason] ?? CONFIDENTIAL_SUBMIT_NEXT_STEP.refused}</p>
                            {confidentialFailure.sameReport && <p className="mt-2 text-black/60">{SAME_REPORT_RETRY_NOTE}</p>}
                          </div>
                        )}
                        {confidential && uploadPaused && (
                          <div role="alert" className="mt-6 border border-black/30 p-4 text-sm">
                            <p>{uploadPaused}</p>
                            <p className="mt-2 text-black/60">Keep this page open and your files where they are. Parts already sent are kept for 12 hours.</p>
                            <button type="button" className="mt-3 underline underline-offset-4" onClick={discardPendingConfidential}>
                              Start over instead
                            </button>
                          </div>
                        )}
                        <div className="mt-8 flex justify-end">
                          <SendButton label={confidential && uploadPaused ? "Resume upload" : "Submit Report"}
                            disabled={confidential && (!releaseIdentity || channelState === 'pending')} onClick={handleConfirm} />
                        </div>
                      </section>
                      {canGoBack && <BackButton onClick={handleGoBack} />}
                    </motion.div>
                  )}

                  {/* Typing and submission indicator */}
                  <AnimatePresence>
                    {((isTyping && !typingMessageId) || step === "submitting") && (
                      <motion.div
                        initial={{ opacity: 0, y: 5 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="flex items-center gap-[8px]"
                      >
                        {[0, 1, 2].map((i) => (
                          <motion.span
                            key={i}
                            className="block size-[8px]"
                            style={{ backgroundColor: "rgba(0,0,0,0.4)" }}
                            animate={{ opacity: [0.2, 0.7, 0.2] }}
                            transition={{
                              duration: 1.2,
                              repeat: Infinity,
                              delay: i * 0.2,
                            }}
                          />
                        ))}
                        <span
                          className="ml-[4px] uppercase"
                          style={{
                            fontFamily: "var(--font-display)",
                            fontSize: "var(--fs-label)",
                            letterSpacing: "1px",
                            color: "rgba(0,0,0,0.4)",
                          }}
                          aria-live="polite"
                        >
                          {step === "submitting" ? submittingLabel : "Vera is typing"}
                        </span>
                      </motion.div>
                    )}
                  </AnimatePresence>
                  {step === "submitting" && submittingProgress && submittingProgress.bytesTotal > 0 && (
                    <div className="mt-[12px] max-w-[420px]">
                      <div role="progressbar" aria-label="Encrypted file transfer" aria-valuemin={0} aria-valuemax={100}
                        aria-valuenow={percent(submittingProgress)} className="h-[4px] w-full bg-black/10">
                        <div className="h-full bg-black transition-[width] duration-300" style={{ width: `${percent(submittingProgress)}%` }} />
                      </div>
                      {uploadingFiles && (
                        <button type="button" onClick={() => uploadAbort.current?.abort()}
                          className="mt-[12px] underline underline-offset-4 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black">
                          Pause upload
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </motion.div>
            )}

            {/* ── Saved report receipt ── */}
            {step === "submitted" && confidentialReceipt && (
              <motion.div
                key="confidential-submitted-view"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                onAnimationStart={() => {
                  // Open at the top so the recovery code is the first thing seen and read.
                  if (scrollRef.current) scrollRef.current.scrollTop = 0;
                  confidentialHeadingRef.current?.focus({ preventScroll: true });
                }}
                className="mx-auto w-full max-w-[var(--col-max)] px-[var(--col-pad)] py-[clamp(32px,3.7vw,64px)]"
              >
                <h2 ref={confidentialHeadingRef} tabIndex={-1} className="mb-6 uppercase outline-none" style={{ fontFamily: "var(--font-display)", fontWeight: 600, fontSize: "var(--fs-meta)", letterSpacing: "2px" }}>
                  Report Submitted
                </h2>
                <p className="mb-6 max-w-[62ch] leading-relaxed">Your report has been submitted. Registered legal organizations can now request to view your evidence. Only the legal organizations you approve can see your confidential information.</p>
                <RecoveryReceipt {...confidentialReceipt} onSaved={() => setReceiptSaved(true)} />
                {/* Both links stay behind the leave-page warning until the backup is checked. */}
                <div className="mt-[clamp(24px,2.3vw,40px)] flex flex-wrap items-center gap-[12px]">
                  <Link
                    href="/status"
                    className="inline-flex items-center gap-[8px] bg-[#f2f2f2] px-[16px] py-[12px] transition-colors duration-200 hover:bg-[#e6e6e6] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2"
                    style={{ fontFamily: "var(--font-sans)", fontWeight: 500, fontSize: "13px", lineHeight: "16px", color: "rgba(0,0,0,0.6)" }}
                  >
                    <ShieldCheck className="size-[14px]" aria-hidden />
                    Go to the status page
                  </Link>
                  <Link
                    href="/"
                    className="inline-flex items-center gap-[4px] uppercase transition-opacity duration-200 hover:opacity-60"
                    style={{ fontFamily: "var(--font-display)", fontWeight: 600, fontSize: "var(--fs-label)", letterSpacing: "1px", color: "rgba(0,0,0,0.4)" }}
                  >
                    <ChevronLeft className="size-[14px]" />
                    Back to home
                  </Link>
                </div>
              </motion.div>
            )}
            {step === "submitted" && !confidentialReceipt && (
              <motion.div
                key="submitted-view"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                onAnimationStart={() => {
                  if (scrollRef.current) scrollRef.current.scrollTop = 0;
                }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.5 }}
                className="mx-auto w-full max-w-[var(--col-max)] px-[var(--col-pad)] py-[clamp(32px,3.7vw,64px)]"
              >
                <div className="w-full">
                  <div>
                    <div
                      className="mb-[clamp(24px,2.3vw,40px)] flex items-center gap-[12px] pb-[clamp(12px,1.16vw,20px)]"
                      style={{ borderBottom: "1px solid rgba(0,0,0,0.12)" }}
                    >
                      <span
                        className="block shrink-0"
                        style={{ width: "var(--tick-w)", height: "var(--tick-h)", backgroundColor: "#000" }}
                        aria-hidden="true"
                      />
                      <span
                        className="uppercase"
                        style={{
                          fontFamily: "var(--font-display)",
                          fontWeight: 600,
                          fontSize: "var(--fs-meta)",
                          letterSpacing: "2px",
                          lineHeight: 1,
                          color: "#000",
                        }}
                      >
                        Report Submitted
                      </span>
                    </div>
                    <div>
                      <motion.div
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.2 }}
                        className="mb-[clamp(20px,1.85vw,32px)] flex size-[40px] items-center justify-center bg-black"
                      >
                        <Check className="size-[20px] text-white" />
                      </motion.div>
                      <p className="mb-[8px]" style={fieldLabelStyle}>
                        Your Report ID
                      </p>
                      <p
                        className="vera-doc-id break-all select-all mb-[clamp(24px,2.3vw,40px)]"
                        style={{ fontSize: "clamp(1.25rem, 1.85vw, 2rem)", color: "#000" }}
                      >
                        {reportId}
                      </p>
                      <div className="mb-6 border border-red-700 bg-red-50 p-4">
                        <p className="mb-2 font-semibold text-red-800">IMPORTANT: Save your Report ID before leaving: you need it to check progress.</p>
                        <p className="mb-4 text-red-800">Without your Report ID, you won’t be able to check your report’s status. Copy it or download your key now and keep it somewhere safe.</p>
                        <div className="flex flex-wrap gap-3">
                          <OptionButton onClick={copyReportId} active={copied} aria-label="Copy submission ID" aria-live="polite">
                            {copied ? <Check className="size-[14px]" /> : <Copy className="size-[14px]" />}
                            {copied ? "Copied" : "Copy"}
                          </OptionButton>
                          <OptionButton onClick={downloadReportKey}>
                            <Download className="size-[14px]" />
                            Download key
                          </OptionButton>
                        </div>
                        {receiptCopyError && <p role="alert" className="mt-3">Copy failed. Try again or select and save your submission ID above before leaving.</p>}
                      </div>
                      <p
                        className="mb-[16px] max-w-[62ch]"
                        style={{
                          fontFamily: "var(--font-display)",
                          fontSize: "var(--fs-meta)",
                          lineHeight: 1.5,
                          color: "rgba(0,0,0,0.6)",
                        }}
                      >
                        Treat your Report ID as a password: anyone with it can read your report status.
                      </p>
                      <p
                        className="mb-[clamp(24px,2.3vw,40px)] max-w-[62ch]"
                        style={{
                          fontFamily: "var(--font-display)",
                          fontSize: "var(--fs-meta)",
                          lineHeight: 1.5,
                          color: "rgba(0,0,0,0.4)",
                        }}
                      >
                        Your report is ready for review. Keep your Report ID to check progress. Authorized administrators can use your supplied contact methods for follow-up.
                      </p>

                      {/* Proof progress is available even before proof metadata exists. */}
                      <div className="mb-[clamp(24px,2.3vw,40px)]" style={{ border: "1px solid rgba(0,0,0,0.12)" }}>
                        <div className="px-[16px] py-[12px]" style={{ borderBottom: "1px solid rgba(0,0,0,0.12)" }}>
                          <span className="inline-flex items-center gap-[6px]" style={fieldLabelStyle}>
                            <ShieldCheck className="size-[12px]" />
                            Blockchain Proof
                          </span>
                        </div>
                        <div className="space-y-[10px] p-[16px] text-left">
                          <div className="flex justify-between items-center">
                            <span style={proofKeyStyle}>Status:</span>
                            {proofSummary.state === "verified" ? (
                              <span className="inline-flex items-center gap-[6px]" style={proofValueStyle}>
                                <Check className="size-[12px]" strokeWidth={2.5} />
                                {proofSummary.label}
                              </span>
                            ) : (
                              <span
                                style={{
                                  fontFamily: "var(--font-display)",
                                  fontSize: "var(--fs-label)",
                                  color: proofSummary.state === "failed" ? "#b91c1c" : proofSummary.state === "not_applicable" ? "rgba(0,0,0,0.6)" : "#92400e",
                                }}
                              >
                                {proofSummary.label}
                              </span>
                            )}
                          </div>
                          <p role="status" style={{ ...proofKeyStyle, lineHeight: 1.5 }}>
                            {proofStatus === "pending"
                              ? "Your report is saved. Its blockchain proof is pending and should take about 30 seconds to verify. This section updates automatically when the proof status changes."
                              : proofSummary.message}
                          </p>
                          {zkProof && (
                            <>
                              <div className="flex justify-between items-center">
                                <span style={proofKeyStyle}>Proof Hash:</span>
                                <span className="font-mono" style={proofMonoStyle}>
                                  {zkProof.proofHash.substring(0, 16)}...
                                </span>
                              </div>
                              {zkProof.nullifier && <div className="flex justify-between items-center">
                                <span style={proofKeyStyle}>Nullifier:</span>
                                <span className="font-mono" style={proofMonoStyle}>
                                  {zkProof.nullifier.substring(0, 12)}...
                                  {zkProof.nullifier.substring(52, 64)}
                                </span>
                              </div>}
                              {zkProof.publicSignals && <div className="flex justify-between items-center">
                                <span style={proofKeyStyle}>Public Signals:</span>
                                <span style={proofValueStyle}>{zkProof.publicSignals.length} parameters</span>
                              </div>}
                              <div className="flex justify-between items-center">
                                <span style={proofKeyStyle}>Transaction:</span>
                                {zkProof.txHash ? (
                                  proofExplorerUrl ? (
                                    <Link
                                      href={proofExplorerUrl}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="font-mono inline-flex items-center gap-1 hover:underline"
                                      style={{ fontSize: "var(--fs-label)", color: "#000" }}
                                    >
                                      {zkProof.txHash.substring(0, 10)}...{zkProof.txHash.substring(zkProof.txHash.length - 10)}
                                      <ExternalLink className="size-2.5" />
                                    </Link>
                                  ) : (
                                    <span className="font-mono" style={proofMonoStyle}>
                                      {zkProof.txHash.substring(0, 10)}...{zkProof.txHash.substring(zkProof.txHash.length - 10)}
                                    </span>
                                  )
                                ) : (
                                  <span
                                    style={{
                                      fontFamily: "var(--font-display)",
                                      fontSize: "var(--fs-label)",
                                      color: "#b45309",
                                    }}
                                  >
                                    Not recorded on-chain
                                  </span>
                                )}
                              </div>
                              {zkProof.txHash && (
                                <div className="flex justify-between items-center">
                                  <span style={proofKeyStyle}>Network:</span>
                                  <span style={proofValueStyle}>{receiptNetworkLabel(readReceiptNetwork(zkProof))}</span>
                                </div>
                              )}
                              {proofSummary.state === "verified" && (
                                <div className="flex justify-between items-center">
                                  <span style={proofKeyStyle}>Double Submission:</span>
                                  <span className="inline-flex items-center gap-[6px]" style={proofValueStyle}>
                                    <Check className="size-[12px]" strokeWidth={2.5} />
                                    Prevented
                                  </span>
                                </div>
                              )}
                              <div className="flex justify-between items-center">
                                <span style={proofKeyStyle}>Account Required:</span>
                                <span className="inline-flex items-center gap-[6px]" style={proofValueStyle}>
                                  <Check className="size-[12px]" strokeWidth={2.5} />
                                  No
                                </span>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-[12px]">
                        <a href="/status">
                          <OptionButton>
                            <ShieldCheck className="size-[14px]" />
                            Check Status
                          </OptionButton>
                        </a>
                      </div>
                    </div>
                  </div>
                  <div className="mt-[clamp(24px,2.3vw,40px)] flex items-center">
                    <Link
                      href="/"
                      className="inline-flex items-center gap-[4px] uppercase transition-opacity duration-200 hover:opacity-60"
                      style={{
                        fontFamily: "var(--font-display)",
                        fontWeight: 600,
                        fontSize: "var(--fs-label)",
                        letterSpacing: "1px",
                        color: "rgba(0,0,0,0.4)",
                      }}
                    >
                      <ChevronLeft className="size-[14px]" />
                      Back to Home
                    </Link>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </main>

        {/* ── Input Area ── */}
        {!["submitted", "submitting", "confirm", "summary"].includes(step) && (
          <div className="relative z-10 shrink-0 bg-white">
            <div className="mx-auto w-full max-w-[var(--col-max)] px-[var(--col-pad)] pb-[clamp(20px,1.85vw,32px)] pt-[clamp(12px,1.16vw,20px)]">
              <AnimatePresence mode="wait">
                {/* ── Contact methods ── */}
                {step === "contact" && !isTyping && (
                  <motion.div
                    key="contact"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.2 }}
                  >
                    <form className="space-y-4" onSubmit={event => { event.preventDefault(); handleContactsSubmit(); }}>
                      <p className="text-sm"><strong>Add at least one contact method.</strong> You can add more than one.</p>
                      {(Object.keys(CONTACT_LABELS) as (keyof ReportContacts)[]).map(method => <label key={method} className="block text-sm">
                        {CONTACT_LABELS[method]}
                        <input className="mt-2 block w-full border border-black/30 bg-transparent px-3 py-3" type={method === 'email' ? 'email' : 'text'}
                          autoComplete="off" autoCapitalize="off" spellCheck={false} maxLength={250}
                          placeholder={method === 'email' ? 'you@example.com' : method === 'signal' ? 'Username, phone number, or Signal link' : 'Email address or phone number'}
                          value={formData.contacts[method]} onChange={event => { setContactError(''); setFormData(previous => ({ ...previous, contacts: { ...previous.contacts, [method]: event.target.value } })); }} />
                      </label>)}
                      {contactError && <p role="alert" className="text-sm text-red-700">{contactError}</p>}
                      <button className="border border-black bg-black px-4 py-3 text-white" type="submit">Continue</button>
                    </form>
                  </motion.div>
                )}

                {/* ── Category ── */}
                {step === "category" && !isTyping && (
                  <motion.div
                    key="category"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.2 }}
                  >
                    <div className="flex flex-wrap gap-[12px]">
                      {CATEGORIES.map((cat) => (
                        <OptionButton key={cat.value} onClick={() => handleCategorySelect(cat.value)}>
                          {cat.label}
                        </OptionButton>
                      ))}
                    </div>
                  </motion.div>
                )}

                {/* ── Report (description) ── */}
                {step === "report" && !isTyping && (
                  <motion.div
                    key="report"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.2 }}
                  >
                    <div
                      className="flex min-h-[clamp(104px,7.29vw,126px)] flex-col p-[10px]"
                      style={{ border: "1px solid rgba(0,0,0,0.3)" }}
                    >
                      <Textarea
                        data-slot="textarea"
                        // Confidential text must not reach a cloud spelling service
                        // (browser "enhanced" spell check sends field contents out).
                        spellCheck={!confidential}
                        autoCorrect={confidential ? "off" : undefined}
                        placeholder="Describe what happened"
                        value={textInput}
                        onChange={(e) => setTextInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        rows={2}
                        className="min-h-[52px] flex-1 resize-none rounded-none border-none bg-transparent p-0 shadow-none placeholder:text-[#999] focus-visible:border-none focus-visible:ring-0 dark:bg-transparent"
                        style={{
                          fontFamily: "var(--font-display)",
                          fontSize: "var(--fs-msg)",
                          lineHeight: 1.4,
                          color: "#000",
                          fieldSizing: "fixed",
                          outline: "none",
                          boxShadow: "none",
                        }}
                      />
                      <div className="mt-[8px] flex items-end justify-between gap-[12px]">
                        <p
                          className="hidden sm:block"
                          style={{
                            fontFamily: "var(--font-display)",
                            fontSize: "var(--fs-label)",
                            color: "rgba(0,0,0,0.35)",
                          }}
                        >
                          Enter to send · Shift+Enter for new line
                        </p>
                        <SendButton
                          onClick={handleReportSubmit}
                          disabled={!textInput.trim()}
                          className="ml-auto"
                        />
                      </div>
                    </div>
                    {canGoBack && (
                      <div className="mt-[12px]">
                        <BackButton onClick={handleGoBack} />
                      </div>
                    )}
                  </motion.div>
                )}

                {/* ── Files ── */}
                {step === "files" && !isTyping && (
                  <motion.div
                    key="files"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.2 }}
                  >
                    <div className="space-y-[12px]">
                      <input
                        ref={fileInputRef}
                        type="file"
                        multiple
                        accept={EVIDENCE_FILE_ACCEPT}
                        className="hidden"
                        onChange={handleFileChange}
                        aria-describedby="evidence-limits"
                      />
                      {confidential ? <>
                        <p id="evidence-limits" className="text-sm text-black/70">{CONFIDENTIAL_EVIDENCE_LIMIT_TEXT}</p>
                        <p className="text-xs text-neutral-500">{EVIDENCE_FILE_TYPES_LABEL}. Remove hidden details, such as photo location or document author, before attaching.</p>
                      </> : <>
                        <p id="evidence-limits" className="text-xs text-neutral-500">{EVIDENCE_FILE_TYPES_LABEL}. Up to 5 files. {EVIDENCE_SIZE_LABEL}</p>
                        <p className="text-xs text-neutral-500">PDFs retain their text and forms. Signed PDFs, attachments and unsupported embedded content are rejected rather than altered.</p>
                      </>}
                      {files.length > 0 && (
                        <div className="flex flex-wrap gap-[8px]">
                          {files.map((file, i) => (
                            <span
                              key={`${file.name}-${i}`}
                              className="flex items-center gap-[8px] bg-[#f2f2f2] px-[12px] py-[8px]"
                              style={{
                                fontFamily: "var(--font-sans)",
                                fontSize: "12px",
                                color: "rgba(0,0,0,0.6)",
                              }}
                            >
                              <Paperclip className="size-[12px] shrink-0" />
                              <span className="max-w-[140px] truncate">{file.name}</span>
                              <button
                                type="button"
                                onClick={() => removeFile(i)}
                                aria-label={`Remove ${file.name}`}
                                className="transition-opacity hover:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black"
                              >
                                <X className="size-[12px]" />
                              </button>
                            </span>
                          ))}
                        </div>
                      )}
                      <div className="flex flex-wrap items-center gap-[12px]">
                        <OptionButton onClick={() => fileInputRef.current?.click()}
                          disabled={confidential && files.length >= CONFIDENTIAL_MAX_FILES}>
                          {files.length > 0 ? "Add more files" : "Attach files"}
                        </OptionButton>
                        {files.length > 0 ? (
                          <SendButton label="Continue" onClick={handleFilesContinue} />
                        ) : (
                          <OptionButton onClick={handleFilesSkip}>Skip</OptionButton>
                        )}
                      </div>
                    </div>
                  </motion.div>
                )}

                {/* ── Details (urgency, location, date) ── */}
                {step === "details" && !isTyping && (
                  <motion.div
                    key="details"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.2 }}
                  >
                    <div className="space-y-[16px]">
                      {/* Urgency chips */}
                      <div>
                        <p className="mb-[8px]" style={fieldLabelStyle}>
                          Have you considered the sensitivity of this report
                        </p>
                        <div className="flex flex-wrap gap-[12px]">
                          {URGENCY_LEVELS.map((level) => (
                            <OptionButton
                              key={level.value}
                              active={formData.urgency === level.value}
                              aria-pressed={formData.urgency === level.value}
                              onClick={() =>
                                setFormData((prev) => ({
                                  ...prev,
                                  urgency:
                                    prev.urgency === level.value
                                      ? ""
                                      : level.value,
                                }))
                              }
                            >
                              {level.label}
                            </OptionButton>
                          ))}
                        </div>
                      </div>

                      {/* Location + Date row */}
                      <div className="grid grid-cols-1 gap-[16px] sm:grid-cols-2">
                        <div>
                          <label
                            htmlFor="report-location"
                            className="mb-[8px] block"
                            style={fieldLabelStyle}
                          >
                            Location
                          </label>
                          <Input
                            id="report-location"
                            type="text"
                            spellCheck={!confidential}
                            placeholder="Where did it happen?"
                            value={formData.location}
                            onChange={(e) =>
                              setFormData((prev) => ({
                                ...prev,
                                location: e.target.value,
                              }))
                            }
                            className="h-[42px] rounded-none border-0 bg-transparent px-0 shadow-none placeholder:text-[#999] focus-visible:border-none focus-visible:ring-0 dark:bg-transparent"
                            style={{
                              borderBottom: "1px solid rgba(0,0,0,0.3)",
                              fontFamily: "var(--font-display)",
                              fontSize: "var(--fs-meta)",
                              color: "#000",
                            }}
                          />
                        </div>
                        <fieldset className="sm:col-span-2">
                          <legend className="mb-[8px]" style={fieldLabelStyle}>
                            Is this tied to a date or timeframe?
                          </legend>
                          <div className="mb-3 inline-flex border border-black/30 p-1" role="radiogroup" aria-label="Incident date type">
                            {([['date', 'Date'], ['timeframe', 'Timeframe']] as const).map(([mode, label]) => (
                              <label key={mode} className={`relative cursor-pointer px-4 py-2 text-sm focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-black ${formData.incidentDateMode === mode ? "bg-black text-white" : "text-black"}`}>
                                <input className="absolute inset-0 h-full w-full cursor-pointer opacity-0" type="radio" name="incident-date-mode" value={mode}
                                  checked={formData.incidentDateMode === mode}
                                  onChange={() => setFormData(prev => ({ ...prev, incidentDateMode: mode, incidentEndDate: mode === 'date' ? '' : prev.incidentEndDate }))}
                                />
                                {label}
                              </label>
                            ))}
                          </div>
                          <p className="mb-3 text-sm text-black/60">{formData.incidentDateMode === 'date' ? 'Choose a date, or leave it blank if you’re unsure.' : 'Choose a start and end date, or leave both blank if you’re unsure.'}</p>
                          <div className="grid grid-cols-1 gap-[16px] sm:grid-cols-2">
                            <div>
                              <label htmlFor="report-date-start" className="mb-[8px] block" style={fieldLabelStyle}>{formData.incidentDateMode === "date" ? "Date" : "Start date"}</label>
                              <Input
                                id="report-date-start"
                                type="date"
                                // A report describes something that already
                                // happened; the picker used to accept 2099 (#853).
                                max={formData.incidentEndDate || maxIncidentDate()}
                                value={formData.dateOfIncident}
                                onChange={(e) =>
                                  setFormData((prev) => ({
                                    ...prev,
                                    dateOfIncident: e.target.value,
                                  }))
                                }
                                className="h-[42px] rounded-none border-0 bg-transparent px-0 shadow-none focus-visible:border-none focus-visible:ring-0 dark:bg-transparent"
                                style={{
                                  borderBottom: "1px solid rgba(0,0,0,0.3)",
                                  fontFamily: "var(--font-display)",
                                  fontSize: "var(--fs-meta)",
                                  color: "#000",
                                }}
                              />
                            </div>
                            {formData.incidentDateMode === "timeframe" && <div>
                              <label htmlFor="report-date-end" className="mb-[8px] block" style={fieldLabelStyle}>End date</label>
                              <Input
                                id="report-date-end"
                                type="date"
                                // A report describes something that already
                                // happened; the picker used to accept 2099 (#853).
                                max={maxIncidentDate()}
                                min={formData.dateOfIncident || undefined}
                                value={formData.incidentEndDate}
                                onChange={(e) =>
                                  setFormData((prev) => ({
                                    ...prev,
                                    incidentEndDate: e.target.value,
                                  }))
                                }
                                className="h-[42px] rounded-none border-0 bg-transparent px-0 shadow-none focus-visible:border-none focus-visible:ring-0 dark:bg-transparent"
                                style={{
                                  borderBottom: "1px solid rgba(0,0,0,0.3)",
                                  fontFamily: "var(--font-display)",
                                  fontSize: "var(--fs-meta)",
                                  color: "#000",
                                }}
                              />
                            </div>}
                          </div>
                        </fieldset>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center justify-between gap-[12px] pt-[4px]">
                        {canGoBack ? <BackButton onClick={handleGoBack} /> : <div />}
                        <SendButton label="Ready to submit" onClick={handleDetailsSubmit} />
                      </div>
                    </div>
                  </motion.div>
                )}

                {/* ── Jurisdiction (Phase 4c) ── */}
                {step === "jurisdiction" && !isTyping && (
                  <motion.div
                    key="jurisdiction"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.2 }}
                  >
                    <div className="flex flex-wrap gap-[12px]">
                      {JURISDICTIONS.map((j) => (
                        <OptionButton
                          key={j.value}
                          onClick={() => handleJurisdictionSelect(j.value)}
                        >
                          {j.label}
                        </OptionButton>
                      ))}
                    </div>
                  </motion.div>
                )}

              </AnimatePresence>
              {canGoBack && !["report", "details"].includes(step) && (
                <div className="mt-[12px]">
                  <BackButton onClick={handleGoBack} />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Privacy footer */}
        <div className="relative z-10 mx-auto w-full max-w-[var(--col-max)] shrink-0 px-[var(--col-pad)] pb-[clamp(14px,1.16vw,20px)]">
          <div className="flex items-center gap-[6px]">
            <ShieldCheck className="size-[12px]" style={{ color: "rgba(0,0,0,0.4)" }} />
            <span
              className="uppercase"
              style={{
                fontFamily: "var(--font-display)",
                fontWeight: 600,
                fontSize: "var(--fs-label)",
                letterSpacing: "1px",
                color: "rgba(0,0,0,0.4)",
              }}
            >
              No account required
            </span>
          </div>
          {confidential ? <SecurityDetails className="mt-2" />
            : <p className="mt-2 text-sm font-bold text-red-800">{LEGACY_ADMIN_DISCLOSURE}</p>}
        </div>
      </div>
    </>
  );
}

// Per-request rendering binds the intake CSP nonce to this response.
export const getServerSideProps = async () => ({ props: {} });
