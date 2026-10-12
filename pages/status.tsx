import { takeRecoveryLink } from '@/lib/confidential/recoveryLink';
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import Head from "next/head";
import { motion, AnimatePresence } from "motion/react";
import { toast } from "sonner";
import {
  Search,
  FileText,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ArrowLeft,
  CircleDot,
  ExternalLink,
} from "lucide-react";
import { VeraReportLogo } from "@/components/vera/VeraReportLogo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  mapBackendStatus,
  buildTimeline,
  classifyLookupStatus,
  lookupFailureMessage,
  CREDENTIAL_EXAMPLE,
  ReportLookupError,
  TRACKING_ID_PATTERN,
  type TimelineEntry,
} from "@/lib/reportStatus";
import { categoryLabel } from "@/lib/reportCategories";
import { confidentialCasesEnabled } from "@/lib/confidential/config";
import { formatRecoveryCode, recoveryCodeProblem, recoveryCodeProblemText, recoveryCodeShape } from "@/enclave/src/confidential/recoveryCode";
import { RecoveryFileDrop } from "@/components/vera/confidential/RecoveryFileDrop";
import { SecurityDetails } from "@/components/vera/confidential/SecurityDetails";
import { OtherWaysToOpen, SavedWorkspaces, useParticipantLock } from '@/components/vera/confidential/DeviceWorkspaces';
import { statusWorkspaceUnlocked } from '@/lib/confidential/participantLock';
import { markDeviceLocked, readOwnerWorkspace } from '@/lib/confidential/deviceWorkspace';
import type { UnlockedVault } from '@/lib/confidential/deviceVault';
import type { CheckpointPin } from '@/enclave/src/confidential/recovery';
import { ConfidentialCaseStatus } from "@/components/vera/confidential/ConfidentialCaseStatus";
import {
  getReportProofSummary,
  readReportProofStatus,
  readReceiptNetwork,
  receiptExplorerUrl,
  receiptNetworkLabel,
  type ReportProofStatus,
  type ReportProofReference,
} from "@/lib/reportProof";

/* ─── Types ─── */
interface DisseminationChannelStatus {
  entityId: string;
  entityName: string;
  state: string;
  receipted: boolean;
}

interface RelayMessage {
  direction: "to-reporter" | "from-reporter";
  entityName?: string;
  body: string;
  at: string;
}

interface ReportStatus {
  id: string;
  title: string;
  category: string;
  urgency: string;
  submittedAt: string;
  currentStatus: string;
  assignedTeam: string;
  timeline: TimelineEntry[];
  evidenceHash?: string | null;
  ipfsHash?: string | null;
  credibilityScore?: number | null;
  proofStatus: ReportProofStatus;
  zkProof?: ReportProofReference | null;
  dissemination: DisseminationChannelStatus[];
  relay: RelayMessage[];
}

/** Reporter-friendly labels for dissemination channel states. */
const CHANNEL_STATE_LABELS: Record<string, string> = {
  approved: "Queued for submission",
  packet_ready: "Preparing submission",
  deferred: "Preparing submission",
  dispatched: "Submitted",
  receipted: "Submitted — receipt on file",
  acknowledged: "Acknowledged by recipient",
  feedback_received: "Feedback received",
  failed: "Submission delayed",
};

/* ─── Helpers ─── */
const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

// mapBackendStatus + buildTimeline live in @/lib/reportStatus (pure, unit-tested).

const urgencyColors: Record<string, string> = {
  Low: "text-blue-400 border-blue-400/30 bg-blue-400/5",
  Medium: "text-amber-400 border-amber-400/30 bg-amber-400/5",
  High: "text-orange-400 border-orange-400/30 bg-orange-400/5",
  Critical: "text-red-400 border-red-400/30 bg-red-400/5",
};

interface StatusResponse {
  success: boolean;
  trackingId: string;
  status: string;
  category?: string;
  urgency?: string;
  createdAt?: string;
  evidenceHash?: string;
  ipfsHash?: string;
  verification?: { category?: string; credibilityScore?: number };
  proofStatus?: ReportProofStatus;
  zkProof?: ReportProofReference;
  dissemination?: DisseminationChannelStatus[];
  relay?: RelayMessage[];
}

async function fetchReportStatus(credential: string, signal: AbortSignal): Promise<ReportStatus | null> {
  const response = await fetch('/api/whistleblower/status/access', {
    headers: { 'X-Reporter-Credential': credential },
    cache: 'no-store',
    signal,
  });
  if (response.status === 404) return null;
  // A 400 (malformed credential) and a 429 (rate limit) are both answers from a
  // server that was plainly reachable. Classify them so the page can say what
  // actually happened instead of blaming the network (#853).
  if (!response.ok) throw new ReportLookupError(classifyLookupStatus(response.status));
  const data: StatusResponse = await response.json();
  if (!data?.success || typeof data.trackingId !== 'string') return null;
  // Category label from the shared taxonomy (single source of truth with the
  // /report wizard) — renders a proper label instead of a raw slug (#451).
  const categoryDisplay = data.category
    ? categoryLabel(data.category)
    : data.verification?.category
      ? categoryLabel(data.verification.category)
      : "Confidential Report";

  // Map urgency value to display label
  const urgencyLabels: Record<string, string> = {
    low: "Low",
    medium: "Medium",
    high: "High",
    critical: "Critical",
  };
  const urgencyDisplay = data.urgency
    ? urgencyLabels[data.urgency] || data.urgency
    : "Medium";

  return {
    id: data.trackingId,
    // Title is a generic descriptor; the category carries the specifics, so
    // the case file no longer prints the same value twice (#451).
    title: "Confidential Report",
    category: categoryDisplay,
    urgency: urgencyDisplay,
    submittedAt: data.createdAt || new Date().toISOString(),
    currentStatus: mapBackendStatus(data.status),
    assignedTeam: "Response Team",
    timeline: buildTimeline(data.status, data.createdAt || new Date().toISOString()),
    evidenceHash: data.evidenceHash || null,
    ipfsHash: data.ipfsHash,
    credibilityScore: data.verification?.credibilityScore,
    proofStatus: readReportProofStatus(data.proofStatus),
    zkProof: data.zkProof ?? null,
    dissemination: Array.isArray(data.dissemination) ? data.dissemination : [],
    relay: Array.isArray(data.relay) ? data.relay : [],
  };
}

export default function Status() {
  /* ── Dark mode toggle ── */
  const [isDark] = useState(false); // Light mode primary; theme toggle hidden for now

  const [query, setQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [report, setReport] = useState<ReportStatus | null>(null);
  const [searched, setSearched] = useState(false);
  const [replyText, setReplyText] = useState("");
  const [replySending, setReplySending] = useState(false);


  const [activeCredential, setActiveCredential] = useState<string | null>(null);
  // Confidential recovery codes stay on this device; they never reach the legacy lookup.
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  // Encrypted package from a recovery file or saved workspace; read locally, never uploaded.
  const [recoveryPackage, setRecoveryPackage] = useState<string | null>(null);
  // Local feedback on a mistyped recovery code. Never contains the input.
  const [codeError, setCodeError] = useState("");
  const confidential = confidentialCasesEnabled();
  const [savedVault, setSavedVault] = useState<UnlockedVault | null>(null);
  const [savedPin, setSavedPin] = useState<CheckpointPin | undefined>(undefined);
  // Bumped on every open so a newer recovery file for the report already open
  // (same recovery code) remounts the view instead of reusing the older session.
  const [openCount, setOpenCount] = useState(0);
  // Only the confidential workspace locks; a legacy credential lookup never does.
  useParticipantLock('/status', statusWorkspaceUnlocked(recoveryCode));
  const queryInput = useRef<HTMLInputElement>(null);
  const searchRequest = useRef<AbortController | null>(null);
  const revision = useRef(0);

  useEffect(() => () => searchRequest.current?.abort(), []);

  useEffect(() => {
    if (!activeCredential || replySending) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async () => {
      const requestRevision = revision.current;
      try {
        const updated = await fetchReportStatus(activeCredential, controller.signal);
        if (!controller.signal.aborted && revision.current === requestRevision && updated) {
          setReport(updated);
        }
      } catch {
        // Keep the current case visible and retry temporary lookup failures.
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(refresh, 5000);
      }
    };
    timer = setTimeout(refresh, 5000);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [activeCredential, replySending]);

  const openConfidential = (code: string, packageText: string | null, pin?: CheckpointPin, vault: UnlockedVault | null = null) => {
    searchRequest.current?.abort();
    setReport(null); setSearched(false); setActiveCredential(null); setCodeError("");
    savedVault?.lock(); setSavedVault(vault); setSavedPin(pin);
    setRecoveryPackage(packageText);
    setRecoveryCode(code);
    setOpenCount(count => count + 1);
    setQuery("");
  };
  const consumedRecoveryLink = useRef(false);
  useEffect(() => {
    if (consumedRecoveryLink.current) return;
    consumedRecoveryLink.current = true;
    const raw = takeRecoveryLink(window.location, window.history);
    if (raw === null) return;
    if (!confidential) { setCodeError('Confidential reports are not available on this site.'); return; }
    void recoveryCodeProblem(raw).then(problem => {
      if (problem) { setCodeError(recoveryCodeProblemText(problem)); return; }
      openConfidential(formatRecoveryCode(raw), null);
    }).catch(() => setCodeError('This recovery link could not be opened. Enter your recovery code instead.'));
  }, [confidential]);

  /** Opens a reporter backup file saved by an earlier version of this page. */
  const openOwnerBackup = async (payload: unknown, signal: AbortSignal) => {
    const value = await readOwnerWorkspace(payload); signal.throwIfAborted();
    openConfidential(value.recoveryCode, value.recoveryPackage, value.pin);
  };

  const handleSearch = async () => {
    const raw = query.trim();
    // Anything shaped like a recovery code stays on this device, even when mistyped.
    // Only a well-formed legacy Report ID is ever sent to the server.
    const legacyLooking = /^VR[AC]-/i.test(raw);
    if (!legacyLooking && (recoveryCodeShape(raw) || (confidential && raw))) {
      if (!confidential) { toast.error("Confidential reports are not available on this site yet."); return; }
      const problem = await recoveryCodeProblem(raw);
      if (problem) { setCodeError(recoveryCodeProblemText(problem)); queryInput.current?.focus(); return; }
      openConfidential(formatRecoveryCode(raw), null);
      return;
    }
    setCodeError("");
    const trimmed = query.trim().toUpperCase();
    if (!trimmed) {
      if (confidential) { setCodeError("Enter your recovery code, or open your recovery file."); queryInput.current?.focus(); }
      else toast.error("Please enter a report ID.");
      return;
    }
    setRecoveryCode(null); setRecoveryPackage(null);
    // Catch a malformed ID here rather than letting it round-trip to a 400 that
    // the reporter only ever saw as a network error (#853).
    if (!TRACKING_ID_PATTERN.test(trimmed)) {
      setReport(null);
      setSearched(false);
      toast.error(lookupFailureMessage("format"));
      return;
    }

    searchRequest.current?.abort();
    const controller = new AbortController();
    searchRequest.current = controller;
    revision.current += 1;
    setActiveCredential(null);
    setIsSearching(true);
    setReport(null);
    setSearched(false);

    try {
      const updated = await fetchReportStatus(trimmed, controller.signal);
      if (controller.signal.aborted) return;
      if (updated) {
        setReport(updated);
        setActiveCredential(trimmed);
      } else {
        setReport(null);
        toast.error("No report found with that ID.");
      }
    } catch (error) {
      if (controller.signal.aborted) return;
      setReport(null);
      toast.error(
        lookupFailureMessage(
          error instanceof ReportLookupError ? error.reason : "unavailable",
        ),
      );
    }

    setSearched(true);
    setIsSearching(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch();
  };

  /* ── Relay reply (Phase 3c): anonymous follow-up from this page ── */

  const handleSendReply = async () => {
    if (!report || !replyText.trim()) return;
    setReplySending(true);
    try {
      const res = await fetch(
        '/api/whistleblower/status/access/relay',
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Reporter-Credential": report.id },
          body: JSON.stringify({ message: replyText.trim() }),
        }
      );
      const data = await res.json();
      if (data.success) {
        revision.current += 1;
        setReport((current) => current?.id === report.id ? ({
          ...current,
          relay: [
            ...current.relay,
            { direction: "from-reporter", body: replyText.trim(), at: new Date().toISOString() },
          ],
        }) : current);
        setReplyText("");
        toast.success("Reply sent.");
      } else {
        toast.error(data.error || "Could not send the reply.");
      }
    } catch {
      toast.error("Unable to reach the server. Please try again.");
    }
    setReplySending(false);
  };

  // Active step derived from the built timeline (not a fixed 4-stage order), so
  // terminal timelines (declined / unknown) highlight their own final entry.
  const currentIdx = report
    ? report.timeline.findIndex((e) => e.status === report.currentStatus)
    : -1;
  const proofSummary = getReportProofSummary(report?.proofStatus, report?.zkProof);
  const proofExplorerUrl = receiptExplorerUrl(report?.zkProof, process.env.NEXT_PUBLIC_BLOCK_EXPLORER_URL, process.env.NEXT_PUBLIC_BLOCK_EXPLORER_NETWORK);

  return (
    <>
      <Head>
        <title>Status - Vera</title>
        <meta
          name="description"
          content="Track the progress of your confidential report"
        />
      </Head>

      <a
        href="#main-content"
        className="absolute left-[-9999px] focus:left-4 focus:top-4 focus:z-[100] focus:px-4 focus:py-2 focus:bg-background focus:text-foreground focus:ring-2 focus:ring-[var(--ring)] focus:ring-offset-2 focus:rounded-md focus:overflow-visible focus:w-auto focus:h-auto focus:no-underline"
      >
        Skip to main content
      </a>

      <div
        className="min-h-screen transition-colors duration-500"
        style={{ backgroundColor: "var(--vera-paper)" }}
      >
        {/* Header */}
        <header
          className="sticky top-0 z-50 backdrop-blur-xl transition-colors duration-500"
          style={{
            borderBottom: `1px solid ${isDark ? ink(4) : "rgba(0,0,0,0.08)"}`,
            backgroundColor: isDark
              ? "var(--vera-header-bg)"
              : "rgba(248,248,248,0.95)",
          }}
        >
          <div
            className="mx-auto max-w-7xl px-7 flex items-center justify-between"
            style={{ paddingTop: "0.85rem", paddingBottom: "0.85rem" }}
          >
            <Link
              href="/"
              style={{
                width: 90,
                height: 34,
                display: "block",
                overflow: "hidden",
              }}
              className="hover:opacity-80 transition-opacity"
            >
              <VeraReportLogo
                style={{
                  width: "100%",
                  height: "100%",
                  maxWidth: 90,
                  maxHeight: 34,
                  display: "block",
                  color: ink(90),
                }}
              />
            </Link>
            {/* Theme toggle hidden for now — light mode primary */}
          </div>
        </header>

        {/* Main Content */}
        <main id="main-content" className="mx-auto px-6 py-10 md:py-14 scroll-mt-4" style={{ maxWidth: confidential && recoveryCode ? "1480px" : "var(--vera-doc-max-w)" }} tabIndex={-1}>
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            {/* Classified Header */}
            <div className="mb-10">
              <div className="flex items-center gap-4 mb-6">
                <div
                  className="w-8 shrink-0"
                  style={{ height: "var(--vera-classification-bar)", backgroundColor: "var(--vera-ink)" }}
                  aria-hidden
                />
                <span
                  style={{
                    fontSize: "10px",
                    letterSpacing: "0.3em",
                    textTransform: "uppercase",
                    color: ink(45),
                  }}
                >
                  Confidential
                </span>
              </div>

              <h1
                className="font-serif mb-3"
                style={{
                  fontSize: "clamp(1.8rem, 5vw, 2.6rem)",
                  fontWeight: 300,
                  lineHeight: 1.15,
                  color: ink(85),
                }}
              >
                Report <em style={{ color: ink(50) }}>Status</em>
              </h1>

              <p
                className="max-w-lg"
                style={{ fontSize: "14px", lineHeight: 1.7, color: ink(55) }}
              >
                {confidential && recoveryCode
                  ? "Manage your report and choose which law firms can read it. Use Leave for now when you are done on this device."
                  : confidential
                  ? "Enter your recovery code, or open your recovery file, to read your report and decide who may see it."
                  : "Enter your Report ID to check progress."}
              </p>
            </div>

            {/* Hide recovery controls while a report is open. */}
            {!recoveryCode && <div
              className="py-6 pl-5 pr-4 mb-2"
              style={{ borderLeft: "3px solid var(--vera-ink)" }}
            >
              <label
                id="report-id-label"
                className="block mb-3"
                style={{
                  fontSize: "10px",
                  letterSpacing: "0.15em",
                  textTransform: "uppercase",
                  color: ink(50),
                }}
              >
                {confidential ? "Recovery code" : "Report ID"}
              </label>
              <div className="flex gap-3">
                <Input
                  id="report-id"
                  ref={queryInput}
                  type="text"
                  placeholder={confidential ? "XXXX-XXXX-XXXX-…" : `e.g. ${CREDENTIAL_EXAMPLE}`}
                  value={query}
                  onChange={(e) => { setQuery(e.target.value); if (codeError) setCodeError(""); }}
                  onKeyDown={handleKeyDown}
                  aria-labelledby="report-id-label"
                  aria-describedby={codeError ? "report-id-error report-id-hint" : "report-id-hint"}
                  aria-invalid={codeError ? true : undefined}
                  autoComplete="off"
                  // Holds a recovery code: never offered to cloud spell check or
                  // mobile autocorrect/suggestion dictionaries.
                  autoCapitalize="characters"
                  autoCorrect="off"
                  spellCheck={false}
                  className="flex-1 border-0 rounded-none bg-transparent dark:bg-transparent h-10 px-0 focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:border-none shadow-none vera-doc-id"
                  style={{
                    borderBottom: `1px solid ${ink(8)}`,
                    color: ink(75),
                    boxShadow: "none",
                  }}
                />
                <Button
                  onClick={handleSearch}
                  disabled={isSearching}
                  aria-label={isSearching ? "Searching for report" : "Retrieve report status"}
                  className="rounded-none gap-2 px-6 shrink-0 hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                  style={{
                    fontSize: "11px",
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    backgroundColor: "var(--vera-ink)",
                    color: "var(--vera-paper)",
                  }}
                >
                  {isSearching ? (
                    <div
                      className="size-4 border-2 rounded-full animate-spin"
                      style={{
                        borderColor: ink(20),
                        borderTopColor: ink(60),
                      }}
                    />
                  ) : (
                    <Search className="size-3.5" />
                  )}
                  {isSearching ? "Searching..." : "Retrieve"}
                </Button>
              </div>
              {codeError && (
                <p id="report-id-error" role="alert" className="mt-2" style={{ fontSize: "13px", color: "#b91c1c" }}>
                  {codeError}
                </p>
              )}
              <p id="report-id-hint" className="mt-2" style={{ fontSize: "11px", lineHeight: 1.6, color: ink(50) }}>
                {confidential
                  ? "Paste your recovery code (14 groups of 4 letters and numbers), or open your recovery file below. It is checked on this device and never sent to VERA. " +
                    "Older reports use a Report ID that starts with VRC- or VRA-; you can enter it here too."
                  : "Use the Report ID you saved after submitting. Reports filed here start with VRC-; older report codes start with VRA-."}
              </p>
              {confidential && (
                <div className="mt-4">
                  <RecoveryFileDrop onOpened={file => openConfidential(file.code, file.recoveryPackage)} />
                  <OtherWaysToOpen onRecovered={openOwnerBackup} />
                </div>
              )}
            </div>}

            {confidential && !recoveryCode && <SavedWorkspaces role="owner" onRecovered={openOwnerBackup} onUnlocked={async (vault, signal) => {
              const value = await readOwnerWorkspace(vault.read()); signal.throwIfAborted();
              openConfidential(value.recoveryCode, value.recoveryPackage, value.pin, vault);
            }} />}
            {recoveryCode && (
              <ConfidentialCaseStatus key={`open-${openCount}`} recoveryCode={recoveryCode}
                recoveryPackage={recoveryPackage} savedVault={savedVault} savedPin={savedPin} onClose={() => {
                  markDeviceLocked(); setQuery(""); setCodeError("");
                  savedVault?.lock(); setSavedVault(null); setSavedPin(undefined); setRecoveryCode(null); setRecoveryPackage(null);
                }} />
            )}

            {/* Results */}
            <AnimatePresence mode="wait">
              {searched && !report && (
                <motion.div
                  key="not-found"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.35 }}
                  className="mt-10 text-center py-16"
                  role="status"
                  aria-live="polite"
                >
                  <AlertTriangle
                    className="size-8 mx-auto mb-4"
                    style={{ color: ink(45) }}
                    aria-hidden
                  />
                  <p
                    className="font-serif"
                    style={{
                      fontSize: "18px",
                      fontWeight: 300,
                      color: ink(60),
                    }}
                  >
                    No report found
                  </p>
                  <p
                    className="mt-2"
                    style={{
                      fontSize: "13px",
                      lineHeight: 1.6,
                      color: ink(55),
                    }}
                  >
                    The report ID you entered does not match any records. Please
                    verify the ID and try again.
                  </p>
                </motion.div>
              )}

              {report && (
                <motion.div
                  key="result"
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.4 }}
                  className="mt-10"
                >
                  {/* Case Summary */}
                  <div
                    className="mb-8"
                    style={{ border: `1px solid ${ink(6)}`, borderLeft: "3px solid var(--vera-ink)" }}
                  >
                    <div
                      className="px-5 py-3 flex items-center justify-between"
                      style={{
                        borderBottom: `1px solid ${ink(6)}`,
                        background: `linear-gradient(90deg, ${ink(2)} 0%, transparent 100%)`,
                      }}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className="w-6 shrink-0"
                          style={{ height: "var(--vera-classification-bar)", backgroundColor: "var(--vera-ink)" }}
                          aria-hidden
                        />
                        <FileText
                          className="size-3.5"
                          style={{ color: ink(45) }}
                          aria-hidden
                        />
                        <span
                          style={{
                            fontSize: "10px",
                            letterSpacing: "0.2em",
                            textTransform: "uppercase",
                            color: ink(50),
                          }}
                        >
                          Case File
                        </span>
                      </div>
                      <span className="vera-doc-id" style={{ color: ink(50) }}>
                        {report.id}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2">
                      {/* Left col */}
                      <div
                        className="p-5 space-y-4"
                        style={{ borderRight: `1px solid ${ink(4)}` }}
                      >
                        <div>
                          <p
                            className="uppercase mb-1"
                            style={{
                              fontSize: "9px",
                              letterSpacing: "0.2em",
                              color: ink(45),
                            }}
                          >
                            Title
                          </p>
                          <p
                            style={{
                              fontSize: "14px",
                              lineHeight: 1.5,
                              color: ink(70),
                            }}
                          >
                            {report.title}
                          </p>
                        </div>
                        <div>
                          <p
                            className="uppercase mb-1"
                            style={{
                              fontSize: "9px",
                              letterSpacing: "0.2em",
                              color: ink(45),
                            }}
                          >
                            Category
                          </p>
                          <p style={{ fontSize: "13px", color: ink(60) }}>
                            {report.category}
                          </p>
                        </div>
                      </div>

                      {/* Right col */}
                      <div className="p-5 space-y-4">
                        <div>
                          <p
                            className="uppercase mb-1"
                            style={{
                              fontSize: "9px",
                              letterSpacing: "0.2em",
                              color: ink(45),
                            }}
                          >
                            Urgency
                          </p>
                          <span
                            className={`inline-block px-2.5 py-0.5 border ${urgencyColors[report.urgency] || ""}`}
                            style={{
                              fontSize: "11px",
                              letterSpacing: "0.05em",
                            }}
                          >
                            {report.urgency}
                          </span>
                        </div>
                        <div>
                          <p
                            className="uppercase mb-1"
                            style={{
                              fontSize: "9px",
                              letterSpacing: "0.2em",
                              color: ink(45),
                            }}
                          >
                            Assigned Team
                          </p>
                          <p style={{ fontSize: "13px", color: ink(60) }}>
                            {report.assignedTeam}
                          </p>
                        </div>
                        <div>
                          <p
                            className="uppercase mb-1"
                            style={{
                              fontSize: "9px",
                              letterSpacing: "0.2em",
                              color: ink(45),
                            }}
                          >
                            Submitted
                          </p>
                          <p
                            className="font-mono"
                            style={{ fontSize: "12px", color: ink(60) }}
                          >
                            {new Date(report.submittedAt).toLocaleDateString(
                              "en-US",
                              {
                                year: "numeric",
                                month: "long",
                                day: "numeric",
                              }
                            )}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Blockchain Proof */}
                  <div className="mb-10">
                    <div className="flex items-center gap-4 mb-6">
                      <div
                        className="w-6 shrink-0"
                        style={{ height: "var(--vera-classification-bar)", backgroundColor: "var(--vera-ink)" }}
                        aria-hidden
                      />
                      <span
                        style={{
                          fontSize: "10px",
                          letterSpacing: "0.2em",
                          textTransform: "uppercase",
                          color: ink(45),
                        }}
                      >
                        Blockchain Proof
                      </span>
                      <div className="flex-1 h-px" style={{ backgroundColor: ink(4) }} />
                    </div>

                    <div
                      className="p-5"
                      style={{
                        border: `1px solid ${ink(6)}`,
                        background: ink(1),
                      }}
                    >
                      <div className="flex justify-between items-center mb-3">
                        <span style={{ fontSize: "11px", color: ink(25) }}>Proof status:</span>
                        <span style={{ fontSize: "11px", color: ink(60) }}>{proofSummary.label}</span>
                      </div>
                      <p role="status" className="mb-4" style={{ fontSize: "12px", lineHeight: 1.6, color: ink(60) }}>
                        {report.proofStatus === "pending"
                            ? "Your report is saved. Its blockchain proof is still pending. This section updates automatically when the proof status changes."
                            : proofSummary.message}
                      </p>
                      {report.evidenceHash && (
                        <div className="flex justify-between items-center mb-3">
                          <span style={{ fontSize: "11px", color: ink(25) }}>Evidence Hash:</span>
                          <span className="font-mono" style={{ fontSize: "10px", color: ink(40) }}>
                            {report.evidenceHash.substring(0, 10)}...{report.evidenceHash.substring(report.evidenceHash.length - 10)}
                          </span>
                        </div>
                      )}
                      <div className="flex justify-between items-center">
                        <span style={{ fontSize: "11px", color: ink(25) }}>Transaction:</span>
                        {report.zkProof?.txHash ? (
                          proofExplorerUrl ? (
                            <Link
                              href={proofExplorerUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono inline-flex items-center gap-1 hover:underline"
                              style={{ fontSize: "10px", color: "var(--vera-accent-muted)" }}
                            >
                              {report.zkProof.txHash.substring(0, 10)}...
                              {report.zkProof.txHash.substring(report.zkProof.txHash.length - 10)}
                              <ExternalLink className="size-2.5" />
                            </Link>
                          ) : (
                            <span className="font-mono" style={{ fontSize: "10px", color: ink(40) }}>
                              {report.zkProof.txHash.substring(0, 10)}...
                              {report.zkProof.txHash.substring(report.zkProof.txHash.length - 10)}
                            </span>
                          )
                        ) : (
                          <span style={{ fontSize: "11px", color: "rgb(245,158,11)" }}>Not recorded on-chain</span>
                        )}
                      </div>
                      {report.zkProof?.txHash && (
                        <div className="flex justify-between items-center mt-3">
                          <span style={{ fontSize: "11px", color: ink(25) }}>Network:</span>
                          <span style={{ fontSize: "11px", color: ink(60) }}>{receiptNetworkLabel(readReceiptNetwork(report.zkProof))}</span>
                        </div>
                      )}
                    </div>
                  </div>
                  {/* Timeline */}
                  <div className="mb-10">
                    <div className="flex items-center gap-4 mb-6">
                      <div
                        className="w-6 shrink-0"
                        style={{ height: "var(--vera-classification-bar)", backgroundColor: "var(--vera-ink)" }}
                        aria-hidden
                      />
                      <span
                        style={{
                          fontSize: "10px",
                          letterSpacing: "0.2em",
                          textTransform: "uppercase",
                          color: ink(45),
                        }}
                      >
                        Case Progress
                      </span>
                      <div
                        className="flex-1 h-px"
                        style={{ backgroundColor: ink(4) }}
                      />
                    </div>

                    <div className="relative pl-7">
                      <div
                        className="absolute left-[9px] top-2 bottom-2 w-px"
                        style={{ backgroundColor: ink(6) }}
                      />

                      {report.timeline.map((entry, i) => {
                        const isTerminalNegative =
                          entry.status === "declined" ||
                          entry.status === "unknown";
                        const isCompleted = i <= currentIdx;
                        const isCurrent = i === currentIdx;
                        const isFuture = i > currentIdx;

                        return (
                          <motion.div
                            key={entry.status}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ duration: 0.3, delay: i * 0.1 }}
                            className={`relative pb-8 last:pb-0 ${isFuture ? "opacity-30" : ""}`}
                          >
                            <div className="absolute -left-7 top-0.5 flex items-center justify-center">
                              {isTerminalNegative ? (
                                <div className="size-[18px] border border-amber-500/30 bg-amber-500/10 flex items-center justify-center">
                                  <AlertTriangle
                                    className="size-3 text-amber-400"
                                    aria-hidden
                                  />
                                </div>
                              ) : isCurrent ? (
                                <div className="relative">
                                  <div
                                    className="size-[18px] flex items-center justify-center"
                                    style={{
                                      border: `1px solid ${ink(40)}`,
                                      backgroundColor: ink(10),
                                    }}
                                  >
                                    <CircleDot
                                      className="size-3"
                                      style={{ color: ink(70) }}
                                    />
                                  </div>
                                  <div
                                    className="absolute inset-0 animate-ping"
                                    style={{ border: `1px solid ${ink(20)}` }}
                                  />
                                </div>
                              ) : isCompleted ? (
                                <div className="size-[18px] border border-emerald-500/30 bg-emerald-500/10 flex items-center justify-center">
                                  <CheckCircle2 className="size-3 text-emerald-400" />
                                </div>
                              ) : (
                                <div
                                  className="size-[18px] flex items-center justify-center"
                                  style={{
                                    border: `1px solid ${ink(8)}`,
                                    backgroundColor: ink(2),
                                  }}
                                >
                                  <Clock
                                    className="size-3"
                                    style={{ color: ink(50) }}
                                    aria-hidden
                                  />
                                </div>
                              )}
                            </div>

                            <div>
                              <div className="flex items-baseline gap-3 mb-1">
                                <p
                                  style={{
                                    fontSize: "14px",
                                    color: isCurrent
                                      ? ink(80)
                                      : isCompleted
                                        ? ink(60)
                                        : ink(50),
                                  }}
                                >
                                  {entry.label}
                                </p>
                                {entry.date && (
                                  <span
                                    className="font-mono"
                                    style={{
                                      fontSize: "11px",
                                      color: ink(20),
                                    }}
                                  >
                                    {entry.date}
                                  </span>
                                )}
                              </div>
                              {entry.note && (
                                <p
                                  style={{
                                    fontSize: "13px",
                                    lineHeight: 1.6,
                                    color: ink(30),
                                  }}
                                >
                                  {entry.note}
                                </p>
                              )}
                              {isFuture && (
                                <p
                                  className="font-serif italic"
                                  style={{ fontSize: "13px", color: ink(50) }}
                                >
                                  Pending
                                </p>
                              )}
                            </div>
                          </motion.div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Agency Submissions (identity-free channel states) */}
                  {report.dissemination.length > 0 && (
                    <div className="mb-10">
                      <div className="flex items-center gap-4 mb-6">
                        <div
                          className="w-6 shrink-0"
                          style={{ height: "var(--vera-classification-bar)", backgroundColor: "var(--vera-ink)" }}
                          aria-hidden
                        />
                        <span
                          style={{ fontSize: "10px", letterSpacing: "0.2em", textTransform: "uppercase", color: ink(45) }}
                        >
                          Agency Submissions
                        </span>
                        <div className="flex-1 h-px" style={{ backgroundColor: ink(4) }} />
                      </div>
                      <div className="space-y-2">
                        {report.dissemination.map((ch) => (
                          <div
                            key={ch.entityId}
                            className="flex items-center justify-between gap-3 p-3 flex-wrap"
                            style={{ border: `1px solid ${ink(6)}`, background: ink(1) }}
                          >
                            <span style={{ fontSize: "13px", color: ink(60) }}>{ch.entityName}</span>
                            <span style={{ fontSize: "12px", color: ink(45) }}>
                              {CHANNEL_STATE_LABELS[ch.state] || ch.state}
                              {ch.receipted ? " ✓" : ""}
                            </span>
                          </div>
                        ))}
                      </div>
                      <p className="mt-2" style={{ fontSize: "11px", lineHeight: 1.6, color: ink(40) }}>
                        Submissions were made with your consent and contain no information about
                        who you are.
                      </p>
                    </div>
                  )}



                  {/* Privacy Notice */}
                  <div className="flex items-start gap-3 py-4 mb-6">
                    <ShieldCheck
                      className="size-4 mt-0.5 shrink-0"
                      style={{ color: ink(50) }}
                      aria-hidden
                    />
                    <p
                      style={{
                        fontSize: "12px",
                        lineHeight: 1.6,
                        color: ink(55),
                      }}
                    >
                      No account is required to check status. Keep your Report ID private:
                      anyone with it can read your status.
                    </p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Footer */}
            <div
              className="flex items-center gap-4 mt-8 pt-6"
              style={{ borderTop: `1px solid ${ink(4)}` }}
            >
              <Link href="/">
                <Button
                  variant="ghost"
                  className="rounded-none gap-2 focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
                  style={{
                    fontSize: "12px",
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: ink(55),
                  }}
                >
                  <ArrowLeft className="size-3.5" aria-hidden /> Back to Home
                </Button>
              </Link>
              <a
                href="/report"
                className="transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:rounded"
                style={{
                  fontSize: "12px",
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: ink(55),
                }}
              >
                File a Report
              </a>
            </div>
            {confidentialCasesEnabled() && <SecurityDetails className="mt-4" />}
          </motion.div>
        </main>
      </div>
    </>
  );
}

// Per-request rendering binds the intake CSP nonce to this response.
export const getServerSideProps = async () => ({ props: {} });
