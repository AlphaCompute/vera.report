import { formatBrowserDateTime } from "@/lib/formatBrowserDateTime";
import { useState, useEffect } from "react";
import {
  ArrowLeft,
  Download,
  Sparkles,
  Paperclip,
  Shield,
  Clock,
  Search,
  Eye,
  CheckCircle2,
  XCircle,
  Send,
  ChevronRight,
  FileImage,
  RefreshCw,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { motion } from "motion/react";
import { toast } from "sonner";
import { DisseminationPanel } from "./DisseminationPanel";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

export interface ReportData {
  id: string;
  trackingId?: string;
  title: string;
  category: string;
  status: "pending" | "investigating" | "reviewing" | "resolved" | "dismissed";
  priority: "high" | "medium" | "low";
  date: string;
  description: string;
  aiAnalysis?: {
    authenticity: number;
    flags: string[];
    version: string;
    analyzedAt: string;
  };
  evidence?: { name: string; size: string; type: string; url?: string }[];
  reward?: { wantsReward: boolean; contactMethod?: string };
  urgency?: string;
  location?: string;
  dateOfIncident?: string;
  timeline?: { event: string; time: string; type: "ai" | "submit" | "status" | "note" }[];
  assignedTo?: string;
}

const statusOptions = [
  { value: "pending", label: "Pending", icon: Clock, color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20" },
  { value: "investigating", label: "Investigating", icon: Search, color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20" },
  { value: "dismissed", label: "Dismissed", icon: XCircle, color: "", bg: "" },
  { value: "reviewing", label: "Reviewing", icon: Eye, color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20" },
  { value: "resolved", label: "Resolved", icon: CheckCircle2, color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20" },
] as const;

interface ReportDetailProps {
  report: ReportData;
  onBack: () => void;
  onUpdateStatus: (reportId: string, status: ReportData["status"]) => Promise<ReportData["status"] | false>;
  isAdmin?: boolean;
}

/* ── Decorative divider with centered label ── */
function SectionDivider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-4 my-8">
      <div className="flex-1 h-px" style={{ backgroundColor: ink(6) }} />
      <span
        className="shrink-0"
        style={{
          fontSize: "9px",
          letterSpacing: "0.25em",
          textTransform: "uppercase",
          fontFamily: "var(--font-sans)",
          color: ink(50),
        }}
      >
        {label}
      </span>
      <div className="flex-1 h-px" style={{ backgroundColor: ink(6) }} />
    </div>
  );
}

/**
 * Display a report with evidence, analysis, activity, and status controls.
 * Admin mode also fetches the narrative, notes, and eligible reward contact.
 * onUpdateStatus must resolve to the saved status or false to restore the prior status.
 */
export function ReportDetail({ report, onBack, onUpdateStatus, isAdmin = false }: ReportDetailProps) {
  const [currentStatus, setCurrentStatus] = useState(report.status);
  useEffect(() => {
    setCurrentStatus(report.status);
  }, [report.id, report.status]);
  const [statusSaving, setStatusSaving] = useState<ReportData["status"] | null>(null);
  const [noteText, setNoteText] = useState("");
  const [notes, setNotes] = useState<{ id: string; text: string; timestamp: string }[]>([]);
  const [noteSaving, setNoteSaving] = useState(false);
  const [noteError, setNoteError] = useState("");
  const [noteSaved, setNoteSaved] = useState(false);
  useEffect(() => {
    let cancelled = false;
    setNotes([]);
    setNoteText("");
    setNoteError("");
    setNoteSaved(false);
    if (!isAdmin || !report.trackingId) return;
    fetch(`/api/admin/dashboard/reports/${encodeURIComponent(report.trackingId)}/notes`)
      .then(async response => {
        const data = await response.json();
        if (!response.ok || !data.success || !Array.isArray(data.notes)) throw new Error();
        if (!cancelled) setNotes(current => [...data.notes, ...current.filter(note => !data.notes.some((saved: { id: string }) => saved.id === note.id))]);
      })
      .catch(() => { if (!cancelled) setNoteError("Could not load saved notes. Reopen this report to retry."); });
    return () => { cancelled = true; };
  }, [isAdmin, report.trackingId]);
  const addNote = async () => {
    if (noteSaving || !noteText.trim() || !report.trackingId) return;
    setNoteSaving(true);
    setNoteError("");
    setNoteSaved(false);
    try {
      const response = await fetch(`/api/admin/dashboard/reports/${encodeURIComponent(report.trackingId)}/notes`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: noteText.trim() }),
      });
      const data = await response.json();
      if (!response.ok || !data.success || !data.note) throw new Error();
      setNotes(current => [...current, data.note]);
      setNoteText("");
      setNoteSaved(true);
    } catch {
      setNoteError("Could not save your note. Your draft has been kept; please try again.");
    } finally { setNoteSaving(false); }
  };
  const timeline = [...(report.timeline || []), ...notes.map(note => ({
    event: note.text, type: 'note' as const,
    time: formatBrowserDateTime(note.timestamp),
  }))];
  const [analyzing, setAnalyzing] = useState(false);
  const [selectedEvidence, setSelectedEvidence] = useState<NonNullable<ReportData["evidence"]>[number] | null>(null);
  const previewImage = !!selectedEvidence && /\.(jpe?g|png|webp|gif|avif)$/i.test(selectedEvidence.name);

  // Fetch the private follow-up contact regardless of reward eligibility.
  const [contactValue, setContactValue] = useState<string | null>(null);
  const [contactLoading, setContactLoading] = useState(false);
  useEffect(() => {
    if (isAdmin && report.reward?.contactMethod && report.trackingId) {
      setContactLoading(true);
      fetch(`/api/whistleblower/reward-contact/${report.trackingId}`)
        .then((res) => res.json())
        .then((data) => {
          if (data.success && data.contactValue) setContactValue(data.contactValue);
        })
        .catch(() => {})
        .finally(() => setContactLoading(false));
    }
  }, [isAdmin, report.reward?.contactMethod, report.trackingId]);

  // Fetch the decrypted narrative on-demand (encrypted at rest; admin-gated + audit-logged).
  const [narrative, setNarrative] = useState<string | null>(null);
  const [narrativeLoading, setNarrativeLoading] = useState(false);
  useEffect(() => {
    // Reset on report change so a previous report's decrypted narrative (PII)
    // never lingers, and ignore a stale in-flight response via the cancel flag.
    setNarrative(null);
    if (!isAdmin || !report.trackingId) return;
    let cancelled = false;
    setNarrativeLoading(true);
    fetch(`/api/admin/narrative/${report.trackingId}`)
      .then((res) => res.json())
      .then((data) => {
        if (!cancelled && data.success && data.narrative) setNarrative(data.narrative);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setNarrativeLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin, report.trackingId]);

  // No fallback: an unscored report shows no gauge rather than 0%.
  const authenticity = report.aiAnalysis?.authenticity;

  const authenticityColor =
    authenticity == null ? "" : authenticity > 70 ? "bg-emerald-500" : authenticity > 40 ? "bg-amber-500" : "bg-red-500";

  const priorityBadge: Record<string, string> = {
    high: "bg-red-500/10 text-red-400 border-red-500/20",
    medium: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    low: "",
  };

  const currentStatusCfg = statusOptions.find((s) => s.value === currentStatus);

  const handleStatusChange = async (nextStatus: ReportData["status"]) => {
    if (nextStatus === currentStatus || statusSaving) return;

    const previousStatus = currentStatus;
    setCurrentStatus(nextStatus);
    setStatusSaving(nextStatus);
    const saved = await onUpdateStatus(report.id, nextStatus);
    setStatusSaving(null);

    if (saved) {
      setCurrentStatus(saved);
      const label = statusOptions.find((option) => option.value === saved)?.label ?? saved;
      toast.success(`Status saved as ${label}.`);
      return;
    }

    setCurrentStatus(previousStatus);
    toast.error("Status could not be saved. Please try again.");
  };

  // Re-analyze report
  const handleReanalyze = async () => {
    setAnalyzing(true);
    try {
      const response = await fetch(`/api/admin/dashboard/reports/${report.id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      const result = await response.json().catch(() => null);
      if (!response.ok) {
        if (result?.error === 'scoring_unavailable') {
          toast.error("AI scoring is not enabled in this environment. The report was not re-analyzed.");
          return;
        }
        throw new Error(`Failed to trigger analysis: ${response.status}`);
      }

      console.log('[ReportDetail] Analysis triggered:', result);
      toast.success("Re-analysis complete. Refresh to see the updated score.");
    } catch (error) {
      console.error('[ReportDetail] Failed to trigger analysis:', error);
      toast.error("Re-analysis failed. The existing score, if any, is unchanged.");
    } finally {
      setAnalyzing(false);
    }
  };

  // Stagger delay helper
  const stagger = (i: number) => ({ delay: 0.08 * i });

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.4 }}
      className="pb-12 relative"
    >
      <div className="relative z-10">
        {/* ── Top bar ── */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="flex items-center justify-between mb-10"
        >
          <button
            onClick={onBack}
            className="flex items-center gap-2 transition-colors"
            style={{ color: ink(40) }}
          >
            <ArrowLeft className="size-4" />
            <span style={{ fontSize: "12px", letterSpacing: "0.05em" }}>Back</span>
          </button>
        </motion.div>

        {/* ── Classified header ── */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ...stagger(1) }}
          className="mb-10"
        >
          {/* Classification banner */}
          <div className="flex items-center gap-4 mb-6">
            <div
              className="w-8 shrink-0"
              style={{ height: "var(--vera-classification-bar)", backgroundColor: "var(--vera-ink)" }}
              aria-hidden
            />
            <span
              style={{
                fontSize: "9px",
                letterSpacing: "0.3em",
                textTransform: "uppercase",
                color: ink(50),
              }}
            >
              Case File
            </span>
          </div>

          {/* Report ID — document identifier */}
          <p className="vera-doc-id mb-3" style={{ color: ink(50) }}>
            {report.id}
          </p>

          {/* Title — serif */}
          <h2
            className="font-serif mb-4"
            style={{
              fontSize: "clamp(1.6rem, 4vw, 2.4rem)",
              fontWeight: 300,
              letterSpacing: "0.04em",
              lineHeight: 1.15,
              color: ink(90),
            }}
          >
            {report.title}
          </h2>

          {/* Status + Priority + Date */}
          <div className="flex items-center gap-3 flex-wrap">
            {currentStatusCfg && (
              <Badge
                variant="outline"
                className={currentStatusCfg.bg || ""}
                style={{
                  fontSize: "11px",
                  ...(currentStatusCfg.value === "dismissed" ? { backgroundColor: ink(4), color: ink(40), borderColor: ink(8) } : {}),
                }}
              >
                {currentStatusCfg.label}
              </Badge>
            )}
            <Badge
              variant="outline"
              className={priorityBadge[report.priority] || ""}
              style={{
                fontSize: "11px",
                ...(report.priority === "low" ? { backgroundColor: ink(4), color: ink(40), borderColor: ink(8) } : {}),
              }}
            >
              {report.priority.charAt(0).toUpperCase() + report.priority.slice(1)} Priority
            </Badge>
            <span style={{ fontSize: "11px", color: ink(40) }}>
              {report.date}
            </span>
          </div>
        </motion.div>

        {/* ── Description — memo excerpt ── */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ...stagger(2) }}
          className="mb-0"
        >
          <div className="py-2 pl-6" style={{ borderLeft: "3px solid var(--vera-ink)" }}>
            <p
              className="font-serif italic mb-4"
              style={{ fontSize: "13px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(50) }}
            >
              Submitted Account
            </p>
            <p
              className="whitespace-pre-wrap"
              style={{ fontSize: "14px", lineHeight: 1.85, color: ink(50) }}
            >
              {narrativeLoading ? "Decrypting…" : (narrative ?? report.description) || "Narrative unavailable"}
            </p>
          </div>
        </motion.div>

        {/* ── Report Details (urgency, location, date) ── */}
        {(report.urgency || report.location || report.dateOfIncident) && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ...stagger(2.5) }}
            className="mb-8 p-5 transition-colors duration-500"
            style={{
              backgroundColor: "var(--vera-card-bg)",
              border: `1px solid ${ink(4)}`,
              borderLeft: "3px solid var(--vera-ink)",
            }}
          >
            <div className="space-y-2">
              {report.urgency && (
                <div className="flex items-center justify-between">
                  <span style={{ fontSize: "12px", color: ink(50) }}>Urgency</span>
                  <Badge
                    variant="outline"
                    style={{
                      fontSize: "10px",
                      backgroundColor: report.urgency === "critical" ? "rgba(239,68,68,0.08)" : report.urgency === "high" ? "rgba(245,158,11,0.08)" : ink(3),
                      borderColor: report.urgency === "critical" ? "rgba(239,68,68,0.2)" : report.urgency === "high" ? "rgba(245,158,11,0.2)" : ink(6),
                      color: report.urgency === "critical" ? "rgb(248,113,113)" : report.urgency === "high" ? "rgb(251,191,36)" : ink(40),
                    }}
                  >
                    {report.urgency.charAt(0).toUpperCase() + report.urgency.slice(1)}
                  </Badge>
                </div>
              )}
              {report.location && (
                <div className="flex items-center justify-between">
                  <span style={{ fontSize: "12px", color: ink(50) }}>Location</span>
                  <span style={{ fontSize: "12px", color: ink(50) }}>{report.location}</span>
                </div>
              )}
              {report.dateOfIncident && (
                <div className="flex items-center justify-between">
                  <span style={{ fontSize: "12px", color: ink(50) }}>Timeframe</span>
                  <span style={{ fontSize: "12px", color: ink(50) }}>{report.dateOfIncident}</span>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {report.aiAnalysis && <SectionDivider label="Analysis" />}

        {/* ── AI Analysis ── */}
        {report.aiAnalysis && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ...stagger(3) }}
            className="mb-8 relative"
          >
            <div className="relative p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-ai-bg)", border: "1px solid rgba(96,165,250,0.08)" }}>
              {/* Header */}
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="size-8 bg-blue-500/10 border border-blue-500/15 flex items-center justify-center">
                    <Sparkles className="size-3.5 text-blue-400/70" />
                  </div>
                  <div>
                    <h3
                      className="font-serif"
                      style={{ fontSize: "16px", fontWeight: 400, letterSpacing: "0.03em", color: ink(75) }}
                    >
                      Narrative analysis
                    </h3>
                    <p style={{ fontSize: "10px", color: ink(40) }}>
                      {report.aiAnalysis.version} &middot; {report.aiAnalysis.analyzedAt}
                      <br />
                      Text assessment only; attachments are not analyzed. Scores do not verify allegations.
                    </p>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleReanalyze}
                  disabled={analyzing}
                  className="rounded-none gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ borderColor: ink(6), color: ink(40), fontSize: "11px" }}
                >
                  <RefreshCw className={`size-3 ${analyzing ? 'animate-spin' : ''}`} />
                  {analyzing ? 'Analyzing...' : 'Re-Analyze'}
                </Button>
              </div>

              {/* Gauges */}
              <div className="grid grid-cols-2 gap-8 mb-6">
                {(authenticity == null ? [] : [
                  { label: "Model score", value: authenticity, barColor: authenticityColor },
                ]).map((gauge, gi) => (
                  <div key={gauge.label}>
                    <p className="mb-3 uppercase" style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(50) }}>
                      {gauge.label}
                    </p>
                    <div className="flex items-baseline gap-1 mb-3">
                      <span
                        className={`tabular-nums ${
                          gauge.value > 70 ? "text-emerald-400" :
                          gauge.value > 40 ? "text-amber-400" : "text-red-400"
                        }`}
                        style={{ fontSize: "2.2rem", fontWeight: 300, fontFamily: "var(--font-serif)" }}
                      >
                        {Math.round(gauge.value)}
                      </span>
                      <span
                        className={`${
                          gauge.value > 70 ? "text-emerald-400/50" :
                          gauge.value > 40 ? "text-amber-400/50" : "text-red-400/50"
                        }`}
                        style={{ fontSize: "14px" }}
                      >
                        %
                      </span>
                    </div>
                    <div className="h-[3px] w-full" style={{ backgroundColor: ink(4) }}>
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${gauge.value}%` }}
                        transition={{ duration: 1, delay: 0.5 + gi * 0.1, ease: "easeOut" }}
                        className={`h-full ${gauge.barColor}`}
                      />
                    </div>
                  </div>
                ))}
              </div>

              {/* Flags */}
              {report.aiAnalysis.flags.length > 0 && (
                <div className="pt-4" style={{ borderTop: `1px solid ${ink(4)}` }}>
                  <p className="mb-2.5 uppercase" style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(50) }}>
                    Flags
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {report.aiAnalysis.flags.map((flag) => (
                      <span
                        key={flag}
                        className="px-3 py-1 bg-red-500/[0.06] border border-red-500/10 text-red-400/70"
                        style={{ fontSize: "11px" }}
                      >
                        {flag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}

        <SectionDivider label="Evidence" />

        {/* ── Evidence ── */}
        {report.evidence && report.evidence.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ...stagger(5) }}
            className="mb-8 p-5 transition-colors duration-500"
            style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Paperclip className="size-4" style={{ color: ink(40) }} />
                <h3
                  className="font-serif"
                  style={{ fontSize: "14px", fontWeight: 500, letterSpacing: "0.03em", color: ink(70) }}
                >
                  Evidence ({report.evidence.length} file{report.evidence.length !== 1 ? "s" : ""})
                </h3>
              </div>
              {isAdmin && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="gap-1.5"
                  style={{ fontSize: "11px", color: ink(40) }}
                >
                  <Download className="size-3.5" />
                  Download All
                </Button>
              )}
            </div>
            {isAdmin ? (
              <div className="space-y-2">
                {report.evidence.map((file, i) => (
                  file.url ? (
                    <button
                      key={`${file.name}-${i}`}
                      onClick={() => setSelectedEvidence(file)}
                      className="w-full flex items-center justify-between p-3 group transition-colors cursor-pointer"
                      style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = ink(3); }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = ink(2); }}
                    >
                      <div className="flex items-center gap-3">
                        <div className="size-8 flex items-center justify-center" style={{ backgroundColor: ink(4) }}>
                          <FileImage className="size-4" style={{ color: ink(40) }} />
                        </div>
                        <div>
                          <p className="truncate max-w-[250px]" style={{ fontSize: "13px", color: ink(55) }}>
                            {file.name}
                          </p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span style={{ fontSize: "11px", color: ink(50) }}>{file.size}</span>
                            <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20" style={{ fontSize: "9px" }}>
                              {file.type}
                            </Badge>
                          </div>
                        </div>
                      </div>
                      <ChevronRight className="size-4" style={{ color: ink(40) }} />
                    </button>
                  ) : (
                    <div
                      key={`${file.name}-${i}`}
                      className="flex items-center justify-between p-3 opacity-50"
                      style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}
                    >
                      <div className="flex items-center gap-3">
                        <div className="size-8 flex items-center justify-center" style={{ backgroundColor: ink(4) }}>
                          <FileImage className="size-4" style={{ color: ink(40) }} />
                        </div>
                        <div>
                          <p className="truncate max-w-[250px]" style={{ fontSize: "13px", color: ink(55) }}>
                            {file.name}
                          </p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span style={{ fontSize: "11px", color: ink(50) }}>{file.size}</span>
                            <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/20" style={{ fontSize: "9px" }}>
                              {file.type}
                            </Badge>
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                ))}
              </div>
            ) : (
              <div
                className="flex items-center gap-3 p-4"
                style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}
              >
                <Shield className="size-4 shrink-0" style={{ color: ink(40) }} />
                <span style={{ fontSize: "13px", color: ink(45) }}>
                  {report.evidence.length} file{report.evidence.length !== 1 ? "s" : ""} attached — Admin access required
                </span>
              </div>
            )}
          </motion.div>
        )}

        {/* ── Reward Eligibility ── */}
        {report.reward && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ...stagger(6) }}
            className="mb-8 p-5 transition-colors duration-500"
            style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}
          >
            <div className="flex items-center gap-2 mb-4">
              <Shield className="size-4" style={{ color: ink(40) }} />
              <h3
                className="font-serif"
                style={{ fontSize: "14px", fontWeight: 500, letterSpacing: "0.03em", color: ink(70) }}
              >
                Reward Eligibility
              </h3>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span style={{ fontSize: "12px", color: ink(50) }}>Status</span>
                <Badge
                  className="border"
                  style={{
                    fontSize: "10px",
                    backgroundColor: report.reward.wantsReward ? "rgba(16,185,129,0.08)" : ink(3),
                    borderColor: report.reward.wantsReward ? "rgba(16,185,129,0.2)" : ink(6),
                    color: report.reward.wantsReward ? "rgb(52,211,153)" : ink(40),
                  }}
                >
                  {report.reward.wantsReward ? "Opted In" : "Not requested"}
                </Badge>
              </div>
              {report.reward.contactMethod && (
                <>
                  <div className="flex items-center justify-between">
                    <span style={{ fontSize: "12px", color: ink(50) }}>Contact Method</span>
                    <span style={{ fontSize: "12px", color: ink(50) }}>
                      {report.reward.contactMethod.charAt(0).toUpperCase() + report.reward.contactMethod.slice(1)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span style={{ fontSize: "12px", color: ink(50) }}>Contact</span>
                    <span className="font-mono" style={{ fontSize: "11px", color: ink(50) }}>
                      {isAdmin
                        ? (contactLoading ? "Decrypting..." : contactValue || "Unavailable")
                        : "Restricted — Admin only"}
                    </span>
                  </div>
                </>
              )}
            </div>
          </motion.div>
        )}

        <SectionDivider label="Activity" />

        {/* ── Activity Timeline ── */}
        {timeline.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ...stagger(7) }}
            className="mb-8 p-5 transition-colors duration-500"
            style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}
          >
            <div className="flex items-center gap-2 mb-5">
              <Clock className="size-4" style={{ color: ink(40) }} />
              <h3
                className="font-serif"
                style={{ fontSize: "14px", fontWeight: 500, letterSpacing: "0.03em", color: ink(70) }}
              >
                Activity Timeline
              </h3>
            </div>
            <div className="space-y-0">
              {timeline.map((entry, i) => {
                const dotColor =
                  entry.type === "ai"
                    ? "bg-amber-400"
                    : entry.type === "submit"
                    ? "bg-emerald-400"
                    : entry.type === "status"
                    ? "bg-blue-400"
                    : "";
                return (
                  <motion.div
                    key={`${entry.event}-${i}`}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: 0.6 + i * 0.08 }}
                    className="flex gap-3 relative"
                  >
                    {/* Vertical line */}
                    {i < timeline.length - 1 && (
                      <div className="absolute left-[5px] top-[14px] w-px h-full" style={{ backgroundColor: ink(6) }} />
                    )}
                    <div
                      className={`size-[11px] rounded-full ${dotColor} shrink-0 mt-[5px] relative z-10`}
                      style={entry.type === "note" ? { backgroundColor: ink(40) } : {}}
                    />
                    <div className="min-w-0 pb-5">
                      <p className="whitespace-pre-wrap break-words" style={{ fontSize: "13px", color: ink(50) }}>
                        {entry.event}
                      </p>
                      <p className="mt-0.5" style={{ fontSize: "11px", color: ink(50) }}>
                        {entry.time}
                      </p>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </motion.div>
        )}

        {/* ── Dissemination (agency submission pipeline) ── */}
        {isAdmin && report.trackingId && (
          <>
            <SectionDivider label="Dissemination" />
            <DisseminationPanel trackingId={report.trackingId} />
          </>
        )}

        <SectionDivider label="Actions" />

        {/* ── Update Status ── */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ...stagger(8) }}
          className="mb-8"
        >
          <h3
            className="mb-4 uppercase"
            style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(50) }}
          >
            Update Status
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {statusOptions.map((opt) => {
              const isActive = currentStatus === opt.value;
              return (
                <button
                  type="button"
                  key={opt.value}
                  onClick={() => void handleStatusChange(opt.value)}
                  disabled={statusSaving !== null}
                  aria-busy={statusSaving === opt.value}
                  className={`flex items-center gap-2 px-3 py-2.5 border transition-all ${
                    isActive && opt.bg ? `${opt.bg} ${opt.color}` : ""
                  } disabled:cursor-wait disabled:opacity-60`}
                  style={{
                    fontSize: "12px",
                    ...(!isActive ? { borderColor: ink(4), color: ink(40) } : {}),
                    ...(isActive && opt.value === "dismissed" ? { backgroundColor: ink(4), borderColor: ink(8), color: ink(40) } : {}),
                  }}
                >
                  <opt.icon className="size-3.5" />
                  {opt.label}
                  {statusSaving === opt.value
                    ? <RefreshCw className="size-3 ml-auto animate-spin opacity-60" />
                    : isActive && <CheckCircle2 className="size-3 ml-auto opacity-50" />}
                </button>
              );
            })}
          </div>
        </motion.div>

        {/* ── Add Note ── */}
        {isAdmin && <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ...stagger(9) }}
          className="mb-10"
        >
          <div className="flex items-center gap-2 mb-3">
            <Send className="size-3.5" style={{ color: ink(40) }} />
            <h3
              className="font-serif"
              style={{ fontSize: "14px", fontWeight: 500, letterSpacing: "0.03em", color: ink(70) }}
            >
              Add Note
            </h3>
          </div>
          <Textarea
            aria-label="Internal note"
            maxLength={5000}
            disabled={noteSaving}
            placeholder="Add internal notes..."
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
            rows={3}
            className="rounded-none resize-none mb-3 focus-visible:ring-0"
            style={{ border: `1px solid ${ink(6)}`, backgroundColor: ink(2), color: ink(60) }}
          />
          <button
            type="button"
            onClick={() => void addNote()}
            disabled={noteSaving || !noteText.trim()}
            className="w-full py-2.5 transition-opacity hover:opacity-90 disabled:opacity-50"
            style={{
              backgroundColor: "var(--vera-ink)",
              color: "var(--vera-paper)",
              fontSize: "11px",
              letterSpacing: "0.12em",
              textTransform: "uppercase",
            }}
          >
            <div className="flex items-center justify-center gap-2">
              <Send className="size-3.5" />
              {noteSaving ? "Saving…" : "Add Note"}
            </div>
          </button>
          {noteError && <p role="alert" className="mt-3 text-sm text-red-600">{noteError}</p>}
          {noteSaved && <p role="status" className="mt-3 text-sm">Saved note in activity</p>}
        </motion.div>}

        {/* ── Vera footer watermark ── */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8, delay: 1.2 }}
          className="flex flex-col items-center pt-6"
          style={{ borderTop: `1px solid ${ink(4)}` }}
        >
          <div className="w-8 h-px mb-4" style={{ backgroundColor: ink(8) }} />
          <p
            className="font-serif italic"
            style={{ fontSize: "13px", letterSpacing: "0.1em", color: ink(40) }}
          >
            The truth, spoken softly.
          </p>
          <p
            className="mt-2"
            style={{ fontSize: "9px", letterSpacing: "0.3em", textTransform: "uppercase", color: ink(40) }}
          >
            Vera &middot; Confidential
          </p>
        </motion.div>
      </div>

      {/* Evidence preview and download */}
      <Dialog open={!!selectedEvidence} onOpenChange={() => setSelectedEvidence(null)}>
        <DialogContent className="max-w-4xl" style={{ backgroundColor: "var(--vera-paper)", borderColor: ink(8) }}>
          <DialogHeader>
            <DialogTitle className="font-serif" style={{ color: ink(80) }}>{previewImage ? "Evidence Image" : "Evidence File"}</DialogTitle>
          </DialogHeader>
          <div className="relative bg-black/50 rounded-sm overflow-hidden">
            {selectedEvidence && previewImage && (
              <img
                src={selectedEvidence.url}
                alt={selectedEvidence.name}
                className="w-full h-auto"
                onError={(e) => {
                  const target = e.target as HTMLImageElement;
                  target.src = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300"><rect width="400" height="300" fill="%23111"/><text x="50%" y="50%" text-anchor="middle" fill="%23666" font-family="monospace" font-size="14">Failed to load image</text></svg>';
                }}
              />
            )}
          </div>
          {selectedEvidence && !previewImage && (
            <div className="space-y-2" style={{ color: ink(70) }}>
              <p className="break-all">{selectedEvidence.name}</p>
              <p>Preview is not available for this file type. Download the file to review its contents.</p>
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setSelectedEvidence(null)}
              style={{ color: ink(50) }}
            >
              Close
            </Button>
            {selectedEvidence?.url && (
              <Button
                variant="outline"
                size="sm"
                asChild
                style={{ borderColor: ink(8), color: ink(70) }}
              >
                <a href={selectedEvidence.url} download={selectedEvidence.name} target="_blank" rel="noopener noreferrer">
                  <Download className="size-3.5 mr-2" />
                  Download
                </a>
              </Button>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
