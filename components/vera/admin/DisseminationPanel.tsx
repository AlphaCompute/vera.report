import { formatBrowserDateTime } from "@/lib/formatBrowserDateTime";
import { disseminationErrorMessage } from "@/lib/disseminationErrorMessage";
import { normalizeRecipientEmail } from "@/src/utils/recipientEmail";
import { useEffect, useId, useState } from "react";
import {
  Send,
  Copy,
  Check,
  AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { motion } from "motion/react";
import { useDissemination } from "@/hooks/useDissemination";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

interface DisseminationPanelProps {
  trackingId: string;
}

export function DisseminationPanel({ trackingId }: DisseminationPanelProps) {
  const {
    status,
    loading,
    actionPending,
    error,
    emailSecurePacket,
    generateSecurePacket,
    proposeRedaction,
    acceptRedaction,
    clearRedaction,
    markNarrativeClean,
  } = useDissemination(trackingId);

  const [copyError, setCopyError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [secureRecipient, setSecureRecipient] = useState("");
  const recipientErrorId = useId();
  const recipientEmail = normalizeRecipientEmail(secureRecipient);
  const recipientValid = recipientEmail !== null;
  const showRecipientError = secureRecipient.trim().length > 0 && !recipientValid;
  const [securePacketResult, setSecurePacketResult] = useState<{ url: string; sentTo?: string; mode?: string } | null>(null);
  useEffect(() => { setSecurePacketResult(null); }, [trackingId]);

  // AI redaction pass (§7.2): propose → review/edit → accept freezes the
  // narrative override; the raw text stays on-platform.
  const [redactionProposal, setRedactionProposal] = useState<{
    original: string;
    redacted: string;
    notes: string[];
    clean: boolean;
  } | null>(null);
  const [redactionDraft, setRedactionDraft] = useState("");

  const handleProposeRedaction = async () => {
    const proposal = await proposeRedaction();
    if (proposal) {
      setRedactionProposal(proposal);
      setRedactionDraft(proposal.redacted);
    }
  };

  const handleAcceptRedaction = async () => {
    if (!redactionProposal || actionPending || (!redactionProposal.clean && !redactionDraft.trim())) return;
    const ok = redactionProposal.clean
      ? await markNarrativeClean()
      : await acceptRedaction(redactionDraft, redactionProposal.notes);
    if (ok) {
      setRedactionProposal(null);
      setRedactionDraft("");
    }
  };

  const consent = status?.consent ?? null;

  // One-time secure packet (reporter-reward flow): email a single-use link that
  // serves the identity-free dossier packet to an external recipient.
  const handleGenerateSecurePacket = async () => {
    setSecurePacketResult(null);
    setCopyError(null);
    setCopiedKey(null);
    const result = await generateSecurePacket();
    if (result) {
      setSecurePacketResult(result);
      await copyText("secure-packet", result.url);
    }
  };

  const handleEmailSecurePacket = async () => {
    if (actionPending || !consent?.legalReview || !recipientEmail) return;
    setSecurePacketResult(null);
    setCopyError(null);
    const result = await emailSecurePacket(recipientEmail);
    if (result) {
      setSecurePacketResult(result);
      setSecureRecipient("");
    }
  };

  const copyText = async (key: string, text: string) => {
    setCopyError(null);
    setCopiedKey(null);
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      setCopyError("Copy failed. Select the link and copy it manually.");
    }
  };

  return (
    <motion.section
      aria-label="Secure report sharing"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="mb-8 p-5 transition-colors duration-500"
      style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Send className="size-4" style={{ color: ink(40) }} />
          <h3
            className="font-serif"
            style={{ fontSize: "14px", fontWeight: 500, letterSpacing: "0.03em", color: ink(70) }}
          >
            Secure Report Sharing
          </h3>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-center gap-2 p-3 mb-4 border border-red-300 bg-red-50 text-red-900"
        >
          <AlertTriangle className="size-3.5 shrink-0" />
          <span style={{ fontSize: "12px" }}>{disseminationErrorMessage(error)}</span>
        </div>
      )}

      {/* ── Consent status ── */}
      <div className="mb-5 p-3" style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}>
        <p className="mb-2 uppercase" style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(50) }}>
          Reporter Consent
        </p>
        {consent ? (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span style={{ fontSize: "12px", color: ink(50) }}>Trusted legal reviewers</span>
              <Badge
                variant="outline"
                style={{
                  fontSize: "10px",
                  backgroundColor: consent.legalReview ? "rgba(16,185,129,0.08)" : ink(3),
                  borderColor: consent.legalReview ? "rgba(16,185,129,0.2)" : ink(6),
                  color: consent.legalReview ? "rgb(52,211,153)" : ink(40),
                }}
              >
                {consent.legalReview ? "Granted" : "Not granted"}
              </Badge>
            </div>
            <p style={{ fontSize: "10px", color: ink(35) }}>
              Captured {formatBrowserDateTime(consent.capturedAt)} · consent text {consent.textVersion}
            </p>
          </div>
        ) : (
          <p style={{ fontSize: "12px", color: ink(40) }}>
            {loading
              ? "Loading consent..."
              : "No consent on record. Report sharing is unavailable."}
          </p>
        )}
      </div>

      {/* ── Narrative review (AI redaction pass, §7.2) ── */}
      {status && (
        <div className="mb-5 p-3" style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}>
          <div className="flex items-center justify-between mb-2">
            <p className="uppercase" style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(50) }}>
              Narrative Review
            </p>
            {!redactionProposal && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleProposeRedaction}
                disabled={actionPending}
                className="rounded-none disabled:opacity-50"
                style={{ borderColor: ink(6), color: ink(40), fontSize: "10px" }}
              >
                {status.disposition?.narrativeOverride ? "Re-run AI Redaction" : "Run AI Redaction"}
              </Button>
            )}
          </div>

          {status.disposition?.narrativeOverride && !redactionProposal && (
            <div className="space-y-1.5">
              <div className="flex items-center gap-2 flex-wrap">
                <Badge
                  variant="outline"
                  style={{ fontSize: "10px", backgroundColor: "rgba(16,185,129,0.08)", borderColor: "rgba(16,185,129,0.2)", color: "rgb(52,211,153)" }}
                >
                  Redacted narrative active
                </Badge>
                <span style={{ fontSize: "10px", color: ink(35) }}>
                  set by {status.disposition?.narrativeOverride.setBy} · {formatBrowserDateTime(status.disposition?.narrativeOverride.setAt)}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={clearRedaction}
                  disabled={actionPending}
                  style={{ fontSize: "10px", color: "rgb(248,113,113)" }}
                >
                  Revert to raw
                </Button>
              </div>
              {status.disposition?.narrativeOverride.notes.length > 0 && (
                <ul className="space-y-0.5">
                  {status.disposition?.narrativeOverride.notes.map((note, i) => (
                    <li key={i} style={{ fontSize: "10px", color: ink(40) }}>• {note}</li>
                  ))}
                </ul>
              )}
              <p style={{ fontSize: "10px", color: ink(35) }}>
                All packets generated from now on carry the redacted narrative. The raw text stays on-platform.
              </p>
            </div>
          )}

          {!status.disposition?.narrativeOverride && !redactionProposal && (
            <div className="space-y-2">
              <p style={{ fontSize: "11px", color: ink(40) }}>
                Ask AI to suggest removing identifying details from the narrative.
                Review the result before accepting it.
              </p>
              {status.disposition?.narrativeReviewedAt && (
                <p style={{ fontSize: "11px", color: "rgb(52,211,153)" }}>
                  Narrative reviewed — no redaction needed · {formatBrowserDateTime(status.disposition.narrativeReviewedAt)}
                </p>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={markNarrativeClean}
                disabled={actionPending}
                className="rounded-none gap-1.5 disabled:opacity-50"
                style={{ borderColor: ink(6), color: ink(40), fontSize: "10px" }}
              >
                <Check className="size-3" />
                Mark reviewed — no redaction needed
              </Button>
            </div>
          )}

          {redactionProposal && (
            <div className="space-y-2">
              {redactionProposal.clean ? (
                <div className="space-y-2">
                  <p style={{ fontSize: "11px", color: "rgb(52,211,153)" }}>
                    No redactions suggested. Check for identifying details before accepting the narrative.
                  </p>
                  <p className="whitespace-pre-wrap" style={{ fontSize: "11px", color: ink(60) }}>{redactionProposal.original}</p>
                </div>
              ) : (
                <>
                  {redactionProposal.notes.length > 0 && (
                    <ul className="space-y-0.5">
                      {redactionProposal.notes.map((note, i) => (
                        <li key={i} style={{ fontSize: "10px", color: "rgb(251,191,36)" }}>• {note}</li>
                      ))}
                    </ul>
                  )}
                  <p className="uppercase" style={{ fontSize: "9px", letterSpacing: "0.15em", color: ink(30) }}>
                    Proposed narrative (editable)
                  </p>
                  <textarea
                    value={redactionDraft}
                    onChange={(e) => setRedactionDraft(e.target.value)}
                    rows={8}
                    className="w-full p-2 focus:outline-none"
                    style={{ fontSize: "11px", backgroundColor: ink(2), border: `1px solid ${ink(6)}`, color: ink(60), resize: "vertical" }}
                  />
                  <details>
                    <summary className="cursor-pointer" style={{ fontSize: "10px", color: ink(35) }}>
                      Show original narrative
                    </summary>
                    <p className="mt-1 whitespace-pre-wrap p-2" style={{ fontSize: "11px", color: ink(45), backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}>
                      {redactionProposal.original}
                    </p>
                  </details>
                </>
              )}
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  onClick={handleAcceptRedaction}
                  disabled={actionPending || (!redactionProposal.clean && !redactionDraft.trim())}
                  className="rounded-none gap-1.5 disabled:opacity-40"
                  style={{ fontSize: "10px", backgroundColor: "var(--vera-ink)", color: "var(--vera-paper)" }}
                >
                  <Check className="size-3" />
                  {redactionProposal.clean ? "Accept" : "Accept Redaction"}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setRedactionProposal(null);
                    setRedactionDraft("");
                  }}
                  style={{ fontSize: "10px", color: ink(40) }}
                >
                  {redactionProposal.clean ? "Close" : "Discard"}
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── One-time secure packet (reporter-reward flow): email a single-use link ── */}
      <div className="mb-3">
        <p className="mb-2 uppercase" style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(50) }}>
          Secure One-Time Packet
        </p>
        <p className="mb-2" style={{ fontSize: "11px", color: ink(40) }}>
          Generate a single-use link to the report and all attached files. Copy it to share yourself, or send it by email.
          Review the narrative and attachments for identifying details before sharing.
          Recipients download one ZIP containing the PDF report and all attachments.
          Extract the ZIP to open the files. Keep the complete folder when sharing the report.
        </p>
        <Button
          size="sm"
          onClick={handleGenerateSecurePacket}
          disabled={actionPending || !consent?.legalReview}
          className="rounded-none disabled:opacity-40 gap-1 mb-2"
          style={{ fontSize: "10px", backgroundColor: "var(--vera-ink)", color: "var(--vera-paper)" }}
        >
          <Copy className="size-3" />
          Generate and Copy Link
        </Button>
        {copyError && <p role="alert">{copyError}</p>}
        <div className="flex items-center gap-2 flex-wrap">
          <Input
            type="email"
            aria-label="Recipient email"
            aria-invalid={showRecipientError}
            aria-describedby={showRecipientError ? recipientErrorId : undefined}
            placeholder="recipient@example.org"
            value={secureRecipient}
            onChange={(e) => setSecureRecipient(e.target.value)}
            className="rounded-none h-9 flex-1 min-w-[220px] focus-visible:ring-0"
            style={{ border: `1px solid ${showRecipientError ? "rgb(185,28,28)" : ink(6)}`, backgroundColor: ink(2), color: ink(60), fontSize: "12px" }}
          />
          <Button
            size="sm"
            onClick={handleEmailSecurePacket}
            disabled={actionPending || !consent?.legalReview || !recipientValid}
            className="rounded-none disabled:opacity-40 gap-1"
            style={{ fontSize: "10px", backgroundColor: "var(--vera-ink)", color: "var(--vera-paper)" }}
          >
            <Send className="size-3" />
            Generate and Send Link
          </Button>
        </div>
        {showRecipientError && (
          <p id={recipientErrorId} role="alert" className="mt-1 text-red-700" style={{ fontSize: "12px" }}>
            Enter a valid email address.
          </p>
        )}
        {securePacketResult && (
          <div className="mt-2 p-2" style={{ backgroundColor: ink(3), border: `1px solid ${ink(6)}` }}>
            <p style={{ fontSize: "10px", color: ink(45) }}>
              {securePacketResult.sentTo ? (
                <>
                  {securePacketResult.mode === "live" ? "Sent to:" : "Dryrun — sent to test inbox:"}{" "}
                  <span className="font-mono">{securePacketResult.sentTo}</span>
                </>
              ) : "Link generated. No email sent."}
            </p>
            <div className="flex items-start gap-2 mt-1">
              <span className="flex-1 font-mono break-all" style={{ fontSize: "10px", color: ink(40) }}>
                {securePacketResult.url}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => copyText("secure-packet", securePacketResult.url)}
                className="gap-1 shrink-0"
                style={{ fontSize: "10px", color: copiedKey === "secure-packet" ? "rgb(52,211,153)" : ink(40) }}
              >
                {copiedKey === "secure-packet" ? <Check className="size-3" /> : <Copy className="size-3" />}
                {copiedKey === "secure-packet" ? "Copied" : "Copy"}
              </Button>
            </div>
          </div>
        )}
      </div>

    </motion.section>
  );
}
