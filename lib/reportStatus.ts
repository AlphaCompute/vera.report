/**
 * Pure helpers for the reporter-facing /status timeline.
 *
 * Extracted from pages/status.tsx so the backend-status → timeline mapping can
 * be unit-tested without pulling the whole page component (and its React /
 * motion imports) into the test runner.
 */

export interface TimelineEntry {
  status: string;
  label: string;
  date: string | null;
  note: string | null;
}

/** Canonical tracking-ID shape: `VRA-` + 16 hex. Mirrors the API validator. */
export const TRACKING_ID_PATTERN = /^(?:VRA-[A-F0-9]{16}|VRC-[A-F0-9]{64})$/i;

/**
 * Well-formed tracking-ID example for UI hints. MUST satisfy
 * TRACKING_ID_PATTERN — the /status placeholder used to advertise a 6-char
 * shape the validator rejects with a 400 (#452).
 *
 * MUST NEVER be a real, resolvable report ID (#498). /status is
 * unauthenticated — anyone who types the example gets the case behind it — so a
 * working ID here is a public link to that report. This all-zero sentinel is
 * structurally valid but reserved: it 404s on every environment and no real,
 * randomly-generated ID can collide with it. Do not "refresh" it with a value
 * copied from a live report or a QA run.
 */
export const TRACKING_ID_EXAMPLE = "VRA-0000000000000000";

/**
 * The same reserved sentinel for the `VRC-` + 64 hex reporter credential, which
 * is what the /report wizard hands a web reporter. The VRA form above only ever
 * was issued by a retired intake channel, so advertising it on /status
 * showed web reporters an example in a shape their own receipt never takes.
 * Every rule on TRACKING_ID_EXAMPLE applies here: structurally valid, reserved,
 * never refreshed from a live report.
 */
export const CREDENTIAL_EXAMPLE =
  "VRC-0000000000000000000000000000000000000000000000000000000000000000";

/** Why a /status lookup could not return a report. */
export type ReportLookupFailure = "format" | "rate-limited" | "unavailable";

/**
 * A /status lookup that failed for a reason the reporter can act on.
 *
 * The page used to collapse every non-404 response into "Unable to reach the
 * server", so a mistyped ID (400) and a rate-limited reporter (429) both sent
 * someone off to check their network for a problem that was never there.
 */
export class ReportLookupError extends Error {
  constructor(readonly reason: ReportLookupFailure) {
    super(`Report lookup failed: ${reason}`);
    this.name = "ReportLookupError";
  }
}

/** Map a lookup failure onto the message shown to the reporter. */
export function lookupFailureMessage(reason: ReportLookupFailure): string {
  switch (reason) {
    case "format":
      return "That does not look like a Report ID. Check it against the one you saved when you submitted.";
    case "rate-limited":
      return "Too many lookups from here. Wait a minute and try again.";
    default:
      return "Unable to reach the server. Please try again.";
  }
}

/**
 * Classify a failing lookup response status. 404 is not a failure — it means the
 * ID was well formed and matched nothing — and is handled before this is called.
 */
export function classifyLookupStatus(status: number): ReportLookupFailure {
  if (status === 400 || status === 422) return "format";
  if (status === 429) return "rate-limited";
  return "unavailable";
}

/**
 * Map a raw backend report status onto a display stage.
 *
 * Positive path: processing/pending/received → received → review →
 * investigation → resolved. Terminal-negative states (dismissed, rejected) map
 * to "declined" — they END the case and must NOT fall through to "received",
 * which would present a closed report as freshly logged with stages still
 * pending (#450). Anything unmapped returns "unknown" so a new backend state
 * fails visibly instead of masquerading as the first stage.
 */
export function mapBackendStatus(status: string): string {
  const map: Record<string, string> = {
    processing: "received",
    pending: "received",
    received: "received",
    review: "review",
    under_review: "review",
    verified: "investigation",
    investigation: "investigation",
    resolved: "resolved",
    closed: "resolved",
    dismissed: "declined",
    rejected: "declined",
  };
  return map[status?.toLowerCase()] || "unknown";
}

export function buildTimeline(status: string, createdAt: string): TimelineEntry[] {
  const mapped = mapBackendStatus(status);
  const createdDate = createdAt
    ? new Date(createdAt).toISOString().split("T")[0]
    : null;

  const receivedEntry: TimelineEntry = {
    status: "received",
    label: "Report Received",
    date: createdDate,
    note: "Your report has been securely logged into the system.",
  };

  // Terminal-negative: received, then closed without moving forward. Show that
  // plainly instead of parking it at "Received" behind three stages that will
  // never advance (#450).
  if (mapped === "declined") {
    return [
      receivedEntry,
      {
        status: "declined",
        label: "Report Closed",
        date: null,
        note: "After review, this report was not taken forward. If you believe this is an error, you can submit again with additional detail or escalate through an external channel.",
      },
    ];
  }

  // Unmapped backend status: surface it honestly rather than flatter it.
  if (mapped === "unknown") {
    return [
      receivedEntry,
      {
        status: "unknown",
        label: "Status Unavailable",
        date: null,
        note: "This report's current status could not be displayed. Please check back later, or contact the channel you submitted through.",
      },
    ];
  }

  const statusOrder = ["received", "review", "investigation", "resolved"];
  const currentIdx = statusOrder.indexOf(mapped);

  const labels: Record<string, { label: string; note: string }> = {
    received: {
      label: "Report Received",
      note: "Your report has been securely logged into the system.",
    },
    review: {
      label: "Under Review",
      note: "A case officer has been assigned and is reviewing the details.",
    },
    investigation: {
      label: "Investigation",
      note: "Active investigation underway. Additional evidence is being gathered.",
    },
    resolved: { label: "Resolved", note: "Case has been resolved." },
  };

  return statusOrder.map((s, i) => ({
    status: s,
    label: labels[s].label,
    date: i <= currentIdx ? (i === 0 ? createdDate : null) : null,
    note: i <= currentIdx ? labels[s].note : null,
  }));
}
