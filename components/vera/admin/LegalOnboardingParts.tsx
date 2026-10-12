import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  LegalAdminError, ORGANIZATION_STATUS_LABELS, formatAdminTime, legalAdminMessage, listLegalAudit, listLegalOrganizations,
} from "@/lib/legalOnboardingClient";
import type { LegalAdminFailure } from "@/lib/legalOnboardingClient";
import { LEGAL_AUDIT_ACTION_LABELS } from "@/src/utils/legalOnboarding";
import type { LegalAuditView, LegalOrganizationStatus } from "@/src/utils/legalOnboarding";

/** Shared pieces of the admin legal-organization screens (existing admin styling). */
export const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;
export const headStyle = { fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase" as const, color: ink(45) };
export const cardStyle = { backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` };

const STATUS_TONE: Record<LegalOrganizationStatus, string> = {
  "awaiting-registration": "bg-amber-500/10 text-amber-700 border-amber-500/30",
  active: "bg-emerald-500/10 text-emerald-700 border-emerald-500/30",
  revoked: "bg-red-500/10 text-red-700 border-red-500/30",
};
export function OrganizationStatusBadge({ status }: { status: LegalOrganizationStatus }) {
  return <span className={`inline-flex items-center border px-2 py-0.5 text-xs whitespace-nowrap ${STATUS_TONE[status]}`}>
    {ORGANIZATION_STATUS_LABELS[status]}
  </span>;
}

/** `message` replaces the default wording for screens other than legal
 * organizations (the Encrypted tab), keeping the same sign-in and retry rules. */
export function FailureNotice({ failure, onRetry, message }: { failure: LegalAdminFailure; onRetry?: () => void; message?: string }) {
  return <div role="alert" className="py-6 text-sm" style={{ color: ink(65) }}>
    <p>{message ?? legalAdminMessage(failure)}</p>
    <div className="mt-3 flex flex-wrap gap-2">
      {failure.kind === "signed-out" && <Button variant="outline" size="sm" onClick={() => { window.location.href = "/auth/login?returnTo=/legal/organizations"; }}>Sign in again</Button>}
      {onRetry && failure.kind !== "signed-out" && failure.kind !== "forbidden" && failure.kind !== "not-enabled" &&
        <Button variant="outline" size="sm" onClick={onRetry}>Try again</Button>}
    </div>
  </div>;
}

/** Onboarding audit trail, newest first. Organization and invitation lifecycle only. */
export function AuditTrail({ organizationId, names }: { organizationId?: string; names?: Record<string, string> }) {
  const [events, setEvents] = useState<LegalAuditView[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "more">("loading");
  const [failure, setFailure] = useState<LegalAdminFailure | null>(null);
  const [directory, setDirectory] = useState<Record<string, string>>(names ?? {});
  const load = useCallback(async (before: string | null) => {
    setFailure(null); setState(before ? "more" : "loading");
    try {
      const page = await listLegalAudit({ organizationId, before, limit: 25 });
      setEvents(current => before ? [...current, ...page.events] : page.events);
      setNext(page.next);
    } catch (error) { setFailure(error instanceof LegalAdminError ? error.failure : { kind: "unavailable" }); }
    finally { setState("ready"); }
  }, [organizationId]);
  useEffect(() => { void load(null); }, [load]);
  useEffect(() => {
    if (organizationId || names) return;
    listLegalOrganizations().then(items => setDirectory(Object.fromEntries(items.map(item => [item.organizationId, item.displayName]))))
      .catch(() => { /* names are optional; IDs remain */ });
  }, [organizationId, names]);

  if (state === "loading") return <p role="status" className="py-6 text-sm" style={{ color: ink(55) }}>Loading audit trail…</p>;
  return <div className="space-y-3">
    {failure && <FailureNotice failure={failure} onRetry={() => void load(events.length ? next : null)} />}
    {!failure && events.length === 0 && <p className="text-sm" style={{ color: ink(50) }}>No onboarding events yet.</p>}
    {events.length > 0 && <ol className="space-y-0" style={{ borderTop: `1px solid ${ink(4)}` }}>
      {events.map(event => (
        <li key={event.eventId} className="grid gap-1 py-3 sm:grid-cols-[12rem_1fr]" style={{ borderBottom: `1px solid ${ink(4)}` }}>
          <time dateTime={new Date(event.at).toISOString()} style={{ fontSize: "12px", color: ink(50) }}>{formatAdminTime(event.at)}</time>
          <div className="min-w-0" style={{ fontSize: "13px", color: ink(80) }}>
            <span className="font-medium">{LEGAL_AUDIT_ACTION_LABELS[event.action]}</span>
            {!organizationId && <span style={{ color: ink(60) }}> · {directory[event.organizationId] ?? `${event.organizationId.slice(0, 12)}…`}</span>}
            <span className="block break-all" style={{ fontSize: "12px", color: ink(50) }}>
              By {event.actor}{event.subject && event.subject !== event.actor ? ` · Person: ${event.subject}` : ""}
            </span>
          </div>
        </li>
      ))}
    </ol>}
    {next && <Button variant="outline" size="sm" disabled={state === "more"} onClick={() => void load(next)}>
      {state === "more" ? "Loading…" : "Show older events"}
    </Button>}
  </div>;
}
