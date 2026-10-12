import { formatBrowserDateTime } from "@/lib/formatBrowserDateTime";
import { AlertTriangle, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useDisseminationAlerts, type DisseminationAlert } from "@/hooks/useDissemination";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

const KIND_LABELS: Record<DisseminationAlert["kind"], string> = {
  dead_letter: "Dead-lettered",
  ack_sla_breached: "7-day ack SLA breached",
  feedback_sla_breached: "3-month feedback SLA breached",
};

/**
 * Alerts rail (NFR-3 + PDR §8): dissemination channels needing attention —
 * dead-lettered submissions (retryable) and SLA-breached channels.
 * Renders nothing while the queue is clean.
 */
export function DisseminationAlerts() {
  const { alerts, retrying, error, retry } = useDisseminationAlerts();

  if (alerts.length === 0 && !error) return null;

  return (
    <div className="p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <AlertTriangle className="size-4" style={{ color: "rgba(245,158,11,0.6)" }} />
          <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
            Dissemination Alerts
          </h3>
          <Badge variant="outline" style={{ fontSize: "9px", borderColor: "rgba(245,158,11,0.3)", color: "rgba(245,158,11,0.8)" }}>
            {alerts.length}
          </Badge>
        </div>
      </div>

      {error && (
        <p className="mb-3" style={{ fontSize: "12px", color: "rgb(248,113,113)" }}>{error}</p>
      )}

      <div className="space-y-2">
        {alerts.map((alert) => {
          const key = `${alert.trackingId}:${alert.entityId}`;
          return (
            <div
              key={key}
              className="flex items-center justify-between gap-2 p-3 flex-wrap"
              style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}` }}
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono" style={{ fontSize: "11px", color: ink(60) }}>
                    {alert.trackingId}
                  </span>
                  <span style={{ fontSize: "12px", color: ink(55) }}>{alert.entityName}</span>
                  <Badge
                    variant="outline"
                    style={{
                      fontSize: "9px",
                      borderColor: alert.kind === "dead_letter" ? "rgba(248,113,113,0.35)" : "rgba(245,158,11,0.3)",
                      color: alert.kind === "dead_letter" ? "rgb(248,113,113)" : "rgba(245,158,11,0.8)",
                    }}
                  >
                    {KIND_LABELS[alert.kind]}
                  </Badge>
                </div>
                <p style={{ fontSize: "10px", color: ink(35) }}>
                  {alert.kind === "dead_letter"
                    ? `${alert.attempts} attempt${alert.attempts === 1 ? "" : "s"}${alert.lastError ? ` · ${alert.lastError}` : ""}`
                    : `dispatched ${formatBrowserDateTime(alert.dispatchedAt)} · state: ${alert.state}`}
                </p>
              </div>
              {alert.kind === "dead_letter" && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => retry(alert.trackingId, alert.entityId)}
                  disabled={retrying === key}
                  className="gap-1.5"
                  style={{ fontSize: "10px", color: ink(50) }}
                >
                  <RotateCcw className="size-3" />
                  {retrying === key ? "Retrying..." : "Retry"}
                </Button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
