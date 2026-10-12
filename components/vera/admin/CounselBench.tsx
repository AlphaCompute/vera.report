import { useState } from "react";
import { Scale, Plus, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useCounselPartners, type CounselPartner } from "@/hooks/useDissemination";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

/** Tier C channels a counsel partner can be scoped to. */
const COUNSEL_CHANNELS = [
  { id: "sec-tcr", label: "SEC TCR" },
  { id: "cftc-tcr", label: "CFTC TCR" },
  { id: "irs-211", label: "IRS 211" },
  { id: "eeoc", label: "EEOC" },
  { id: "osha", label: "OSHA" },
  { id: "osc", label: "OSC" },
  { id: "agency-oig", label: "Agency OIG" },
];

const ENGAGEMENT_LABELS: Record<CounselPartner["engagementModel"], string> = {
  "psst-legal": "Psst Legal",
  panel: "Panel firm",
  "reporter-own": "Reporter's own attorney",
};

const EMPTY_FORM = {
  name: "",
  contactHandle: "",
  engagementModel: "panel" as CounselPartner["engagementModel"],
  channels: [] as string[],
};

/**
 * Counsel partner bench (Phase 3a): Tier C routing targets as data.
 * Psst Legal, panel firms, and "reporter's own attorney" are rows here —
 * deactivating a row removes it from assignment without a deploy.
 */
export function CounselBench() {
  const { partners, loading, saving, error, savePartner } = useCounselPartners();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editingId, setEditingId] = useState<string | null>(null);

  const toggleChannel = (id: string) =>
    setForm((f) => ({
      ...f,
      channels: f.channels.includes(id) ? f.channels.filter((c) => c !== id) : [...f.channels, id],
    }));

  const startEdit = (p: CounselPartner) => {
    setEditingId(p.counselId);
    setForm({
      name: p.name,
      contactHandle: p.contactHandle,
      engagementModel: p.engagementModel,
      channels: p.channels,
    });
    setShowForm(true);
  };

  const submit = async () => {
    const ok = await savePartner({
      ...(editingId ? { counselId: editingId } : {}),
      name: form.name,
      contactHandle: form.contactHandle,
      engagementModel: form.engagementModel,
      channels: form.channels,
      active: true,
    });
    if (ok) {
      setShowForm(false);
      setEditingId(null);
      setForm(EMPTY_FORM);
    }
  };

  const setActive = (p: CounselPartner, active: boolean) =>
    savePartner({ ...p, active });

  return (
    <div className="p-5" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Scale className="size-4" style={{ color: ink(40) }} />
          <h3 className="font-serif" style={{ fontSize: "14px", fontWeight: 500, letterSpacing: "0.03em", color: ink(70) }}>
            Counsel Bench (Tier C)
          </h3>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            setShowForm(!showForm);
            setEditingId(null);
            setForm(EMPTY_FORM);
          }}
          className="rounded-none gap-1.5"
          style={{ borderColor: ink(6), color: ink(40), fontSize: "11px" }}
        >
          <Plus className="size-3" />
          Add Partner
        </Button>
      </div>

      <p className="mb-4" style={{ fontSize: "11px", color: ink(35) }}>
        Counsel partners are routing targets for counsel-mediated channels. Assignment generates a
        matter code; the reporter contacts counsel directly, off-platform.
      </p>

      {error && (
        <p className="mb-3" style={{ fontSize: "12px", color: "rgb(248,113,113)" }}>{error}</p>
      )}

      {showForm && (
        <div className="mb-4 p-3 space-y-3" style={{ backgroundColor: ink(2), border: `1px solid ${ink(6)}` }}>
          <div className="flex gap-2 flex-wrap">
            <Input
              placeholder="Firm / attorney name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              className="rounded-none h-9 flex-1 min-w-[180px] focus-visible:ring-0"
              style={{ border: `1px solid ${ink(6)}`, backgroundColor: ink(2), color: ink(60), fontSize: "12px" }}
            />
            <Input
              placeholder="Contact handle (e.g. Signal: @firm.01)"
              value={form.contactHandle}
              onChange={(e) => setForm((f) => ({ ...f, contactHandle: e.target.value }))}
              className="rounded-none h-9 flex-1 min-w-[180px] focus-visible:ring-0"
              style={{ border: `1px solid ${ink(6)}`, backgroundColor: ink(2), color: ink(60), fontSize: "12px" }}
            />
            <select
              value={form.engagementModel}
              onChange={(e) => setForm((f) => ({ ...f, engagementModel: e.target.value as CounselPartner["engagementModel"] }))}
              className="h-9 px-2"
              style={{ fontSize: "11px", backgroundColor: ink(2), border: `1px solid ${ink(6)}`, color: ink(50) }}
            >
              {Object.entries(ENGAGEMENT_LABELS).map(([id, label]) => (
                <option key={id} value={id}>{label}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {COUNSEL_CHANNELS.map((ch) => (
              <button
                key={ch.id}
                type="button"
                onClick={() => toggleChannel(ch.id)}
                className="px-2 py-1"
                style={{
                  fontSize: "10px",
                  border: `1px solid ${form.channels.includes(ch.id) ? ink(30) : ink(6)}`,
                  backgroundColor: form.channels.includes(ch.id) ? ink(6) : "transparent",
                  color: form.channels.includes(ch.id) ? ink(70) : ink(40),
                }}
              >
                {ch.label}
              </button>
            ))}
          </div>
          <Button
            size="sm"
            onClick={submit}
            disabled={saving || !form.name.trim() || !form.contactHandle.trim()}
            className="rounded-none gap-1.5 disabled:opacity-40"
            style={{ fontSize: "10px", backgroundColor: "var(--vera-ink)", color: "var(--vera-paper)" }}
          >
            <Check className="size-3" />
            {editingId ? "Update Partner" : "Save Partner"}
          </Button>
        </div>
      )}

      {loading ? (
        <p style={{ fontSize: "12px", color: ink(40) }}>Loading...</p>
      ) : partners.length === 0 ? (
        <p style={{ fontSize: "12px", color: ink(40) }}>
          No counsel partners yet — Tier C channels cannot be assigned until one is added.
        </p>
      ) : (
        <div className="space-y-2">
          {partners.map((p) => (
            <div
              key={p.counselId}
              className="flex items-center justify-between gap-2 p-3 flex-wrap"
              style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}`, opacity: p.active ? 1 : 0.5 }}
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span style={{ fontSize: "13px", color: ink(60) }}>{p.name}</span>
                  <Badge variant="outline" style={{ fontSize: "9px", borderColor: ink(8), color: ink(40) }}>
                    {ENGAGEMENT_LABELS[p.engagementModel]}
                  </Badge>
                  {!p.active && (
                    <Badge variant="outline" style={{ fontSize: "9px", borderColor: ink(8), color: ink(35) }}>
                      Inactive
                    </Badge>
                  )}
                </div>
                <p style={{ fontSize: "10px", color: ink(35) }}>
                  {p.contactHandle} · {p.channels.length > 0 ? p.channels.join(", ") : "no channels"}
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => startEdit(p)}
                  style={{ fontSize: "10px", color: ink(40) }}
                >
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setActive(p, !p.active)}
                  disabled={saving}
                  style={{ fontSize: "10px", color: p.active ? "rgb(248,113,113)" : "rgb(52,211,153)" }}
                >
                  {p.active ? "Deactivate" : "Activate"}
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
