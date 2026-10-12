import { useState } from "react";
import { GitBranch, Plus, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useRoutingRules, type RoutingRule } from "@/hooks/useDissemination";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

/* Match-dimension options — mirror the backend taxonomy. */
const CATEGORY_OPTIONS = [
  "ai-safety", "trust-safety", "encryption", "financial-fraud",
  "discrimination-harassment", "cyber-security", "crypto",
  "environment-climate", "government-accountability", "illegal-government-activity",
];
const SEVERITY_OPTIONS = ["low", "medium", "high", "critical"];
const JURISDICTION_OPTIONS = ["us", "eu", "other"];
const ORG_TYPE_OPTIONS = [
  "us-federal-government", "state-government", "local-government",
  "other-government", "for-profit", "nonprofit",
];
const ENTITY_OPTIONS = [
  "cisa", "gao-fraudnet", "epa-oig", "psst-safe", "securedrop", "fbi-ic3", "epa-violation",
  "sec-tcr", "cftc-tcr", "fincen", "irs-211", "ftc", "doj",
  "eeoc", "osha", "osc", "agency-oig",
  "eu-olaf", "ec-competition", "de-external", "fr-external", "ie-external", "nl-external",
];

interface RuleForm {
  ruleId: string;
  categories: string[];
  severity: string[];
  jurisdiction: string[];
  orgType: string[];
  route: string[];
}

const EMPTY_FORM: RuleForm = {
  ruleId: "",
  categories: [],
  severity: [],
  jurisdiction: [],
  orgType: [],
  route: [],
};

function TogglePills({
  options,
  selected,
  onToggle,
}: {
  options: string[];
  selected: string[];
  onToggle: (value: string) => void;
}) {
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {options.map((opt) => {
        const on = selected.includes(opt);
        return (
          <button
            key={opt}
            type="button"
            onClick={() => onToggle(opt)}
            className="px-2 py-1"
            style={{
              fontSize: "10px",
              border: `1px solid ${on ? ink(30) : ink(6)}`,
              backgroundColor: on ? ink(6) : "transparent",
              color: on ? ink(70) : ink(40),
            }}
          >
            {opt}
          </button>
        );
      })}
    </div>
  );
}

function matchSummary(rule: RoutingRule): string {
  const parts: string[] = [];
  if (rule.match.categories?.length) parts.push(`categories: ${rule.match.categories.join(", ")}`);
  if (rule.match.severity?.length) parts.push(`severity: ${rule.match.severity.join(", ")}`);
  if (rule.match.jurisdiction?.length) parts.push(`jurisdiction: ${rule.match.jurisdiction.join(", ")}`);
  const org = rule.match.orgType;
  const orgList = Array.isArray(org) ? org : org ? [org] : [];
  if (orgList.length) parts.push(`org type: ${orgList.join(", ")}`);
  return parts.length > 0 ? parts.join(" · ") : "matches every report";
}

/**
 * Routing-rules editor (FR-2, PDR §6): compliance admins edit
 * category/severity/jurisdiction/org-type routing without a redeploy.
 * Every save bumps the rule version and lands in the audit trail.
 */
export function RoutingRulesEditor() {
  const { rules, loading, saving, error, saveRule } = useRoutingRules();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<RuleForm>(EMPTY_FORM);
  const [editingId, setEditingId] = useState<string | null>(null);

  const toggle = (field: keyof Omit<RuleForm, "ruleId">) => (value: string) =>
    setForm((f) => ({
      ...f,
      [field]: f[field].includes(value) ? f[field].filter((v) => v !== value) : [...f[field], value],
    }));

  const startEdit = (rule: RoutingRule) => {
    const org = rule.match.orgType;
    setEditingId(rule.ruleId);
    setForm({
      ruleId: rule.ruleId,
      categories: rule.match.categories ?? [],
      severity: rule.match.severity ?? [],
      jurisdiction: rule.match.jurisdiction ?? [],
      orgType: Array.isArray(org) ? org : org ? [org] : [],
      route: rule.route.map((r) => r.entityId),
    });
    setShowForm(true);
  };

  const submit = async () => {
    const ok = await saveRule({
      ruleId: form.ruleId.trim(),
      match: {
        ...(form.categories.length ? { categories: form.categories } : {}),
        ...(form.severity.length ? { severity: form.severity } : {}),
        ...(form.jurisdiction.length ? { jurisdiction: form.jurisdiction } : {}),
        ...(form.orgType.length ? { orgType: form.orgType } : {}),
      },
      route: form.route.map((entityId) => ({ entityId })),
      active: true,
    });
    if (ok) {
      setShowForm(false);
      setEditingId(null);
      setForm(EMPTY_FORM);
    }
  };

  const setActive = (rule: RoutingRule, active: boolean) => {
    const org = rule.match.orgType;
    return saveRule({
      ruleId: rule.ruleId,
      match: {
        ...(rule.match.categories?.length ? { categories: rule.match.categories } : {}),
        ...(rule.match.severity?.length ? { severity: rule.match.severity } : {}),
        ...(rule.match.jurisdiction?.length ? { jurisdiction: rule.match.jurisdiction } : {}),
        ...(org ? { orgType: Array.isArray(org) ? org : [org] } : {}),
      },
      route: rule.route.map((r) => ({ entityId: r.entityId })),
      active,
    });
  };

  return (
    <div className="p-5" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <GitBranch className="size-4" style={{ color: ink(40) }} />
          <h3 className="font-serif" style={{ fontSize: "14px", fontWeight: 500, letterSpacing: "0.03em", color: ink(70) }}>
            Routing Rules
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
          Add Rule
        </Button>
      </div>

      <p className="mb-4" style={{ fontSize: "11px", color: ink(35) }}>
        Rules are data, not code: a rule fires when every set dimension matches the report, and its
        route entities join the recommended plan. Edits take effect on the next plan run — no deploy.
      </p>

      {error && (
        <p className="mb-3" style={{ fontSize: "12px", color: "rgb(248,113,113)" }}>{error}</p>
      )}

      {showForm && (
        <div className="mb-4 p-3 space-y-3" style={{ backgroundColor: ink(2), border: `1px solid ${ink(6)}` }}>
          <Input
            placeholder="Rule ID (e.g. custom-fraud-forprofit-v1)"
            value={form.ruleId}
            onChange={(e) => setForm((f) => ({ ...f, ruleId: e.target.value }))}
            disabled={!!editingId}
            className="rounded-none h-9 max-w-[320px] focus-visible:ring-0"
            style={{ border: `1px solid ${ink(6)}`, backgroundColor: ink(2), color: ink(60), fontSize: "12px" }}
          />
          {([
            ["Categories (any of)", "categories", CATEGORY_OPTIONS],
            ["Severity (any of)", "severity", SEVERITY_OPTIONS],
            ["Jurisdiction (any of)", "jurisdiction", JURISDICTION_OPTIONS],
            ["Org type (any of)", "orgType", ORG_TYPE_OPTIONS],
            ["Route to entities", "route", ENTITY_OPTIONS],
          ] as const).map(([label, field, options]) => (
            <div key={field}>
              <p className="mb-1.5 uppercase" style={{ fontSize: "9px", letterSpacing: "0.15em", color: ink(30) }}>
                {label}
              </p>
              <TogglePills options={[...options]} selected={form[field]} onToggle={toggle(field)} />
            </div>
          ))}
          <Button
            size="sm"
            onClick={submit}
            disabled={saving || !form.ruleId.trim() || form.route.length === 0}
            className="rounded-none gap-1.5 disabled:opacity-40"
            style={{ fontSize: "10px", backgroundColor: "var(--vera-ink)", color: "var(--vera-paper)" }}
          >
            <Check className="size-3" />
            {editingId ? "Update Rule" : "Save Rule"}
          </Button>
        </div>
      )}

      {loading ? (
        <p style={{ fontSize: "12px", color: ink(40) }}>Loading...</p>
      ) : rules.length === 0 ? (
        <p style={{ fontSize: "12px", color: ink(40) }}>No routing rules found.</p>
      ) : (
        <div className="space-y-2">
          {rules.map((rule) => (
            <div
              key={rule.ruleId}
              className="flex items-center justify-between gap-2 p-3 flex-wrap"
              style={{ backgroundColor: ink(2), border: `1px solid ${ink(4)}`, opacity: rule.active ? 1 : 0.5 }}
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono" style={{ fontSize: "12px", color: ink(60) }}>{rule.ruleId}</span>
                  <Badge variant="outline" style={{ fontSize: "9px", borderColor: ink(8), color: ink(40) }}>
                    v{rule.version}
                  </Badge>
                  {!rule.active && (
                    <Badge variant="outline" style={{ fontSize: "9px", borderColor: ink(8), color: ink(35) }}>
                      Inactive
                    </Badge>
                  )}
                </div>
                <p style={{ fontSize: "10px", color: ink(35) }}>{matchSummary(rule)}</p>
                <p style={{ fontSize: "10px", color: ink(45) }}>
                  → {rule.route.map((r) => r.entityId).join(", ")}
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => startEdit(rule)}
                  style={{ fontSize: "10px", color: ink(40) }}
                >
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setActive(rule, !rule.active)}
                  disabled={saving}
                  style={{ fontSize: "10px", color: rule.active ? "rgb(248,113,113)" : "rgb(52,211,153)" }}
                >
                  {rule.active ? "Deactivate" : "Activate"}
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
