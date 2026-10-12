import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { motion } from "motion/react";
import { Scale } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { LegalAdminError, createLegalOrganization, legalAdminMessage, listLegalOrganizations } from "@/lib/legalOnboardingClient";
import type { LegalAdminFailure } from "@/lib/legalOnboardingClient";
import { validateNewLegalOrganization } from "@/src/utils/legalOnboarding";
import type { LegalOrganizationView, NewLegalOrganizationErrors } from "@/src/utils/legalOnboarding";
import { LegalOrganizationDetail } from "./LegalOrganizationDetail";
import { AuditTrail, FailureNotice, OrganizationStatusBadge, cardStyle, headStyle, ink } from "./LegalOnboardingParts";

type View = { kind: "list" } | { kind: "create" } | { kind: "detail"; organizationId: string; created?: boolean } | { kind: "audit" };

/** Admin screens for onboarding legal organizations. Roster metadata only: names,
 * domains, public keys, invitations, member access and the onboarding audit trail.
 * There is no case, access request or case content anywhere on these screens. */
export function LegalOrganizationsView() {
  const [view, setView] = useState<View>({ kind: "list" });
  const heading = useRef<HTMLHeadingElement>(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    heading.current?.focus();
  }, [view]);
  const title = view.kind === "create" ? "Add a legal organization" : view.kind === "audit" ? "Onboarding audit trail" : "Legal organizations";

  return (
    <motion.div key="legal" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-6">
      <div className="flex items-start gap-3">
        <Scale className="mt-1 h-4 w-4 shrink-0" style={{ color: ink(45) }} aria-hidden />
        <div className="min-w-0">
          {view.kind !== "detail" && <h2 ref={heading} tabIndex={-1} className="font-serif outline-none" style={{ fontSize: "1.4rem", fontWeight: 300, color: ink(85) }}>{title}</h2>}
          {view.kind === "list" && <p style={{ fontSize: "13px", color: ink(55), maxWidth: "46rem" }}>
            Review legal applications in the staff Slack channel. Approved firms submit their public key through VERA for signed approval.
            Nothing here gives access to any report: only the reporter can allow that.
          </p>}
        </div>
      </div>

      {view.kind === "list" && <OrganizationList onOpen={organizationId => setView({ kind: "detail", organizationId })}
        onCreate={() => setView({ kind: "create" })} onAudit={() => setView({ kind: "audit" })} />}
      {view.kind === "create" && <CreateOrganizationForm onCancel={() => setView({ kind: "list" })}
        onCreated={organization => setView({ kind: "detail", organizationId: organization.organizationId, created: true })} />}
      {view.kind === "detail" && <LegalOrganizationDetail organizationId={view.organizationId} justCreated={!!view.created}
        headingRef={heading} onBack={() => setView({ kind: "list" })} />}
      {view.kind === "audit" && <>
        <Button variant="outline" size="sm" onClick={() => setView({ kind: "list" })}>Back to legal organizations</Button>
        <AuditTrail />
      </>}
    </motion.div>
  );
}

function OrganizationList({ onOpen, onCreate, onAudit }: { onOpen: (id: string) => void; onCreate: () => void; onAudit: () => void }) {
  const [organizations, setOrganizations] = useState<LegalOrganizationView[] | null>(null);
  const [failure, setFailure] = useState<LegalAdminFailure | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);
  const load = useCallback(async () => {
    setFailure(null); setOrganizations(null);
    try { setOrganizations(await listLegalOrganizations()); }
    catch (error) { setFailure(error instanceof LegalAdminError ? error.failure : { kind: "unavailable" }); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  if (failure) return <FailureNotice failure={failure} onRetry={() => void load()} />;
  if (!organizations) return <p role="status" className="py-8 text-sm" style={{ color: ink(55) }}>Loading legal organizations…</p>;
  const revoked = organizations.filter(item => item.status === "revoked").length;
  const shown = showRevoked ? organizations : organizations.filter(item => item.status !== "revoked");
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" onClick={onCreate}>Add legal organization</Button>
      <Button size="sm" variant="outline" onClick={onAudit}>Audit trail</Button>
      {revoked > 0 && <Button size="sm" variant="ghost" aria-pressed={showRevoked} onClick={() => setShowRevoked(value => !value)}>
        {showRevoked ? "Hide revoked" : `Show revoked (${revoked})`}
      </Button>}
    </div>
    {shown.length === 0 ? (
      <div className="p-10 text-center" style={cardStyle}>
        <p className="font-serif italic" style={{ fontSize: "14px", color: ink(55) }}>No legal organizations yet</p>
        <p className="mx-auto mt-2 max-w-md" style={{ fontSize: "13px", color: ink(50) }}>
          Add an organization after you have vetted it. You will get an organization ID to send them for their key setup.
        </p>
      </div>
    ) : (
      <div className="overflow-x-auto" style={{ border: `1px solid ${ink(4)}` }}>
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent" style={{ borderColor: ink(4) }}>
              <TableHead style={headStyle}>Organization</TableHead>
              <TableHead style={headStyle}>Status</TableHead>
              <TableHead style={headStyle}>People with access</TableHead>
              <TableHead style={headStyle}>Pending invitations</TableHead>
              <TableHead style={headStyle}><span className="sr-only">Open</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shown.map(organization => (
              <TableRow key={organization.organizationId} style={{ borderColor: ink(4) }}>
                <TableCell className="align-top">
                  <span className="block" style={{ fontSize: "13px", color: ink(85) }}>{organization.displayName}</span>
                  <span className="block font-mono" style={{ fontSize: "11px", color: ink(50) }}>{organization.domain}</span>
                </TableCell>
                <TableCell className="align-top"><OrganizationStatusBadge status={organization.status} /></TableCell>
                <TableCell className="align-top" style={{ fontSize: "13px", color: ink(70) }}>{organization.activeMembers}</TableCell>
                <TableCell className="align-top" style={{ fontSize: "13px", color: ink(70) }}>{organization.pendingInvitations}</TableCell>
                <TableCell className="align-top text-right">
                  <Button variant="outline" size="sm" onClick={() => onOpen(organization.organizationId)}
                    aria-label={`Open ${organization.displayName}`}>Open</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    )}
  </div>;
}

export function CreateOrganizationForm({ onCreated, onCancel }: { onCreated: (organization: LegalOrganizationView) => void; onCancel: () => void }) {
  const [fields, setFields] = useState({ displayName: "", domain: "", providerOrganizationId: "" });
  const [errors, setErrors] = useState<NewLegalOrganizationErrors>({});
  const [failure, setFailure] = useState<LegalAdminFailure | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    const checked = validateNewLegalOrganization(fields);
    setFailure(null);
    if (!checked.ok) { setErrors(checked.errors); return; }
    setErrors({}); setBusy(true);
    try { onCreated(await createLegalOrganization(checked.value)); }
    catch (error) {
      const value = error instanceof LegalAdminError ? error.failure : { kind: "unavailable" as const };
      if (value.kind === "invalid") setErrors(value.fields);
      else if (value.kind === "conflict" && value.code === "duplicate-domain") setErrors({ domain: legalAdminMessage(value) });
      else if (value.kind === "conflict" && value.code === "duplicate-provider-organization") setErrors({ providerOrganizationId: legalAdminMessage(value) });
      else setFailure(value);
    } finally { setBusy(false); }
  };
  const field = (name: keyof typeof fields, label: string, hint: string, extra: Record<string, unknown> = {}) => (
    <div>
      <Label htmlFor={`legal-${name}`} className="mb-1 block" style={{ fontSize: "12px", color: ink(60) }}>{label}</Label>
      <Input id={`legal-${name}`} value={fields[name]} autoComplete="off" spellCheck={false} disabled={busy}
        aria-invalid={errors[name] ? true : undefined} aria-describedby={`legal-${name}-hint${errors[name] ? ` legal-${name}-error` : ""}`}
        onChange={event => setFields(value => ({ ...value, [name]: event.target.value }))} {...extra} />
      <p id={`legal-${name}-hint`} className="mt-1" style={{ fontSize: "12px", color: ink(45) }}>{hint}</p>
      {errors[name] && <p id={`legal-${name}-error`} className="mt-1 text-sm text-red-700">{errors[name]}</p>}
    </div>
  );
  return <form noValidate onSubmit={event => void submit(event)} className="max-w-xl space-y-5 p-6" style={cardStyle}>
    <p style={{ fontSize: "13px", color: ink(60) }}>
      Add an organization only after vetting it outside VERA. This creates an unapproved record and an organization ID. It gives
      no access to anything until the organization submits its key and you issue an invitation.
    </p>
    {field("displayName", "Organization name", "As it should appear to reporters, for example “Harbor Counsel LLP”.")}
    {field("domain", "Organization’s own web domain", "Approve the exact domain used in members’ verified email addresses, for example harborcounsel.example. No website changes are needed.", { inputMode: "url" })}
    {field("providerOrganizationId", "Identity-provider organization ID", "From the legal sign-in tenant (Auth0 Organizations). Starts with “org_”.", { className: "font-mono" })}
    {failure && <FailureNotice failure={failure} />}
    <div className="flex flex-wrap gap-2">
      <Button type="submit" disabled={busy}>{busy ? "Adding…" : "Add organization"}</Button>
      <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>Cancel</Button>
    </div>
  </form>;
}

