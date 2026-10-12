import { useCallback, useEffect, useState } from "react";
import type { RefObject } from "react";
import { CheckCircle2, Circle, AlertTriangle, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  DOMAIN_CHECK_MESSAGES, INVITATION_STATUS_LABELS, LegalAdminError, MEMBER_STATUS_LABELS, checkLegalDomain, formatAdminTime,
  getLegalOrganization, canRemoveMember, legalAdminMessage, needsRenewal, onboardingNote, onboardingSteps,
  rememberInvitationSelection, removeLegalMember, revokeLegalInvitation, revokeLegalOrganization,
} from "@/lib/legalOnboardingClient";
import type { DomainCheck, LegalAdminFailure } from "@/lib/legalOnboardingClient";
import { onboardingAuthConfig } from "@/lib/confidential/onboardingAuth";
import { groupKeyId } from "@/src/utils/legalOnboarding";
import type { LegalInvitationView, LegalMemberView, LegalOrganizationDetail as Detail } from "@/src/utils/legalOnboarding";
import { AuditTrail, FailureNotice, OrganizationStatusBadge, cardStyle, headStyle, ink } from "./LegalOnboardingParts";

type Pending =
  | { kind: "invitation"; invitation: LegalInvitationView }
  | { kind: "member"; member: LegalMemberView }
  | { kind: "organization" };

export function startInvitation(organizationId: string) {
  rememberInvitationSelection({ organizationId });
  // Hard navigation: the invitation page runs in a fresh page with its own idle lock.
  window.location.assign("/legal/administration");
}

async function copyText(value: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(value); return true; } catch { return false; }
}

export function LegalOrganizationDetail({ organizationId, justCreated, headingRef, onBack }: {
  organizationId: string; justCreated: boolean; headingRef: RefObject<HTMLHeadingElement | null>; onBack: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [failure, setFailure] = useState<LegalAdminFailure | null>(null);
  const [check, setCheck] = useState<DomainCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [actionError, setActionError] = useState("");
  const [acting, setActing] = useState(false);
  const [confirmDomain, setConfirmDomain] = useState("");
  const [announcement, setAnnouncement] = useState(justCreated ? "Organization added. Send it the details below." : "");
  const [auditVersion, setAuditVersion] = useState(0);
  const issuing = onboardingAuthConfig() !== null;

  const load = useCallback(async () => {
    setFailure(null);
    try { setDetail(await getLegalOrganization(organizationId)); }
    catch (error) { setFailure(error instanceof LegalAdminError ? error.failure : { kind: "unavailable" }); }
  }, [organizationId]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (detail) headingRef.current?.focus(); }, [detail !== null]);

  const runCheck = useCallback(async (organization: Detail["organization"]) => {
    setChecking(true);
    try { setCheck(await checkLegalDomain(organization)); } finally { setChecking(false); }
  }, []);

  if (failure) return <><Button variant="outline" size="sm" onClick={onBack}>Back to legal organizations</Button>
    <FailureNotice failure={failure} onRetry={() => void load()} /></>;
  if (!detail) return <p role="status" className="py-8 text-sm" style={{ color: ink(55) }}>Loading organization…</p>;
  const { organization, invitations, members } = detail;
  const revoked = organization.status === "revoked";
  const now = Date.now();

  const confirm = async () => {
    if (!pending || acting) return;
    setActing(true); setActionError("");
    try {
      if (pending.kind === "invitation") {
        await revokeLegalInvitation(pending.invitation.invitationId);
        setAnnouncement(`Invitation for ${pending.invitation.subject} revoked. The link no longer works.`);
      } else if (pending.kind === "member") {
        await removeLegalMember(organization.organizationId, pending.member.subject);
        setAnnouncement(`${pending.member.subject} removed. Their pending invitations were revoked too.`);
      } else {
        const result = await revokeLegalOrganization(organization.organizationId);
        setAnnouncement(`${organization.displayName} revoked. ${result.membersRemoved} ${result.membersRemoved === 1 ? "person" : "people"} removed, ` +
          `${result.invitationsRevoked} pending invitation${result.invitationsRevoked === 1 ? "" : "s"} revoked.`);
      }
      setPending(null); setConfirmDomain("");
      setAuditVersion(value => value + 1);
      await load();
    } catch (error) {
      setActionError(legalAdminMessage(error instanceof LegalAdminError ? error.failure : { kind: "unavailable" }));
    } finally { setActing(false); }
  };

  return <div className="space-y-6">
    <Button variant="outline" size="sm" onClick={onBack}>Back to legal organizations</Button>
    <div className="flex flex-wrap items-center gap-3">
      <h2 ref={headingRef} tabIndex={-1} className="font-serif outline-none" style={{ fontSize: "1.4rem", fontWeight: 300, color: ink(85) }}>
        {organization.displayName}
      </h2>
      <OrganizationStatusBadge status={organization.status} />
    </div>
    <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-[14rem_1fr]" style={{ fontSize: "13px" }}>
      <dt style={{ color: ink(50) }}>Domain</dt><dd className="font-mono break-all" style={{ color: ink(80) }}>{organization.domain}</dd>
      <dt style={{ color: ink(50) }}>Organization ID</dt><dd className="font-mono break-all" style={{ color: ink(80) }}>{organization.organizationId}</dd>
      <dt style={{ color: ink(50) }}>Identity-provider organization</dt><dd className="font-mono break-all" style={{ color: ink(80) }}>{organization.providerOrganizationId ?? "—"}</dd>
      <dt style={{ color: ink(50) }}>Added</dt><dd style={{ color: ink(80) }}>{formatAdminTime(organization.createdAt)}{organization.createdBy ? ` by ${organization.createdBy}` : ""}</dd>
      {organization.registeredAt && <><dt style={{ color: ink(50) }}>Key registered</dt><dd style={{ color: ink(80) }}>{formatAdminTime(organization.registeredAt)}</dd></>}
      {organization.recipientKeyId && <><dt style={{ color: ink(50) }}>Registered Key ID</dt>
        <dd className="font-mono break-all" style={{ color: ink(80) }}>{groupKeyId(organization.recipientKeyId)}</dd></>}
      {revoked && <><dt style={{ color: ink(50) }}>Revoked</dt><dd style={{ color: ink(80) }}>{formatAdminTime(organization.revokedAt)}{organization.revokedBy ? ` by ${organization.revokedBy}` : ""}</dd></>}
    </dl>
    <p role="status" aria-live="polite" className="text-sm" style={{ color: ink(70) }}>{announcement}</p>

    {organization.status === "awaiting-registration" && <SendDetails organization={organization} />}

    {!revoked && <section aria-labelledby="legal-steps" className="p-6" style={cardStyle}>
      <h3 id="legal-steps" className="mb-4" style={{ fontSize: "14px", fontWeight: 500, color: ink(75) }}>Onboarding progress</h3>
      <ol className="space-y-3">
        {onboardingSteps(detail, check).map(step => (
          <li key={step.id} className="flex gap-3">
            {step.state === "done" ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-600" aria-hidden />
              : step.state === "problem" ? <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-600" aria-hidden />
              : <Circle className="mt-0.5 size-4 shrink-0" style={{ color: ink(35) }} aria-hidden />}
            <div>
              <p style={{ fontSize: "13px", color: ink(80) }}>
                {step.label}<span className="sr-only">{step.state === "done" ? " (done)" : step.state === "problem" ? " (needs attention)" : " (not yet)"}</span>
              </p>
              <p style={{ fontSize: "12px", color: ink(50) }}>{step.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>}

    {!revoked && <section aria-labelledby="legal-domain" className="p-6" style={cardStyle}>
      <h3 id="legal-domain" className="mb-2" style={{ fontSize: "14px", fontWeight: 500, color: ink(75) }}>Submitted organization key</h3>
      <p className="mb-3 break-all" style={{ fontSize: "12px", color: ink(50) }}>
        Submitted public key awaiting independent confirmation with the approved organization.
      </p>
      <Button variant="outline" size="sm" disabled={checking} onClick={() => void runCheck(organization)}>
        {checking ? "Checking…" : check ? "Check again" : "Check submitted key"}
      </Button>
      <div aria-live="polite" className="mt-3">
        {check && check.kind === "verified" && <div className="space-y-2" style={{ fontSize: "13px", color: ink(80) }}>
          <p>{check.matchesRegistered === false
            ? <strong className="text-red-700">The organization has submitted a replacement key.</strong>
            : "The submitted public key has a valid signature."}</p>
          <p>Submitted Key ID: <span className="font-mono break-all">{groupKeyId(check.recipientKeyId)}</span></p>
          <p style={{ fontSize: "12px", color: ink(50) }}>Submitted {formatAdminTime(check.issuedAt)}</p>
          {check.matchesRegistered === null && <p className="border-l-2 pl-3" style={{ borderColor: ink(20), fontSize: "12px", color: ink(60) }}>
            Confirm this Key ID with an authorized representative by phone or in person before issuing its first invitation.
          </p>}
          {check.matchesRegistered === false && <p style={{ fontSize: "12px", color: ink(60) }}>
            People enrolled with the old key lose access until they are invited again, and every reporter must allow the new key
            before it can read their report. Replace the registered key from the invitation page only if the organization confirms it
            changed its key.
          </p>}
        </div>}
        {check && check.kind !== "verified" && <p role="alert" className="text-sm text-red-700">{DOMAIN_CHECK_MESSAGES[check.kind]}</p>}
      </div>
    </section>}

    <section aria-labelledby="legal-invitations" className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="legal-invitations" style={{ fontSize: "14px", fontWeight: 500, color: ink(75) }}>Invitations</h3>
        {!revoked && <Button size="sm" disabled={!issuing} onClick={() => startInvitation(organization.organizationId)}>Issue invitation</Button>}
      </div>
      {!revoked && !issuing && <p style={{ fontSize: "12px", color: ink(50) }}>Issuing invitations needs the onboarding sign-in, which is not configured on this deployment.</p>}
      {invitations.length === 0 ? <p style={{ fontSize: "13px", color: ink(50) }}>No invitations yet.</p> :
        <div className="overflow-x-auto" style={{ border: `1px solid ${ink(4)}` }}>
          <Table>
            <TableHeader><TableRow className="hover:bg-transparent" style={{ borderColor: ink(4) }}>
              <TableHead style={headStyle}>Person</TableHead><TableHead style={headStyle}>Issued</TableHead>
              <TableHead style={headStyle}>Expires</TableHead><TableHead style={headStyle}>Status</TableHead>
              <TableHead style={headStyle}><span className="sr-only">Actions</span></TableHead>
            </TableRow></TableHeader>
            <TableBody>{invitations.map(invitation => (
              <TableRow key={invitation.invitationId} style={{ borderColor: ink(4) }}>
                <TableCell className="align-top font-mono break-all" style={{ fontSize: "12px", color: ink(80) }}>{invitation.subject}</TableCell>
                <TableCell className="align-top" style={{ fontSize: "12px", color: ink(65) }}>{formatAdminTime(invitation.createdAt)}</TableCell>
                <TableCell className="align-top" style={{ fontSize: "12px", color: ink(65) }}>{formatAdminTime(invitation.expiresAt)}</TableCell>
                <TableCell className="align-top" style={{ fontSize: "12px", color: ink(75) }}>{INVITATION_STATUS_LABELS[invitation.status]}</TableCell>
                <TableCell className="align-top text-right">
                  {invitation.status === "pending" && <Button variant="outline" size="sm" onClick={() => { setActionError(""); setPending({ kind: "invitation", invitation }); }}
                    aria-label={`Revoke invitation for ${invitation.subject}`}>Revoke</Button>}
                </TableCell>
              </TableRow>))}
            </TableBody>
          </Table>
        </div>}
    </section>

    <section aria-labelledby="legal-members" className="space-y-3">
      <h3 id="legal-members" style={{ fontSize: "14px", fontWeight: 500, color: ink(75) }}>People with access</h3>
      <p style={{ fontSize: "12px", color: ink(50) }}>Access lasts until the invitation’s end date. Renew it by issuing a new invitation to the same person.</p>
      {!revoked && members.some(member => member.status === "key-replaced") && <p role="note" className="border-l-2 pl-3"
        style={{ borderColor: ink(20), fontSize: "12px", color: ink(65) }}>
        The organization replaced its key. People marked “Needs a new invitation” cannot open anything until they accept a new
        invitation. Use Renew to invite them again.
      </p>}
      {members.length === 0 ? <p style={{ fontSize: "13px", color: ink(50) }}>Nobody has accepted an invitation yet.</p> :
        <div className="overflow-x-auto" style={{ border: `1px solid ${ink(4)}` }}>
          <Table>
            <TableHeader><TableRow className="hover:bg-transparent" style={{ borderColor: ink(4) }}>
              <TableHead style={headStyle}>Person</TableHead><TableHead style={headStyle}>Access until</TableHead>
              <TableHead style={headStyle}>Status</TableHead><TableHead style={headStyle}><span className="sr-only">Actions</span></TableHead>
            </TableRow></TableHeader>
            <TableBody>{members.map(member => (
              <TableRow key={member.subject} style={{ borderColor: ink(4) }}>
                <TableCell className="align-top font-mono break-all" style={{ fontSize: "12px", color: ink(80) }}>{member.subject}</TableCell>
                <TableCell className="align-top" style={{ fontSize: "12px", color: ink(65) }}>
                  {formatAdminTime(member.accessUntil)}
                  {member.status === "active" && needsRenewal(member.accessUntil, now) && <span className="ml-2 text-amber-700">Ends soon</span>}
                </TableCell>
                <TableCell className="align-top" style={{ fontSize: "12px", color: ink(75) }}>{MEMBER_STATUS_LABELS[member.status]}</TableCell>
                <TableCell className="align-top">
                  <div className="flex flex-wrap justify-end gap-2">
                    {!revoked && member.status !== "removed" && issuing && <Button variant="outline" size="sm"
                      onClick={() => startInvitation(organization.organizationId)} aria-label={`Renew access for ${member.subject}`}>Renew</Button>}
                    {!revoked && canRemoveMember(member.status) && <Button variant="outline" size="sm"
                      onClick={() => { setActionError(""); setPending({ kind: "member", member }); }} aria-label={`Remove ${member.subject}`}>Remove</Button>}
                  </div>
                </TableCell>
              </TableRow>))}
            </TableBody>
          </Table>
        </div>}
    </section>

    <section aria-labelledby="legal-audit" className="space-y-3">
      <h3 id="legal-audit" style={{ fontSize: "14px", fontWeight: 500, color: ink(75) }}>Audit trail</h3>
      <AuditTrail key={auditVersion} organizationId={organization.organizationId} />
    </section>

    {!revoked && <section aria-labelledby="legal-revoke" className="border border-red-500/30 p-6">
      <h3 id="legal-revoke" className="mb-2 text-red-800" style={{ fontSize: "14px", fontWeight: 500 }}>Revoke this organization</h3>
      <p className="mb-3 max-w-2xl" style={{ fontSize: "13px", color: ink(65) }}>
        Removes it from the list reporters choose from, ends access for everyone at the organization and revokes pending
        invitations. It cannot be undone; to work with them again, add them as a new organization.
      </p>
      <Button variant="destructive" size="sm" onClick={() => { setActionError(""); setConfirmDomain(""); setPending({ kind: "organization" }); }}>
        Revoke organization
      </Button>
    </section>}

    <AlertDialog open={pending !== null} onOpenChange={open => { if (!open && !acting) { setPending(null); setActionError(""); } }}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {pending?.kind === "invitation" ? "Revoke this invitation?" : pending?.kind === "member" ? "Remove this person?" : `Revoke ${organization.displayName}?`}
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2 text-sm">
              {pending?.kind === "invitation" && <p>The link sent to {pending.invitation.subject} stops working immediately.</p>}
              {pending?.kind === "member" && <>
                <p>{pending.member.subject} loses access to VERA’s legal portal, and any invitation still pending for them is revoked.</p>
                <p>Also remove them in the identity provider. Anything they already downloaded, and any copy of the organization’s key they
                  hold, cannot be recalled; ask the organization to replace its key if needed.</p>
              </>}
              {pending?.kind === "organization" && <>
                <p>Everyone at {organization.displayName} loses access, pending invitations are revoked and reporters no longer see the
                  organization. This is permanent.</p>
                <p>Reports or files the organization already downloaded cannot be recalled. Also disable the organization in the identity provider.</p>
              </>}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {pending?.kind === "organization" && <div>
          <Label htmlFor="legal-confirm-domain" className="mb-1 block text-sm">Type <span className="font-mono">{organization.domain}</span> to confirm</Label>
          <Input id="legal-confirm-domain" value={confirmDomain} autoComplete="off" spellCheck={false} onChange={event => setConfirmDomain(event.target.value)} />
        </div>}
        {actionError && <p role="alert" className="text-sm text-red-600">{actionError}</p>}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={acting}>Cancel</AlertDialogCancel>
          <Button type="button" variant="destructive" onClick={() => void confirm()}
            disabled={acting || (pending?.kind === "organization" && confirmDomain.trim().toLowerCase() !== organization.domain)}>
            {acting ? "Working…" : pending?.kind === "invitation" ? "Revoke invitation" : pending?.kind === "member" ? "Remove person" : "Revoke organization"}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </div>;
}

export function SendDetails({ organization }: { organization: Detail["organization"] }) {
  const [copied, setCopied] = useState("");
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  const copy = async (value: string, what: string) => setCopied(await copyText(value) ? `${what} copied.` : "Copy failed. Select the text instead.");
  return <section aria-labelledby="legal-send" className="p-6" style={cardStyle}>
    <h3 id="legal-send" className="mb-2" style={{ fontSize: "14px", fontWeight: 500, color: ink(75) }}>Send these details to the organization</h3>
    <p className="mb-3 max-w-2xl" style={{ fontSize: "13px", color: ink(60) }}>
      The organization ID is not a secret. The organization uses it to create its key and submit it to VERA for approval.
      Then check its Key ID here and issue the first invitation.
    </p>
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" size="sm" onClick={() => void copy(organization.organizationId, "Organization ID")}><Copy aria-hidden />Copy organization ID</Button>
      <Button variant="outline" size="sm" onClick={() => void copy(onboardingNote(organization, origin), "Instructions")}><Copy aria-hidden />Copy instructions</Button>
    </div>
    <p aria-live="polite" className="mt-2" style={{ fontSize: "12px", color: ink(55) }}>{copied}</p>
  </section>;
}
