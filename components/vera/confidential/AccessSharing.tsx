import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { ReactNode, Ref } from "react";
import { ArrowRight, ChevronDown, MessageSquare, ShieldCheck } from "lucide-react";
import boardStyles from './WorkspaceBoard.module.css';
import { trustedNow } from "@/lib/confidential/attestedTime";
import { FirmProfileSummary } from "./FirmProfileSummary";
import { grantActiveAt } from "@/enclave/src/confidential/grantPolicy";
import type { AccessGrant } from "@/enclave/src/confidential/authorization";
import type { OwnerGrantDecision } from "@/enclave/src/confidential/ownerGrant";
import type { CurrentGrantee, RevokeBlocker, VerifiedRequest } from "@/lib/confidential/ownerCase";
import {
  AccessChoiceError, DURATIONS, FEE_LABELS, RESPONSE_LABELS, changeChoice, changeDecisionFromChoice, changeParts, choiceSummary,
  decisionFromChoice, defaultChoice, describeAccess, expiryState, expiryText, fileLabel, formatDate, isContactOnly, requestedParts,
  trustedWebsite, unsharedFiles,
} from "@/lib/confidential/accessChoices";
import type { AccessChoice, DurationId, EvidenceEntry, RequestedParts } from "@/lib/confidential/accessChoices";

const primary = "inline-flex min-h-11 items-center justify-center gap-2 border border-[#19352a] bg-[#19352a] px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#294c3a] disabled:opacity-50";
const secondary = "inline-flex min-h-11 items-center justify-center border border-black/20 bg-white px-5 py-2.5 text-sm font-semibold transition-colors hover:bg-black/5 disabled:opacity-50";
const muted = "text-sm text-black/60";

/** One verified access request with the Allow chooser. Nothing is shared until
 * the reporter presses "Allow access" on an explicit, visible choice. */
export function AccessRequestCard({ item, evidence, fileNames, currentRevision, existing, replacedKey = false, busy, panel, onAllow, onDecline, shareCheck,
  actionError = null }: {
  item: VerifiedRequest; evidence: EvidenceEntry[]; fileNames: ReadonlyMap<string, string>; currentRevision: number;
  /** The organization holds access under a key it has since replaced (for example after a lawyer left). */
  replacedKey?: boolean;
  /** The organization's current grants, if it already has access (renewal or a repeat request). */
  existing: readonly AccessGrant[]; busy: boolean; panel: string;
  /** "Check before you share", shown only when this device cannot confirm the newest state. */
  shareCheck?: ReactNode;

  /** Why the last Allow or Decline on this card did not happen, shown here rather
   * than only at the top of the page. */
  actionError?: string | null;
  onAllow: (decision: OwnerGrantDecision) => Promise<boolean>; onDecline: () => Promise<boolean>;
}) {
  const id = useId();
  const { request, organization } = item;
  const details = request.details;
  const renewal = details?.kind === "renewal" || existing.some(grant => !isContactOnly(grant));
  const contactShared = existing.some(grant => isContactOnly(grant) && grantActiveAt(grant, trustedNow()));
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState<AccessChoice>(() => defaultChoice(request, evidence, existing));
  const [error, setError] = useState<string | null>(null);
  const [declining, setDeclining] = useState(false);
  const failureRef = useRef<HTMLParagraphElement>(null);
  useEffect(() => { if (actionError) failureRef.current?.focus(); }, [actionError]);
  // One profile only: once this visit's key check read the organization's signed
  // domain profile, the copy carried in the request is not shown next to it.
  const requestProfile = organization.profile ? null : details;
  const website = trustedWebsite(requestProfile?.website, organization.domain);
  const asks = useMemo(() => requestedParts(request.scopes), [request.scopes]);
  const update = (next: Partial<AccessChoice>) => { setError(null); setChoice(current => ({ ...current, ...next })); };
  const allow = async () => {
    let decision: OwnerGrantDecision;
    try { decision = decisionFromChoice(choice, request, evidence, currentRevision, trustedNow()); }
    catch (caught) { setError(caught instanceof AccessChoiceError ? caught.message : "Check your choices and try again."); return; }
    if (await onAllow(decision)) setOpen(false);
  };
  const summary = useMemo(() => choiceSummary(choice, asks, evidence, organization.displayName), [asks, choice, evidence, organization.displayName]);

  return (
    <section className={`${panel} border-t-2 border-t-[#b39a5c]`} aria-labelledby={`${id}-title`}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <span className="border border-[#e2d5b5] bg-[#fcf8ed] px-2.5 py-1 text-xs font-semibold text-[#6d531c]">
          {renewal ? 'Access renewal' : 'New access request'}
        </span>
        <p className="text-xs text-black/60">Respond by <span className="font-semibold">{formatDate(request.expiresAt)}</span></p>
      </div>
      <h3 id={`${id}-title`} className="break-words font-serif text-2xl leading-snug sm:text-3xl">
        {organization.displayName}{' '}
        <span className="block font-sans text-base font-normal text-black/60">{renewal ? 'asks to renew access' : 'requests access'}</span>
      </h3>
      <p className="mt-3 break-words text-sm text-black/65">Website: {organization.domain}</p>
      <p className="mt-2 flex items-start gap-2 text-xs leading-relaxed text-[#395944]">
        <ShieldCheck aria-hidden="true" size={16} className="mt-0.5 shrink-0" />VERA approved this organization and its email domain.
      </p>
      <div className="my-6 grid gap-5 md:grid-cols-[1.3fr_1fr]">
        <div className="min-w-0 bg-[#f5f7f3] p-5">
          <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-black/60">
            <MessageSquare aria-hidden="true" size={16} />Their message
          </p>
          <blockquote className="whitespace-pre-wrap break-words text-base leading-relaxed">{request.purpose}</blockquote>
        </div>
        <dl className="min-w-0 space-y-4 text-sm">
          {details && <>
            <div><dt className="mb-1 text-black/60">Fees</dt><dd className="font-medium">{FEE_LABELS[details.feeBasis]}</dd></div>
            <div><dt className="mb-1 text-black/60">Expected reply</dt><dd className="font-medium">{RESPONSE_LABELS[details.responseTime]}</dd></div>
            <div><dt className="mb-1 text-black/60">Conflicts of interest</dt>
              <dd className="font-medium">{details.conflictsChecked ? "Checked: they say they have no conflict" : "Not checked yet"}</dd></div>
          </>}
          <div><dt className="mb-1 text-black/60">Requested access</dt><dd className="flex flex-wrap gap-1.5">
            {[...(asks.report ? ['Report'] : []), ...(asks.evidence ? ['Files'] : []),
              ...(request.scopes.includes('contact') || request.scopes.includes('identity') ? ['Contact or identity details (separate approval)'] : [])]
              .map(label => <span key={label} className="border border-black/10 px-2 py-1 text-xs">{label}</span>)}
          </dd></div>
        </dl>
      </div>
      <details className="group mb-5 border-y border-black/10 py-4">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-semibold [&::-webkit-details-marker]:hidden">
          Organization profile and contacts <ChevronDown aria-hidden="true" size={17} className="shrink-0 transition-transform group-open:rotate-180" />
        </summary>
        <div className="pt-4">
          {organization.profile ? <FirmProfileSummary profile={organization.profile} /> : <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
            {requestProfile && requestProfile.practiceAreas.length > 0 && <>
              <dt className="text-black/60">Practice areas</dt><dd>{requestProfile.practiceAreas.join(", ")}</dd>
            </>}
            {requestProfile?.jurisdiction && <><dt className="text-black/60">Jurisdiction</dt><dd>{requestProfile.jurisdiction}</dd></>}
            {website && <><dt className="text-black/60">Website</dt><dd className="break-all">{website}</dd></>}
            {!requestProfile && <dd>No additional profile details were provided.</dd>}
          </dl>}
        </div>
      </details>
      {replacedKey && (
        <p className="mb-4 max-w-[62ch] border border-black/20 p-3 text-sm">
          The key of {organization.displayName} has changed since you allowed access. The new key has received nothing you
          shared, and receives nothing unless you allow this request. Organizations replace their key when a lawyer leaves,
          but a changed key can also mean someone else is using their name. Before you allow it, confirm with the organization,
          through a contact you already trust, that it replaced its key. If you allow it, access moves to the new key and the
          old key cannot open anything new. Anything already read with the old key cannot be taken back.
        </p>
      )}
      <p className="mb-5 max-w-[80ch] text-sm leading-relaxed text-black/65">
        These details come from the organization. Check that {organization.domain} is its real website through a
        source you trust before you allow access. VERA&apos;s directory name alone does not prove who they are.
        Your device confirms the approved organization key before sharing. You choose what it can read.
      </p>
      {!asks.report && !asks.evidence && (
        <p className="mb-4 max-w-[62ch] text-sm text-black/70">
          This request asks only for your contact or identity details. Those are never part of Allow: you can share them
          separately with an organization that already has access. You can decline this request.
        </p>
      )}
      {!open ? (
        <div className="flex flex-wrap items-center gap-3 border-t border-black/10 pt-5">
          <button type="button" disabled={busy} className={primary} onClick={() => { setOpen(true); setDeclining(false); }}>
            Choose what to share <ArrowRight aria-hidden="true" size={17} />
          </button>
          {!declining ? (
            <button type="button" disabled={busy} className={secondary} onClick={() => setDeclining(true)}>Decline</button>
          ) : (
            <div className="w-full">
              <p className="mb-3 max-w-[62ch] text-sm text-black/70">
                {organization.displayName} will see that the request was declined, with no reason and no date.
                {renewal ? " Their current access continues until it ends or you revoke it." : " They could send a new request later."}
              </p>
              <div className="flex flex-wrap gap-3">
                <button type="button" disabled={busy} className={primary}
                  onClick={() => void onDecline().then(ok => { if (ok) setDeclining(false); })}>Confirm: decline</button>
                <button type="button" className={secondary} onClick={() => setDeclining(false)}>Cancel</button>
              </div>
            </div>
          )}
          {!declining && <p className="w-full text-xs text-black/60">Next: choose the information and access duration. Nothing changes until you confirm.</p>}
          {actionError && <ActionFailure text={actionError} refTo={failureRef} />}
        </div>
      ) : (
        <div className="border-t border-black/10 pt-4">
          <AccessChooser id={id} asks={asks} evidence={evidence} fileNames={fileNames} choice={choice} onChange={update} />
          <ul className="mb-4 max-w-[62ch] list-disc space-y-1 pl-5 text-sm text-black/70">
            {contactShared
              ? <li>You already share your contact details with {organization.displayName}. That continues for as long as this access lasts; you can stop it separately.</li>
              : <li>Your contact details stay private. You can choose to share them later, separately.</li>}
            <li>Your report or files may still contain details that identify you.</li>
            <li>{organization.displayName} can also see which kinds of information your report includes, such as whether
              contact details or files exist, even for parts you do not share with it.</li>
            <li>VERA’s storage can see when you allow access and how many encrypted parts you share, with their sizes
              rounded up to fixed steps. It cannot see what they contain.</li>
            <li>Revoking later stops new access. It cannot take back anything already downloaded or read.</li>
          </ul>
          <p className="mb-4 font-semibold" aria-live="polite">{summary}</p>
          {shareCheck}
          {error && <p role="alert" className="mb-3 text-sm text-red-800">{error}</p>}
          {!error && actionError && <ActionFailure text={actionError} refTo={failureRef} />}
          <div className="flex flex-wrap gap-3">
            <button type="button" disabled={busy} className={primary} onClick={() => void allow()}>
              {busy ? "Encrypting…" : allowLabel(renewal)}
            </button>
            <button type="button" className={secondary} onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </div>
      )}
    </section>
  );
}

/** Label the owner decision directly. */
export function allowLabel(renewal: boolean): string {
  return renewal ? "Allow and replace current access" : "Allow access";
}

/** A failed action, next to the control that started it. Focused when it appears. */
export function ActionFailure({ text, refTo }: { text: string; refTo?: Ref<HTMLParagraphElement> }) {
  return <p ref={refTo} tabIndex={-1} role="alert" className="mt-3 mb-3 w-full max-w-[62ch] border border-red-700 p-3 text-sm">{text}</p>;
}

/** The explicit choices behind an Allow: report, evidence (all, some, none),
 * future files and duration. Controlled; nothing is shared from here. */
export function AccessChooser({ id, asks, evidence, fileNames, choice, onChange, showDuration = true }: {
  id: string; asks: RequestedParts; evidence: EvidenceEntry[]; fileNames: ReadonlyMap<string, string>;
  choice: AccessChoice; onChange: (next: Partial<AccessChoice>) => void;
  /** Off when changing existing access: the end date stays (Renew changes it). */
  showDuration?: boolean;
}) {
  const update = onChange;
  return (
    <>
      {asks.report && (
        <fieldset className="mb-5">
          <legend className="mb-2 font-semibold">Your report</legend>
          <Radio name={`${id}-report`} checked={choice.report} onChange={() => update({ report: true })}
            label="Share my report" hint="What you wrote about what happened." />
          <Radio name={`${id}-report`} checked={!choice.report} onChange={() => update({ report: false })} label="Don't share it" />
        </fieldset>
      )}
      {asks.evidence && (
        <fieldset className="mb-5">
          <legend className="mb-2 font-semibold">Evidence files</legend>
          {evidence.length > 0 && <Radio name={`${id}-evidence`} checked={choice.evidence === "all"}
            onChange={() => update({ evidence: "all" })} label={`All files (${evidence.length})`} />}
          {evidence.length > 1 && <Radio name={`${id}-evidence`} checked={choice.evidence === "some"}
            onChange={() => update({ evidence: "some" })} label="Only some files" />}
          {choice.evidence === "some" && (
            <ul className="mb-2 ml-7 space-y-1" aria-label="Files to share">
              {evidence.map(entry => (
                <li key={entry.objectId}>
                  <label className="flex items-start gap-2 text-sm">
                    <input type="checkbox" className="mt-1" checked={choice.selected.includes(entry.objectId)}
                      onChange={event => update({ selected: event.target.checked ? [...choice.selected, entry.objectId]
                        : choice.selected.filter(value => value !== entry.objectId) })} />
                    <span className="break-all">{fileLabel(entry, fileNames)}</span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          {choice.evidence === "some" && evidence.some(entry => !fileNames.has(entry.objectId)) && (
            <p className="mb-2 ml-7 text-sm text-black/60">
              File names stay encrypted, so files are numbered in the order you added them.
            </p>
          )}
          <Radio name={`${id}-evidence`} checked={choice.evidence === "none"}
            onChange={() => update({ evidence: "none" })} label={evidence.length ? "No files" : "No files for now"} />
          {(choice.evidence !== "none" || !evidence.length) && (
            <label className="mt-3 flex items-start gap-3 text-sm">
              <input type="checkbox" className="mt-1" checked={choice.future} onChange={event => update({ future: event.target.checked })} />
              <span>{evidence.length ? "Also share files I add later." : "Share files I add later."} If you leave this off, new
                files stay private until you share them under &quot;Who has access&quot;.</span>
            </label>
          )}
        </fieldset>
      )}
      {showDuration && (
        <fieldset className="mb-5">
          <legend className="mb-2 font-semibold">How long</legend>
          {DURATIONS.map(duration => (
            <Radio key={duration.id} name={`${id}-duration`} checked={choice.duration === duration.id}
              onChange={() => update({ duration: duration.id })} label={duration.label}
              hint={duration.ms === null ? "You can revoke access at any time." : undefined} />
          ))}
        </fieldset>
      )}
    </>
  );
}

function Radio({ name, checked, onChange, label, hint }: {
  name: string; checked: boolean; onChange: () => void; label: string; hint?: string;
}) {
  return (
    <label className="mb-1 flex items-start gap-3">
      <input type="radio" className="mt-1" name={name} checked={checked} onChange={onChange} />
      <span>{label}{hint && <span className="block text-sm text-black/60">{hint}</span>}</span>
    </label>
  );
}

/** Banners for access that ends soon or has ended, shown above everything else. */
export function AccessExpiryNotices({ grantees, now }: { grantees: CurrentGrantee[]; now: number }) {
  const notices = grantees.flatMap(grantee => {
    const main = grantee.grants.filter(grant => !isContactOnly(grant));
    if (!main.length) return [];
    const expiresAt = main.some(grant => grant.expiresAt === null) ? null : Math.max(...main.map(grant => grant.expiresAt as number));
    const state = expiryState(expiresAt, now);
    const name = grantee.organization?.displayName ?? "An organization";
    if (state.state === "ending-soon") return [`Access for ${name} ends on ${formatDate(state.endsAt)}. Renew it under "Who has access" if you want it to continue.`];
    if (state.state === "ended") return [`Access for ${name} ended on ${formatDate(state.endsAt)}. Renew it, or revoke it to remove it from your list.`];
    return [];
  });
  if (!notices.length) return null;
  return (
    <div role="status" className="border border-black/20 p-4 text-sm">
      <ul className="space-y-1">{notices.map(text => <li key={text}>{text}</li>)}</ul>
    </div>
  );
}

/** A revoke that did not happen because of other organizations that keep access. */
export type RevokeProblem = { organizationIds: readonly string[]; blockers: readonly RevokeBlocker[] };

/** "Who has access": what each organization can read, until when, and the
 * reporter's controls: change what they can read, renew, share or stop sharing
 * contact details, revoke. */
export function AccessManager({ grantees, roster = [], evidence, fileNames = new Map(), currentRevision, contactLabel, busy, now,
  revokeProblem = null, onChangeAccess, onRenew, onShareContact, onStopContact, onRevoke, shareCheck }: {
  grantees: CurrentGrantee[]; evidence: EvidenceEntry[]; fileNames?: ReadonlyMap<string, string>; currentRevision: number;
  /** Verified directory entries: names an organization whose access is under a key it has since replaced. */
  roster?: readonly { organizationId: string; displayName: string }[];
  /** "Check before you share", shown before renewing or sharing contact details
   * when this device cannot confirm the newest state. */
  shareCheck?: ReactNode;
  /** "contact details" / "name and contact details"; null when the report has none. */
  contactLabel: string | null; busy: boolean; now: number;

  revokeProblem?: RevokeProblem | null;

  onChangeAccess: (grantee: CurrentGrantee, decision: OwnerGrantDecision) => Promise<boolean>;
  onRenew: (grantee: CurrentGrantee, expiresAt: DurationId) => Promise<boolean>;
  onShareContact: (grantee: CurrentGrantee) => Promise<boolean>;
  onStopContact: (grantee: CurrentGrantee) => Promise<boolean>;
  /** Revoke the first organization, and any others listed with it, in one step. */
  onRevoke: (grantees: CurrentGrantee[]) => Promise<boolean>;
}) {
  const nameOf = (grantee: CurrentGrantee) => grantee.organization?.displayName ??
    roster.find(item => item.organizationId === grantee.organizationId)?.displayName ?? "An organization that can no longer be verified";
  return (
    <section className={boardStyles.firmCards} aria-labelledby="access-title">
      <h3 id="access-title" className="mb-3 text-sm font-semibold">Who has access</h3>
      {!grantees.length && <p className={muted}>No legal organization has access to your full report.</p>}
      <ul className={boardStyles.cards}>
        {grantees.map(grantee => (
          <GranteeRow key={grantee.organizationId} grantee={grantee} evidence={evidence} fileNames={fileNames} contactLabel={contactLabel}
            currentRevision={currentRevision}
            replacedName={grantee.organization ? null : roster.find(item => item.organizationId === grantee.organizationId)?.displayName ?? null}
            others={grantees.filter(item => item !== grantee).map(item => ({ grantee: item, name: nameOf(item) }))}

            problem={revokeProblem && revokeProblem.organizationIds.includes(grantee.organizationId) ? revokeProblem : null}
            busy={busy} now={now} shareCheck={shareCheck} onChangeAccess={onChangeAccess} onRenew={onRenew}
            onShareContact={onShareContact} onStopContact={onStopContact} onRevoke={onRevoke} />
        ))}
      </ul>
    </section>
  );
}

const names = (items: readonly string[]) => items.length < 2 ? items.join("")
  : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;

type Confirming = null | "revoke" | "share-contact" | "stop-contact" | "change";
function GranteeRow({ grantee, replacedName, others, evidence, fileNames, currentRevision, contactLabel, busy, now,
  problem, onChangeAccess, onRenew, onShareContact, onStopContact, onRevoke, shareCheck }: {
  grantee: CurrentGrantee; replacedName: string | null; others: { grantee: CurrentGrantee; name: string }[];
  evidence: EvidenceEntry[]; fileNames: ReadonlyMap<string, string>; currentRevision: number;
  contactLabel: string | null; busy: boolean; now: number; shareCheck?: ReactNode;
   problem: RevokeProblem | null;
  onChangeAccess: (grantee: CurrentGrantee, decision: OwnerGrantDecision) => Promise<boolean>;
  onRenew: (grantee: CurrentGrantee, expiresAt: DurationId) => Promise<boolean>;
  onShareContact: (grantee: CurrentGrantee) => Promise<boolean>;
  onStopContact: (grantee: CurrentGrantee) => Promise<boolean>;
  onRevoke: (grantees: CurrentGrantee[]) => Promise<boolean>;
}) {
  const id = useId();
  const [confirming, setConfirming] = useState<Confirming>(null);
  const [duration, setDuration] = useState<DurationId>("until-revoked");
  const [choice, setChoice] = useState<AccessChoice>(() => changeChoice(grantee.grants, evidence));
  const [changeError, setChangeError] = useState<string | null>(null);
  const access = describeAccess(grantee.grants, evidence, now);
  const verified = !!grantee.organization;
  const name = grantee.organization?.displayName ?? replacedName ?? "An organization that can no longer be verified";
  const state = expiryState(access.expiresAt, now);
  const hasMain = grantee.grants.some(grant => !isContactOnly(grant));
  const asks = changeParts(grantee.grants);
  // Evidence this organization cannot open yet: offer to share it here.
  const unshared = hasMain && unsharedFiles(grantee.grants, evidence, now) > 0;
  // Revoking re-keys everyone who keeps access; say so before the reporter confirms.
  const replacedOthers = others.filter(item => !item.grantee.organization);
  const checkedOthers = others.filter(item => item.grantee.organization);
  const blocking = problem ? problem.blockers.filter(item => !problem.organizationIds.includes(item.organizationId)) : [];
  const together = (extra: readonly { organizationId: string }[]) =>
    [grantee, ...others.filter(item => extra.some(entry => entry.organizationId === item.grantee.organizationId)).map(item => item.grantee)];
  const openChange = () => { setChoice(changeChoice(grantee.grants, evidence)); setChangeError(null); setConfirming("change"); };
  const saveChange = async () => {
    let decision: OwnerGrantDecision;
    try { decision = changeDecisionFromChoice(choice, grantee.grants, evidence, currentRevision, trustedNow()); }
    catch (caught) { setChangeError(caught instanceof AccessChoiceError ? caught.message : "Check your choices and try again."); return; }
    if (await onChangeAccess(grantee, decision)) setConfirming(null);
  };
  return (
    <li className={`${boardStyles.card} scroll-mt-24`} id={`firm-access-${grantee.organizationId}`}>
      <span className={boardStyles.firmBadge} data-active={access.active}>{access.active ? 'Access active' : 'Access ended'}</span>
      <h4 className="font-semibold text-base">{name}</h4>
      {grantee.organization && <p className={boardStyles.firmDomain}>Website: {grantee.organization.domain}</p>}
      {replacedName && <p className="my-1 max-w-[62ch] text-sm">
        The key of this legal organization has changed since you allowed access. Its new key cannot open anything you shared,
        and nothing is sent to it until you allow a new request from it. The old key can still open
        what you already shared. Revoke it now, or confirm the change with the organization through a contact you already
        trust before you allow their new request.
      </p>}
      <p className="mt-1 text-sm text-black/70">Can read: {access.items.length ? access.items.join(", ") : "nothing right now"}.</p>
      <p className={`text-sm ${state.state === "ending-soon" || state.state === "ended" ? "font-semibold" : "text-black/70"}`}>
        {expiryText(access.expiresAt, now)}
      </p>
      {verified && unshared && access.active && (
        <p className="mt-1 max-w-[62ch] text-sm">
          Some of your files are not shared with {name}. Use &quot;Change what they can read&quot; under Manage access to share them.
        </p>
      )}
      {problem && (
        <div role="alert" className="mt-3 max-w-[62ch] border border-red-700 p-3 text-sm">
          <p className="mb-2 font-semibold">Access for {name} was not revoked</p>
          <p className="mb-3">
            Revoking gives a new key to every legal organization that keeps access.{" "}
            {blocking.some(item => item.reason === "replaced") && `${names(blocking.filter(item => item.reason === "replaced").map(item => item.name))} replaced its key, so it cannot receive the new key. `}
            {blocking.some(item => item.reason !== "replaced") && "The current approved keys could not be confirmed. Refresh and try again. "}
            You can revoke {names(blocking.map(item => item.name))} at the same time.
          </p>
          <div className="flex flex-wrap gap-3">
            {blocking.some(item => item.reason === "failed") && (
              <button type="button" disabled={busy} className={secondary} onClick={() => void onRevoke([grantee])}>Try again</button>
            )}
            <button type="button" disabled={busy} className={primary}
              onClick={() => void onRevoke(together(blocking))}>Revoke {names([name, ...blocking.map(item => item.name)])} together</button>
          </div>
        </div>
      )}
      <details className="mt-2 text-sm" onToggle={event => { if (!(event.currentTarget as HTMLDetailsElement).open) setConfirming(null); }}>
        <summary className="cursor-pointer underline">Manage access</summary>
        {!verified && (
          <p className="my-3 max-w-[62ch] text-black/70">
            This organization&apos;s key no longer matches the verified directory, so nothing new can be shared with it.
            You can still revoke its access.
          </p>
        )}
        {verified && hasMain && access.active && (
          <div className="my-4">
            <p className="mb-2 font-semibold" id={`${id}-change`}>Change what they can read</p>
            {confirming === "change" ? (
              <div className="border border-black/20 p-3">
                {shareCheck}
                <AccessChooser id={`${id}-chooser`} asks={asks} evidence={evidence} fileNames={fileNames} choice={choice}
                  showDuration={false} onChange={next => { setChangeError(null); setChoice(current => ({ ...current, ...next })); }} />
                <p className="mb-2 max-w-[62ch] text-black/70">
                  Access still ends as it does now ({expiryText(access.expiresAt, now).toLowerCase()}); use Renew to change that.
                  Anything you stop sharing stays with them if they already read or downloaded it.
                  This device verifies the approved organization key before sharing.
                </p>
                <p className="mb-3 font-semibold" aria-live="polite">{choiceSummary({ ...choice, duration: "until-revoked" }, asks, evidence, name)
                  .replace(/, until you revoke access\.$/, ".")}</p>
                {changeError && <p role="alert" className="mb-3 text-red-800">{changeError}</p>}
                <div className="flex flex-wrap gap-3">
                  <button type="button" disabled={busy} className={primary} onClick={() => void saveChange()}>
                    {busy ? "Encrypting…" : "Save what they can read"}</button>
                  <button type="button" className={secondary} onClick={() => setConfirming(null)}>Cancel</button>
                </div>
              </div>
            ) : (
              <>
                <p className="mb-2 max-w-[62ch] text-black/70">Share your report or files with {name}, including files you added
                  after you allowed access, or stop sharing some of them.</p>
                <button type="button" disabled={busy} aria-describedby={`${id}-change`} className={secondary} onClick={openChange}>
                  Change what they can read</button>
              </>
            )}
          </div>
        )}
        {verified && hasMain && (
          <fieldset className="my-4">
            <legend className="mb-2 font-semibold">Renew access</legend>
            {shareCheck}
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1">
                <span>New end</span>
                <select className="border border-black/30 bg-transparent px-2 py-2" value={duration}
                  onChange={event => setDuration(event.target.value as DurationId)}>
                  {DURATIONS.map(item => <option key={item.id} value={item.id}>{item.ms === null ? item.label : `${item.label} from today`}</option>)}
                </select>
              </label>
              <button type="button" disabled={busy} className={secondary} onClick={() => { void onRenew(grantee, duration); }}>
                Renew access
              </button>
            </div>
            <p className="mt-2 max-w-[62ch] text-black/60">Renewing keeps exactly what they can read now and only changes when it
              ends. To share more, use &quot;Change what they can read&quot;.
</p>
          </fieldset>
        )}
        {verified && contactLabel && hasMain && access.active && (
          <div className="my-4">
            <p className="mb-2 font-semibold">Contact details</p>
            {confirming === "share-contact" ? (
              <div className="border border-red-700 p-3">
                {shareCheck}
                <p className="mb-3 max-w-[62ch]">
                  {name} will be able to read the {contactLabel} you gave with your report. They could use them to
                  identify or contact you. You can stop sharing later, but that cannot take back what they already read.
                </p>
                <div className="flex flex-wrap gap-3">
                  <button type="button" disabled={busy} className={primary}
                    onClick={() => { void onShareContact(grantee).then(() => setConfirming(null)); }}>
                    {`Share my ${contactLabel}`}</button>
                  <button type="button" className={secondary} onClick={() => setConfirming(null)}>Cancel</button>
                </div>
              </div>
            ) : confirming === "stop-contact" ? (
              <div className="flex flex-wrap gap-3">
                <button type="button" disabled={busy} className={primary}
                  onClick={() => void onStopContact(grantee).then(() => setConfirming(null))}>Confirm: stop sharing</button>
                <button type="button" className={secondary} onClick={() => setConfirming(null)}>Cancel</button>
              </div>
            ) : access.contactShared ? (
              <>
                <p className="mb-2 text-black/70">You are sharing your {contactLabel} with {name}.</p>
                <button type="button" disabled={busy} className={secondary} onClick={() => setConfirming("stop-contact")}>
                  Stop sharing contact details
                </button>
              </>
            ) : (
              <>
                <p className="mb-2 text-black/70">Not shared. {name} cannot see how to reach you.</p>
                <button type="button" disabled={busy} className={secondary} onClick={() => setConfirming("share-contact")}>
                  Share my {contactLabel} with {name}
                </button>
              </>
            )}
          </div>
        )}
        <div className="my-4">
          <p className="mb-2 font-semibold" id={`${id}-revoke`}>Revoke</p>
          <p className="mb-3 max-w-[62ch] text-black/70">
            Revoking stops this organization from opening your report or receiving files you add later.
            It cannot take back anything it already downloaded or read.
          </p>
          {confirming === "revoke" ? (
            <div>
              {replacedOthers.length > 0 ? (
                <p className="mb-3 max-w-[62ch]">
                  Revoking gives a new key to every legal organization that keeps access. {names(replacedOthers.map(item => item.name))}{" "}
                  replaced its key, so it cannot receive one. Revoke {names(replacedOthers.map(item => item.name))} in the same step.
                </p>
              ) : null}
              <div className="flex flex-wrap gap-3">
                {replacedOthers.length > 0 ? (
                  <button type="button" disabled={busy} className={primary}
                    onClick={() => void onRevoke(together(replacedOthers.map(item => item.grantee))).then(() => setConfirming(null))}>
                    Confirm: revoke {names([name, ...replacedOthers.map(item => item.name)])}</button>
                ) : (
                  <button type="button" disabled={busy} className={primary}
                    onClick={() => void onRevoke([grantee]).then(() => setConfirming(null))}>Confirm: revoke access</button>
                )}
                <button type="button" className={secondary} onClick={() => setConfirming(null)}>Cancel</button>
              </div>
            </div>
          ) : (
            <button type="button" disabled={busy} aria-describedby={`${id}-revoke`} className={secondary}
              onClick={() => setConfirming("revoke")}>Revoke access</button>
          )}
        </div>
      </details>
    </li>
  );
}
