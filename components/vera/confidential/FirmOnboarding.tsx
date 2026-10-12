import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { ChevronDown } from 'lucide-react';
import workspaceStyles from './LegalWorkspace.module.css';
import Link from "next/link";
import { FIRM_CONTACT_LABELS, FIRM_PRACTICE_AREAS, FIRM_PROFILE_MAX_AREAS, canonicalFirmProfile } from "@/enclave/src/confidential/firmProfile";
import type { FirmProfile, FirmProfileDraft } from "@/enclave/src/confidential/firmProfile";
import { CONFIDENTIAL_RELEASE_MANIFEST } from "@/lib/confidential/config";
import {
  EMPTY_ONBOARDING_RECORD, FIRM_ONBOARDING_TERMS, FIRM_ONBOARDING_TERMS_VERSION, onboardingChecklist, pendingSetupSync, readOnboardingRecord,
  recordOnboarding,
} from "@/lib/confidential/firmOnboarding";
import type { ChecklistStep, DomainCheck, MembershipStatus, OnboardingRecord } from "@/lib/confidential/firmOnboarding";
import { LegalSignInRequired, legalAccessToken, legalSignedIn, legalAuthConfig, renewLegalSignIn } from "@/lib/confidential/legalAuth";
import type { LegalAuthConfig } from "@/lib/confidential/legalAuth";
import type { FirmIdentity } from "@/lib/confidential/firmKey";
import { groupKeyId } from "@/src/utils/legalOnboarding";
import type { FirmSession } from "@/lib/confidential/firmCase";
import type { FirmSetupRequirement, FirmSetupStatus } from "@/lib/confidential/firmSetup";

const button = "border border-black px-4 py-2 disabled:opacity-50";
const field = "mt-1 block w-full border border-black/30 px-3 py-2";
type FirmRef = Pick<FirmIdentity, "domain" | "organizationId" | "recipientKeyId">;

function download(text: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url; link.download = filename; link.rel = "noopener";
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const time = (value: number) => new Date(value).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export const DOMAIN_POLL_MS = 20_000;
const DOMAIN_POLL_LIMIT_MS = 30 * 60_000;
export type DomainCheckState = {
  check: DomainCheck | null; checking: boolean; checkedAt: number | null; polling: boolean; checkAgain: () => void;
};

/** Checks the organization's public file now, then every 20 seconds while it is
 * not verified and this tab is visible, for up to 30 minutes. "Check again"
 * restarts the window. Only the public file is fetched, without credentials. */
export function useDomainCheck(firm: FirmRef | null): DomainCheckState {
  const [check, setCheck] = useState<DomainCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkedAt, setCheckedAt] = useState<number | null>(null);
  const [startedAt, setStartedAt] = useState(() => Date.now());
  const [polling, setPolling] = useState(true);
  const sequence = useRef(0), running = useRef(false);
  const domain = firm?.domain, organizationId = firm?.organizationId, recipientKeyId = firm?.recipientKeyId;
  const run = useCallback(async () => {
    if (!domain || !organizationId || !recipientKeyId || running.current) return;
    running.current = true;
    const mine = ++sequence.current;
    setChecking(true);
    try {
      const { checkFirmDomain } = await import("@/lib/confidential/firmOnboarding");
      const result = await checkFirmDomain({ domain, organizationId, recipientKeyId });
      if (mine === sequence.current) { setCheck(result); setCheckedAt(Date.now()); }
    } finally {
      running.current = false;
      if (mine === sequence.current) setChecking(false);
    }
  }, [domain, organizationId, recipientKeyId]);
  useEffect(() => {
    setCheck(null); setCheckedAt(null); setPolling(true); setStartedAt(Date.now());
    sequence.current++;
    running.current = false;
    void run();
  }, [run]);
  const verified = check?.state === "verified";
  useEffect(() => {
    if (!polling || verified || !domain) return;
    const timer = setInterval(() => {
      if (Date.now() - startedAt > DOMAIN_POLL_LIMIT_MS) { setPolling(false); return; }
      if (document.visibilityState === "visible") void run();
    }, DOMAIN_POLL_MS);
    const visible = () => { if (document.visibilityState === "visible") void run(); };
    document.addEventListener("visibilitychange", visible);
    return () => { clearInterval(timer); document.removeEventListener("visibilitychange", visible); };
  }, [polling, verified, domain, run, startedAt]);
  const checkAgain = useCallback(() => { setPolling(true); setStartedAt(Date.now()); void run(); }, [run]);
  return { check, checking, checkedAt, polling, checkAgain };
}

export type MembershipState = { status: MembershipStatus | null; error: string | null; loading: boolean; refresh: () => void };

/** The signed-in member's own enrollment, read through the attested channel. */
export function useMembershipStatus(config: LegalAuthConfig | null, firm: FirmRef | null, refreshKey = 0): MembershipState {
  const [status, setStatus] = useState<MembershipStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Loading from the first render when a check will start, so the checklist
  // never offers its controls for one frame before the check begins.
  const [loading, setLoading] = useState(() => !!config && !!firm?.organizationId && !!firm?.recipientKeyId);
  const [tick, setTick] = useState(0);
  const organizationId = firm?.organizationId, recipientKeyId = firm?.recipientKeyId;
  useEffect(() => {
    if (!config || !organizationId || !recipientKeyId) { setLoading(false); return; }
    if (!legalSignedIn()) { setStatus(null); setError("Sign in to check your membership."); setLoading(false); return; }
    let active = true;
    setLoading(true); setError(null);
    void (async () => {
      try {
        const [{ fetchRelay }, { readMembershipStatus }] = await Promise.all([
          import("@/lib/confidential/client"), import("@/lib/confidential/firmOnboarding")]);
        const result = await readMembershipStatus({ relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST,
          accessToken: await legalAccessToken(config), firm: { organizationId, recipientKeyId }, now: Date.now() });
        if (active) setStatus(result);
      } catch (caught) {
        if (!active) return;
        setStatus(null);
        // Keep the reason: a busy or unreachable service is not a failed verification.
        setError(caught instanceof LegalSignInRequired ? caught.message
          : `Your membership could not be checked. ${caught instanceof Error && caught.message.startsWith("The secure connection")
            ? caught.message : "The secure connection could not be verified."} Try again later.`);
      } finally { if (active) setLoading(false); }
    })();
    return () => { active = false; };
  }, [config, organizationId, recipientKeyId, refreshKey, tick]);
  const refresh = useCallback(() => setTick(value => value + 1), []);
  return { status, error, loading, refresh };
}

export type OnboardingState = {
  record: OnboardingRecord;
  confirmCustody: (recipientKeyId: string) => void;
  acceptTerms: () => void;
};

function onboardingStore(): Storage | null {
  try { return typeof window === "undefined" ? null : window.localStorage; } catch { return null; }
}

/** This device's onboarding acknowledgments for the organization. Read after
 * mount, so the server-rendered page and the first client render agree. */
export function useOnboardingRecord(firm: Pick<FirmRef, "organizationId"> | null): OnboardingState {
  const organizationId = firm?.organizationId;
  const [record, setRecord] = useState<OnboardingRecord>(EMPTY_ONBOARDING_RECORD);
  useEffect(() => {
    setRecord(organizationId ? readOnboardingRecord(onboardingStore(), organizationId) : EMPTY_ONBOARDING_RECORD);
  }, [organizationId]);
  const confirmCustody = useCallback((recipientKeyId: string) => {
    if (organizationId) setRecord(recordOnboarding(onboardingStore(), organizationId, { custody: { recipientKeyId, verifiedAt: Date.now() } }));
  }, [organizationId]);
  const acceptTerms = useCallback(() => {
    if (organizationId) setRecord(recordOnboarding(onboardingStore(), organizationId,
      { terms: { version: FIRM_ONBOARDING_TERMS_VERSION, acceptedAt: Date.now() } }));
  }, [organizationId]);
  return { record, confirmCustody, acceptTerms };
}

/** The organization's enforced setup, read through the attested channel once
 * this member is enrolled with the unlocked organization key. `active` is false
 * before that (the checklist then shows this device's own record). A step this
 * device already finished locally (for example on the setup page, before the
 * invitation was accepted) is signed and recorded automatically, once. */
export type FirmSetupState = {
  active: boolean; status: FirmSetupStatus | null; error: string | null; busy: boolean;
  record: (kind: FirmSetupRequirement) => Promise<boolean>; refresh: () => void;
};

export function useFirmSetup(session: FirmSession | null, membership: MembershipStatus | null, local: OnboardingRecord): FirmSetupState {
  const active = !!session && membership?.state === "enrolled" && membership.keyMatches;
  const [status, setStatus] = useState<FirmSetupStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  const synced = useRef(new Set<string>());
  useEffect(() => {
    if (!active || !session) { setStatus(null); setError(null); return; }
    let live = true;
    setError(null);
    void (async () => {
      try {
        const { readFirmSetup } = await import("@/lib/confidential/firmSetup");
        const result = await readFirmSetup(session, Date.now());
        if (live) setStatus(result);
      } catch (caught) {
        if (!live) return;
        setStatus(null);
        setError(caught instanceof LegalSignInRequired ? caught.message
          : "Your organization's setup could not be checked with VERA. Try again later.");
      }
    })();
    return () => { live = false; };
  }, [active, session, tick]);
  const record = useCallback(async (kind: FirmSetupRequirement) => {
    if (!active || !session) return false;
    setBusy(true); setError(null);
    try {
      const { recordFirmSetup } = await import("@/lib/confidential/firmSetup");
      setStatus(await recordFirmSetup(session, kind, Date.now()));
      return true;
    } catch (caught) {
      setError(caught instanceof LegalSignInRequired ? caught.message
        : "This step could not be recorded with VERA. It is kept on this device; try again later.");
      return false;
    } finally { setBusy(false); }
  }, [active, session]);
  // Record steps this device already finished, once per page.
  const recipientKeyId = session?.firm.recipientKeyId;
  useEffect(() => {
    if (!status || busy) return;
    const pending = pendingSetupSync(status, local, recipientKeyId ?? "").filter(kind => !synced.current.has(kind));
    if (!pending.length) return;
    pending.forEach(kind => synced.current.add(kind));
    void (async () => { for (const kind of pending) await record(kind); })();
  }, [status, busy, local, recipientKeyId, record]);
  const refresh = useCallback(() => setTick(value => value + 1), []);
  return { active, status, error, busy, record, refresh };
}

function Tick({ done }: { done: boolean }) {
  return <span aria-hidden="true" className={workspaceStyles.tick} data-done={done}>✓</span>;
}

/** Onboarding steps with live ticks. Rendered on the setup page and the portal. */
export function FirmOnboardingChecklist({ firm, keySaved, domain, membership, onboarding, setup, now, children, compact = false }: {
  firm: FirmRef; keySaved: boolean; domain: DomainCheckState; membership: MembershipState; onboarding: OnboardingState;
  /** The enforced setup; when active, custody and terms are recorded with VERA. */
  setup?: FirmSetupState;
  /** When given, a lease that has run out by then shows as an ended membership. */
  now?: number;
  compact?: boolean;
  children?: Partial<Record<ChecklistStep["id"], ReactNode>>;
}) {
  const enforced = setup?.active ? setup : null;
  const { steps, complete } = onboardingChecklist({ keySaved, domain: firm.domain, domainCheck: domain.check,
    membership: membership.status, now, recipientKeyId: firm.recipientKeyId, record: onboarding.record,
    setup: enforced ? { status: enforced.status, error: enforced.error } : undefined });
  // While the first membership check is in flight, these steps could still
  // switch from this device's record to VERA's. Hold their controls so a click
  // cannot land on a form that is disabled or replaced when the answer arrives.
  // Any settled check (status, error, timeout) or no check at all releases them.
  const waiting = (!!membership.loading && !membership.status) || (!!enforced && !enforced.status);
  const localCustody = onboarding.record.custody?.recipientKeyId === firm.recipientKeyId;
  const localTerms = onboarding.record.terms !== null && onboarding.record.terms.version >= FIRM_ONBOARDING_TERMS_VERSION;
  const recordAgain = (kind: FirmSetupRequirement) => enforced && enforced.status && (
    <button type="button" className="mt-2 min-h-11 text-sm underline disabled:opacity-50" disabled={enforced.busy}
      onClick={() => void enforced.record(kind)}>{enforced.busy ? "Recording…" : "Record with VERA"}</button>);
  const required = steps.filter(step => !step.optional);
  const done = required.filter(step => step.done).length;
  return (
    <section className={workspaceStyles.checklist} aria-labelledby="checklist-title">
      <div className={workspaceStyles.checklistHeader}>
        <div><h2 id="checklist-title">Organization setup</h2>
          <p>{complete ? 'Your workspace is ready.' : 'Review each step to prepare your workspace.'}</p></div>
        <div className={workspaceStyles.progress}><span aria-live="polite">{complete ? "Setup complete." : `${done} of ${required.length} required steps done`}</span>
          <progress value={done} max={required.length} aria-label="Organization setup progress" /></div>
      </div>
      <ol className={workspaceStyles.steps}>
        {steps.map(step => (
          <li key={step.id}>
            <details className={workspaceStyles.step} open={compact ? undefined : true}>
              <summary className={workspaceStyles.stepSummary}>
                <Tick done={step.done} />
                <span className={workspaceStyles.stepLabel}><strong>{step.label}<span className="sr-only">{step.done ? " (done)" : " (not done yet)"}</span></strong></span>
                <span aria-hidden className={workspaceStyles.stepStatus} data-done={step.done}>{step.done ? 'Complete' : step.optional ? 'Optional' : 'Review step'}</span><ChevronDown size={16} aria-hidden />
              </summary>
            <div className={workspaceStyles.stepBody}>
              <p className="text-sm text-black/70">
                {step.id === "invitation" && membership.error && !membership.status ? membership.error : step.detail}
              </p>
              {step.id === "custody" && !step.done && (waiting ? null
                : enforced && localCustody ? recordAgain("custody")
                  : keySaved
                    ? <SecondKeyHolderCheck firm={firm} onVerified={() => {
                      onboarding.confirmCustody(firm.recipientKeyId);
                      if (enforced) void enforced.record("custody");
                    }} />
                    : <p className="mt-1 text-sm text-black/60">Available after you save and check your own copy.</p>)}
              {step.id === "terms" && !step.done && (enforced && localTerms ? recordAgain("terms")
                : <OnboardingTerms key={`${firm.organizationId}:${firm.recipientKeyId}`}
                  disabled={waiting || !!enforced?.busy}
                  onAccept={() => { onboarding.acceptTerms(); if (enforced) void enforced.record("terms"); }} />)}
              {(step.id === "custody" || step.id === "terms") && enforced && !enforced.status && (
                <button type="button" className="mt-1 min-h-11 text-sm underline" onClick={enforced.refresh}>Check again</button>)}
              {step.id === "domain" && !step.done && <DomainCheckControls state={domain} />}
              {step.id === "invitation" && !step.done && (
                <button type="button" className="mt-1 min-h-11 text-sm underline disabled:opacity-50" disabled={membership.loading} onClick={membership.refresh}>
                  {membership.loading ? "Checking…" : "Check membership again"}</button>
              )}
              {children?.[step.id]}
            </div>
            </details>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Opens the second key holder's copy on this device, the same way the first
 * copy is checked. Nothing is uploaded; only "checked, for this key" is kept. */
export function SecondKeyHolderCheck({ firm, onVerified }: { firm: FirmRef; onVerified: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [secret, setSecret] = useState("");
  const [separate, setSeparate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const verify = async () => {
    if (!file || !secret || !separate || busy) return;
    setBusy(true); setError(null);
    try {
      const { verifyFirmBackup } = await import("@/lib/confidential/backupVerification");
      await verifyFirmBackup(file, secret, firm);
      setSecret(""); setFile(null);
      onVerified();
    } catch { setError("That file and recovery code did not restore this organization key. Ask the second key holder to check their copy."); }
    finally { setBusy(false); }
  };
  return (
    <form className="mt-3 space-y-3" onSubmit={event => { event.preventDefault(); void verify(); }}>
      <label className="block text-sm">Second key holder&apos;s key file
        <input type="file" accept=".txt,text/plain" disabled={busy} className="mt-1 block"
          onChange={event => setFile(event.target.files?.[0] ?? null)} />
      </label>
      <label className="block text-sm">Their recovery code or passphrase
        <input type="password" autoComplete="off" value={secret} disabled={busy}
          onChange={event => setSecret(event.target.value)} className={field} />
      </label>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={separate} disabled={busy} onChange={event => setSeparate(event.target.checked)} />
        <span>This copy is kept by a second authorized person, stored apart from mine.</span>
      </label>
      <button className={button} disabled={busy || !file || !secret || !separate}>{busy ? "Checking…" : "Check their copy"}</button>
      {error && <p role="alert" className="text-sm text-red-800">{error}</p>}
    </form>
  );
}

/** Keep the draft selection mounted during setup checks; only submission waits. */
export function OnboardingTerms({ onAccept, disabled = false }: { onAccept: () => void; disabled?: boolean }) {
  const [agreed, setAgreed] = useState(false);
  return (
    <form className="mt-3 space-y-3" onSubmit={event => { event.preventDefault(); if (agreed && !disabled) onAccept(); }}>
      <dl className="max-w-[62ch] space-y-2 text-sm">
        {FIRM_ONBOARDING_TERMS.map(term => (
          <div key={term.id}><dt className="font-semibold">{term.title}</dt><dd className="text-black/70">{term.text}</dd></div>
        ))}
      </dl>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={agreed} disabled={disabled} onChange={event => setAgreed(event.target.checked)} />
        <span>I have read these and my organization will follow them.</span>
      </label>
      <button className={button} disabled={!agreed || disabled}>Acknowledge</button>
    </form>
  );
}

function DomainCheckControls({ state }: { state: DomainCheckState }) {
  return (
    <div className="mt-2 flex flex-wrap items-center gap-3 text-sm">
      <button type="button" className="min-h-11 underline disabled:opacity-50" disabled={state.checking} onClick={state.checkAgain}>
        {state.checking ? "Checking…" : "Check again"}</button>
      <span className="text-black/60" aria-live="polite">
        {state.checkedAt ? `Last checked at ${time(state.checkedAt)}.` : ""}
        {state.polling ? " Checking automatically every 20 seconds while this page is open." : " Automatic checks paused."}
      </span>
    </div>
  );
}

const DEFAULT_DRAFT = (domain: string): FirmProfileDraft => ({ practiceAreas: [] as string[], jurisdiction: "", website: `https://${domain}/` });

/** Submit a signed public profile for approval without sharing private key material. */
export function OrganizationProfile({ firm, domain, headingLevel = 2, title, onSubmitted }: {
  firm: FirmIdentity; domain: DomainCheckState; headingLevel?: 2 | 3; title: string; onSubmitted?: () => void;
}) {
  const published = domain.check?.state === "verified" ? domain.check.profile : null;
  const [draft, setDraft] = useState(() => DEFAULT_DRAFT(firm.domain));
  const [editing, setEditing] = useState(true);
  const [prepared, setPrepared] = useState<{ document: string; profile: FirmProfile } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const seeded = useRef(false);
  useEffect(() => {
    // Start from the approved profile, once.
    if (seeded.current || !published) return;
    seeded.current = true;
    setDraft({ practiceAreas: [...published.practiceAreas], jurisdiction: published.jurisdiction, website: published.website, contacts: published.contacts });
    setEditing(false);
  }, [published]);
  const Heading = headingLevel === 2 ? "h2" : "h3";
  const prepare = async () => {
    setError(null);
    const result = canonicalFirmProfile(draft, firm.domain);
    if (!result.profile) { setError(result.error); return; }
    setBusy(true);
    try {
      // Open sign-in inside the click gesture, before asynchronous signing.
      if (!legalSignedIn()) {
        const config = legalAuthConfig();
        if (!config) throw new LegalSignInRequired();
        await renewLegalSignIn(config);
      }
      const { firmBindingDocument } = await import("@/lib/confidential/firmKey");
      const document = await firmBindingDocument(firm, Date.now(), result.profile);
      const { submitOrganizationKey } = await import('@/lib/confidential/firmOnboarding');
      await submitOrganizationKey(firm, document);
      setPrepared({ document, profile: result.profile });
      onSubmitted?.();
      domain.checkAgain();
      setEditing(false);
    } catch { setError("Your profile and public key could not be submitted. Keep this page open and try again."); }
    finally { setBusy(false); }
  };
  const shown = prepared?.profile ?? published;
  const livePublished = !!published && (!prepared || JSON.stringify(prepared.profile) === JSON.stringify(published));
  const toggle = (area: string) => setDraft(value => ({ ...value, practiceAreas: value.practiceAreas.includes(area)
    ? value.practiceAreas.filter(item => item !== area) : [...value.practiceAreas, area] }));
  return (
    <section className="border border-black/10 p-4 sm:p-6" aria-labelledby="publish-title">
      <Heading id="publish-title" className="mb-3 font-semibold">{title}</Heading>
      <p className="mb-4 max-w-[62ch] text-sm text-black/70">
        Submit your organization profile and public key to VERA. Your private key stays on this device. No website changes are needed.
      </p>
      <p className="mb-4 text-sm font-bold text-red-800">NOT CONFIDENTIAL: VERA administrators and reporters can read your organization profile.</p>
      {editing || !shown ? (
        <form className="space-y-4" onSubmit={event => { event.preventDefault(); if (!busy) void prepare(); }}>
          <fieldset>
            <legend className="mb-2 text-sm font-semibold">Practice areas (choose up to {FIRM_PROFILE_MAX_AREAS})</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {Object.entries(FIRM_PRACTICE_AREAS).map(([code, label]) => (
                <label key={code} className="flex items-start gap-2 text-sm">
                  <input type="checkbox" className="mt-1" checked={draft.practiceAreas.includes(code)} disabled={busy ||
                    (!draft.practiceAreas.includes(code) && draft.practiceAreas.length >= FIRM_PROFILE_MAX_AREAS)}
                  onChange={() => toggle(code)} />
                  <span>{label}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <label className="block text-sm">Jurisdiction
            <span className="block text-black/60">Where your lawyers are admitted, for example “England and Wales” or “US federal courts; New York”.</span>
            <input className={field} value={draft.jurisdiction} maxLength={160} disabled={busy} autoComplete="off"
              onChange={event => setDraft(value => ({ ...value, jurisdiction: event.target.value }))} />
          </label>
          <label className="block text-sm">Website
            <span className="block text-black/60">Must be on {firm.domain}.</span>
            <input className={field} type="text" inputMode="url" spellCheck={false} value={draft.website} disabled={busy} autoComplete="url"
              onChange={event => setDraft(value => ({ ...value, website: event.target.value }))} />
          </label>
          <details>
            <summary className="cursor-pointer text-sm">Contact options (optional)</summary>
            <p className="my-2 text-sm font-bold text-red-800">NOT CONFIDENTIAL: VERA administrators and reporters can read these contact details.</p>
            {Object.entries(FIRM_CONTACT_LABELS).map(([key, label]) => <label key={key} className="mt-2 block text-sm">{label}
              <input className={field} spellCheck={false} autoCorrect="off" maxLength={200} disabled={busy} autoComplete="off"
                value={draft.contacts?.[key as keyof typeof FIRM_CONTACT_LABELS] ?? ''}
                onChange={event => setDraft(value => ({ ...value, contacts: { ...value.contacts, [key]: event.target.value } }))} />
            </label>)}
          </details>
          <div className="flex flex-wrap gap-3">
            <button className={button} disabled={busy}>{busy ? "Submitting…" : "Submit organization profile"}</button>
            {shown && <button type="button" className="min-h-11 underline" disabled={busy} onClick={() => setEditing(false)}>Cancel</button>}
          </div>
        </form>
      ) : (
        <div className="space-y-3">
          <p className="text-sm">
            {livePublished ? `Organization key approved for ${firm.domain}.` : "Submitted for approval."}
          </p>
          <ul className="list-inside list-disc text-sm">
            <li>Practice areas: {shown.practiceAreas.map(area => FIRM_PRACTICE_AREAS[area]).join(", ")}</li>
            <li>Jurisdiction: {shown.jurisdiction}</li>
            <li className="break-all">Website: {shown.website}</li>
          </ul>
          <button type="button" className="min-h-11 text-sm underline" onClick={() => setEditing(true)}>Change profile</button>
        </div>
      )}
      {error && <p role="alert" className="mt-3 text-sm text-red-800">{error}</p>}
      {prepared && <p className="mt-4 text-sm" role="status">Your public key and profile have been submitted. VERA cannot read your private key.</p>}
      <p className="mt-4 max-w-[62ch] text-sm">
        Your Key ID: <span className="break-all font-mono">{groupKeyId(firm.recipientKeyId)}</span>. Before approving a new key, VERA staff
        ask your key holder to read this Key ID to them by phone or in person.
      </p>
      <p className="mt-4 text-sm" aria-live="polite">
        {domain.check?.state === "verified" ? `Organization key approved for ${firm.domain}.` : null}
      </p>
    </section>
  );
}

/** Link for the "Lawyers added" step. */
export function AddLawyersHint() {
  return (
    <p className="mt-2 text-sm">
      Add each lawyer from <Link className="underline" href="/legal/members">Lawyers and devices</Link>: they create their own
      device key after accepting your email invitation, then you approve the device. Do not share the organization key file.
    </p>
  );
}

/** The final "Continue" of new-key setup. Its failure is shown directly under
 * the button the user just pressed, not in a section several panels above. */
export function ContinueToWorkspace({ saved, busy, error, onContinue }: {
  saved: boolean; busy: boolean; error: string | null; onContinue: () => void;
}) {
  return (
    <div>
      <button type="button" className="border border-black bg-black px-4 py-2 text-white disabled:opacity-50" disabled={!saved || busy} onClick={onContinue}>
        {busy ? "Opening…" : "Continue"}
      </button>
      {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
      {!saved && <p className="mt-3 text-sm text-black/60">Save and verify your key file and recovery code to continue.</p>}
    </div>
  );
}
