import { useCallback, useEffect, useId, useRef, useState } from "react";
import { FEE_BASES, RESPONSE_TIMES } from "@/enclave/src/confidential/requestDetails";
import type { FirmProfile } from "@/enclave/src/confidential/firmProfile";
import { assertFirmWorkspaceCapacity } from "@/lib/confidential/firmWorkspace";
import { rememberRequest, rememberedRequests } from "@/lib/confidential/firmPortal";
import type { RememberedRequest } from "@/lib/confidential/firmPortal";
import type { DirectoryListing, FirmSession } from "@/lib/confidential/firmCase";
import type { CaseScope } from "@/enclave/src/confidential/authorization";
import { FEE_LABELS, RESPONSE_LABELS, validateRequestForm } from "@/lib/confidential/accessChoices";
import { submitAccessRequest } from "@/lib/confidential/requestSubmission";
import type { RequestOutcome } from "@/lib/confidential/requestSubmission";
import { failureMessage, primaryButton } from "./LegalPortal";
import { FirmProfileSummary } from "./FirmProfileSummary";

/** The organization's approved signed public profile. */
export type SignedProfileState = { state: "checking" } | { state: "read"; profile: FirmProfile | null };

/** Reads the approved signed profile through the attested channel.
 * A request carries this profile, never one typed
 * into the form, so the reporter cannot be shown two profiles that disagree. */
function useSignedProfile(firm: FirmSession["firm"]): { profile: SignedProfileState; checkAgain: () => void } {
  const [profile, setProfile] = useState<SignedProfileState>({ state: "checking" });
  const sequence = useRef(0);
  const { domain, organizationId, recipientKeyId } = firm;
  const run = useCallback(async () => {
    const mine = ++sequence.current;
    setProfile({ state: "checking" });
    let next: FirmProfile | null = null;
    try {
      const { checkFirmDomain } = await import("@/lib/confidential/firmOnboarding");
      const check = await checkFirmDomain({ domain, organizationId, recipientKeyId });
      next = check.state === "verified" ? check.profile : null;
    } catch { next = null; }
    if (mine === sequence.current) setProfile({ state: "read", profile: next });
  }, [domain, organizationId, recipientKeyId]);
  useEffect(() => {
    void run();
    return () => { sequence.current++; };
  }, [run]);
  return { profile, checkAgain: () => void run() };
}

const REQUESTABLE_SCOPES: { scope: CaseScope; label: string }[] = [
  { scope: "narrative", label: "Report" }, { scope: "evidence", label: "Files" },
  { scope: "contact", label: "Contact details (may identify the reporter)" },
  { scope: "identity", label: "Identity (may identify the reporter)" },
];
/** Structured access request (or renewal request). The message and details are
 * encrypted to the reporter and signed with the organization key. The request
 * is saved in the workspace before it is sent, so a lost reply cannot strand it,
 * but it is reported as sent only after delivery is confirmed. */
export function RequestForm({ session, listing, kind, initialPurpose = "", previous = null, onRequested, onDelivered, onCancel, onOutcome }: {
  session: FirmSession; listing: DirectoryListing; kind: "new" | "renewal";
  /** Prefilled message (for example after the organization replaced its key). */
  initialPurpose?: string;
  /** An older request for this report that may still be open: withdrawn first, since only one can wait at a time. */
  previous?: { caseId: string; requestId: string } | null;
  /** The request was saved in the shared list (refresh lists). Runs once the attempt settles, never mid-send. */
  onRequested?: (request: RememberedRequest) => void; onCancel: () => void;
  /** The single result: `ok` only after the enclave confirmed delivery. Close the form on success only. */
  onOutcome?: (outcome: RequestOutcome) => void;
  /** After the enclave confirmed delivery. */
  onDelivered?: (caseId: string) => void;
}) {
  const id = useId();
  const [scopes, setScopes] = useState<CaseScope[]>(["narrative", "evidence"]);
  const { profile: signed, checkAgain } = useSignedProfile(session.firm);
  const [purpose, setPurpose] = useState(initialPurpose);
  const [conflicts, setConflicts] = useState<"yes" | "no" | "">("");
  const [feeBasis, setFeeBasis] = useState("");
  const [responseTime, setResponseTime] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if (busy || signed.state !== "read") return;
    const checked = validateRequestForm({ purpose, conflicts, feeBasis, responseTime }, signed.profile);
    if (!scopes.length) { checked.errors.scopes = "Choose at least one thing to request."; delete checked.details; }
    setErrors(checked.errors);
    if (!checked.details) {
      setTimeout(() => document.getElementById(`${id}-${Object.keys(checked.errors)[0]}`)?.focus(), 0);
      return;
    }
    setBusy(true); setError(null);
    const { details } = checked;
    const outcome = await submitAccessRequest({
      caseId: listing.caseId, kind,
      send: async beforeSend => {
        assertFirmWorkspaceCapacity(session, rememberedRequests(session.firm.organizationId), listing.caseId);
        const { assertFirmSetupComplete, requestCaseAccess, withdrawCaseRequest } = await import("@/lib/confidential/firmCase");
        // Refused for incomplete organization setup: stop before anything is saved or withdrawn.
        await assertFirmSetupComplete(session, Date.now());
        // Best effort: an older request under a replaced key may still be open.
        if (previous) await withdrawCaseRequest(session, previous.caseId, previous.requestId, Date.now()).catch(() => {});
        const now = Date.now();
        await requestCaseAccess(session, listing, { purpose: purpose.trim(), scopes: [...scopes],
          details: { ...details, kind } }, now, ({ requestId, expiresAt }) => beforeSend({ caseId: listing.caseId, requestId,
          ownerPublicKey: listing.owner!.ownerPublicKey.armor(), summary: listing.summary, requestedAt: now, expiresAt }));
      },
      // Save the routing secret in the organization's shared list before
      // sending, so a lost reply cannot strand a pending request.
      save: async record => { await rememberRequest(session.firm.organizationId, record); },
      describeFailure: failureMessage,
    }, { onRequested, onDelivered, onOutcome });
    // The caller closes the form on success; a failure stays here, next to the report.
    if (!outcome.ok) setError(outcome.message);
    setBusy(false);
  };
  if (!listing.owner) return <p className="text-sm text-black/50">Requests are not available for this report.</p>;
  const field = "w-full border border-black/30 bg-transparent px-3 py-2";
  const describe = (name: string, help?: string) => [help ? `${id}-${name}-help` : "", errors[name] ? `${id}-${name}-error` : ""]
    .filter(Boolean).join(" ") || undefined;
  const fieldError = (name: string) => errors[name]
    ? <p id={`${id}-${name}-error`} className="mt-1 text-sm text-red-800">{errors[name]}</p> : null;
  return (
    <form className="mt-3 space-y-4" noValidate onSubmit={event => { event.preventDefault(); void submit(); }}
      aria-label={kind === "renewal" ? "Ask to renew access" : "Request access"}>
      <p className="max-w-[62ch] text-sm text-black/60">
        Everything in this form is encrypted to the reporter and signed with your organization key; VERA cannot read it.
        The reporter chooses what to share and for how long. A request gives no access and does not establish an
        attorney-client relationship.
      </p>
      <label className="block text-sm">
        <span className="mb-1 block font-semibold">{kind === "renewal" ? "Why you need access to continue" : "Message to the reporter"}</span>
        <textarea id={`${id}-purpose`} value={purpose} maxLength={1000} rows={4} className={field}
          spellCheck={false} autoCorrect="off" autoCapitalize="off"
          aria-invalid={!!errors.purpose} aria-describedby={describe("purpose", "help")} onChange={event => setPurpose(event.target.value)} />
        <span id={`${id}-purpose-help`} className="mt-1 block text-black/50">{purpose.length}/1000. Say who you are, why you are
          asking and how you would help, and why you need each selected item, especially anything that may identify the reporter.</span>
        {fieldError("purpose")}
      </label>
      <fieldset aria-describedby={describe("scopes")} disabled={busy}>
        <legend className="mb-1 text-sm font-semibold">Request only what your organization needs</legend>
        {REQUESTABLE_SCOPES.map(item => <label key={item.scope} className="flex items-start gap-2 text-sm">
          <input id={item.scope === "narrative" ? `${id}-scopes` : undefined} type="checkbox" className="mt-1"
            checked={scopes.includes(item.scope)} onChange={event => setScopes(previous =>
              event.target.checked ? [...previous, item.scope] : previous.filter(scope => scope !== item.scope))} />
          <span>{item.label}</span>
        </label>)}
        {fieldError("scopes")}
      </fieldset>
      <fieldset aria-describedby={describe("conflicts")}>
        <legend className="mb-1 text-sm font-semibold">Conflicts of interest</legend>
        <label className="flex items-start gap-2 text-sm">
          <input id={`${id}-conflicts`} type="radio" name={`${id}-conflicts`} className="mt-1" checked={conflicts === "yes"} onChange={() => setConflicts("yes")} />
          <span>We have checked and found no conflict</span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input type="radio" name={`${id}-conflicts`} className="mt-1" checked={conflicts === "no"} onChange={() => setConflicts("no")} />
          <span>Not checked yet (we will check before advising)</span>
        </label>
        {fieldError("conflicts")}
      </fieldset>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <label className="block text-sm">
          <span className="mb-1 block font-semibold">Fees</span>
          <select id={`${id}-feeBasis`} className={field} value={feeBasis} aria-invalid={!!errors.feeBasis}
            aria-describedby={describe("feeBasis")} onChange={event => setFeeBasis(event.target.value)}>
            <option value="">Choose…</option>
            {FEE_BASES.map(value => <option key={value} value={value}>{FEE_LABELS[value]}</option>)}
          </select>
          {fieldError("feeBasis")}
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-semibold">Expected reply</span>
          <select id={`${id}-responseTime`} className={field} value={responseTime} aria-invalid={!!errors.responseTime}
            aria-describedby={describe("responseTime")} onChange={event => setResponseTime(event.target.value)}>
            <option value="">Choose…</option>
            {RESPONSE_TIMES.map(value => <option key={value} value={value}>{RESPONSE_LABELS[value]}</option>)}
          </select>
          {fieldError("responseTime")}
        </label>
      </div>
      <section className="border-t border-black/10 pt-3" aria-labelledby={`${id}-profile`} aria-live="polite">
        <h4 id={`${id}-profile`} className="mb-1 text-sm font-semibold">Your organization profile</h4>
        {signed.state === "checking" ? (
          <p className="text-sm text-black/60">Reading your approved organization profile…</p>
        ) : signed.profile ? (<>
          <p className="mb-2 text-sm text-black/60">
            Sent with this request exactly as your organization signed it. To change it, update
            the profile under Organization profile.
          </p>
          <FirmProfileSummary profile={signed.profile} />
        </>) : (
          <p className="text-sm text-black/60">
            No approved signed profile is available, so this request is sent without one. The reporter
            sees your organization&apos;s name and domain.{" "}
            <button type="button" className="underline" onClick={checkAgain}>Check again</button>
          </p>
        )}
      </section>
      <div className="flex flex-wrap gap-3">
        <button type="submit" className={primaryButton} disabled={busy || signed.state !== "read"}>
          {busy ? "Encrypting and sending…" : signed.state !== "read" ? "Reading your profile…" : kind === "renewal" ? "Send renewal request" : "Send request"}
        </button>
        <button type="button" className="underline" onClick={onCancel}>Cancel</button>
      </div>
      {error && <p role="alert" className="text-sm text-red-800">{error}</p>}
    </form>
  );
}
