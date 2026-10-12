import type { ReactNode } from "react";
import { WorkspaceBoard, BoardLane, BoardEmpty } from "@/components/vera/confidential/WorkspaceBoard";
import boardStyles from "@/components/vera/confidential/WorkspaceBoard.module.css";
import { requestBoardLane } from "@/lib/confidential/workspaceBoard";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { legalDirectoryPages, mergeDirectoryListings, newestLegalReports } from "@/lib/confidential/legalDirectory";
import { trustedNow } from "@/lib/confidential/attestedTime";
import Link from "next/link";
import { useRouter } from "next/router";
import workspaceStyles from '@/components/vera/confidential/LegalWorkspace.module.css';
import {
  Banner, LegalGate, LegalPortalLayout, StatusBadge, failureMessage, panel, primaryButton, secondaryButton,
} from "@/components/vera/confidential/LegalPortal";
import { useRequestStatuses } from "@/components/vera/confidential/useRequestStatuses";
import { RequestForm } from "@/components/vera/confidential/FirmRequests";
import { EndedMembershipRequests } from "@/components/vera/confidential/EndedMembershipRequests";
import { AddLawyersHint, FirmOnboardingChecklist, OrganizationProfile, useDomainCheck, useFirmSetup, useMembershipStatus, useOnboardingRecord } from "@/components/vera/confidential/FirmOnboarding";
import { AutomaticApplicationActivation } from '@/components/vera/confidential/AutomaticApplicationActivation';
import type { MembershipState } from "@/components/vera/confidential/FirmOnboarding";
import { membershipEndDate, membershipLease, membershipNotice, onboardingChecklist, portalView } from "@/lib/confidential/firmOnboarding";
import { setupNextSteps } from "@/lib/confidential/firmSetup";
import type { LegalAuthConfig } from "@/lib/confidential/legalAuth";
import { clearRequest, currentSharedList, loadSharedRequests, ownerFromRequest, rememberedRequests } from "@/lib/confidential/firmPortal";
import type { RememberedRequest } from "@/lib/confidential/firmPortal";
import type { RequestAction, RequestActionFailure, RequestOutcome } from "@/lib/confidential/requestSubmission";
import {
  WITHDRAW_UNCONFIRMED, canRetryRequestAction, removeFailureMessage, withRequestActionFailure, withRequestOutcome,
} from "@/lib/confidential/requestSubmission";
import type { SharedListState, SharedRequest } from "@/lib/confidential/firmSharedRequests";
import { openLegalCase } from "@/lib/confidential/legalCaseLink";
import type { DirectoryListing, FirmSession } from "@/lib/confidential/firmCase";
import type { OwnerTrust } from "@/enclave/src/confidential/authorization";
import {
  RENEW_PURPOSE, canAskToRenew, canRequestAgain, canWithdraw, formatDate, statusBadge,
} from "@/lib/confidential/firmCaseView";
import type { FirmCaseStatus } from "@/lib/confidential/firmCaseView";

/** Removing clears the entry from the organization's shared list, so every
 * lawyer loses it, not only this device. Both remove paths confirm with this. */
const REMOVE_CONFIRMATION = "Remove this report from your organization's list? Every lawyer in your organization will stop seeing it.";

function sharedListError(caught: unknown): string {
  if (caught instanceof Error && (caught.name === "FirmSharedListKeyChanged" || caught.message.startsWith("The organization key changed"))) {
    return "Your organization replaced its key. Lock this page and unlock your saved workspace again to update this device.";
  }
  if (caught instanceof Error && caught.message.startsWith("The shared request list is older")) return caught.message;
  return failureMessage(caught, "Your organization's requests could not be loaded. Please try again.");
}

/** Report-key warnings and the structured form for retrying an existing request. */
function RequestAccess({ session, listing, failure, onRequested, onDelivered, onOutcome }: {
  session: FirmSession; listing: DirectoryListing; failure: string | undefined;
  onRequested: (request: RememberedRequest) => void; onDelivered: (caseId: string) => void; onOutcome: (outcome: RequestOutcome) => void;
}) {
  const [open, setOpen] = useState(false);
  if (listing.ownerKeyChanged) {
    return <p role="alert" className="max-w-[62ch] text-sm text-red-800">
      The key shown for this report changed since this workspace last saw it, so requests are paused. Only continue if the
      reporter confirms a new report check code with you directly.
    </p>;
  }
  if (!listing.owner) return <p className="text-sm text-black/60">Requests are not available for this report.</p>;
  if (!open) {
    return <>
      <button type="button" className={secondaryButton} onClick={() => setOpen(true)}>
        Request access again
      </button>
      <RequestFailure message={failure} />
    </>;
  }
  // The form closes only once delivery is confirmed; a failure stays in it as an alert.
  return <RequestForm session={session} listing={listing} kind="new" onCancel={() => setOpen(false)} onDelivered={onDelivered}
    onRequested={onRequested} onOutcome={outcome => { if (outcome.ok) setOpen(false); onOutcome(outcome); }} />;
}

/** A request that failed for this report, shown next to it after its form closed. */
function RequestFailure({ message }: { message: string | undefined }) {
  return message ? <p role="alert" className="mt-2 max-w-[62ch] text-sm text-red-800">{message}</p> : null;
}

/** Withdraw or remove is running for one report. */
type PendingRequestAction = { caseId: string; action: RequestAction };

/** A withdraw or remove that failed for this entry, with its own retry. A
 * withdrawal is offered again only while the request is still confirmed as waiting. */
function ActionFailure({ failure, status, busy, onRetry }: {
  failure: RequestActionFailure | undefined; status: FirmCaseStatus | undefined; busy: boolean; onRetry: () => void;
}) {
  if (!failure) return null;
  return (
    <div role="alert" className="mt-2 max-w-[62ch] text-sm text-red-800">
      <p>{failure.message}</p>
      {canRetryRequestAction(failure, status?.kind) && (
        <button type="button" className="mt-1 underline" disabled={busy} onClick={onRetry}>Try again</button>
      )}
    </div>
  );
}

function Status({ status }: { status: FirmCaseStatus | undefined }) {
  const badge = statusBadge(status ?? { kind: "checking" }, trustedNow());
  const description = status?.kind === 'unconfirmed'
    ? 'Choose “Check report access” to verify your organization’s current access.'
    : status?.kind === 'error'
    ? 'Current access could not be confirmed. Choose “Check report access” to verify it with the secure service.'
    : badge.description;
  return (
    <div className="mb-3">
      <StatusBadge label={badge.label} tone={badge.tone} />
      <p className="mt-1 text-sm text-black/60">{description}</p>
    </div>
  );
}

function YourRequests({ retryRequest, session, requests, directShares, listings, statuses, shared, sharedError, sharedBusy, failures, actionFailures, pending, onWithdraw, onForget, onRefresh, onRetryFailed, unavailableCount, onRequested, onDelivered, onOutcome }: {
  session: FirmSession; requests: RememberedRequest[]; statuses: Map<string, FirmCaseStatus>;
  directShares: DirectoryListing[]; listings: DirectoryListing[];
  retryRequest: (item: RememberedRequest) => ReactNode;
  /** The organization's shared list; null while loading or when it could not be loaded (then `requests` is this device's copy). */
  shared: SharedListState | null; sharedError: string | null; sharedBusy: boolean;
  /** Request failures per report, kept after the form that sent them closed. */
  failures: ReadonlyMap<string, string>;
  /** Withdraw and remove failures per report, each with its own retry. */
  actionFailures: ReadonlyMap<string, RequestActionFailure>;
  /** The withdraw or remove in progress, if any; its controls show progress and the others wait. */
  pending: PendingRequestAction | null;
  onWithdraw: (request: RememberedRequest) => Promise<void>; onForget: (request: RememberedRequest) => Promise<void>;
  onRefresh: () => void; onRequested: (request: RememberedRequest) => void; onDelivered: (caseId: string) => void;
  onRetryFailed: () => void; unavailableCount: number;
  onOutcome: (outcome: RequestOutcome) => void;
}) {
  const router = useRouter();
  const [confirming, setConfirming] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [renewing, setRenewing] = useState<{ caseId: string; owner: OwnerTrust } | null>(null);
  const [renewError, setRenewError] = useState<string | null>(null);
  // The reporter key comes from the request row itself, so renewal works after
  // unlocking with the key file and for requests another lawyer made.
  const startRenewal = async (item: RememberedRequest) => {
    setRenewError(null);
    const owner = await ownerFromRequest(session, item);
    if (owner) setRenewing({ caseId: item.caseId, owner });
    else setRenewError(item.caseId);
  };
  const ordered = newestLegalReports(requests, listings);
  // Requests made under a key the organization has since replaced: the reporter must allow access again.
  const entries = new Map<string, SharedRequest>((shared?.list.requests ?? []).map(item => [item.caseId, item]));
  const renderDirectShare = (listing: DirectoryListing) => <li key={listing.caseId} className={boardStyles.card}>
    <Status status={statuses.get(listing.caseId)} />
    <p className="mb-3 whitespace-pre-wrap break-words">{listing.summary}</p>
    <p className="mb-3 text-sm text-black/60">Shared directly by the reporter</p>
    <button type="button" className={primaryButton} onClick={() => {
      void ownerFromRequest(session, { caseId: listing.caseId, ownerPublicKey: listing.owner!.ownerPublicKey.armor() })
        .then(owner => owner && openLegalCase(router, listing.caseId));
    }}>{statuses.get(listing.caseId)?.kind === 'granted' ? 'Open report' : 'Check report access'}</button>
  </li>;
  const byCase = new Map(listings.map(item => [item.caseId, item]));
  const renderRequest = (item: RememberedRequest) => {
    const listing = byCase.get(item.caseId);
    const entry = entries.get(item.caseId);
    if (entry && entry.recipientKeyId !== session.firm.recipientKeyId) {
      return <ReplacedKeyRequest key={item.caseId} session={session} item={item} entry={entry} onDelivered={onDelivered}
        failure={failures.get(item.caseId)} actionFailure={actionFailures.get(item.caseId)} pending={pending}
        onRequested={onRequested} onOutcome={onOutcome} onForget={onForget} />;
    }
    const status = statuses.get(item.caseId);
    const openable = !status || ["granted", "unconfirmed", "update-pending", "checking", "error"].includes(status.kind);
    const terminal = status && ["declined", "expired", "withdrawn", "ended", "unknown"].includes(status.kind);
    // A structured renewal request when access is ending soon or has ended.
    const renewable = canAskToRenew(status, trustedNow());
    // Only a confirmed pending request (a first request or a renewal) can be
    // withdrawn; an unavailable status cannot establish that (use "Refresh").
    const withdrawable = canWithdraw(status);
    const withdrawingThis = pending?.caseId === item.caseId && pending.action === "withdraw";
    const removingThis = pending?.caseId === item.caseId && pending.action === "remove";
    return (
      <li key={item.caseId} className={boardStyles.card}>
        <Status status={status} />
        <p className="mb-3 whitespace-pre-wrap break-words">{listing?.summary ?? item.summary}</p>
        {listing?.checkCode && <p className="mb-3 text-xs text-black/60">Report check code <code>{listing.checkCode}</code></p>}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
          {/* The case ID stays out of every URL: select it in this tab, then navigate. */}
          {openable && <button type="button" className={primaryButton}
            onClick={() => void openLegalCase(router, item.caseId)}>{status?.kind === 'granted' ? 'Open report' : 'Check report access'}</button>}
          <span className="text-black/50">Requested {formatDate(item.requestedAt)}</span>
          {renewable && renewing?.caseId !== item.caseId && (
            <button type="button" className="underline" onClick={() => void startRenewal(item)}>Ask to renew</button>
          )}
          {withdrawingThis ? <span role="status">Withdrawing…</span>
            : withdrawable && (confirming === item.caseId
            ? <span className="flex flex-wrap items-center gap-3">
              <span>Withdraw this request?</span>
              <button type="button" className="underline" disabled={pending !== null} onClick={() => { setConfirming(null); void onWithdraw(item); }}>Yes, withdraw</button>
              <button type="button" className="underline" onClick={() => setConfirming(null)}>Keep it</button>
            </span>
            : <button type="button" className="underline" disabled={pending !== null} onClick={() => setConfirming(item.caseId)}>Withdraw request</button>)}
          {removingThis ? <span role="status">Removing…</span>
            : terminal && (removing === item.caseId
            ? <span className="flex flex-wrap items-center gap-3">
              <span>{REMOVE_CONFIRMATION}</span>
              <button type="button" className="underline" disabled={pending !== null} onClick={() => { setRemoving(null); void onForget(item); }}>Yes, remove</button>
              <button type="button" className="underline" onClick={() => setRemoving(null)}>Keep it</button>
            </span>
            : <button type="button" className="underline" disabled={pending !== null} onClick={() => setRemoving(item.caseId)}>Remove from this list</button>)}
        </div>
        {renewable && renewError === item.caseId && (
          <p role="alert" className="mt-2 text-red-800">
            This renewal request could not be prepared because the reporter&apos;s key on it could not be confirmed.
            Refresh to check the reporter&apos;s key and try again.
          </p>
        )}
        {renewing?.caseId === item.caseId ? (
          <RequestForm session={session} kind="renewal" listing={{ caseId: item.caseId, summary: item.summary, owner: renewing.owner }} onDelivered={onDelivered}
            onCancel={() => setRenewing(null)} onRequested={onRequested}
            onOutcome={outcome => { if (outcome.ok) setRenewing(null); onOutcome(outcome); }} />
        ) : <RequestFailure message={failures.get(item.caseId)} />}
        {status && canRequestAgain(status) && retryRequest(item)}
        <ActionFailure failure={actionFailures.get(item.caseId)} status={status} busy={pending !== null}
          onRetry={() => void (actionFailures.get(item.caseId)?.action === "remove" ? onForget(item) : onWithdraw(item))} />
        {session.pins.has(item.caseId) && status?.kind === "ended" && (
          <p className="mt-3 text-sm text-black/60">Files you downloaded earlier stay under your organization&apos;s obligations.</p>
        )}
      </li>
    );
  };
  const laneOf = (item: RememberedRequest) => requestBoardLane(statuses.get(item.caseId),
    !!entries.get(item.caseId) && entries.get(item.caseId)!.recipientKeyId !== session.firm.recipientKeyId);
  const renderLane = (lane: 'shared' | 'attention') => newestLegalReports<RememberedRequest | DirectoryListing>([
    ...ordered.filter(item => laneOf(item) === lane),
    ...directShares.filter(item => (statuses.get(item.caseId)?.kind === 'granted' ? 'shared' : 'attention') === lane),
  ], listings).map(item => 'requestId' in item ? renderRequest(item) : renderDirectShare(item));
  return (
    <section aria-labelledby="requests-title" aria-busy={sharedBusy}>
      <div className={boardStyles.toolbar}>
        <h2 id="requests-title" className="font-semibold">Your organization&apos;s requests</h2>
        <button type="button" className="text-sm underline" disabled={sharedBusy} onClick={onRefresh}>
          {sharedBusy ? "Checking…" : "Refresh"}
        </button>
      </div>
      {unavailableCount > 0 && (
        <p role="status" className="mb-4 text-sm">
          {unavailableCount} report access {unavailableCount === 1 ? 'check is' : 'checks are'} unavailable.{' '}
          <button type="button" className="underline" disabled={sharedBusy} onClick={onRetryFailed}>Retry unavailable checks</button>
        </p>
      )}
      <p className="mb-4 max-w-[62ch] text-sm text-black/60">
        Reports shared directly by a reporter appear here alongside requests your organization sent.
        Columns reflect the latest access check. Use each card&apos;s controls to take action.
        Your organization&apos;s saved request list is encrypted with your organization key; VERA cannot read it.
      </p>
      {shared?.previousKeySigned && (
        <p role="status" className="mb-4 border border-black/20 p-4 text-sm">
          Your organization is replacing its key. Until VERA registers the new key and each lawyer accepts a new
          invitation, reports cannot be opened. See <Link className="underline" href="/legal/members">Lawyers and devices</Link>.
        </p>
      )}
      {sharedError && <p role="alert" className="mb-4 text-red-800">{sharedError}</p>}
      {!shared && !sharedBusy && requests.length > 0 && (
        <p role="status" className="mb-4 border border-black/20 p-4 text-sm">
          Showing this device&apos;s saved copy of your organization&apos;s requests. Other lawyers&apos; requests may be missing
          until the list loads.
        </p>
      )}
      {!requests.length && !directShares.length && (shared || !sharedBusy) && (
        <p className="text-sm text-black/60">
          No requests or confirmed direct shares are shown yet. Refresh to check for reports shared with you.
        </p>
      )}
      {!shared && sharedBusy && <p role="status">Loading…</p>}
      <p className={boardStyles.notice}>Private reports open only with the reporter&apos;s permission.</p>
      <WorkspaceBoard label="Legal report board" three>
        <BoardLane title="Waiting for a reply" description="Requests sent. The reporter decides what to share." count={ordered.filter(item => laneOf(item) === 'waiting').length} tone="waiting">
          <ul className={boardStyles.cards}>{ordered.filter(item => laneOf(item) === 'waiting').map(renderRequest)}</ul>
          {!ordered.some(item => laneOf(item) === 'waiting') && <BoardEmpty>No requests waiting for a reply.</BoardEmpty>}
        </BoardLane>
        <BoardLane title="Shared with you" description="The secure service confirmed current access. Opening a report lets the reporter see when your organization first opened it." count={ordered.filter(item => laneOf(item) === 'shared').length + directShares.filter(item => statuses.get(item.caseId)?.kind === 'granted').length} tone="shared">
          <ul className={boardStyles.cards}>
            {renderLane('shared')}
          </ul>
          {!ordered.some(item => laneOf(item) === 'shared') && !directShares.some(item => statuses.get(item.caseId)?.kind === 'granted') && <BoardEmpty>Reports appear here when access is confirmed.</BoardEmpty>}
        </BoardLane>
        <BoardLane title="Needs attention" description="Check access, review an update, or revisit an ended request." count={ordered.filter(item => laneOf(item) === 'attention').length + directShares.filter(item => statuses.get(item.caseId)?.kind !== 'granted').length} tone="attention">
          <ul className={boardStyles.cards}>
            {renderLane('attention')}
          </ul>
          {!ordered.some(item => laneOf(item) === 'attention') && !directShares.some(item => statuses.get(item.caseId)?.kind !== 'granted') && <BoardEmpty>Nothing needs attention right now.</BoardEmpty>}
        </BoardLane>
      </WorkspaceBoard>
    </section>
  );
}

/** A request made under a key the organization has since replaced (for example
 * after a lawyer left). The old access cannot be used; the reporter must allow
 * access again, and on doing so revokes the old key first. */
function ReplacedKeyRequest({ session, item, entry, failure, actionFailure, pending, onRequested, onDelivered, onOutcome, onForget }: {
  session: FirmSession; item: RememberedRequest; entry: SharedRequest; failure: string | undefined;
  actionFailure: RequestActionFailure | undefined; pending: PendingRequestAction | null;
  onRequested: (request: RememberedRequest) => void; onDelivered: (caseId: string) => void; onOutcome: (outcome: RequestOutcome) => void;
  onForget: (request: RememberedRequest) => Promise<void>;
}) {
  const [asking, setAsking] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [listing, setListing] = useState<DirectoryListing | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ask = async () => {
    setError(null);
    try {
      const { readKey } = await import("@/enclave/src/confidential/pgp");
      const key = await readKey({ armoredKey: item.ownerPublicKey });
      if (key.isPrivate()) throw new Error("invalid");
      setListing({ caseId: item.caseId, summary: item.summary,
        owner: { caseId: item.caseId, ownerFingerprint: key.getFingerprint(), ownerPublicKey: key } });
      setAsking(true);
    } catch { setError("This request could not be prepared. Please try again."); }
  };
  return (
    <li className={boardStyles.card}>
      <div className="mb-3">
        <StatusBadge label="Needs new access" tone="attention" />
        <p className="mt-1 text-sm text-black/60">
          Your organization replaced its key. The reporter must allow access again before anyone can open this report.
        </p>
      </div>
      <p className="mb-3 whitespace-pre-wrap break-words">{item.summary}</p>
      <p className="mb-3 text-xs text-black/50">First requested {formatDate(entry.requestedAt)}. Updated {formatDate(entry.updatedAt)}.</p>
      {asking && listing ? (
        <RequestForm session={session} kind="renewal" listing={listing} initialPurpose={RENEW_PURPOSE} onDelivered={onDelivered}
          previous={entry.state === "requested" && entry.expiresAt > trustedNow() ? { caseId: entry.caseId, requestId: entry.requestId } : null}
          onCancel={() => setAsking(false)} onRequested={onRequested}
          onOutcome={outcome => { if (outcome.ok) setAsking(false); onOutcome(outcome); }} />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
            <button type="button" className={primaryButton} onClick={() => void ask()}>Ask the reporter to allow access again</button>
            {pending?.caseId === item.caseId && pending.action === "remove" ? <span role="status">Removing…</span>
              : removing
              ? <span className="flex flex-wrap items-center gap-3">
                <span>{REMOVE_CONFIRMATION}</span>
                <button type="button" className="underline" disabled={pending !== null} onClick={() => { setRemoving(false); void onForget(item); }}>Yes, remove</button>
                <button type="button" className="underline" onClick={() => setRemoving(false)}>Keep it</button>
              </span>
              : <button type="button" className="underline" disabled={pending !== null} onClick={() => setRemoving(true)}>Remove from this list</button>}
          </div>
          <RequestFailure message={failure} />
          <ActionFailure failure={actionFailure} status={undefined} busy={pending !== null} onRetry={() => void onForget(item)} />
        </>
      )}
      {error && <p role="alert" className="mt-2 text-red-800">{error}</p>}
    </li>
  );
}

/** Live onboarding checklist. Collapsed once every step is done; the profile and
 * recovery commitments stay editable from here. The membership end date stays visible
 * outside the collapsed details, because memberships are short leases. */
function FirmSetup({ session, membership, now }: { session: FirmSession; membership: MembershipState; now: number }) {
  const domain = useDomainCheck(session.firm);
  const onboarding = useOnboardingRecord(session.firm);
  const setup = useFirmSetup(session, membership.status, onboarding.record);
  const { complete } = onboardingChecklist({ keySaved: true, domain: session.firm.domain, domainCheck: domain.check,
    membership: membership.status, now, recipientKeyId: session.firm.recipientKeyId, record: onboarding.record,
    setup: setup.active ? { status: setup.status, error: setup.error } : undefined });
  const lease = membershipLease(membership.status, now);
  const publish = <OrganizationProfile firm={session.firm} domain={domain} headingLevel={3} title="Organization profile" />;
  const blocked = setup.active && setup.status && !setup.status.complete ? setupNextSteps(setup.status.missing) : [];
  const checklist = <FirmOnboardingChecklist compact firm={session.firm} keySaved domain={domain} membership={membership} onboarding={onboarding}
    setup={setup} now={now}>
    {{ domain: complete ? undefined : domain.check?.state === "verified"
      ? <details className="mt-2 text-sm"><summary className="cursor-pointer underline">Change your profile</summary><div className="mt-3">{publish}</div></details>
      : <div className="mt-3">{publish}</div>,
      lawyers: <AddLawyersHint /> }}
  </FirmOnboardingChecklist>;
  // VERA refuses requests and report opening until these are recorded.
  const notice = blocked.length > 0 && (
    <Banner tone="attention" title="Finish organization setup to request or open reports" role="status">
      <p>VERA will not send access requests or open reports for your organization until:</p>
      <ul className="mt-2 list-inside list-disc">
        {blocked.map(item => <li key={item.id}><span className="font-semibold">{item.title}.</span> {item.action}</li>)}
      </ul>
    </Banner>);
  if (!complete) return <div className="space-y-4">{notice}{checklist}</div>;
  return (
    <div className="space-y-2 text-sm">
      {(lease.state === "active" || lease.state === "ending-soon") &&
        <p className="text-black/60">Your membership is active until {membershipEndDate(lease.endsAt)}. Reopen your saved approved device to renew access. First key holders without a device approval need a new VERA invitation.</p>}
      <details>
        <summary className="cursor-pointer underline">Organization setup complete. Show details or change your profile</summary>
        <div className="mt-4 space-y-4">{checklist}{publish}</div>
      </details>
    </div>
  );
}

/** Re-render every minute so a lease that ends while the page is open is noticed. */
function useMinuteClock(): number {
  const [now, setNow] = useState(() => trustedNow());
  useEffect(() => {
    const timer = setInterval(() => setNow(trustedNow()), 60_000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

function Portal({ session, config }: { session: FirmSession; config: LegalAuthConfig }) {
  const membership = useMembershipStatus(config, session.firm);
  const now = useMinuteClock();
  const notice = membershipNotice(membership.status, now);
  const view = portalView(membership, now);
  return (
    <div className={workspaceStyles.content}>
      {notice && <Banner tone={notice.tone} title={notice.title} role={notice.tone === "negative" ? "alert" : "status"}>
        <p>{notice.message}</p>
      </Banner>}
      <FirmSetup session={session} membership={membership} now={now} />
      {view === 'not-enrolled' && <AutomaticApplicationActivation firm={session.firm} config={config} onDone={membership.refresh} />}
      {view === "checking" && <p role="status" className={panel}>Checking your membership…</p>}
      {view === "other-key" && <p className={panel}>Your account is enrolled with a different organization key. Unlock that key to see reports, or ask VERA onboarding for a new invitation.</p>}
      {view === "not-enrolled" && <p className={panel}>Reports appear here once your approved access activates with this organization key.</p>}
      {view === "ended" && <EndedMembershipRequests requests={rememberedRequests(session.firm.organizationId)} />}
      {view === "reports" && <RequestsAndDirectory session={session} />}
    </div>
  );
}

function RequestsAndDirectory({ session }: { session: FirmSession }) {
  const [listings, setListings] = useState<DirectoryListing[]>([]);
  const [loading, setLoading] = useState(true);
  // Directory loading only; withdraw and remove failures stay on their request entry.
  const [directoryError, setDirectoryError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // Failures stay next to the report they concern (in the list where the lawyer sent the request).
  const [requestFailures, setRequestFailures] = useState<ReadonlyMap<string, string>>(() => new Map());
  const [requests, setRequests] = useState<RememberedRequest[]>(() => rememberedRequests(session.firm.organizationId));
  const [shared, setShared] = useState<SharedListState | null>(() => currentSharedList());
  const [sharedError, setSharedError] = useState<string | null>(null);
  const [sharedBusy, setSharedBusy] = useState(false);
  const { statuses, refresh, recheck, retryFailed, unavailableCount } = useRequestStatuses(session, requests, listings, !loading && !sharedBusy);

  const directoryRun = useRef(0);
  useEffect(() => () => { directoryRun.current++; }, [session]);
  const load = useCallback(async () => {
    const run = ++directoryRun.current;
    setLoading(true); setDirectoryError(null);
    let collected: DirectoryListing[] = [];
    let received = false;
    try {
      const { readLegalDirectory } = await import("@/lib/confidential/firmCase");
      // A direct grant has no remembered request. Discover every directory page
      // before checking access; a random case ID is not a submission date.
      for await (const page of legalDirectoryPages(
        cursor => readLegalDirectory(session, cursor, Date.now()), null,
        () => directoryRun.current !== run,
      )) {
        if (directoryRun.current !== run) return;
        collected = mergeDirectoryListings(collected, page.listings);
        received = true;
      }
    } catch (caught) {
      if (directoryRun.current === run) setDirectoryError(failureMessage(caught,
        "Some reports could not be loaded. Refresh to check for reports shared with you."));
    } finally {
      if (directoryRun.current === run) {
        // Load the directory before the hook checks its bounded status pages.
        // Keep successfully verified pages if a later page fails.
        if (received) setListings(collected);
        setLoading(false);
      }
    }
  }, [session]);

  // The organization's shared list (every member's requests). On failure this
  // device's encrypted copy stays on screen, with statuses checked live.
  const loadShared = useCallback(async () => {
    setSharedBusy(true); setSharedError(null);
    try { setShared(await loadSharedRequests(session)); }
    catch (caught) { setShared(null); setSharedError(sharedListError(caught)); }
    finally { setSharedBusy(false); setRequests(rememberedRequests(session.firm.organizationId)); }
  }, [session]);

  useEffect(() => {
    setRequests(rememberedRequests(session.firm.organizationId));
    void loadShared();
    void load();
  }, [session, load, loadShared]);

  // Withdraw and remove failures stay on the entry they concern, apart from the
  // directory's loading error, and their "Try again" retries that action.
  const [actionFailures, setActionFailures] = useState<ReadonlyMap<string, RequestActionFailure>>(() => new Map());
  const [pending, setPending] = useState<PendingRequestAction | null>(null);
  const setActionFailure = (caseId: string, failure: RequestActionFailure | null) =>
    setActionFailures(failures => withRequestActionFailure(failures, caseId, failure));
  const withdraw = async (request: RememberedRequest) => {
    if (pending) return;
    setNotice(null); setActionFailure(request.caseId, null); setPending({ caseId: request.caseId, action: "withdraw" });
    try {
      const { withdrawCaseRequest } = await import("@/lib/confidential/firmCase");
      await withdrawCaseRequest(session, request.caseId, request.requestId, Date.now());
    } catch {
      setActionFailure(request.caseId, { action: "withdraw", message: WITHDRAW_UNCONFIRMED });
      // The withdrawal may have reached the enclave: re-check before offering another attempt.
      recheck(request.caseId);
      return;
    } finally { setPending(null); }
    // A request withdrawal is not an access revocation. Keep the saved reference:
    // deleting it could make a report with access already allowed unreachable.
    setNotice("Request withdrawn. This report stays in your list. Any access already allowed remains until the reporter revokes it or it ends.");
    recheck(request.caseId);
  };
  const forget = async (request: RememberedRequest) => {
    if (pending) return;
    setNotice(null); setActionFailure(request.caseId, null); setPending({ caseId: request.caseId, action: "remove" });
    // Removes the finished entry from every member's list.
    try { setShared(await clearRequest(session.firm.organizationId, request.caseId)); }
    catch (caught) { setActionFailure(request.caseId, { action: "remove", message: removeFailureMessage(caught) }); }
    finally { setPending(null); }
    setRequests(rememberedRequests(session.firm.organizationId));
  };

  const outcomeIn = (setFailures: (update: (failures: ReadonlyMap<string, string>) => ReadonlyMap<string, string>) => void) =>
    (outcome: RequestOutcome) => {
      setFailures(failures => withRequestOutcome(failures, outcome));
      if (outcome.ok) setNotice(outcome.message);
    };
  const refreshLists = () => { setShared(currentSharedList()); setRequests(rememberedRequests(session.firm.organizationId)); };

  const requested = useMemo(() => new Set(requests.map(item => item.caseId)), [requests]);
  // Direct grants are not requests: do not invent request IDs, timestamps or
  // withdrawal actions, and do not persist a plaintext case/organization index.
  const directShares = listings.filter(item => item.owner && !item.ownerKeyChanged && !requested.has(item.caseId) &&
    ['granted', 'update-pending'].includes(statuses.get(item.caseId)?.kind ?? ''));

  return (
    <div className={workspaceStyles.content}>
      {notice && <p role="status" className="border border-black/10 p-3 text-sm">{notice}</p>}
      {loading && <p role="status">Checking for shared reports…</p>}
      {directoryError && (
        <div role="alert" className="text-red-800">
          <p>{directoryError}</p>
          <button type="button" className="mt-2 underline" onClick={() => void load()}>Try again</button>
        </div>
      )}
      <YourRequests retryRequest={item => {
        const listing = listings.find(listing => listing.caseId === item.caseId);
        return listing && <RequestAccess session={session} listing={listing} failure={undefined}
          onOutcome={outcomeIn(setRequestFailures)} onDelivered={recheck} onRequested={refreshLists} />;
      }} session={session} requests={requests} directShares={directShares} listings={listings} statuses={statuses} shared={shared} sharedError={sharedError}
        sharedBusy={sharedBusy || loading} failures={requestFailures} actionFailures={actionFailures} pending={pending}
        onWithdraw={withdraw} onForget={forget} onOutcome={outcomeIn(setRequestFailures)} onDelivered={recheck}
        onRetryFailed={retryFailed} unavailableCount={unavailableCount}
        onRefresh={() => { setRequestFailures(new Map()); setActionFailures(new Map()); void refresh(); void loadShared(); void load(); }}
        onRequested={refreshLists} />
    </div>
  );
}

export default function LegalPortalHome() {
  return (
    <LegalPortalLayout title="Your legal workspace." onboarding wide backHref="/" backLabel="VERA"
      intro="Manage your organization, review requests and work with reports shared with your firm.">
      <LegalGate returnPath="/legal" welcome>{({ session, config }) => <Portal session={session} config={config} />}</LegalGate>
    </LegalPortalLayout>
  );
}

/** Server-rendered so `_document` applies the strict key-page headers. */
export const getServerSideProps = async () => ({ props: {} });
