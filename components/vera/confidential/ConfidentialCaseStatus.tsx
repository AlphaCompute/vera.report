import { WorkspaceBoard, BoardLane, BoardEmpty } from "./WorkspaceBoard";
import boardStyles from "./WorkspaceBoard.module.css";
import { DirectSharing } from './DirectSharing';
import { ReportCheckCode } from './ReportCheckCode';
import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { FileUp, X } from "lucide-react";
import { CONFIDENTIAL_RELEASE_MANIFEST, CONFIDENTIAL_RELEASE_NOTES } from "@/lib/confidential/config";
import {
  CONFIDENTIAL_EVIDENCE_LIMIT_TEXT, CONFIDENTIAL_MAX_FILES, checkConfidentialSelection, formatBytes, percent, progressText,
  type TransferProgress,
} from "@/lib/confidential/evidence";
import { EVIDENCE_FILE_ACCEPT, resolveEvidenceMimeType } from "@/src/utils/evidenceFiles";
import { OwnerReportView } from "./OwnerReportView";
import { OwnerFiles } from "./OwnerFiles";
import { SummaryComposer } from './SummaryComposer';
import { listingDraftFrom, listingDraftProblem, type ListingDraft } from '@/lib/confidential/listingDraft';
import type {
  CurrentGrantee, OwnerInbox, OwnerProgress, OwnerSession, PreparedEvidence, VerifiedOrganization,
  VerifiedRequest,
} from "@/lib/confidential/ownerCase";
import type { OwnerJourney, OwnerTimeline as Timeline } from "@/lib/confidential/ownerTimeline";
import type { ReleaseUpdate } from "@/lib/confidential/releaseUpdate";
import { ownerFailureOf } from "@/lib/confidential/failureCopy";
import type { OwnerFailure } from "@/lib/confidential/failureCopy";
import {
  checkFailedNotice, completedChangeNotice, evidenceAddLabel, evidenceAfterCommit, evidenceCanReselect,
  keepsReportOnRefreshFailure, type OwnerLoadOutcome,
} from "@/lib/confidential/ownerActionOutcome";

import { OwnerDevicePanel } from '@/components/vera/confidential/OwnerDevice';
import { ApproveUpdate } from '@/components/vera/confidential/ApproveUpdate';
import { ConfidentialFailure } from '@/components/vera/confidential/ConfidentialFailure';
import { OwnerJourneyHeader, OwnerTimeline } from '@/components/vera/confidential/OwnerTimeline';
import { WhoCanSee } from '@/components/vera/confidential/WhoCanSee';
import { ink } from '@/components/vera/confidential/ink';
import { ACTION_STAGE_TEXT, LoadProgress } from './LoadProgress';
import type { ActionStage, LoadStage } from './LoadProgress';
import { AccessExpiryNotices, AccessManager, AccessRequestCard } from '@/components/vera/confidential/AccessSharing';
import type { RevokeProblem } from '@/components/vera/confidential/AccessSharing';
import { grantActiveAt } from '@/enclave/src/confidential/grantPolicy';
import { trustedNow } from "@/lib/confidential/attestedTime";
import { evidenceEntries, expiresAtFor, isContactOnly } from '@/lib/confidential/accessChoices';
import type { EvidenceEntry } from '@/lib/confidential/accessChoices';
import { ownerWorkspace, ownerRecoveryText, readOwnerWorkspace } from '@/lib/confidential/deviceWorkspace';
import { RecoveryFileDownload } from './RecoveryFileDownload';
import { PARTICIPANT_LOCK_NAVIGATION, useParticipantLockHold } from '@/lib/confidential/participantLock';
import { RecoveryCodeCard } from './RecoveryCodeCard';
import type { UnlockedVault } from '@/lib/confidential/deviceVault';
import type { CheckpointPin } from '@/enclave/src/confidential/recovery';
import { ownerSessionFor, type OwnerSessionSource } from '@/lib/confidential/ownerSessionSource';


type Owner = typeof import("@/lib/confidential/ownerCase");
type Ready = {
  state: "ready"; inbox: OwnerInbox; requests: VerifiedRequest[]; roster: VerifiedOrganization[];
  grantees: CurrentGrantee[]; unverified: number; timeline: Timeline; journey: OwnerJourney;
  evidence: EvidenceEntry[]; contactScopes: ("contact" | "identity")[]; savedSummary: string | null;
};
type View =
  | { state: "loading"; stage: LoadStage }
  | { state: "needs-approval"; update: ReleaseUpdate }
  | Ready
  | { state: "error"; reason: OwnerFailure }
  | { state: "paused"; withdrawn: boolean };
type Notice = { kind: "error" | "done"; text: string } | null;

const REQUESTS_ANCHOR = "access-requests";
const SHOWN: OwnerLoadOutcome = { kind: "shown" };
const SUPERSEDED: OwnerLoadOutcome = { kind: "superseded" };
/** Owner view of a confidential case. The recovery code (and recovery file, when
 * used) is read only in this browser; the service sees ciphertext and owner
 * signatures. Reporter contact remains encrypted; replies stay in the private inbox. */
export function ConfidentialCaseStatus({ recoveryCode, recoveryPackage = null, onClose, savedVault = null, savedPin }: {
  recoveryCode: string; recoveryPackage?: string | null; onClose: () => void; savedVault?: UnlockedVault | null; savedPin?: CheckpointPin;
}) {
  const [view, setView] = useState<View>({ state: "loading", stage: "verifying" });
  const [actionStage, setActionStage] = useState<ActionStage | null>(null);
  const [vault, setVault] = useState<UnlockedVault | null>(savedVault);
  const [revokeProblem, setRevokeProblem] = useState<RevokeProblem | null>(null);
  const [deviceError, setDeviceError] = useState('');
  const saveQueue = useRef<Promise<void>>(Promise.resolve());
  const [busy, setBusy] = useState(false);
  const [confirmedClose, setConfirmedClose] = useState<{ caseId: string; revision: number } | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  // A failed action started from a request card is shown there,
  // next to the control, instead of at the top of the page.
  const [inlineFailure, setInlineFailure] = useState<{ target: string; text: string } | null>(null);
  const noticeRef = useRef<HTMLParagraphElement>(null);
  const [remember, setRemember] = useState(false);
  const [showCode, setShowCode] = useState(false);
  const rememberRef = useRef(false);
  const caseIdRef = useRef<string | null>(null);
  const session = useRef<OwnerSession | null>(null);
  // What `session` was restored from (recovery code, file and pin).
  const sessionSource = useRef<OwnerSessionSource | null>(null);
  // Evidence file names this device learned in this visit (never stored or sent).
  const fileNames = useRef(new Map<string, string>());
  const loadGeneration = useRef(0);
  const viewState = useRef<View["state"]>(view.state);
  viewState.current = view.state;

  // `keepView`: on failure, leave the current view in place and report the reason
  // to the caller (a refresh after a confirmed change, or "Check for updates").
  const load = useCallback(async (quiet = false, keepView = false): Promise<OwnerLoadOutcome> => {
    const generation = ++loadGeneration.current;
    const active = () => generation === loadGeneration.current;
    let currentStage: LoadStage = "verifying";
    const stage = (next: LoadStage) => { currentStage = next; if (!quiet && active()) setView({ state: "loading", stage: next }); };
    stage("verifying");
    let progressOwner: OwnerSession | null = null;
    try {
      const [{ fetchRelay, forgetChannelSessions }, owner, pins] = await Promise.all([import("@/lib/confidential/client"),
        import("@/lib/confidential/ownerCase"), import("@/lib/confidential/devicePin")]);
      if (!active()) return SUPERSEDED;
      // A newer recovery file or pin for the same code replaces the held session;
      // reusing it would ignore the newer file and its newer checkpoint pin.
      const current = await ownerSessionFor({ session, source: sessionSource }, { recoveryCode, recoveryPackage, savedPin }, async source => {
        const caseId = await owner.caseLocator(source.recoveryCode);
        if (!active()) return null;
        caseIdRef.current = caseId;
        const prior = await pins.loadRememberedPin(caseId, source.recoveryCode);
        if (!active()) return null;
        if (prior && source.savedPin && prior.revision === source.savedPin.revision && prior.digest !== source.savedPin.digest) {
          throw new owner.ConfidentialRollbackError();
        }
        const remembered = prior && (!source.savedPin || prior.revision > source.savedPin.revision) ? prior : source.savedPin ?? null;
        rememberRef.current = prior !== null; setRemember(prior !== null);
        const restored = await owner.restoreOwnerSession({ code: source.recoveryCode, recoveryPackage: source.recoveryPackage, relay: fetchRelay(),
          releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST, now: Date.now(), rememberedPin: remembered });
        restored.assertDeviceHistory = async () => {
          if (await pins.rememberedPinRequiresRefresh(restored.pin, source.recoveryCode)) throw new owner.ConfidentialRollbackError();
        };
        restored.onPinAdvance = pin => {
          if (!rememberRef.current) return;
          void pins.rememberPin(pin, source.recoveryCode).then(saved => { if (!saved) setDeviceError('The report history check could not be saved or conflicts with another visit. Keep your latest recovery file and resolve the device history before sharing more.'); });
        };
        if (!active()) { forgetChannelSessions(restored); return null; }
        return restored;
      }, stale => { stale.onProgress = undefined; forgetChannelSessions(stale); });
      if (!current) return SUPERSEDED;
      // "Unlocking" is shown only while an unlock actually runs (after the secure
      // service restarted), then the previous stage returns. The callback is
      // cleared when this load ends, so an unlock during a later action never
      // replaces the page with the loading view.
      let resume: LoadStage = currentStage;
      current.onProgress = (progress: OwnerProgress) => {
        if (!active()) return SUPERSEDED;
        if (progress === "unlocking") { resume = currentStage; stage("unlocking"); } else stage(resume);
      };
      progressOwner = current;
      const review = await owner.releaseApprovalReview(current, Date.now());
      if (!active()) return SUPERSEDED;
      if (review.status !== "approved") {
        const { describeReleaseUpdate } = await import("@/lib/confidential/releaseUpdate");
        const update = await describeReleaseUpdate(current.releaseManifest, CONFIDENTIAL_RELEASE_NOTES, review.approvals);
        if (update.releaseDigest !== current.releaseDigest) throw new Error('Release identity mismatch');
        if (!active()) return SUPERSEDED;
        setView({ state: "needs-approval", update }); return SHOWN;
      }
      stage("opening");
      const inbox = await owner.readOwnerInbox(current, Date.now());
      if (!active()) return SUPERSEDED;
      await current.assertDeviceHistory?.();
      if (!active()) return SUPERSEDED;
      if (rememberRef.current && !(await pins.rememberPin(current.pin, current.recoveryCode))) {
        setDeviceError('The report history check could not be saved or conflicts with another visit. Keep your latest recovery file and resolve the device history before sharing more.');
      }
      if (!active()) return SUPERSEDED;
      stage("checking");
      const roster = await owner.verifiedRoster(current, Date.now());
      if (!active()) return SUPERSEDED;
      const { requests, unverified } = await owner.reviewOwnerRequests(current, inbox, roster, Date.now());
      if (!active()) return SUPERSEDED;
      const grantees = await owner.currentGrantees(current, inbox, roster);
      if (!active()) return SUPERSEDED;
      const { buildOwnerTimeline, ownerJourney } = await import("@/lib/confidential/ownerTimeline");
      const shown = requests;
      const opens = await owner.readReportOpens(current, inbox, roster, trustedNow());
      const timeline = await buildOwnerTimeline({ trust: current.trust, history: current.history ?? [], statements: inbox.statements,
        roster, requests: shown, opens, threads: [], now: trustedNow() });
      const evidence = evidenceEntries(await owner.currentManifest(current, inbox));
      const savedSummary = await owner.previousSummary(current, inbox);
      if (!active()) return SUPERSEDED;
      setView({ state: "ready", inbox, roster, requests, grantees, unverified, timeline,
        journey: ownerJourney(inbox.current, shown, grantees, trustedNow()), evidence, contactScopes: owner.contactScopes(inbox), savedSummary });
      return SHOWN;
    } catch (error) {
      // A withdrawn or unconfirmed release pauses the report; it is never shown as an ordinary failure.
      const withdrawals = await import("@/lib/confidential/releaseWithdrawals").catch(() => null);
      if (!active()) return SUPERSEDED;
      if (withdrawals?.isReleasePaused(error)) { setView({ state: "paused", withdrawn: error.withdrawal !== null }); return SHOWN; }
      const reason = ownerFailureOf(error, session.current !== null);
      if (keepView && keepsReportOnRefreshFailure(reason)) return { kind: "failed", reason };
      setView({ state: "error", reason });
      return { kind: "failed", reason };
    } finally {
      if (progressOwner && active()) progressOwner.onProgress = undefined;
    }
  }, [recoveryCode, recoveryPackage, savedPin]);

  useEffect(() => { void load(); }, [load]);
  // Offline: try again as soon as the browser reports a connection.
  const offline = view.state === "error" && view.reason === "offline";
  useEffect(() => {
    if (!offline) return;
    const retry = () => { void load(); };
    window.addEventListener("online", retry);
    return () => window.removeEventListener("online", retry);
  }, [offline, load]);
  useEffect(() => { if (notice) noticeRef.current?.focus(); }, [notice]);
  // Leaving the view drops the attested session and its unused challenges.
  useEffect(() => () => {
    loadGeneration.current++;
    const current = session.current;
    if (current) current.onProgress = undefined;
    if (current) void import("@/lib/confidential/client").then(client => client.forgetChannelSessions(current));
  }, []);
  useEffect(() => {
    if (!vault || view.state !== 'ready') return;
    let active = true;
    saveQueue.current = saveQueue.current.then(async () => {
      if (!active || !session.current) return;
      const payload = await ownerWorkspace(session.current);
      if (!active) return;
      await vault.save(payload);
      if (active) setDeviceError('');
    }).catch(() => { if (active) setDeviceError('The current report was not saved to this device. Download a fresh recovery file, then open your saved report again.'); });
    return () => { active = false; };
  }, [vault, view]);

  const backupPayload = async () => {
    if (session.current) return ownerWorkspace(session.current);
    if (vault) return readOwnerWorkspace(vault.read());
    throw new Error('Open your report first');
  };
  const prepareDownload = useCallback(async () => {
    const payload = session.current ? await ownerWorkspace(session.current)
      : vault ? await readOwnerWorkspace(vault.read()) : null;
    if (!payload) throw new Error('Open your report first');
    return ownerRecoveryText(payload, `${window.location.origin}/status`);
  }, [vault, view, recoveryCode]);

  const act = async (work: (owner: Owner, current: OwnerSession) => Promise<string | void>,
    options: { rethrow?: boolean; inline?: string } = {}): Promise<boolean> => {
    if (!session.current || busy) return false;
    const current = session.current;
    const generation = loadGeneration.current;
    const active = () => session.current === current && loadGeneration.current === generation;
    setBusy(true); setNotice(null); setInlineFailure(null); setActionStage("saving");
    try {
      await current.assertDeviceHistory?.();
      if (!active()) return false;
      const owner = await import("@/lib/confidential/ownerCase");
      if (!active()) return false;
      const done = await work(owner, current);
      // The service confirmed the change: from here on it is reported as done, even
      // if another load started meanwhile or the refresh below fails.
      if (session.current !== current) return false;
      setActionStage("refreshing");
      // A failed refresh keeps the open report (and this confirmation) on screen
      // rather than replacing it with a full-page error, which would invite the
      // reporter to repeat a change that already applied.
      const refreshed = await load(true, viewState.current === "ready");
      if (session.current !== current) return false;
      const text = completedChangeNotice(done, refreshed.kind === "failed" ? refreshed.reason : null);
      if (text) setNotice({ kind: refreshed.kind === "failed" ? "error" : "done", text });
      return true;
    } catch (error) {
      if (session.current !== current) return false;
      const withdrawals = await import("@/lib/confidential/releaseWithdrawals").catch(() => null);
      if (withdrawals?.isReleasePaused(error)) { setView({ state: "paused", withdrawn: error.withdrawal !== null }); return false; }
      // The caller shows its own, more specific message.
      if (options.rethrow) throw error;
      // Only messages written for the participant are shown; never a raw error.
      let text: string;
      if (error instanceof Error && (error.name === "OrganizationKeyUnconfirmedError" || error.name === "RevokeBlockedError")) {
        // Written for the participant: names the organization and the way out.
        text = error.message;
      } else {
        const { OWNER_FAILURE_COPY } = await import("@/lib/confidential/failureCopy");
        const copy = OWNER_FAILURE_COPY[ownerFailureOf(error, true)];
        // A failure after sending can follow a change the service already applied.
        text = `That change was not confirmed. It may have completed. ${copy.action}`;
      }
      const inline = options.inline;
      if (inline) setInlineFailure({ target: inline, text });
      else setNotice({ kind: "error", text });
      return false;
    } finally {
      setBusy(false); setActionStage(null);
      // Move focus to the outcome so keyboard and screen reader users hear it.
      setTimeout(() => noticeRef.current?.focus(), 0);
    }
  };
  const actionProgress = actionStage && (
    <p role="status" aria-live="polite" className="border border-black/10 p-4 text-sm">{ACTION_STAGE_TEXT[actionStage]}</p>
  );

  const setDeviceMemory = async (on: boolean) => {
    const pins = await import("@/lib/confidential/devicePin");
    rememberRef.current = on; setRemember(on);
    if (on && session.current && !(await pins.rememberPin(session.current.pin, session.current.recoveryCode))) {
      rememberRef.current = false; setRemember(false);
      setDeviceError('The report history check could not be saved. Download a current recovery file.');
    }
    if (!on && caseIdRef.current) await pins.forgetPin(caseIdRef.current, recoveryCode);
  };
  const close = () => {
    loadGeneration.current++;
    vault?.lock();
    const current = session.current;
    if (current) current.onProgress = undefined;
    if (current) void import("@/lib/confidential/client").then(client => client.forgetChannelSessions(current));
    session.current = null; sessionSource.current = null; onClose();
  };

  const panel = "border border-black/10 bg-white p-5 sm:p-7";
  const unconfirmed = session.current?.freshness === "unconfirmed";
  // One "This device" panel (what this browser remembers) and one backup section
  // (the recovery code and file). Freshness is only known once the report is open.
  const deviceControls = <>
      <OwnerDevicePanel className={panel} vault={vault} onVaultChange={setVault} getPayload={backupPayload}
        history={{ on: remember, set: setDeviceMemory }} locked={view.state !== "ready"}
        freshness={view.state === "ready" ? (unconfirmed ? "unconfirmed" : "confirmed") : undefined} />
      <section className={panel} aria-label="Recovery code and file">
        <h3 className="mb-2 font-semibold">Recovery code and file</h3>
        <p className="mb-3 text-sm">Download your current recovery file again, or print a recovery sheet. Anyone with either can act as you.
          Keep them outside browser storage. They restore access; they are not an offline copy of all evidence.</p>
        <RecoveryFileDownload prepare={prepareDownload} className="inline-flex items-center gap-2 border border-current px-3 py-2" />
        <details className="mt-4" onToggle={event => setShowCode((event.currentTarget as HTMLDetailsElement).open)}>
          <summary className="cursor-pointer text-sm underline">Show recovery code and printable sheet</summary>
          {showCode && <div className="mt-3"><RecoveryCodeCard recoveryCode={recoveryCode} heading="Recovery code" /></div>}
        </details>
      </section>
      {deviceError && <p role="alert" className="text-sm">{deviceError}</p>}
  </>;
  // The outcome of the last change. Also shown above a full-page error, so a
  // change that applied is never hidden by a failure that followed it.
  const noticeLine = notice && (
    <p ref={noticeRef} tabIndex={-1} role={notice.kind === "error" ? "alert" : "status"} className="border border-black/10 p-4 text-sm">
      {notice.text}
    </p>
  );
  if (view.state === "loading") return <LoadProgress stage={view.stage} className={panel} />;
  if (view.state === "error") {
    return (
      <div className="mt-10">
        {noticeLine && <div className="mb-6">{noticeLine}</div>}
        <ConfidentialFailure reason={view.reason}>
          {view.reason !== "verification" && (
            <button type="button" className="border border-current px-3 py-2" onClick={() => void load()}>Try again</button>
          )}
          <button type="button" className="underline" onClick={close}>Close</button>
        </ConfidentialFailure>
        {view.reason === "rollback" && <p className="mt-4 max-w-[62ch] text-sm">Keep this device’s history check and your latest backup.
          Removing the check cannot establish which history is correct.</p>}
        {(vault || session.current) && deviceControls}
      </div>
    );
  }
  if (view.state === "paused") {
    // A withdrawn or unconfirmed backend release: never move the report to another
    // release automatically. A replacement needs this owner's explicit approval.
    return (
      <section className={panel} role="alert" aria-labelledby="release-paused-title">
        {noticeLine && <div className="mb-4">{noticeLine}</div>}
        <h2 id="release-paused-title" className="mb-3 font-semibold">Secure service paused</h2>
        <p className="mb-3 max-w-[62ch]">
          {view.withdrawn
            ? "VERA has withdrawn the version of the secure service this page uses, so it is paused. Nothing was sent from this device."
            : "This device could not confirm that the secure service version is still approved, so it is paused. Nothing was sent from this device."}
        </p>
        <p className="mb-4 max-w-[62ch] text-sm">
          Your report stays encrypted and legal organizations cannot open it through this version. When a replacement is
          available you will be asked to approve it here; nothing moves to a new version without your approval. Keep your
          recovery code and file.
        </p>
        <button type="button" className="border border-black px-3 py-2" onClick={() => void load()}>Check again</button>
        <button type="button" className="ml-3 underline" onClick={close}>Close</button>
        {(vault || session.current) && deviceControls}
      </section>
    );
  }
  if (view.state === "needs-approval") {
    return (
      <div className={panel}>
        <ApproveUpdate update={view.update} busy={busy} onLater={close}
          onApprove={() => void act((owner, current) => owner.approveCurrentRelease(current, Date.now())
            .then(() => "Update approved. Your report is open."))}>
          {actionStage && <p role="status" aria-live="polite" className="mt-4 text-sm">{ACTION_STAGE_TEXT[actionStage]}</p>}
          {notice && <p ref={noticeRef} tabIndex={-1} role={notice.kind === "error" ? "alert" : "status"} className="mt-4">{notice.text}</p>}
        </ApproveUpdate>
        {deviceControls}
      </div>
    );
  }
  const { inbox, grantees, evidence } = view;
  // A confirmed close stays closed even if the following refresh fails. Never
  // re-enable sharing using a pre-close snapshot retained for reading.
  const closeNeedsRefresh = confirmedClose?.caseId === session.current?.trust.caseId &&
    confirmedClose !== null && inbox.current.revision < confirmedClose.revision;
  const reportClosed = closeNeedsRefresh ||
    (inbox.current.listingDigest === null && inbox.current.grantDigests.length === 0);
  const requests = reportClosed ? [] : view.requests;
  const activeNames = grantees.filter(item => item.grants.some(grant => grantActiveAt(grant, trustedNow())))
    .map(item => item.organization?.displayName ?? view.roster.find(entry => entry.organizationId === item.organizationId)?.displayName ??
      "An organization that can no longer be verified");
  const shareCheck = unconfirmed ? <ShareCheck names={activeNames} /> : null;
  const contactLabel = view.contactScopes.includes("identity") ? "name and contact details"
    : view.contactScopes.includes("contact") ? "contact details" : null;
  const nameOf = (grantee: CurrentGrantee) => grantee.organization?.displayName ?? "The legal organization";
  return (
    <div className="mt-10 space-y-6">
      <OwnerJourneyHeader journey={view.journey} closed={reportClosed} requestsAnchor={REQUESTS_ANCHOR} />
      <div className="flex flex-wrap items-center gap-4 border-b border-black/10 pb-6">
        <button type="button" disabled={busy} className="min-h-11 border border-black/20 bg-white px-4 py-2 text-sm font-semibold transition-colors hover:bg-black/5 disabled:opacity-50" onClick={() => {
          setBusy(true); setNotice(null);
          void load(true, true).then(outcome => {
            if (outcome.kind === "failed") setNotice({ kind: "error", text: checkFailedNotice(outcome.reason) });
          }).finally(() => setBusy(false));
        }}>{busy ? 'Checking…' : 'Check for updates'}</button>
        {/* Leaves this report in this tab only. "Lock report" (This device) locks every tab. */}
        <button type="button" disabled={busy} className="min-h-11 text-sm underline underline-offset-4 disabled:opacity-50" onClick={close}>Leave for now</button>
        <span className="text-sm text-black/60">Leaving clears this tab. Your report and sharing stay as they are.</span>
      </div>
      {actionProgress}
      {noticeLine}
      <nav aria-label="Report sections" className="flex flex-wrap gap-x-6 gap-y-2 text-sm font-semibold text-[#294932]">
        <a className="min-h-11 content-center underline underline-offset-4" href="#your-report">Read your report</a>
        <a className="min-h-11 content-center underline underline-offset-4" href="#report-activity">Activity</a>
        <a className="min-h-11 content-center underline underline-offset-4" href="#report-sharing">Sharing & requests</a>
        <a className="min-h-11 content-center underline underline-offset-4" href="#report-settings">Edit summary or close report</a>
      </nav>
      <div className={boardStyles.supplement}>
        <div>
          {session.current && <OwnerReportView session={session.current} inbox={inbox} />}
          {session.current && <ReportCheckCode caseId={session.current.trust.caseId}
            ownerFingerprint={session.current.trust.ownerFingerprint} panel={panel} />}
          {session.current && <OwnerFiles session={session.current} inbox={inbox} panel={panel} />}
          {!reportClosed && session.current && <EvidencePanel session={session.current} inbox={inbox} grantees={grantees} busy={busy} panel={panel}
            shareCheck={shareCheck}
            onCommit={prepared => act(async (owner, current) => {
              const { sharedWith, added } = await owner.commitEvidence(current, inbox, view.roster, prepared, Date.now());
              for (const item of added) fileNames.current.set(item.objectId, item.name);
              return (sharedWith.length
                ? `Files added. Shared with ${sharedWith.map(item => item.displayName).join(", ")}.`
                : grantees.some(item => item.organization && item.grants.some(grant => !isContactOnly(grant) && grantActiveAt(grant, trustedNow())))
                  ? "Files added. No legal organization can open them yet. To share them with an organization that has access, " +
                    "use \"Change what they can read\" under \"Who has access\"."
                  : "Files added. No legal organization can open them until you allow access.");
            }, { rethrow: true })}
            onRefresh={() => load(true)} />}
        </div>
        <div>
          <div className={panel}><OwnerTimeline timeline={view.timeline} /></div>
        </div>
      </div>
      <div id="report-settings" className="scroll-mt-24" />
      <SummaryPanel summary={view.savedSummary} closed={reportClosed} busy={busy || closeNeedsRefresh} panel={panel}
        onSave={draft => act((owner, current) => owner.updateSummary(current, inbox, draft.summary.trim(), Date.now())
          .then(() => reportClosed ? "Report reopened. Your summary is visible again. No firm has been given access." : "Your summary was updated."))}
        onClose={() => act(async (owner, current) => {
          await owner.closeReport(current, inbox, Date.now());
          setConfirmedClose({ caseId: current.trust.caseId, revision: inbox.current.revision + 1 });
          return "Report closed. Your summary is hidden and all firm access has ended.";
        })} />
      {closeNeedsRefresh && <p role="status" className="text-sm">Closure is confirmed. Check for updates before reopening this report.</p>}
      {!reportClosed && <>
      <AccessExpiryNotices grantees={grantees} now={trustedNow()} />
      <DirectSharing organizations={view.roster} existingOrganizationIds={grantees.map(item => item.organizationId)} requested={requests.map(item => item.organization.organizationId)}
        busy={busy} published={inbox.current.listingDigest !== null} revision={inbox.current.revision}
        onVerify={async organizationId => {
          const current = session.current, generation = loadGeneration.current;
          if (!current) throw new Error('Unlock your report first');
          const owner = await import("@/lib/confidential/ownerCase");
          const organization = await owner.verifyOrganizationProfile(current, organizationId, Date.now());
          if (session.current !== current || loadGeneration.current !== generation) throw new Error('Visit changed');
          return organization;
        }}
        onShare={(organizationId, decision) => act((owner, current) => owner.shareWithOrganization(current, inbox, organizationId, decision, Date.now())
          .then(() => 'Access granted. Tell the organization your report check code. After checking for updates, it can find your report under Shared with you and choose Open report. This is not a delivery or read confirmation.'))} />
      </>}
      <div id="report-sharing" className="scroll-mt-24" />
      <WorkspaceBoard label="Report status board">
        <BoardLane title="Requests to review" count={requests.length} tone="waiting" description="You decide what to share. A request gives no access.">
          <div id={REQUESTS_ANCHOR} className="scroll-mt-24 space-y-5">
            {!requests.length && <BoardEmpty>{reportClosed ? 'Report closed. Reopen it before reviewing requests or sharing again.' : view.unverified ? 'Some requests could not be verified.' : (grantees.length || inbox.deliveries.length) ? 'No pending access requests' : 'No legal organization has requested access'}</BoardEmpty>}
            {requests.map(item => (
              <AccessRequestCard key={item.delivery.requestId} item={item} evidence={evidence} fileNames={fileNames.current}
                currentRevision={inbox.current.revision} busy={busy} panel={panel} shareCheck={shareCheck}
                existing={grantees.find(grantee => grantee.organizationId === item.request.organizationId)?.grants ?? []}
                replacedKey={grantees.some(grantee => grantee.organizationId === item.request.organizationId && !grantee.organization)}

                actionError={inlineFailure?.target === `request:${item.delivery.requestId}` ? inlineFailure.text : null}
                onAllow={decision => act((owner, current) => owner.allowAccess(current, inbox, view.roster, item, decision, Date.now())
                  .then(() => `${item.organization.displayName} can now open what you chose. You can change or revoke this under "Who has access".`),
                  { inline: `request:${item.delivery.requestId}` })}
                onDecline={() => act((owner, current) => owner.declineAccess(current, item, Date.now())
                  .then(() => `You declined the request from ${item.organization.displayName}.`), { inline: `request:${item.delivery.requestId}` })} />
            ))}
          </div>
          {view.unverified > 0 && (
            <p className="text-sm" style={{ color: ink(60) }}>
              Some requests could not be verified and are not shown.
            </p>
          )}
        </BoardLane>
        <BoardLane title="Access & permissions" count={reportClosed ? 0 : grantees.length} tone="shared" description="Review what you have shared with each firm. Change permissions or revoke access.">
          {reportClosed ? <BoardEmpty>No firm has access. Previously downloaded copies cannot be taken back.</BoardEmpty> : <AccessManager grantees={grantees} roster={view.roster} evidence={evidence} fileNames={fileNames.current}
            currentRevision={inbox.current.revision} contactLabel={contactLabel} busy={busy} now={trustedNow()}
            shareCheck={shareCheck} revokeProblem={revokeProblem}
            onChangeAccess={(grantee, decision) => act((owner, current) => owner.changeAccess(current, inbox, grantee, decision, Date.now())
              .then(() => `${nameOf(grantee)} can now open what you chose.`))}
            onRenew={(grantee, duration) => act((owner, current) => owner.renewAccess(current, inbox, view.roster, grantee,
              expiresAtFor(duration, trustedNow()), Date.now()).then(() => `Access for ${nameOf(grantee)} was renewed.`))}
            onShareContact={grantee => act((owner, current) => owner.shareContactDetails(current, inbox, view.roster, grantee, Date.now())
              .then(() => `${nameOf(grantee)} can now read your ${contactLabel}.`))}
            onStopContact={grantee => act((owner, current) => owner.stopSharingContactDetails(current, inbox, grantee, Date.now())
              .then(() => `You stopped sharing your ${contactLabel} with ${nameOf(grantee)}.`))}
            onRevoke={revoking => {
              setRevokeProblem(null);
              return act(async (owner, current) => {
                try {
                  await owner.revokeOrganizations(current, inbox, view.roster, revoking.map(item => item.organizationId), Date.now());
                } catch (error) {
                  if (error instanceof owner.RevokeBlockedError) {
                    setRevokeProblem({ organizationIds: error.revoking.map(item => item.organizationId), blockers: error.blockers });
                  }
                  throw error;
                }
                const revokedNames = revoking.map(item => item.organization?.displayName ??
                  view.roster.find(entry => entry.organizationId === item.organizationId)?.displayName ?? "The legal organization");
                return `${revokedNames.join(" and ")} no longer ${revokedNames.length > 1 ? "have" : "has"} access to new information.`;
              });
            }} />}
        </BoardLane>
      </WorkspaceBoard>
      <div className={panel}><WhoCanSee allowed={reportClosed ? [] : activeNames} /></div>
      {deviceControls}
    </div>
  );
}

/** Shown only right before an action that shares something new, and only when
 * this device cannot confirm it sees the newest state (freshness decision). */
function ShareCheck({ names }: { names: string[] }) {
  return (
    <div role="note" className="mb-4 max-w-[62ch] p-4 text-sm" style={{ border: `2px solid ${ink(80)}` }}>
      <p className="mb-1 font-semibold">Check before you share</p>
      <p>
        This device can&apos;t confirm it&apos;s seeing the newest state of your report. Right now it shows access for:{" "}
        <strong>{names.length ? names.join(", ") : "no legal organization"}</strong>. If you revoked access on another
        device and that organization still appears here, stop and open your newest recovery file first.
      </p>
    </div>
  );
}

function SummaryPanel({ summary, closed, busy, panel, onSave, onClose }: {
  summary: string | null; closed: boolean; busy: boolean; panel: string;
  onSave: (draft: ListingDraft) => Promise<boolean>; onClose: () => Promise<boolean>;
}) {
  const [mode, setMode] = useState<"view" | "edit" | "close">("view");
  const [draft, setDraft] = useState<ListingDraft>(() => listingDraftFrom(summary));
  const [problem, setProblem] = useState("");
  const save = () => {
    const reason = listingDraftProblem(draft);
    setProblem(reason ?? "");
    if (!reason) void onSave(draft).then(ok => { if (ok) setMode("view"); });
  };
  return (
    <section className={`${panel} rounded-lg`} aria-label="Summary for legal review">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-serif text-2xl">Manage your report</h2>
          <p className="mt-2 max-w-[72ch] text-sm leading-relaxed text-black/65">{closed
            ? 'Your report is closed. Your summary is hidden and no firm has access. You can still read your history and save your recovery file.'
            : 'Edit what law firms see, or close your report when you no longer want to share it.'}</p>
        </div>
        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${closed ? 'border-black/20 bg-black/5' : 'border-[#cbdccb] bg-[#edf4ed] text-[#315f43]'}`}>
          {closed ? 'Closed' : 'Open'}
        </span>
      </div>
      {mode !== "edit" && <div className="border-l-2 border-[#cbd5ca] pl-4">
        <h3 className="mb-2 text-sm font-semibold">{closed ? 'Your saved summary' : 'Summary visible to law firms'}</h3>
        <p className="max-w-[85ch] whitespace-pre-wrap text-sm leading-relaxed">{summary ?? 'No summary is currently published.'}</p>
        <p className="mt-2 text-xs text-black/60">{closed ? 'Hidden from the directory. Reopening does not restore any firm’s access.' : 'This summary is public to VERA staff and approved law firms. Your full report stays private until you share it.'}</p>
      </div>}
      {mode === "view" && (
        <div className="mt-5 flex flex-wrap gap-3 text-sm">
          <button type="button" disabled={busy} className="min-h-11 border border-[#233d2c] bg-[#233d2c] px-4 py-2 font-semibold text-white disabled:opacity-50" onClick={() => { setDraft(listingDraftFrom(summary)); setProblem(""); setMode("edit"); }}>
            {closed ? "Reopen report" : "Edit summary"}
          </button>
          {!closed && (
            <button type="button" disabled={busy} className="min-h-11 border border-black/20 px-4 py-2 font-semibold disabled:opacity-50" onClick={() => setMode("close")}>Close report</button>
          )}
        </div>
      )}
      {mode === "edit" && (
        <div className="mt-2">
          <p className="mb-4 max-w-[62ch] text-sm text-black/70">
            {closed ? 'Review your summary before reopening. Law firms will be able to find it and request access. You must choose to share your private report again.' : 'Saving updates the public summary, not your original report or sharing permissions. Earlier versions may already have been seen and cannot be recalled.'}
          </p>
          <SummaryComposer value={draft} onChange={next => { setDraft(next); if (problem) setProblem(""); }} commitVerb="save" />
          {problem && <p role="alert" className="mt-4 text-sm text-red-800">{problem}</p>}
          <div className="mt-6 flex gap-3">
            <button type="button" disabled={busy} className="border border-black bg-black px-4 py-2 text-white" onClick={save}>
              {closed ? 'Publish summary and reopen' : 'Save summary'}
            </button>
            <button type="button" disabled={busy} className="border border-black px-4 py-2 disabled:opacity-50" onClick={() => setMode("view")}>Cancel</button>
          </div>
        </div>
      )}
      {mode === "close" && (
        <div className="mt-5 rounded border border-[#dec9b4] bg-[#fdf8ef] p-5" role="group" aria-label="Confirm report closure">
          <h3 className="font-semibold">Close this report and stop sharing?</h3>
          <ul className="my-3 list-disc space-y-2 pl-5 text-sm leading-relaxed">
            <li>Hide your summary so law firms cannot find it or send new requests.</li>
            <li>Stop every firm from opening this report or downloading files.</li>
            <li>Keep your encrypted report, history and recovery key so you can return or reopen it later.</li>
          </ul>
          <p className="mb-4 max-w-[80ch] text-sm text-black/70">This cannot take back copies a firm already read or downloaded. It does not delete your report.</p>
          <div className="flex flex-wrap gap-3">
            <button type="button" disabled={busy} className="min-h-11 border border-[#833b2f] bg-[#833b2f] px-4 py-2 text-white disabled:opacity-50"
              onClick={() => void onClose().then(ok => { if (ok) setMode("view"); })}>
              Confirm: close report
            </button>
            <button type="button" disabled={busy} className="min-h-11 border border-black/20 bg-white px-4 py-2 disabled:opacity-50" onClick={() => setMode("view")}>Keep report open</button>
          </div>
        </div>
      )}
    </section>
  );
}

type AddPhase =
  | { kind: "choose" }
  | { kind: "encrypting"; progress: TransferProgress }
  | { kind: "uploading"; progress: TransferProgress }
  | { kind: "paused"; message: string; uploaded: boolean }
  | { kind: "committing" };

/** Add files after submission: encrypt on this device (chunk by chunk, from
 * disk), upload the encrypted chunks with pause and resume, then sign the new
 * file list. Nothing is added to the report until that last step succeeds. */
function EvidencePanel({ session, inbox, grantees, busy, panel, shareCheck, onCommit, onRefresh }: {
  session: OwnerSession; inbox: OwnerInbox; grantees: CurrentGrantee[]; busy: boolean; panel: string; shareCheck: ReactNode;

  onCommit: (prepared: PreparedEvidence) => Promise<boolean>; onRefresh: () => Promise<unknown>;
}) {
  const [files, setFiles] = useState<File[]>([]);
  const [problems, setProblems] = useState<string[]>([]);
  const [phase, setPhase] = useState<AddPhase>({ kind: "choose" });
  const [dragging, setDragging] = useState(false);
  const prepared = useRef<PreparedEvidence | null>(null);
  const abort = useRef<AbortController | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const recipients = grantees.filter(item => item.organization && item.grants.some(grant => !isContactOnly(grant) &&
    grant.objectRevisionLimit === null && grant.scopes.includes("evidence") && (grant.expiresAt === null || grant.expiresAt > trustedNow())))
    .map(item => item.organization!.displayName);
  // Organizations with active access that will not receive new files automatically.
  const others = grantees.filter(item => item.organization && !recipients.includes(item.organization.displayName) &&
    item.grants.some(grant => !isContactOnly(grant) && (grant.expiresAt === null || grant.expiresAt > trustedNow())))
    .map(item => item.organization!.displayName);
  const working = phase.kind === "encrypting" || phase.kind === "uploading" || phase.kind === "committing";
  // Organizations with access to files added later must receive them, and their
  // keys are first checked against the current attested approved roster.
  const addLabel = evidenceAddLabel(phase.kind === "paused" && prepared.current ? (phase.uploaded ? "finish" : "resume") : "add");
  const discard = () => {
    for (const item of prepared.current?.objects ?? []) item.dispose();
    prepared.current = null;
  };
  useEffect(() => () => { abort.current?.abort(); discard(); }, []);
  // An encrypt, upload or commit counts as activity: the idle lock waits for it
  // (and locks at once afterwards if the idle time has passed meanwhile).
  useParticipantLockHold(working);
  // Leaving mid-upload loses its place; ask first. A lock never asks: it must
  // clear the private view instead of waiting on a dialog.
  useEffect(() => {
    if (!working && phase.kind !== "paused") return;
    const unload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    const locking = () => window.removeEventListener("beforeunload", unload);
    window.addEventListener("beforeunload", unload);
    window.addEventListener(PARTICIPANT_LOCK_NAVIGATION, locking);
    return () => { window.removeEventListener("beforeunload", unload); window.removeEventListener(PARTICIPANT_LOCK_NAVIGATION, locking); };
  }, [working, phase.kind]);
  // A file dropped elsewhere must not navigate the browser away from the report.
  useEffect(() => {
    const stop = (event: DragEvent) => {
      if (event.target instanceof HTMLInputElement && event.target.type === "file") return;
      if (event.dataTransfer?.types?.includes("Files")) event.preventDefault();
    };
    window.addEventListener("dragover", stop);
    window.addEventListener("drop", stop);
    return () => { window.removeEventListener("dragover", stop); window.removeEventListener("drop", stop); };
  }, []);

  const choose = (chosen: File[]) => {
    discard();
    const { accepted, problems: found } = checkConfidentialSelection([], chosen);
    setProblems(found);
    setFiles(accepted);
    setPhase({ kind: "choose" });
  };
  const start = async () => {
    const [owner, client, chunks] = await Promise.all([import("@/lib/confidential/ownerCase"),
      import("@/lib/confidential/client"), import("@/enclave/src/confidential/caseChunks")]);
    const controller = new AbortController();
    abort.current = controller;
    let uploaded = false;
    try {
      if (!prepared.current) {
        setPhase({ kind: "encrypting", progress: { bytesDone: 0, bytesTotal: files.reduce((sum, file) => sum + file.size, 0) } });
        prepared.current = await owner.prepareEvidence(session, inbox, files.map(file =>
          ({ ...chunks.blobEvidenceSource(file), type: resolveEvidenceMimeType(file.type, file.name) })),
        progress => setPhase({ kind: "encrypting", progress }));
      }
      let announced = -1;
      await owner.uploadEvidence(session, prepared.current, { signal: controller.signal, onProgress: progress => {
        const bucket = Math.floor(percent(progress) / 5);
        if (bucket !== announced) { announced = bucket; setPhase({ kind: "uploading", progress }); }
      } });
      uploaded = true;
      setPhase({ kind: "committing" });
      const committed = await onCommit(prepared.current);
      const next = evidenceAfterCommit(committed);
      // Not confirmed: keep the prepared, uploaded files for "Finish adding files".
      if (next.kind === "paused") { setPhase(next); return; }
      discard();
      setFiles([]); setProblems([]);
      if (input.current) input.current.value = "";
      setPhase(next);
    } catch (error) {
      if (error instanceof client.ConfidentialUploadInterruptedError) {
        setPhase({ kind: "paused", uploaded: false, message: controller.signal.aborted
          ? "Upload paused. Nothing has been added yet." : error.message });
      } else if (error instanceof chunks.EvidenceChangedError || error instanceof owner.EvidenceStaleError) {
        discard();
        setPhase({ kind: "paused", uploaded: false, message: error instanceof owner.EvidenceStaleError ? error.message
          : "A file changed after it was encrypted. Choose Encrypt and add to encrypt the current version." });
        if (error instanceof owner.EvidenceStaleError) await onRefresh().catch(() => undefined);
      } else if (error instanceof owner.OrganizationKeyUnconfirmedError) {
        // Nothing was signed: keep the uploaded files for "Finish adding files"
        // and say which organization's key was not confirmed, and why.
        setPhase({ kind: "paused", uploaded: true, message: error.message });
      } else if (error instanceof chunks.EvidenceTooLargeError) {
        discard();
        setProblems([error.message]); setPhase({ kind: "choose" });
      } else {
        setPhase({ kind: "paused", uploaded, message: uploaded
          ? "Your files are uploaded, but adding them to your report was not confirmed. It may have completed. Check for updates, then try again if they are not listed under Your files."
          : "The files could not be encrypted or uploaded. Nothing has been added. Try again." });
      }
    } finally { abort.current = null; }
  };
  const cancel = () => {
    abort.current?.abort();
    discard();
    setPhase({ kind: "choose" });
  };

  const progress = phase.kind === "encrypting" || phase.kind === "uploading" ? phase.progress : null;
  const pick = (chosen: File[]) => choose(chosen.slice(0, CONFIDENTIAL_MAX_FILES + 1));
  const clearFiles = () => {
    discard();
    setFiles([]); setProblems([]); setPhase({ kind: "choose" });
    if (input.current) input.current.value = "";
  };
  return (
    <section className={panel} aria-labelledby="evidence-title">
      <h3 id="evidence-title" className="mb-2 font-semibold">Add evidence</h3>
      <p className="mb-3 max-w-[62ch] text-sm text-black/70">
        Files are encrypted on this device before upload. {recipients.length
          ? `They will be shared with ${recipients.join(", ")}, because you allowed access to files you add later.`
          : others.length
            ? `No legal organization will be able to open them until you share them. To share them with ${others.join(", ")}, use "Change what they can read" under "Who has access".`
            : "No legal organization will be able to open them until you allow access."}{recipients.length > 0 && others.length > 0 &&
          ` To also share them with ${others.join(", ")}, use "Change what they can read" under "Who has access".`} Files may contain details
        that identify you, including hidden metadata.
      </p>
      <p id="add-evidence-limits" className="mb-3 text-sm text-black/60">{CONFIDENTIAL_EVIDENCE_LIMIT_TEXT}</p>
      <input ref={input} type="file" multiple accept={EVIDENCE_FILE_ACCEPT} aria-label="Choose evidence files"
        aria-describedby="add-evidence-limits" className="sr-only" tabIndex={-1} disabled={working}
        onChange={event => { pick(Array.from(event.target.files ?? [])); event.target.value = ""; }} />
      {files.length === 0 && (
        <div
          onDragEnter={event => { event.preventDefault(); if (!working) setDragging(true); }}
          onDragOver={event => { event.preventDefault(); event.dataTransfer.dropEffect = working ? "none" : "copy"; }}
          onDragLeave={event => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false); }}
          onDrop={event => { event.preventDefault(); setDragging(false); if (!working) pick(Array.from(event.dataTransfer.files)); }}
          className="flex flex-col items-start gap-3 p-4 sm:flex-row sm:items-center"
          style={{ border: `1px dashed ${dragging ? "var(--vera-ink)" : "rgba(0,0,0,0.3)"}`,
            background: dragging ? "rgba(0,0,0,0.04)" : "transparent" }}
        >
          <button type="button" disabled={working} onClick={() => input.current?.click()}
            aria-describedby="add-evidence-limits"
            className="inline-flex shrink-0 items-center gap-2 border border-black px-3 py-2 disabled:opacity-50"
            style={{ minHeight: 44 }}>
            <FileUp className="size-[14px]" aria-hidden />Choose files
          </button>
          <p className="text-sm text-black/60">
            <span className="hidden sm:inline">Or drop them here. </span>
            Encrypted on this device before upload.
          </p>
        </div>
      )}
      {problems.length > 0 && (
        <ul role="alert" className="mt-2 space-y-1 text-sm text-red-800">
          {problems.map(problem => <li key={problem}>{problem}</li>)}
        </ul>
      )}
      {files.length > 0 && (
        <div className="mt-1">
          {recipients.length > 0 && shareCheck}
          <ul className="mb-3 divide-y divide-black/10 border border-black/10" style={{ color: ink(70) }}>
            {files.map(file => (
              <li key={`${file.name}-${file.size}-${file.lastModified}`}
                className="flex items-start justify-between gap-3 px-3 py-2 text-sm">
                <span className="min-w-0 break-all">{file.name} <span className="text-black/50">({formatBytes(file.size)})</span></span>
              </li>
            ))}
          </ul>
          {evidenceCanReselect(phase.kind, prepared.current !== null) && (
            <div className="mb-3 flex flex-wrap gap-3">
              <button type="button" onClick={() => input.current?.click()}
                className="inline-flex items-center gap-2 border border-black px-3 py-2" style={{ minHeight: 44 }}>
                <FileUp className="size-[14px]" aria-hidden />Change files
              </button>
              <button type="button" onClick={clearFiles}
                className="inline-flex items-center gap-2 border border-black/30 px-3 py-2 text-black/70" style={{ minHeight: 44 }}>
                <X className="size-[14px]" aria-hidden />Clear
              </button>
            </div>
          )}
          {progress && (
            <div className="mb-3 max-w-[420px]">
              <div role="progressbar" aria-label={phase.kind === "encrypting" ? "Encrypting files" : "Uploading encrypted files"}
                aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent(progress)} className="h-[4px] w-full bg-black/10">
                <div className="h-full bg-black" style={{ width: `${percent(progress)}%` }} />
              </div>
              <p role="status" className="mt-1 text-sm text-black/60">
                {progressText(phase.kind === "encrypting" ? "Encrypting on this device" : "Uploading encrypted files", progress)}
              </p>
            </div>
          )}
          {phase.kind === "committing" && <p role="status" className="mb-3 text-sm text-black/60">Adding the files to your report…</p>}
          {phase.kind === "paused" && <p role="alert" className="mb-3 text-sm">{phase.message}</p>}
          <div className="flex flex-wrap items-center gap-3">
            {phase.kind === "uploading" ? (
              <button type="button" className="border border-black px-4 py-2" onClick={() => abort.current?.abort()}>Pause upload</button>
            ) : (
              <button type="button" disabled={busy || working} className="border border-black bg-black px-4 py-2 text-white disabled:opacity-50"
                onClick={() => void start()}>
                {working ? "Working…" : addLabel}
              </button>
            )}
            {(phase.kind === "uploading" || (phase.kind === "paused" && prepared.current)) && (
              <button type="button" className="underline underline-offset-4" onClick={cancel}>Cancel</button>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
