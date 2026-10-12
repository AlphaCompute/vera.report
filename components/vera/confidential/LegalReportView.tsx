/** Legal organization report view (/legal/report, pages/legal/report.tsx). Everything shown here was
 * decrypted and verified on this device; values render as text only. */
import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { trustedNow } from "@/lib/confidential/attestedTime";
import Link from "next/link";
import { FileText, Paperclip, History } from "lucide-react";
import {
  Banner, StatusBadge, downloadBytes, failureMessage, panel, primaryButton, secondaryButton,
} from "./LegalPortal";
import { ReportOpenAcknowledgement } from "./ReportOpenAcknowledgement";
import { FirmLoadProgress } from "./LoadProgress";
import type { FirmLoadStage } from "./LoadProgress";
import { RequestForm } from "./FirmRequests";
import {
  persistFirmWorkspace, recordRequestGranted, rememberedRequests, resolveCaseRequest,
} from "@/lib/confidential/firmPortal";
import type { RememberedRequest } from "@/lib/confidential/firmPortal";
import type { DeferredEvidence, FirmSession, OpenedCase, OpenedEvidence } from "@/lib/confidential/firmCase";
import { EvidenceDownloadButton } from "./EvidenceDownloadButton";
import { LegalPopupBlocked, LegalSignInRequired, legalAuthConfig, legalSignedIn, renewLegalSignIn } from "@/lib/confidential/legalAuth";
import { useParticipantLockHold } from "@/lib/confidential/participantLock";
import {
  accessEnd, caseDocument, firmTimeline, formatBytes, formatDate, formatDateTime, latestAccessEnd, refusedCaseStatus, scopeSentence,
  statusBadge,
} from "@/lib/confidential/firmCaseView";
import type { CaseDocument, DocumentField, FirmCaseStatus, TimelineEvent } from "@/lib/confidential/firmCaseView";
import { setupNextSteps } from "@/lib/confidential/firmSetup";
import type { FirmSetupRequirement } from "@/lib/confidential/firmSetup";

type View =
  | { state: "loading"; stage: FirmLoadStage }
  | { state: "no-request" }
  | { state: "update-pending" }
  | { state: "no-access"; status: FirmCaseStatus | null }
  /** The service refuses case reads until organization setup is recorded. */
  | { state: "setup-incomplete"; missing: readonly FirmSetupRequirement[] }
  | { state: "error"; message: string }
  | { state: "signed-out" }
  | { state: "ready"; opened: OpenedCase; saveWarning?: string };

export const REPORT_WORKSPACE_SAVE_FAILED = "The report is open, but the latest report history could not be saved on this device. Keep this workspace open and save a fresh backup before leaving.";

/** Saves the workspace after a report opened. A failed save is a warning next to
 * the open report, never an open failure: the report did open. */
export async function saveOpenedReport(persist: () => Promise<void>): Promise<string | null> {
  try { await persist(); return null; }
  catch { return REPORT_WORKSPACE_SAVE_FAILED; }
}

function Fields({ fields }: { fields: DocumentField[] }) {
  return (
    <dl className="grid gap-x-5 gap-y-3 sm:grid-cols-[minmax(0,9rem)_1fr]">
      {fields.map(item => (
        <div key={item.label} className="contents">
          <dt className="text-sm text-black/65">{item.label}</dt>
          <dd className="min-w-0 whitespace-pre-wrap break-words leading-7">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function DocumentSection({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} className="border-t border-black/10 pt-6">
      <h3 id={id} className="mb-3 text-base font-semibold text-[#243d2e]">{title}</h3>
      {children}
    </section>
  );
}

/** The decrypted report laid out as a document. Every value is rendered as text. */
export function ReportDocument({ summary, document, shared }: { summary: string | null; document: CaseDocument; shared: boolean }) {
  const empty = !document.account && !document.dates.length && !document.place.length && !document.about.length &&
    !document.other.length;
  return (
    <article id="report-details" className="scroll-mt-6 space-y-6 border border-black/10 bg-white p-5 sm:p-7" aria-labelledby="report-title">
      <header>
        <p className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-[#395944]">
          <FileText size={16} aria-hidden="true" />Shared by the reporter
        </p>
        <h2 id="report-title" className="font-serif text-2xl">Report details</h2>
      </header>
      {summary && (
        <DocumentSection id="summary-title" title="Public summary">
          <p className="max-w-[65ch] whitespace-pre-wrap break-words text-base leading-7">{summary}</p>
          <p className="mt-3 text-sm leading-relaxed text-black/60">Published by the reporter in the directory.</p>
        </DocumentSection>
      )}
      {!shared && <p className="text-sm text-black/60">The reporter has not shared the full report with your organization.</p>}
      {shared && empty && <p className="text-sm text-black/60">The shared report has no details filled in.</p>}
      {document.account && (
        <DocumentSection id="account-title" title="Reporter’s account">
          <p className="mb-3 text-sm text-black/60">Private details shared with your organization.</p>
          <p className="max-w-[65ch] whitespace-pre-wrap break-words text-base leading-7">{document.account}</p>
        </DocumentSection>
      )}
      {document.dates.length > 0 && <DocumentSection id="dates-title" title="Dates"><Fields fields={document.dates} /></DocumentSection>}
      {document.place.length > 0 && <DocumentSection id="place-title" title="Place"><Fields fields={document.place} /></DocumentSection>}
      {document.about.length > 0 && <DocumentSection id="about-title" title="About this report"><Fields fields={document.about} /></DocumentSection>}
      {document.other.length > 0 && <DocumentSection id="other-title" title="Other details"><Fields fields={document.other} /></DocumentSection>}
      {document.records.map((record, index) => (
        <DocumentSection key={record.title} id={`record-${index}-title`} title={record.title}>
          <Fields fields={record.fields} />
        </DocumentSection>
      ))}
    </article>
  );
}

const WORKSPACE_SAVE_FAILED = "The latest report history could not be saved on this device, so the file was not downloaded. Keep this workspace open, save a fresh backup and unlock the saved workspace again.";

/** Download one authorized file at a time; each click re-checks access and the
 * current report state. Files are saved, never opened in this page. */
function FileRow({ session, caseId, objectId, index, encryptedBytes, onDownloaded }: {
  session: FirmSession; caseId: string; objectId: string; index: number; encryptedBytes: number; onDownloaded: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<{ name: string; size: number } | null>(null);
  const generation = useRef(0);
  const pending = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; generation.current++; pending.current = false; };
  }, []);
  // Fetching and decrypting needs no input; the idle lock waits for it.
  useParticipantLockHold(busy);
  const download = async () => {
    if (!mounted.current || pending.current) return;
    pending.current = true;
    const operation = ++generation.current;
    const active = () => mounted.current && generation.current === operation;
    setBusy(true); setError(null);
    let item: OpenedEvidence | undefined;
    try {
      const { openFirmEvidence } = await import("@/lib/confidential/firmCase");
      if (!active()) return;
      item = await openFirmEvidence(session, caseId, objectId);
      if (!active()) return;
      // Persist the newly observed checkpoint before delivering the attachment.
      // A failed save must remain visible rather than silently weakening recovery.
      try { await persistFirmWorkspace(); }
      catch { throw new Error("workspace-save-failed"); }
      if (!active()) return;
      setSaved({ name: item.name, size: item.bytes.length });
      downloadBytes(item.bytes, item.name);
      onDownloaded();
    } catch (caught) {
      if (!active()) return;
      setError(caught instanceof Error && caught.message === "workspace-save-failed"
        ? WORKSPACE_SAVE_FAILED
        : failureMessage(caught, "This file could not be downloaded. Access may have ended or changed. Sign in again if needed."));
    } finally {
      item?.bytes.fill(0);
      if (active()) { pending.current = false; setBusy(false); }
    }
  };
  return (
    <li className="flex flex-col gap-2 border-t border-black/10 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="break-all">{saved ? saved.name : `File ${index + 1}`}</p>
        <p className="text-sm text-black/60">
          {saved ? `${formatBytes(saved.size)} · downloaded` : `About ${formatBytes(encryptedBytes)} encrypted · name shown after download`}
        </p>
        {error && <p role="alert" className="mt-1 text-sm text-red-800">{error}</p>}
      </div>
      <button type="button" className={`${secondaryButton} shrink-0 self-start sm:self-auto`} disabled={busy}
        onClick={() => void download()} aria-label={`Download ${saved ? saved.name : `file ${index + 1}`}`}>
        {busy ? "Decrypting…" : saved ? "Download again" : "Download"}
      </button>
    </li>
  );
}

const renewalFailure = (error: unknown, fallback: string) => error instanceof LegalPopupBlocked ? error.message : fallback;

/** A sign-in that expires mid-download is renewed in a separate window, so the
 * transfer, its file and the unlocked key stay on this page and it resumes. */
const DOWNLOAD_SIGN_IN = {
  required: (error: unknown) => error instanceof LegalSignInRequired,
  renew: () => {
    const config = legalAuthConfig();
    return config ? renewLegalSignIn(config) : Promise.reject(new LegalSignInRequired());
  },
  describeRenewalError: (error: unknown) =>
    renewalFailure(error, "Sign-in did not finish. Try again. The download stays paused until you do."),
};

/** A large file (chunked format): its name and size come from the reporter-signed
 * index, and it streams to disk in verified chunks with pause and resume. Every
 * start and resume re-checks access and the current report state, and saves the
 * newly observed report history before any bytes are written. */
function ChunkedFileRow({ session, caseId, item, onDownloaded }: {
  session: FirmSession; caseId: string; item: DeferredEvidence; onDownloaded: () => void;
}) {
  const name = item.name ?? "file";
  return (
    <li className="flex flex-col gap-2 border-t border-black/10 py-3">
      <div className="min-w-0">
        <p className="break-all">{name}</p>
        {item.size !== undefined && <p className="text-sm text-black/60">{formatBytes(item.size)}</p>}
      </div>
      <EvidenceDownloadButton name={name} size={item.size} buttonClassName={secondaryButton} onDone={onDownloaded}
        describeError={error => error instanceof Error && error.message === "workspace-save-failed" ? WORKSPACE_SAVE_FAILED
          : failureMessage(error, "This file could not be downloaded. Access may have ended or changed. Sign in again if needed.")}
        signIn={DOWNLOAD_SIGN_IN}
        open={async () => {
          const { openFirmChunkedEvidence } = await import("@/lib/confidential/firmCase");
          const opened = await openFirmChunkedEvidence(session, caseId, item.objectId);
          // A failed save must stay visible rather than weaken recovery.
          try { await persistFirmWorkspace(); }
          catch { opened.reader.dispose(); throw new Error("workspace-save-failed"); }
          return opened;
        }} />
    </li>
  );
}

export function Files({ session, caseId, opened }: { session: FirmSession; caseId: string; opened: OpenedCase }) {
  const [downloaded, setDownloaded] = useState(false);
  const granted = opened.scopes.includes("evidence");
  return (
    <section id="report-files" className="scroll-mt-6 border border-black/10 bg-white p-5 sm:p-7" aria-labelledby="files-title">
      <h2 id="files-title" className="mb-3 flex items-center gap-3 font-serif text-2xl"><Paperclip size={20} aria-hidden="true" />Files</h2>
      {!granted ? <p className="text-sm text-black/60">The reporter has not shared files with your organization.</p>
        : !opened.deferredEvidence.length ? <p className="text-sm text-black/60">The reporter has not added any files.</p> : <>
          <p className="mb-3 max-w-[62ch] text-sm text-black/60">
            Files are decrypted on this device and saved as downloads. They are never opened in this page. A large file can be
            paused and resumed. Check them with your organization&apos;s usual malware and handling procedures before opening.
          </p>
          <ul>
            {opened.deferredEvidence.map((item, index) => item.chunked
              ? <ChunkedFileRow key={item.objectId} session={session} caseId={caseId} item={item} onDownloaded={() => setDownloaded(true)} />
              : <FileRow key={item.objectId} session={session} caseId={caseId} objectId={item.objectId} index={index}
                encryptedBytes={item.encryptedBytes} onDownloaded={() => setDownloaded(true)} />)}
          </ul>
          {downloaded && (
            <p role="status" className="mt-3 text-sm text-black/60">
              Downloaded files stay on your device under your organization&apos;s retention obligations, even if access ends.
            </p>
          )}
        </>}
    </section>
  );
}

export function Timeline({ events }: { events: TimelineEvent[] }) {
  return (
    <section id="report-activity" className="scroll-mt-6 border border-black/10 bg-white p-5 sm:p-7" aria-labelledby="timeline-title">
      <h2 id="timeline-title" className="mb-3 flex items-center gap-3 font-serif text-2xl"><History size={20} aria-hidden="true" />Activity</h2>
      <p className="mb-4 text-sm text-black/60">What your organization can see: your request, the access the reporter allowed.</p>
      {!events.length ? <p className="text-sm text-black/60">No activity yet.</p> : (
        <ol className="border-l border-black/20 pl-5">
          {events.map((event, index) => (
            <li key={`${event.kind}-${event.at}-${index}`} className="relative pb-4 last:pb-0">
              <span aria-hidden className={`absolute -left-[1.6rem] top-1.5 h-2.5 w-2.5 border border-black ${event.upcoming ? "bg-white" : "bg-black"}`} />
              <p className="text-sm text-black/60">
                {event.upcoming ? "Scheduled: " : ""}<time dateTime={new Date(event.at).toISOString()}>
                  {event.kind === "access-ends" ? formatDate(event.at) : formatDateTime(event.at)}
                </time>
              </p>
              <p>{event.title}</p>
              {event.detail && <p className="text-sm text-black/60">{event.detail}</p>}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/** A structured renewal request for this report: the reporter can approve it
 * with a new end date, replacing the current access. */
function RenewalRequest({ session, caseId, remembered }: { session: FirmSession; caseId: string; remembered: RememberedRequest | null }) {
  const [asking, setAsking] = useState(false);
  const [sent, setSent] = useState(false);
  const owner = session.owners.get(caseId);
  if (!remembered || !owner) return null;
  if (sent) return <p role="status" className="mt-2">Renewal request sent. The reporter decides; you will see the outcome under Your organization&apos;s requests on the portal page.</p>;
  if (!asking) return <button type="button" className={`mt-2 ${secondaryButton}`} onClick={() => setAsking(true)}>Ask to renew</button>;
  // "Sent" only once delivery is confirmed; a failure stays in the open form as an alert.
  return (
    <RequestForm session={session} kind="renewal" listing={{ caseId, summary: remembered.summary, owner }}
      onCancel={() => setAsking(false)} onOutcome={outcome => { if (outcome.ok) { setAsking(false); setSent(true); } }} />
  );
}

export function AccessBanner({ session, caseId, remembered, opened }: {
  session: FirmSession; caseId: string; remembered: RememberedRequest | null;
  opened: OpenedCase;
}) {
  // All current grants together: access ends only when the last one does.
  const end = accessEnd(latestAccessEnd(opened.grants), trustedNow());
  const shared = `The reporter shared ${scopeSentence(opened.scopes)}.`;
  if (end.kind === "open-ended") {
    return <p className="border-l-2 border-[#7e9976] bg-[#f1f5ee] px-5 py-4 text-sm leading-relaxed text-[#344e3d]">{shared} Access lasts until the reporter revokes it.</p>;
  }
  if (!end.endingSoon) {
    return <p className="border-l-2 border-[#7e9976] bg-[#f1f5ee] px-5 py-4 text-sm leading-relaxed text-[#344e3d]">{shared} Access ends {formatDate(end.at)} unless the reporter renews it.</p>;
  }
  return (
    <Banner tone="attention" title={end.daysLeft <= 1 ? "Access ends within a day" : `Access ends in ${end.daysLeft} days`}>
      <p>
        {shared} Access ends {formatDate(end.at)}. After that your organization cannot open the report or download files
        unless the reporter renews access.
      </p>
      <RenewalRequest session={session} caseId={caseId} remembered={remembered} />
    </Banner>
  );
}

export function CaseView({ session, caseId }: { session: FirmSession; caseId: string }) {
  const [view, setView] = useState<View>({ state: "loading", stage: "verifying" });
  const heading = useRef<HTMLDivElement | null>(null);
  // Held in state and refreshed by load(): the request may only become known once the shared list loads.
  const [remembered, setRemembered] = useState<RememberedRequest | null>(() =>
    rememberedRequests(session.firm.organizationId).find(item => item.caseId === caseId) ?? null);

  const loadGeneration = useRef(0);
  const load = useCallback(async () => {
    // Progress from this load only, and only until it settles: a later stage
    // report must never replace a result or error with the loading screen.
    const generation = ++loadGeneration.current;
    let settled = false;
    const active = () => generation === loadGeneration.current;
    const publish = (next: View) => { if (active()) setView(next); };
    publish({ state: "loading", stage: "verifying" });
    // What this device knows now (never a previous case's request); replaced once the shared list is checked.
    let request = rememberedRequests(session.firm.organizationId).find(item => item.caseId === caseId) ?? null;
    setRemembered(request);
    let opened: OpenedCase;
    try {
      // Another member may have sent the request: the organization's shared list names the reporter's key.
      const resolved = await resolveCaseRequest(session, caseId);
      if (!active()) return;
      request = resolved.request;
      setRemembered(request);
      if (!resolved.pinned) { publish({ state: "no-request" }); return; }
      const { openFirmCase } = await import("@/lib/confidential/firmCase");
      opened = await openFirmCase(session, caseId, Date.now(), { deferEvidence: true,
        onProgress: stage => { if (!settled && active()) publish({ state: "loading", stage }); } });
      settled = true;
      publish({ state: "ready", opened });
    } catch (caught) {
      settled = true;
      if (!active()) return;
      const { FirmCaseError, readRequestStatus } = await import("@/lib/confidential/firmCase");
      if (caught instanceof LegalSignInRequired) { publish({ state: "signed-out" }); return; }
      if (caught instanceof FirmCaseError && caught.code === "release-not-approved") { publish({ state: "update-pending" }); return; }
      if (caught instanceof FirmCaseError && caught.code === "setup-incomplete") { publish({ state: "setup-incomplete", missing: caught.missing }); return; }
      if (caught instanceof FirmCaseError && caught.code === "not-granted") {
        let status: FirmCaseStatus | null = null;
        if (request) {
          // A locked report answers `unknown` access; the refusal itself says there is none now.
          try { status = refusedCaseStatus(await readRequestStatus(session, caseId, request.requestId, Date.now()), session.pins.has(caseId)); }
          catch { status = null; }
        }
        publish({ state: "no-access", status });
        return;
      }
      publish({ state: "error", message: failureMessage(caught,
        "This report could not be opened. The secure connection may be unavailable, or the service could not prove it is the approved version. Try again in a moment.") });
      return;
    }
    // The report is open: what follows must never replace it with an open failure.
    if (!active()) return;
    const saveWarning = await saveOpenedReport(persistFirmWorkspace);
    if (saveWarning && active()) setView(current => current.state === "ready" && current.opened === opened ? { ...current, saveWarning } : current);
    // Every member sees that the reporter allowed access. Best effort: the report is already open.
    if (active()) await recordRequestGranted(caseId, opened.grantExpiresAt).catch(() => {});
  }, [session, caseId]);
  useEffect(() => { void load(); return () => { loadGeneration.current++; }; }, [load]);
  // The sign-in expired while opening: reopen once it is renewed, here or in the portal's own prompt.
  // Only a change from signed out to signed in reloads, so a sign-in the service rejects never loops.
  const [renewing, setRenewing] = useState(false), [renewalError, setRenewalError] = useState("");
  useEffect(() => {
    if (view.state !== "signed-out") { setRenewing(false); setRenewalError(""); return; }
    let signedIn = legalSignedIn();
    const timer = setInterval(() => {
      const now = legalSignedIn();
      if (now && !signedIn) void load();
      signedIn = now;
    }, 1000);
    return () => clearInterval(timer);
  }, [view.state, load]);
  const renew = () => {
    setRenewing(true); setRenewalError("");
    // Opened straight from this click so the browser allows the window.
    DOWNLOAD_SIGN_IN.renew().then(() => load(), error => {
      setRenewing(false);
      setRenewalError(renewalFailure(error, "Sign-in did not finish. Try again."));
    });
  };
  // Move focus to the result so screen reader and keyboard users land on it.
  useEffect(() => { if (view.state !== "loading") heading.current?.focus(); }, [view.state]);

  const back = <Link className="underline" href="/legal">Back to the portal</Link>;
  const summary = remembered ? <p className="mb-4 whitespace-pre-wrap break-words text-black/80">{remembered.summary}</p> : null;
  let body: ReactNode;
  if (view.state === "loading") {
    body = <FirmLoadProgress stage={view.stage} className={panel} />;
  } else if (view.state === "no-request") {
    body = <div className={panel}>
      <p className="mb-4">This workspace has not verified the report check code. Return to the portal and check for updates. Reports with confirmed access appear under Shared with you. For other reports, compare the report check code if the reporter contacted you, then request access from its public summary.</p>
      {back}
    </div>;
  } else if (view.state === "update-pending") {
    body = <div className="space-y-4">
      {summary}
      <Banner tone="attention" title="Waiting for the reporter to approve an update">
        <p>
          VERA updated its secure service. Each reporter approves new versions for their own report, and this report stays
          closed until they do. Ask the reporter to open their report status page with their recovery key and choose
          “Approve update”. Current access will be checked after they approve the update.
        </p>
      </Banner>
      <div className="flex flex-wrap items-center gap-4">
        <button type="button" className={secondaryButton} onClick={() => void load()}>Check again</button>
        {back}
      </div>
    </div>;
  } else if (view.state === "no-access") {
    const badge = view.status ? statusBadge(view.status, trustedNow()) : null;
    body = <div className="space-y-4">
      {summary}
      <Banner tone={view.status?.kind === "waiting" ? "neutral" : "negative"} title="Your organization does not have access to this report">
        {badge
          ? <><p className="mb-2"><StatusBadge label={badge.label} tone={badge.tone} /></p><p>{badge.description}</p></>
          : <p>The reporter has not allowed access, or access has ended.</p>}
        {view.status?.kind === "ended" && <RenewalRequest session={session} caseId={caseId} remembered={remembered} />}
      </Banner>
      <div className="flex flex-wrap items-center gap-4">
        <button type="button" className={secondaryButton} onClick={() => void load()}>Check again</button>
        {back}
      </div>
    </div>;
  } else if (view.state === "signed-out") {
    body = <div className={panel} role="status">
      <p className="mb-4">Your sign-in has expired. Sign in again to open this report. It opens here as soon as you do.</p>
      <div className="flex flex-wrap items-center gap-4">
        <button type="button" className={primaryButton} disabled={renewing} onClick={renew}>
          {renewing ? "Waiting for sign-in…" : "Sign in again"}
        </button>
        {back}
      </div>
      {renewalError && <p role="alert" className="mt-2 text-sm">{renewalError}</p>}
    </div>;
  } else if (view.state === "setup-incomplete") {
    body = <div className="space-y-4">
      {summary}
      <Banner tone="attention" title="Finish organization setup to open reports">
        <p>VERA does not open reports for your organization until its setup is recorded. Nothing about this report changed.</p>
        <ul className="mt-2 list-inside list-disc">
          {setupNextSteps(view.missing).map(item => <li key={item.id}><span className="font-semibold">{item.title}.</span> {item.action}</li>)}
        </ul>
      </Banner>
      <div className="flex flex-wrap items-center gap-4">
        <Link className={secondaryButton} href="/legal">Go to organization setup</Link>
        <button type="button" className="underline" onClick={() => void load()}>Check again</button>
      </div>
    </div>;
  } else if (view.state === "error") {
    body = <div className={panel} role="alert">
      <p className="mb-4">{view.message}</p>
      <div className="flex flex-wrap items-center gap-4">
        <button type="button" className={secondaryButton} onClick={() => void load()}>Try again</button>
        {back}
      </div>
    </div>;
  } else {
    const { opened } = view;
    const document = caseDocument(opened.narrative, opened.records);
    const events = firmTimeline({ requestedAt: remembered?.requestedAt ?? null, grants: opened.grants,
      releaseApprovedAt: opened.releaseApprovedAt, messages: [], now: trustedNow() });
    body = <div className="space-y-6">
      {view.saveWarning && <Banner tone="attention" title="Report history not saved on this device"><p>{view.saveWarning}</p></Banner>}
      <AccessBanner session={session} caseId={caseId} remembered={remembered} opened={opened} />
      <nav aria-label="In this report" className="flex flex-wrap gap-x-6 gap-y-2 text-sm font-semibold text-[#395944] [&_a]:inline-flex [&_a]:min-h-11 [&_a]:items-center [&_a]:gap-2 [&_a]:underline [&_a]:underline-offset-4">
        <a href="#report-details"><FileText size={16} aria-hidden="true" />Report details</a>
        <a href="#report-files"><Paperclip size={16} aria-hidden="true" />Files</a>
        <a href="#report-activity"><History size={16} aria-hidden="true" />Activity</a>
      </nav>
      <div className="space-y-6">
        <ReportDocument summary={remembered?.summary ?? null} document={document} shared={opened.scopes.includes("narrative")} />
        <ReportOpenAcknowledgement session={session} opened={opened} />
      </div>
      <div className="grid items-start gap-6 xl:grid-cols-2">
        <Files session={session} caseId={caseId} opened={opened} />
        <Timeline events={events} />
      </div>
      <p className="text-sm text-black/60">
        Decrypted on this device only. Anything you download or copy stays under your organization&apos;s obligations,
        even after access ends. {back}
      </p>
    </div>;
  }
  return <div ref={heading} tabIndex={-1} className="outline-none">{body}</div>;
}

