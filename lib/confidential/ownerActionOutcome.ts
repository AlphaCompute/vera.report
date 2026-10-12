import { OWNER_FAILURE_COPY, type OwnerFailure } from './failureCopy';

/** What a report load did: its result is on screen (`shown`), a newer load or a
 * close replaced it (`superseded`), or it failed and, because the caller asked to
 * keep the current view, left that view in place (`failed`). */
export type OwnerLoadOutcome = { kind: 'shown' } | { kind: 'superseded' } | { kind: 'failed'; reason: OwnerFailure };

/** After a change the service confirmed, a failed refresh must not hide that
 * confirmation behind a full-page error: the reporter could then repeat the change
 * (send a message twice, allow access again). The open report stays on screen with
 * the confirmation and a "could not refresh" line. Failures that mean the service
 * or its history cannot be trusted (`danger`: verification, rollback) still replace
 * the report, so nothing more is shared from a view that may be false; the
 * confirmation is shown above that error instead. */
export function keepsReportOnRefreshFailure(reason: OwnerFailure): boolean {
  return OWNER_FAILURE_COPY[reason].severity !== 'danger';
}

export const REFRESH_FAILED_TEXT = 'This page could not be refreshed, so it may still show the earlier state. ' +
  'Choose Check for updates before making the same change again.';

/** The notice after a change the service confirmed. `done` is the change's own
 * confirmation (a message send has none); `refreshFailure` is set when the
 * refresh after it did not complete. */
export function completedChangeNotice(done: string | void, refreshFailure: OwnerFailure | null): string | null {
  if (!refreshFailure) return done || null;
  return `${done || 'Your change was saved.'} ${REFRESH_FAILED_TEXT}`;
}

/** Shown when "Check for updates" fails; the open report stays on screen. */
export function checkFailedNotice(reason: OwnerFailure): string {
  return `Could not check for updates. This page may not show the newest state of your report. ${OWNER_FAILURE_COPY[reason].action}`;
}

export const EVIDENCE_COMMIT_UNCONFIRMED = 'Your files are uploaded, but adding them to your report was not confirmed. ' +
  'Check for updates: if they are not listed under Your files, choose Finish adding files.';

/** The add-evidence step after the commit call returned. `false` means the change
 * was not confirmed (another refresh started, or the report closed), so the
 * prepared, uploaded files are kept for "Finish adding files" instead of being
 * discarded as if they had been added. */
export function evidenceAfterCommit(committed: boolean):
  { kind: 'choose' } | { kind: 'paused'; uploaded: true; message: string } {
  return committed ? { kind: 'choose' } : { kind: 'paused', uploaded: true, message: EVIDENCE_COMMIT_UNCONFIRMED };
}

export function evidenceAddLabel(step: 'add' | 'resume' | 'finish'): string {
  return { add: 'Encrypt and add', resume: 'Resume upload', finish: 'Finish adding files' }[step];
}

/** Whether Change files/Clear may be shown for the current add-evidence step.
 * Hidden while encrypting, uploading, or committing. Shown in choose, and when
 * paused after prepared work was discarded (changed/stale evidence or a prepare
 * failure), so the reporter can remove or replace the selection without reloading.
 * When prepared work is still held for resume/finish, Cancel is the safe reset. */
export function evidenceCanReselect(
  phase: 'choose' | 'encrypting' | 'uploading' | 'paused' | 'committing',
  hasPrepared: boolean,
): boolean {
  if (phase === 'encrypting' || phase === 'uploading' || phase === 'committing') return false;
  return phase === 'choose' || !hasPrepared;
}
