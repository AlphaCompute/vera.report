import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  EVIDENCE_COMMIT_UNCONFIRMED, REFRESH_FAILED_TEXT, checkFailedNotice, completedChangeNotice, evidenceAddLabel, evidenceAfterCommit,
  evidenceCanReselect, keepsReportOnRefreshFailure,
} from '../../../lib/confidential/ownerActionOutcome';
import { OWNER_FAILURE_COPY, type OwnerFailure } from '../../../lib/confidential/failureCopy';
import { EvidenceStaleError } from '../../../lib/confidential/ownerCase';

const status = readFileSync(join(__dirname, '../../../components/vera/confidential/ConfidentialCaseStatus.tsx'), 'utf8');

describe('a change that applied is never hidden by a failed refresh', () => {
  test('availability failures keep the open report; untrusted-service failures still replace it', () => {
    for (const reason of ['offline', 'unavailable', 'busy', 'clock', 'refused'] as OwnerFailure[]) {
      expect(keepsReportOnRefreshFailure(reason)).toBe(true);
    }
    expect(keepsReportOnRefreshFailure('verification')).toBe(false);
    expect(keepsReportOnRefreshFailure('rollback')).toBe(false);
  });

  test('the confirmation stays, with a line saying the page could not be refreshed', () => {
    const done = 'Acme Law can now open what you chose.';
    expect(completedChangeNotice(done, null)).toBe(done);
    expect(completedChangeNotice(done, 'unavailable')).toBe(`${done} ${REFRESH_FAILED_TEXT}`);
    // A message send has no confirmation of its own, but a failed refresh must still say it was saved.
    expect(completedChangeNotice(undefined, null)).toBeNull();
    expect(completedChangeNotice(undefined, 'offline')).toContain('Your change was saved.');
    expect(completedChangeNotice(undefined, 'offline')).toContain('Check for updates before making the same change again');
  });

  test('a failed "Check for updates" says so without removing the report', () => {
    expect(checkFailedNotice('busy')).toContain('Could not check for updates.');
    expect(checkFailedNotice('busy')).toContain(OWNER_FAILURE_COPY.busy.action);
  });

  test('act refreshes with keepView and reports the change even when the refresh fails', () => {
    const act = status.slice(status.indexOf('const act = async'), status.indexOf('const actionProgress'));
    expect(act).toContain('const refreshed = await load(true, viewState.current === "ready");');
    expect(act).toContain('completedChangeNotice(done, refreshed.kind === "failed" ? refreshed.reason : null)');
    // After the work succeeds, only closing the report stops the confirmation.
    const afterWork = act.slice(act.indexOf('const done = await work'));
    expect(afterWork.slice(0, afterWork.indexOf('setActionStage("refreshing")'))).not.toContain('if (!active()) return false;');
    expect(act).not.toMatch(/await load\(true\);/);
  });

  test('load leaves the current view in place on a kept failure, and the error views show the notice', () => {
    expect(status).toContain('if (keepView && keepsReportOnRefreshFailure(reason)) return { kind: "failed", reason };');
    const errorView = status.slice(status.indexOf('if (view.state === "error") {'), status.indexOf('if (view.state === "paused") {'));
    expect(errorView).toContain('{noticeLine');
    const pausedView = status.slice(status.indexOf('if (view.state === "paused") {'), status.indexOf('if (view.state === "needs-approval") {'));
    expect(pausedView).toContain('{noticeLine');
  });
});

describe('adding evidence when the commit is not confirmed', () => {
  test('false from onCommit keeps the uploaded files for "Finish adding files"', () => {
    expect(evidenceAfterCommit(true)).toEqual({ kind: 'choose' });
    expect(evidenceAfterCommit(false)).toEqual({ kind: 'paused', uploaded: true, message: EVIDENCE_COMMIT_UNCONFIRMED });
  });

  test('EvidencePanel reads the commit result before discarding the prepared files', () => {
    const panel = status.slice(status.indexOf('function EvidencePanel('));
    expect(panel).toContain('const committed = await onCommit(prepared.current);');
    const afterCommit = panel.slice(panel.indexOf('const committed = await onCommit'));
    expect(afterCommit.indexOf('if (next.kind === "paused") { setPhase(next); return; }'))
      .toBeLessThan(afterCommit.indexOf('discard();'));
    expect(panel).not.toMatch(/\n\s*await onCommit\(/);
  });
});

describe('adding evidence that organizations with access to later files should receive', () => {
  test('file actions need no website consent', () => {
    expect(evidenceAddLabel('add')).toBe('Encrypt and add');
    expect(evidenceAddLabel('finish')).toBe('Finish adding files');
    expect(evidenceAddLabel('resume')).toBe('Resume upload');
  });

  test('a report that changed during upload names the button that is on screen, not "choose the files again"', () => {
    // EvidencePanel discards only the prepared encryption and keeps the chosen
    // files, so the list stays and the button reads "Encrypt and add".
    const message = new EvidenceStaleError().message;
    expect(message).toBe('Your report changed while the files were uploading. Choose Encrypt and add to try again.');
    expect(message).not.toMatch(/choose the files again/i);
    expect(message).toContain(evidenceAddLabel('add'));
    const panel = status.slice(status.indexOf('function EvidencePanel('));
    const stale = panel.slice(panel.indexOf('error instanceof owner.EvidenceStaleError) {'));
    expect(stale.slice(0, stale.indexOf('} else if'))).toMatch(/discard\(\);/);
    expect(stale.slice(0, stale.indexOf('} else if'))).not.toContain('setFiles([])');
  });

  test('Change files/Clear stay available when paused without prepared evidence', () => {
    expect(evidenceCanReselect('choose', false)).toBe(true);
    expect(evidenceCanReselect('choose', true)).toBe(true);
    expect(evidenceCanReselect('paused', false)).toBe(true);
    expect(evidenceCanReselect('paused', true)).toBe(false);
    expect(evidenceCanReselect('encrypting', false)).toBe(false);
    expect(evidenceCanReselect('uploading', false)).toBe(false);
    expect(evidenceCanReselect('committing', false)).toBe(false);
    const panel = status.slice(status.indexOf('function EvidencePanel('));
    expect(panel).toContain('evidenceCanReselect(phase.kind, prepared.current !== null)');
    expect(panel).toContain('Change files');
    expect(panel).toContain('clearFiles');
  });
});

describe('leaving an open report without locking every tab', () => {
  test('the ready view has a "Leave for now" button next to "Check for updates" that closes this tab only', () => {
    const ready = status.slice(status.indexOf('const { inbox, grantees, evidence } = view;'));
    const checkAt = ready.indexOf("'Check for updates'");
    const closeAt = ready.indexOf('onClick={close}>Leave for now</button>');
    expect(checkAt).toBeGreaterThan(-1);
    expect(closeAt).toBeGreaterThan(checkAt);
    // Same group of controls, before anything else in the report.
    expect(ready.slice(checkAt, closeAt)).not.toContain('{actionProgress}');
    // close() leaves the report in this tab; it never broadcasts the all-tabs manual lock.
    const closeStart = status.indexOf('const close = () => {');
    const closeEnd = status.indexOf('const panel = ', closeStart);
    expect(closeStart).toBeGreaterThan(-1);
    expect(closeEnd).toBeGreaterThan(closeStart);
    const close = status.slice(closeStart, closeEnd);
    expect(close).toContain('onClose();');
    expect(close).not.toMatch(/lockParticipantTabs|PARTICIPANT_LOCK/);
  });
});
