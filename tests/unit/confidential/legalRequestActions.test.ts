import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  REMOVE_FAILED, WITHDRAW_UNCONFIRMED, canRetryRequestAction, removeFailureMessage, withRequestActionFailure,
} from '../../../lib/confidential/requestSubmission';
import type { RequestActionFailure } from '../../../lib/confidential/requestSubmission';

/** Withdraw and remove failures in the legal portal stay on the request entry
 * they concern, retry that action, and never share the directory's error. */
const page = readFileSync(path.join(__dirname, '../../../pages/legal/index.tsx'), 'utf8');
const section = (start: string, end: string) => page.slice(page.indexOf(start), page.indexOf(end, page.indexOf(start)));

describe('request action failures (per report)', () => {
  const withdraw: RequestActionFailure = { action: 'withdraw', message: WITHDRAW_UNCONFIRMED };
  const remove: RequestActionFailure = { action: 'remove', message: REMOVE_FAILED };

  test('are recorded and cleared per report without touching the others', () => {
    const one = withRequestActionFailure(new Map(), 'A', withdraw);
    const two = withRequestActionFailure(one, 'B', remove);
    expect([...two]).toEqual([['A', withdraw], ['B', remove]]);
    const cleared = withRequestActionFailure(two, 'A', null);
    expect([...cleared]).toEqual([['B', remove]]);
    expect(one.size).toBe(1); // the input map is never mutated
  });

  test('a withdrawal is retried only while the request is still confirmed as waiting', () => {
    expect(canRetryRequestAction(withdraw, 'waiting')).toBe(true);
    for (const kind of [undefined, 'checking', 'error', 'withdrawn', 'granted']) expect(canRetryRequestAction(withdraw, kind)).toBe(false);
    expect(canRetryRequestAction(remove, undefined)).toBe(true);
  });

  test('remove failures keep the list-full explanation and otherwise use the generic message', () => {
    expect(removeFailureMessage(new Error('Your organization request list is full.'))).toBe('Your organization request list is full.');
    expect(removeFailureMessage(new Error('boom 500 internal'))).toBe(REMOVE_FAILED);
  });
});

describe('legal portal requests list wiring', () => {
  const directory = section('function RequestsAndDirectory', 'export default function');
  const withdrawFn = section('const withdraw = async', 'const forget = async');
  const forgetFn = section('const forget = async', 'const outcomeIn');

  test('withdraw and remove never write the directory error', () => {
    for (const fn of [withdrawFn, forgetFn]) {
      expect(fn).not.toMatch(/setDirectoryError|setError/);
      expect(fn).toMatch(/setActionFailure\(request\.caseId, \{ action: "(withdraw|remove)"/);
    }
    // The directory alert's "Try again" reloads the directory and shows only its own error.
    expect(directory).toMatch(/\{directoryError && \(\s*<div role="alert"[^]*?<p>\{directoryError\}<\/p>[^]*?onClick=\{\(\) => void load\(\)\}>Try again/);
  });

  test('a failed withdrawal re-checks the status so a retry is offered only if it is still waiting', () => {
    expect(withdrawFn).toMatch(/catch \{[^}]*WITHDRAW_UNCONFIRMED[^]*?recheck\(request\.caseId\);\s*return;/);
  });

  test('failures render on the request entry with a retry of that action', () => {
    const requests = section('function YourRequests', 'function ReplacedKeyRequest');
    expect(requests).toMatch(/<ActionFailure failure=\{actionFailures\.get\(item\.caseId\)\}[^]*?onRetry=\{\(\) => void \(actionFailures\.get\(item\.caseId\)\?\.action === "remove" \? onForget\(item\) : onWithdraw\(item\)\)\}/);
    const replaced = section('function ReplacedKeyRequest', 'function FirmSetup');
    expect(replaced).toMatch(/<ActionFailure failure=\{actionFailure\}[^]*?onRetry=\{\(\) => void onForget\(item\)\}/);
    expect(directory).toMatch(/actionFailures=\{actionFailures\} pending=\{pending\}/);
  });

  test('withdrawing and removing show progress and disable the other controls', () => {
    const requests = section('function YourRequests', 'function ReplacedKeyRequest');
    expect(requests).toMatch(/withdrawingThis \? <span role="status">Withdrawing…<\/span>/);
    expect(requests).toMatch(/removingThis \? <span role="status">Removing…<\/span>/);
    expect(requests).toMatch(/disabled=\{pending !== null\} onClick=\{\(\) => \{ setConfirming\(null\); void onWithdraw\(item\); \}\}>Yes, withdraw/);
    expect(requests).toMatch(/disabled=\{pending !== null\} onClick=\{\(\) => setConfirming\(item\.caseId\)\}>Withdraw request/);
    expect(withdrawFn).toMatch(/if \(pending\) return;/);
    expect(forgetFn).toMatch(/if \(pending\) return;/);
  });

  test('background discovery exposes loading and retries without rendering an available-report directory', () => {
    expect(directory).toMatch(/loading && <p role="status">Checking for shared reports/);
    expect(directory).not.toMatch(/AvailableLane|No published reports|!loading && !directoryError && !listings\.length/);
  });
});
