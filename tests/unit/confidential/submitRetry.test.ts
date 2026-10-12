import { readFileSync } from 'node:fs';
import path from 'node:path';
import { keepPreparedSubmission, SAME_REPORT_RETRY_NOTE, SUBMIT_FAILED_MESSAGE, submitFailureMessage } from '../../../lib/confidential/submitRetry';
import { EvidenceTooLargeError } from '../../../enclave/src/confidential/caseChunks';

const report = readFileSync(path.resolve(__dirname, '../../../pages/report.tsx'), 'utf8');
const base = { mayHavePublished: false, evidenceChanged: false, releasePaused: false, reason: null };

describe('prepared confidential report after a failed submit', () => {
  test.each(['offline', 'unavailable', 'busy', 'verification', 'clock', 'refused', null])(
    'is always kept once the publish request may have been sent (%s)', reason => {
      expect(keepPreparedSubmission({ ...base, mayHavePublished: true, reason })).toBe(true);
      expect(keepPreparedSubmission({ ...base, mayHavePublished: true, reason, releasePaused: true })).toBe(true);
      expect(keepPreparedSubmission({ ...base, mayHavePublished: true, reason, evidenceChanged: true })).toBe(true);
    });

  test.each(['offline', 'unavailable', 'busy', null])('is kept for a %s failure before sending', reason => {
    expect(keepPreparedSubmission({ ...base, reason })).toBe(true);
  });

  test('is discarded only for failures before sending that a retry of the same report cannot fix', () => {
    expect(keepPreparedSubmission({ ...base, reason: 'verification' })).toBe(false);
    expect(keepPreparedSubmission({ ...base, reason: 'clock' })).toBe(false);
    expect(keepPreparedSubmission({ ...base, evidenceChanged: true })).toBe(false);
    expect(keepPreparedSubmission({ ...base, releasePaused: true })).toBe(false);
  });

  test('the note says trying again finishes the same report', () => {
    expect(SAME_REPORT_RETRY_NOTE).toMatch(/finishes this same report/);
    expect(SAME_REPORT_RETRY_NOTE).toMatch(/does not create a second one/);
  });
});

describe('report page submit failure handling', () => {
  const start = report.indexOf('const handleConfidentialConfirm');
  const handler = report.slice(start, report.indexOf('// Confirm', start));

  test('records when the publish request may have been sent', () => {
    expect(handler).toMatch(/onPublishSending: \(\) => \{ attempt\.mayHavePublished = true; \}/);
    expect(handler).toContain('mayHavePublished: false }');
  });

  test('keeps the prepared report unless the failure policy says it can be discarded', () => {
    const failure = handler.slice(handler.indexOf('} catch (error) {'), handler.indexOf('} finally {'));
    // The only discard in the failure path is guarded by the policy.
    expect(failure.match(/discardPendingConfidential\(\)/g)).toHaveLength(1);
    expect(failure).toMatch(/if \(!sameReport\) discardPendingConfidential\(\);/);
    expect(failure).toMatch(/keepPreparedSubmission\(\{ mayHavePublished: pending\.mayHavePublished/);
    // An ambiguous failure never claims the report was not sent.
    expect(failure).toMatch(/sameReport \? 'We could not confirm your report was received\./);
  });

  test('a changed review still starts a new report; an unchanged one retries the same one', () => {
    expect(handler).toMatch(/if \(pending && !resuming\) discardPendingConfidential\(\);/);
    expect(handler).toMatch(/let current = resuming \? pendingConfidential\.current! : null;/);
  });

  test('the failure note shows the same-report sentence when the report is kept', () => {
    expect(report).toMatch(/\{confidentialFailure\.sameReport && <p\b[^>]*>\{SAME_REPORT_RETRY_NOTE\}<\/p>\}/);
  });
});

describe('failed confidential submit toast', () => {
  test.each(['Invalid recovery secret', 'Release identity mismatch', 'Unable to prepare confidential submission',
    'Error: Misformed armored text'])('never shows an internal error message (%s)', message => {
    expect(submitFailureMessage(new Error(message), false)).toBe(SUBMIT_FAILED_MESSAGE);
  });

  test('the fixed message says nothing was sent, the report is kept and what to do next', () => {
    expect(SUBMIT_FAILED_MESSAGE).toBe('Your report was not sent. It is still here. Try again; if it keeps failing, try later.');
    expect(submitFailureMessage('not an error', false)).toBe(SUBMIT_FAILED_MESSAGE);
    expect(submitFailureMessage(undefined, true)).toBe(SUBMIT_FAILED_MESSAGE);
  });

  test('shows messages written for the reporter when the caller classified them', () => {
    expect(submitFailureMessage(new EvidenceTooLargeError('Files must total 256 MB or less.'), true))
      .toBe('Files must total 256 MB or less.');
    // Even a classified error falls back when its text is not plain guidance.
    expect(submitFailureMessage(new EvidenceTooLargeError('{"file":"C:\\\\x"} is larger than 256 MB.'), true))
      .toBe(SUBMIT_FAILED_MESSAGE);
  });

  test('the report page routes unclassified errors through the fixed message, never error.message', () => {
    const start = report.indexOf('const handleConfidentialConfirm');
    const handler = report.slice(start, report.indexOf('// Confirm', start));
    const failure = handler.slice(handler.indexOf('} catch (error) {'), handler.indexOf('} finally {'));
    expect(failure).not.toMatch(/\? error\.message\s*:/);
    expect(failure).toMatch(/submitFailureMessage\(error, \(!!chunks && error instanceof chunks\.EvidenceTooLargeError\)/);
    expect(failure).toMatch(/client\.isReleasePaused\(error\)/);
  });
});
