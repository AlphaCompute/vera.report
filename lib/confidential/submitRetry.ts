import { userFacingMessage } from './userFacingError';

/** What to do with a prepared (encrypted and signed) confidential submission
 * after a submit attempt fails.
 *
 * Once the publish request may have left this device, the service may already
 * have created the report even though no reply arrived. Discarding the prepared
 * submission then would lose the only copy of that report's recovery code, and
 * the next Submit would create a second report. The service accepts an exact
 * retry of the same first checkpoint idempotently, so the same prepared
 * submission is kept and Submit finishes it.
 *
 * It is discarded only when the failure certainly happened before the publish
 * request could be sent and retrying the same prepared submission cannot help:
 * a file changed after it was encrypted, the approved release was paused, or the
 * service could not be verified (or this device's clock is wrong) before sending.
 * Other failures before sending (offline, busy, unavailable, unknown) keep it:
 * retrying the same submission is harmless and avoids encrypting again. */
export type SubmitFailure = {
  /** The publish request may have been sent in this attempt or an earlier one. */
  mayHavePublished: boolean;
  /** A selected file changed after it was encrypted. */
  evidenceChanged: boolean;
  /** The approved release is paused or its status could not be confirmed. */
  releasePaused: boolean;
  /** `ConfidentialUnavailableError.reason`, when the failure was one. */
  reason: string | null;
};

export function keepPreparedSubmission(failure: SubmitFailure): boolean {
  if (failure.mayHavePublished) return true;
  if (failure.evidenceChanged || failure.releasePaused) return false;
  return failure.reason !== 'verification' && failure.reason !== 'clock';
}

/** Shown with a failure whenever the prepared submission is kept. */
export const SAME_REPORT_RETRY_NOTE =
  'Choosing Submit again finishes this same report. It does not create a second one.';

/** Shown when a confidential submit fails for a reason not written for the reporter. */
export const SUBMIT_FAILED_MESSAGE =
  'Your report was not sent. It is still here. Try again; if it keeps failing, try later.';

/** The toast text for a failed confidential submit that has no dedicated handling.
 * Errors from preparing, encrypting or chunking the report (OpenPGP, recovery,
 * release identity) carry internal wording and no next step, so only errors the
 * caller classified as written for the reporter (a file too large, a paused
 * release) show their own message, and even then only when it reads as plain
 * guidance. Everything else gets the fixed message. */
export function submitFailureMessage(error: unknown, participantFacing: boolean): string {
  return participantFacing ? userFacingMessage(error, SUBMIT_FAILED_MESSAGE) : SUBMIT_FAILED_MESSAGE;
}
