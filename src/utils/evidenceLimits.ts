// Keep media below V8's single-string ceiling while the encryption envelope is base64.
export const MAX_MEDIA_BYTES = 256 * 1024 * 1024;
export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;
export const MAX_REPORT_EVIDENCE_BYTES = MAX_MEDIA_BYTES;
// Small remux overhead is allowed; encrypted GCM tags are stored separately.
export const MAX_STORED_EVIDENCE_BYTES = MAX_MEDIA_BYTES + 8 * 1024 * 1024;
/** End-to-end budget after the request body is complete (proof/storage work). */
export const EVIDENCE_TRANSFER_TIMEOUT_MS = 15 * 60 * 1000;
/** Abort an incomplete body with no byte progress for this long. */
export const UPLOAD_IDLE_MS = 10_000;
/** Grace before the average-rate floor applies to an incomplete body. */
export const UPLOAD_PROGRESS_GRACE_MS = 30_000;
/** Minimum average receive rate after the grace period (incomplete bodies only). */
export const UPLOAD_MIN_BYTES_PER_SEC = 32 * 1024;
/** Floor for the Content-Length-scaled incomplete-body deadline (latency headroom). */
export const UPLOAD_RECEIVE_MIN_MS = 60_000;
/** Cap on how long an incomplete body may hold a transfer slot. */
export const UPLOAD_RECEIVE_MAX_MS = 5 * 60 * 1000;
/** Upper bound; the API admits only one transfer until its local relay reports fully synced and connected. */
export const MAX_PROCESS_UPLOADS = 2;
/** Concurrent evidence transfers allowed per rate-limit principal. */
export const MAX_CLIENT_UPLOADS = 1;
/** A body declared at or below this size (a text-only report, at most a small file)
 * never takes an evidence slot, so slow large uploads cannot block report intake. */
export const SMALL_REQUEST_MAX_BYTES = 1024 * 1024;
/** Concurrent small bodies per process (bounded memory) and per rate-limit principal.
 * One per client, like evidence, so a principal's concurrent retries stay serialized. */
export const MAX_PROCESS_SMALL_REQUESTS = 16;
export const MAX_CLIENT_SMALL_REQUESTS = 1;

/**
 * Incomplete-body deadline from declared size at the minimum receive rate,
 * clamped so small drips release quickly while max-size media still get five minutes.
 */
export function uploadReceiveDeadlineMs(contentLength: number): number {
  if (!Number.isFinite(contentLength) || contentLength <= 0) return UPLOAD_RECEIVE_MAX_MS;
  const fromRate = Math.ceil((contentLength / UPLOAD_MIN_BYTES_PER_SEC) * 1000);
  return Math.min(UPLOAD_RECEIVE_MAX_MS, Math.max(UPLOAD_RECEIVE_MIN_MS, fromRate));
}

/**
 * True when an incomplete body is behind the linear schedule needed to finish
 * `contentLength` within `receiveDeadlineMs`. Applied only after the progress grace
 * so slow starts and small latency spikes do not abort early; above-floor drips that
 * cannot complete within the ceiling are cut so they cannot monopolize a transfer slot.
 */
export function uploadBehindReceivePace(
  bytesReceived: number,
  contentLength: number,
  elapsedMs: number,
  receiveDeadlineMs: number,
): boolean {
  if (elapsedMs < UPLOAD_PROGRESS_GRACE_MS) return false;
  if (!Number.isFinite(contentLength) || contentLength <= 0) return false;
  if (!Number.isFinite(receiveDeadlineMs) || receiveDeadlineMs <= 0) return false;
  if (!Number.isFinite(bytesReceived) || bytesReceived < 0) return false;
  const expected = contentLength * (elapsedMs / receiveDeadlineMs);
  return bytesReceived < expected;
}
