/** Lifecycle of one access (or renewal) request sent from the legal portal.
 *
 * Saving and delivering are separate steps: the request is saved in the
 * organization's shared list before it is sent (so a lost reply cannot strand
 * it), but nothing tells the lawyer it was "sent" until delivery is confirmed.
 * Callers refresh their lists once the attempt settles and learn the result
 * from a single outcome, so a failure is never reported on an unmounted form. */
import type { RememberedRequest } from "./firmPortal";

export type RequestKind = "new" | "renewal";
export type RequestOutcome = { caseId: string; ok: boolean; message: string };

export const WORKSPACE_SAVE_FAILED = "The request was not sent because your organization's request list could not be saved. Check your connection and try again.";
export const DELIVERY_UNCONFIRMED = "Request delivery was not confirmed. It may have reached the reporter. Check its status under Your organization's requests before trying again. If a request is already waiting for this report, you cannot send another yet.";

export function sentMessage(kind: RequestKind): string {
  return kind === "renewal"
    ? "Renewal request sent. The reporter decides; the answer appears under Your organization's requests."
    : "Request sent. The reporter decides whether to allow access; the answer appears under Your organization's requests.";
}

class WorkspaceSaveFailed extends Error {}

export async function submitAccessRequest(input: {
  caseId: string; kind: RequestKind;
  /** Sends the request; `beforeSend` must run (and succeed) before anything leaves this device. */
  send: (beforeSend: (record: RememberedRequest & { expiresAt: number }) => Promise<void>) => Promise<void>;
  /** Saves the request in the organization's shared list. */
  save: (record: RememberedRequest & { expiresAt: number }) => Promise<void>;
  describeFailure: (caught: unknown, fallback: string) => string;
}, events: {
  /** The shared list changed (the request was saved): refresh lists. Runs once the attempt settles. */
  onRequested?: (request: RememberedRequest) => void;
  /** The enclave confirmed delivery. */
  onDelivered?: (caseId: string) => void;
  /** The single result of this attempt: success only after delivery, or the failure. */
  onOutcome?: (outcome: RequestOutcome) => void;
} = {}): Promise<RequestOutcome> {
  let saved: RememberedRequest | null = null;
  let outcome: RequestOutcome;
  try {
    await input.send(async record => {
      try { await input.save(record); }
      catch { throw new WorkspaceSaveFailed(); }
      const { expiresAt: _expiresAt, ...base } = record;
      saved = base;
    });
    outcome = { caseId: input.caseId, ok: true, message: sentMessage(input.kind) };
  } catch (caught) {
    outcome = { caseId: input.caseId, ok: false, message: caught instanceof WorkspaceSaveFailed
      ? WORKSPACE_SAVE_FAILED : input.describeFailure(caught, DELIVERY_UNCONFIRMED) };
  }
  if (saved) events.onRequested?.(saved);
  if (outcome.ok) events.onDelivered?.(input.caseId);
  events.onOutcome?.(outcome);
  return outcome;
}

/** Per-report request failures kept by the page, so a failure stays next to the
 * report it concerns even after the form that sent it closed. */
export function withRequestOutcome(failures: ReadonlyMap<string, string>, outcome: RequestOutcome): Map<string, string> {
  const next = new Map(failures);
  if (outcome.ok) next.delete(outcome.caseId);
  else next.set(outcome.caseId, outcome.message);
  return next;
}

/** Withdraw and remove act on one entry in "Your organization's requests". Their
 * failures stay on that entry, apart from directory loading errors, and carry
 * which action to retry there. */
export type RequestAction = "withdraw" | "remove";
export type RequestActionFailure = { action: RequestAction; message: string };

export const WITHDRAW_UNCONFIRMED = "Withdrawal was not confirmed. The request is still shown so you can check its status or try again.";
export const REMOVE_FAILED = "Your organization's request list could not be updated. Please try again.";

export function removeFailureMessage(caught: unknown): string {
  return caught instanceof Error && caught.message.includes("full") ? caught.message : REMOVE_FAILED;
}

/** Records (or, with `failure` null, clears) the action failure for one report. */
export function withRequestActionFailure(failures: ReadonlyMap<string, RequestActionFailure>, caseId: string,
  failure: RequestActionFailure | null): Map<string, RequestActionFailure> {
  const next = new Map(failures);
  if (failure) next.set(caseId, failure);
  else next.delete(caseId);
  return next;
}

/** A failed withdrawal may be retried only while the request is still confirmed
 * as waiting; otherwise the lawyer checks its status first. Removal is always safe to retry. */
export function canRetryRequestAction(failure: RequestActionFailure, statusKind: string | undefined): boolean {
  return failure.action === "remove" || statusKind === "waiting";
}
