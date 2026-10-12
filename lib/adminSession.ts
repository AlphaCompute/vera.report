/**
 * Once the sign-in session has expired, admin polling cannot recover without a
 * new sign-in, so every admin poller stops until the page is reloaded instead
 * of failing every few seconds for as long as the tab stays open.
 *
 * Only the Auth0 session gate's 401 (`{ error: 'not_authenticated' }`) latches
 * this. A 401 forwarded from the backend (for example an internal-secret
 * mismatch during a rotation) stays retryable.
 */
let expired = false;

export const ADMIN_SESSION_EXPIRED_MESSAGE = 'Your session has expired. Reload the page to sign in again.';

export function isAdminSessionExpired(): boolean {
  return expired;
}

/** Record the session as expired when a response is the session gate's 401. */
export async function noteAdminResponse(response: Response): Promise<void> {
  if (response.status !== 401 || expired) return;
  const body = await response.clone().json().catch(() => null) as { error?: unknown } | null;
  if (body?.error === 'not_authenticated') expired = true;
}

/** Test hook: module state otherwise lives for the lifetime of the page. */
export function resetAdminSessionForTests(): void {
  expired = false;
}
