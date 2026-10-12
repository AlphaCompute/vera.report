
/** Public listings contain the approved summary, opaque reference and optional signed submission facts. */
export type ConfidentialAdminListing = {
  caseId: string; summary: string; publishedAt?: number; hasAttachments?: boolean; hidden?: boolean;
};
export type ConfidentialAdminListingPage = { listings: ConfidentialAdminListing[]; next: string | null };

const HEX64 = /^[a-f0-9]{64}$/;

export function projectConfidentialListings(data: unknown): ConfidentialAdminListingPage {
  const body = (data && typeof data === 'object' ? data : {}) as { listings?: unknown; next?: unknown };
  const listings = Array.isArray(body.listings) ? body.listings.flatMap((item: unknown) => {
    const row = (item && typeof item === 'object' ? item : {}) as { caseId?: unknown; summary?: unknown; publishedAt?: unknown; hasAttachments?: unknown; hidden?: unknown };
    if (typeof row.caseId !== 'string' || !HEX64.test(row.caseId) || typeof row.summary !== 'string' || row.summary.length > 600) return [];
    if (row.publishedAt !== undefined && (typeof row.publishedAt !== 'number' || !Number.isSafeInteger(row.publishedAt) || row.publishedAt < 0 || row.publishedAt > 8_640_000_000_000_000)) return [];
    if (row.hasAttachments !== undefined && typeof row.hasAttachments !== 'boolean') return [];
    return [{ caseId: row.caseId, summary: row.summary,
      ...(typeof row.publishedAt === 'number' ? { publishedAt: row.publishedAt } : {}),
      ...(typeof row.hasAttachments === 'boolean' ? { hasAttachments: row.hasAttachments } : {}), ...(row.hidden === true ? { hidden: true } : {}) }];
  }) : [];
  return { listings, next: typeof body.next === 'string' && HEX64.test(body.next) ? body.next : null };
}

export const CONFIDENTIAL_LISTINGS_PAGE_SIZE = 25;

export type ConfidentialListingsLoadResult =
  | { status: 'ready'; page: ConfidentialAdminListingPage }
  | { status: 'disabled' }
  | ConfidentialListingsFailureResult;

/** Why a page did not load. 401, 403 and 429 are told apart (as on the Legal
 * organizations tab) so an ended session asks the admin to sign in again and a
 * rate limit asks them to wait, instead of a Try again that repeats the failure. */
export type ConfidentialListingsFailureResult =
  | { status: 'signed-out' } | { status: 'forbidden' } | { status: 'busy' } | { status: 'error' };

type FetchLike = (input: string, init: RequestInit) => Promise<Pick<Response, 'ok' | 'status' | 'json'>>;

/** Loads one page of the admin directory. The cursor is a case ID, so it goes in
 * the POST body, never the URL (request logs). Never throws. */
export async function fetchConfidentialListingsPage(
  after: string | null, signal: AbortSignal, fetchImpl: FetchLike = (input, init) => fetch(input, init),
): Promise<ConfidentialListingsLoadResult> {
  try {
    const response = await fetchImpl('/api/admin/confidential/listings', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ limit: CONFIDENTIAL_LISTINGS_PAGE_SIZE, ...(after ? { after } : {}) }),
      signal,
    });
    if (response.status === 404) return { status: 'disabled' };
    if (response.status === 401) return { status: 'signed-out' };
    if (response.status === 403) return { status: 'forbidden' };
    if (response.status === 429) return { status: 'busy' };
    if (!response.ok) return { status: 'error' };
    return { status: 'ready', page: projectConfidentialListings(await response.json()) };
  } catch {
    return { status: 'error' };
  }
}

/** Keeps only the newest page request. Starting a load aborts the previous one,
 * and a response that resolves after a newer load started (or after cancel) is
 * dropped, so quick Next/Previous/Try again clicks can never let an older page
 * overwrite the rows and Next cursor shown for the current page number. */
export function createLatestConfidentialListingsLoader(fetchImpl?: FetchLike) {
  let current: AbortController | null = null;
  return {
    load(after: string | null, onResult: (result: ConfidentialListingsLoadResult) => void): void {
      current?.abort();
      const controller = new AbortController();
      current = controller;
      void fetchConfidentialListingsPage(after, controller.signal, fetchImpl).then((result) => {
        if (current === controller && !controller.signal.aborted) onResult(result);
      });
    },
    cancel(): void {
      current?.abort();
      current = null;
    },
  };
}

/** Moderation changes visibility only; page loading still uses the guarded loader. */
export async function setConfidentialListingVisibility(caseId: string, hidden: boolean): Promise<boolean> {
  if (!HEX64.test(caseId)) return false;
  try {
    const response = await fetch('/api/admin/confidential/listings/moderation', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caseId, hidden }),
    });
    return response.ok;
  } catch { return false; }
}
