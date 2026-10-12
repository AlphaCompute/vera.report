import type { DirectoryListing } from './firmCase';

type DirectoryPage = { listings: DirectoryListing[]; next: string | null };

/** Use submission dates across request and direct-share cards. Saved requests
 * without a directory date fall back to when the organization requested them. */
export function newestLegalReports<T extends { caseId: string; requestedAt?: number }>(
  reports: readonly T[], listings: readonly DirectoryListing[],
): T[] {
  const dates = new Map(listings.map(item => [item.caseId, item.publishedAt]));
  const date = (item: T) => dates.get(item.caseId) ?? item.requestedAt ?? 0;
  return [...reports].sort((a, b) => date(b) - date(a) || a.caseId.localeCompare(b.caseId));
}

/** Consume the existing signed directory protocol without a plaintext grant index. */
export async function* legalDirectoryPages(
  readPage: (after: string | null) => Promise<DirectoryPage>,
  after: string | null = null,
  cancelled: () => boolean = () => false,
): AsyncGenerator<DirectoryPage> {
  let cursor = after;
  const seen = new Set<string>();
  if (cursor !== null) seen.add(cursor);
  do {
    if (cancelled()) return;
    const page = await readPage(cursor);
    if (cancelled()) return;
    if (page.next !== null && (seen.has(page.next) || (cursor !== null && page.next <= cursor))) {
      throw new Error('The report directory did not advance. Please refresh.');
    }
    yield page;
    cursor = page.next;
    if (cursor !== null) seen.add(cursor);
  } while (cursor !== null);
}

/** Only owner-verified publication times enter this list. Unknown dates sort last. */
export function mergeDirectoryListings(current: DirectoryListing[], incoming: DirectoryListing[]): DirectoryListing[] {
  return [...new Map([...current, ...incoming].map(item => [item.caseId, item])).values()]
    .sort((a, b) => (b.publishedAt ?? 0) - (a.publishedAt ?? 0) || a.caseId.localeCompare(b.caseId));
}
