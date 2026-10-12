import { legalDirectoryPages, mergeDirectoryListings, newestLegalReports } from '../../../lib/confidential/legalDirectory';
import type { DirectoryListing } from '../../../lib/confidential/firmCase';

const listing = (id: string, publishedAt?: number): DirectoryListing => ({
  caseId: id, summary: `QA ${id}`, owner: null, ownerKeyChanged: false, checkCode: id, publishedAt,
});

describe('legal directory discovery', () => {
  it('orders requests and direct shares together by submission date, not request date', () => {
    const requests = [{ caseId: 'old', requestedAt: 900 }, { caseId: 'new', requestedAt: 100 }];
    const direct = listing('direct', 200);
    const reports = [...requests, direct];
    expect(newestLegalReports(reports, [listing('old', 100), listing('new', 300), direct])
      .map(item => item.caseId)).toEqual(['new', 'direct', 'old']);
    expect(reports.map(item => item.caseId)).toEqual(['old', 'new', 'direct']);
  });

  it('falls back to saved request dates and keeps unknown dates last with deterministic ties', () => {
    const reports = [{ caseId: 'unknown' }, { caseId: 'b', requestedAt: 100 }, { caseId: 'a', requestedAt: 100 }];
    expect(newestLegalReports(reports, []).map(item => item.caseId)).toEqual(['a', 'b', 'unknown']);
  });

  it('discovers a new/directly shared report beyond the first 20 random IDs', async () => {
    const first = Array.from({ length: 20 }, (_, i) => listing(String(i).padStart(2, '0'), i));
    const newest = listing('99', 1000);
    const read = jest.fn(async (after: string | null) => after === null
      ? { listings: first, next: '19' }
      : { listings: [newest], next: null });
    let all: DirectoryListing[] = [];
    for await (const page of legalDirectoryPages(read)) all = mergeDirectoryListings(all, page.listings);
    expect(read.mock.calls).toEqual([[null], ['19']]);
    expect(all).toHaveLength(21);
    expect(all[0]).toBe(newest);
  });

  it('continues through an empty page of omitted unverifiable listings', async () => {
    const read = jest.fn(async (after: string | null) => after === null
      ? { listings: [], next: '20' }
      : { listings: [listing('21')], next: null });
    const pages = [];
    for await (const page of legalDirectoryPages(read)) pages.push(page);
    expect(pages).toHaveLength(2);
    expect(pages[1].listings[0].caseId).toBe('21');
  });

  it('retains completed pages and exposes a later failure for retry', async () => {
    const read = jest.fn(async (after: string | null) => {
      if (after !== null) throw new Error('offline');
      return { listings: [listing('01')], next: '20' };
    });
    const pages = [];
    await expect((async () => {
      for await (const page of legalDirectoryPages(read)) pages.push(page);
    })()).rejects.toThrow('offline');
    expect(pages).toHaveLength(1);
    expect(pages[0].next).toBe('20');
  });

  it('rejects a repeated cursor instead of scanning forever', async () => {
    const read = jest.fn(async () => ({ listings: [], next: '20' }));
    await expect((async () => {
      for await (const _page of legalDirectoryPages(read)) { /* consume */ }
    })()).rejects.toThrow('did not advance');
    expect(read).toHaveBeenCalledTimes(2);
  });

  it('drops an in-flight result when the workspace is closed or refreshed', async () => {
    let cancelled = false;
    const read = jest.fn(async () => {
      cancelled = true;
      return { listings: [listing('01')], next: '20' };
    });
    const pages = [];
    for await (const page of legalDirectoryPages(read, null, () => cancelled)) pages.push(page);
    expect(pages).toEqual([]);
    expect(read).toHaveBeenCalledTimes(1);
  });

  it('deduplicates refreshed listings and orders verified dates ahead of unknown ones', () => {
    const latest = listing('a', 3);
    expect(mergeDirectoryListings([listing('a', 1), listing('b')], [latest, listing('c', 2)]))
      .toEqual([latest, listing('c', 2), listing('b')]);
  });
});
