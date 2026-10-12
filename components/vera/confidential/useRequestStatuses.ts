import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { caseStatus } from "@/lib/confidential/firmCaseView";
import type { FirmCaseStatus } from "@/lib/confidential/firmCaseView";
import type { DirectoryListing, FirmSession } from "@/lib/confidential/firmCase";
import type { RememberedRequest } from "@/lib/confidential/firmPortal";

const CHECK_TIMEOUT_MS = 60_000;
// Keep each encrypted status response small and publish it independently.
const STATUS_PAGE_SIZE = 50;
const NO_LISTINGS: readonly DirectoryListing[] = [];
type StatusTarget = { caseId: string; requestId: string | null; owner?: DirectoryListing['owner'] };
const targetKey = (item: StatusTarget) => JSON.stringify([item.requestId, item.owner?.ownerFingerprint ?? null]);

/** Checks the board once after its lists load, publishing each bounded page
 * independently; it never unlocks reports in the background.
 * New targets are checked once, and only explicit refresh/recheck retries them. */
export function useRequestStatuses(session: FirmSession, requests: RememberedRequest[], listings: readonly DirectoryListing[] = NO_LISTINGS,
  ready = true) {
  const targets = useMemo(() => {
    const byCase = new Map<string, StatusTarget>(requests.map(item => [item.caseId, item]));
    for (const listing of listings) {
      if (listing.owner && !listing.ownerKeyChanged) {
        byCase.set(listing.caseId, { caseId: listing.caseId, requestId: byCase.get(listing.caseId)?.requestId ?? null, owner: listing.owner });
      }
    }
    return [...byCase.values()];
  }, [requests, listings]);
  const [statuses, setStatuses] = useState<Map<string, FirmCaseStatus>>(new Map());
  const checked = useRef(new Map<string, string>());
  const attempts = useRef(new Map<string, symbol>());
  const pending = useRef(new Set<AbortController>());
  const [revision, setRevision] = useState(0);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    checked.current.clear(); attempts.current.clear(); setStatuses(new Map());
    return () => {
      attempts.current.clear();
      for (const controller of pending.current) controller.abort();
      pending.current.clear();
    };
  }, [session]);

  const check = useCallback(async (items: StatusTarget[], verifyLocked = false) => {
    if (!items.length) return;
    const batch = items.map(item => {
      const attempt = Symbol();
      checked.current.set(item.caseId, targetKey(item));
      attempts.current.set(item.caseId, attempt);
      return { ...item, attempt };
    });
    setStatuses(current => {
      const next = new Map(current);
      for (const item of items) next.set(item.caseId, { kind: "checking" });
      return next;
    });
    const controller = new AbortController();
    pending.current.add(controller);
    try {
      const pageSize = verifyLocked ? 1 : STATUS_PAGE_SIZE;
      for (let offset = 0; offset < batch.length; offset += pageSize) {
        if (controller.signal.aborted) break;
        const page = batch.slice(offset, offset + pageSize).filter(item => attempts.current.get(item.caseId) === item.attempt);
        if (!page.length) continue;
        const pageController = new AbortController();
        const abortPage = () => pageController.abort();
        controller.signal.addEventListener('abort', abortPage, { once: true });
        let timer: ReturnType<typeof setTimeout> | undefined;
        let rejectAborted: () => void = () => {};
        const answers = new Map<string, FirmCaseStatus>();
        try {
          const results = await Promise.race([
            import("@/lib/confidential/firmCase").then(async client => {
              pageController.signal.throwIfAborted();
              if (!verifyLocked) return client.checkReportAccessBatch(session, page, Date.now(), pageController.signal);
              // Only an explicit per-report action may unlock a case to resolve unknown access.
              const item = page[0];
              return new Map([[item.caseId, await client.checkReportAccess(session, item.caseId, item.requestId, Date.now(), item.owner)]]);
            }),
            new Promise<never>((_, reject) => {
              rejectAborted = () => reject(pageController.signal.reason);
              pageController.signal.addEventListener('abort', rejectAborted, { once: true });
              // A deadline belongs to one page, never the entire directory.
              timer = setTimeout(abortPage, CHECK_TIMEOUT_MS);
            }),
          ]);
          for (const item of page) {
            const result = results.get(item.caseId);
            answers.set(item.caseId, result ? caseStatus(result, session.pins.has(item.caseId), item.requestId !== null) : { kind: "error" });
          }
        } catch { for (const item of page) answers.set(item.caseId, { kind: "error" }); }
        finally {
          clearTimeout(timer);
          pageController.signal.removeEventListener('abort', rejectAborted);
          controller.signal.removeEventListener('abort', abortPage);
        }
        if (!alive.current || controller.signal.aborted) break;
        setStatuses(current => {
          const next = new Map(current);
          for (const item of page) {
            // Ignore results superseded by a refresh, request replacement or unmount.
            if (attempts.current.get(item.caseId) === item.attempt) next.set(item.caseId, answers.get(item.caseId)!);
          }
          return next;
        });
      }
    } finally { pending.current.delete(controller); }
  }, [session]);

  useEffect(() => {
    if (!ready) return;
    const currentIds = new Set(targets.map(item => item.caseId));
    for (const id of checked.current.keys()) if (!currentIds.has(id)) {
      checked.current.delete(id); attempts.current.delete(id);
    }
    const fresh = targets.filter(item => checked.current.get(item.caseId) !== targetKey(item));
    void check(fresh);
  }, [check, targets, ready, revision]);

  const refresh = useCallback(() => {
    for (const controller of pending.current) controller.abort();
    checked.current.clear(); attempts.current.clear();
    setRevision(value => value + 1);
  }, []);
  // Callers may hold an older `recheck` across an await (a request form that
  // saved the request, then delivered it); look the request up in the latest list.
  const latest = useRef(targets);
  latest.current = targets;
  const recheck = useCallback((caseId: string) => {
    const found = latest.current.find(item => item.caseId === caseId);
    if (found) void check([found]);
  }, [check]);
  const verify = useCallback((caseId: string) => {
    const found = latest.current.find(item => item.caseId === caseId);
    if (found) void check([found], true);
  }, [check]);
  const unavailable = useMemo(() => targets.filter(item => statuses.get(item.caseId)?.kind === 'error'), [targets, statuses]);
  const retryFailed = useCallback(() => { void check(unavailable); }, [check, unavailable]);
  return { statuses, refresh, recheck, verify, retryFailed, unavailableCount: unavailable.length };
}
