import { useEffect, useRef, useState } from "react";
import { motion } from "motion/react";
import { Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  createLatestConfidentialListingsLoader, setConfidentialListingVisibility, type ConfidentialAdminListing, type ConfidentialListingsFailureResult,
} from "@/lib/confidentialAdminListings";
import { FailureNotice } from "@/components/vera/admin/LegalOnboardingParts";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

const headStyle = { fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase" as const, color: ink(45) };

/** Column headers. User-facing copy says "report", never "case", so the admin
 * tab uses the same term as the reporter and legal organization screens. */
export const CONFIDENTIAL_LISTING_COLUMNS = ["Report reference", "Approved summary"] as const;


/** Failure notice for the tab, shared with the Legal organizations tab: an ended
 * session offers Sign in again, forbidden offers nothing, a rate limit asks the
 * admin to wait, and only busy or unavailable offer Try again. */
export function ConfidentialListingsFailure({ result, onRetry }: { result: ConfidentialListingsFailureResult; onRetry: () => void }) {
  switch (result.status) {
    case "signed-out": return <FailureNotice failure={{ kind: "signed-out" }} onRetry={onRetry} />;
    case "forbidden":
      return <FailureNotice failure={{ kind: "forbidden" }} onRetry={onRetry} message="Only VERA administrators can view encrypted reports." />;
    case "busy": return <FailureNotice failure={{ kind: "busy" }} onRetry={onRetry} />;
    default: return <FailureNotice failure={{ kind: "unavailable" }} onRetry={onRetry} message="Unable to load encrypted reports." />;
  }
}

/** Public summary directory. Moderation changes visibility only, not private access. */

export function ConfidentialListingsView() {
  // Cursor stack: cursors[i] is the `after` value that loads page i.
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [page, setPage] = useState(0);
  const [listings, setListings] = useState<ConfidentialAdminListing[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "disabled" | "error">("loading");
  const [failure, setFailure] = useState<ConfidentialListingsFailureResult>({ status: "error" });

  // Bumped by "Try again" so a retry goes through the same guarded effect.
  const [attempt, setAttempt] = useState(0);
  const loaderRef = useRef<ReturnType<typeof createLatestConfidentialListingsLoader> | null>(null);

  // Each page change or retry aborts the previous request, and the loader drops
  // any response that is not the newest, so rows, page number and the Next
  // cursor always come from the same request.
  useEffect(() => {
    const loader = (loaderRef.current ??= createLatestConfidentialListingsLoader());
    setState("loading");
    loader.load(cursors[page] ?? null, (result) => {
      if (result.status === "ready") {
        setListings(result.page.listings);
        setNext(result.page.next);
        setState("ready");
      } else if (result.status === "disabled") {
        setListings([]);
        setNext(null);
        setState("disabled");
      } else {
        setFailure(result);
        setState("error");
      }
    });
    return () => loader.cancel();
  }, [cursors, page, attempt]);

  const [moderating, setModerating] = useState<string | null>(null);
  const [moderationError, setModerationError] = useState('');
  const moderate = async (listing: ConfidentialAdminListing) => {
    if (moderating) return;
    setModerating(listing.caseId); setModerationError('');
    try {
      if (!await setConfidentialListingVisibility(listing.caseId, !listing.hidden)) throw new Error('unconfirmed');
      setAttempt(value => value + 1);
    } catch { setModerationError('The visibility change was not confirmed. Reload the list before trying again.'); }
    finally { setModerating(null); }
  };

  const goNext = () => {
    if (!next) return;
    setCursors((prev) => [...prev.slice(0, page + 1), next]);
    setPage((value) => value + 1);
  };
  const goPrevious = () => setPage((value) => Math.max(0, value - 1));

  return (
    <motion.div key="confidential" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
      <div className="flex items-start gap-3">
        <Lock className="mt-1 h-4 w-4 shrink-0" style={{ color: ink(45) }} aria-hidden />
        <div>
          <h2 className="font-serif" style={{ fontSize: "1.4rem", fontWeight: 300, color: ink(85) }}>Encrypted reports</h2>
          <p style={{ fontSize: "13px", color: ink(55), maxWidth: "46rem" }}>
            These reports are encrypted on the reporter&apos;s device. You can see only the report reference, the
            summary and submission facts the reporter approved for publication. The full report, evidence and contact details are not available to administrators. Hiding spam removes only its directory listing; it does not delete the report or revoke existing access.
          </p>
        </div>
      </div>

      {moderationError && <p role="alert">{moderationError}</p>}
      {state === "disabled" && (
        <p role="status" className="py-8 text-sm" style={{ color: ink(55) }}>Encrypted reports are not enabled on this deployment.</p>
      )}
      {state === "error" && <ConfidentialListingsFailure result={failure} onRetry={() => setAttempt((value) => value + 1)} />}
      {state === "loading" && <p role="status" className="py-8 text-sm" style={{ color: ink(55) }}>Loading encrypted reports…</p>}

      {state === "ready" && (
        <>
          <div style={{ border: `1px solid ${ink(4)}` }}>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent" style={{ borderColor: ink(4) }}>
                  {CONFIDENTIAL_LISTING_COLUMNS.map((label) => (
                    <TableHead key={label} style={headStyle}>{label}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {listings.map((listing) => (
                  <TableRow key={listing.caseId} style={{ borderColor: ink(4) }}>
                    <TableCell className="align-top font-mono" style={{ fontSize: "11px", color: ink(60), whiteSpace: "nowrap" }}>
                      <span title={listing.caseId}>{listing.caseId.slice(0, 12)}…</span>
                    </TableCell>
                    <TableCell className="align-top" style={{ fontSize: "13px", color: ink(80), whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                      {listing.summary}
                      {(listing.publishedAt !== undefined || listing.hasAttachments !== undefined) && <p className="mt-1 text-xs">
                        {listing.publishedAt !== undefined && <>Submitted {new Date(listing.publishedAt).toLocaleString()}</>}
                        {listing.publishedAt !== undefined && listing.hasAttachments !== undefined && ' · '}
                        {listing.hasAttachments !== undefined && (listing.hasAttachments ? 'Attachments included at submission' : 'No attachments at submission')}
                      </p>}
                      <div className="mt-2 text-xs">
                        <span>{listing.hidden ? 'Hidden from legal directory' : 'Visible in legal directory'}</span>{' · '}
                        <button type="button" className="underline" disabled={moderating !== null}
                          onClick={() => void moderate(listing)}>
                          {listing.hidden ? 'Restore listing' : 'Hide as spam'}
                        </button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {listings.length === 0 && (
              <p className="p-16 text-center font-serif italic" style={{ fontSize: "13px", color: ink(45) }}>
                No encrypted reports on this page
              </p>
            )}
          </div>
          <div className="flex items-center justify-between pt-2">
            <span style={{ fontSize: "11px", color: ink(45) }}>Page {page + 1}</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={goPrevious} disabled={page === 0}>Previous</Button>
              <Button variant="outline" size="sm" onClick={goNext} disabled={!next}>Next</Button>
            </div>
          </div>
        </>
      )}
    </motion.div>
  );
}
