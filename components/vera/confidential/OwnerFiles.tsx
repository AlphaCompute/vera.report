import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import type { ReactNode } from "react";
import { formatBytes } from "@/lib/confidential/evidence";
import type { OwnerEvidence, OwnerInbox, OwnerSession } from "@/lib/confidential/ownerCase";
import { ownerFileListReducer, type OwnerFileListState } from "@/lib/confidential/ownerFileList";
import { EvidenceDownloadButton } from "./EvidenceDownloadButton";

/** The reporter's own files, decrypted on this device. Large files stream to disk.
 * Refreshes keep the current rows mounted so an in-progress download is never
 * cancelled by an unrelated update (see ownerFileList.ts). */
export function OwnerFiles({ session, inbox, panel }: { session: OwnerSession; inbox: OwnerInbox; panel: string }) {
  const [state, dispatch] = useReducer(ownerFileListReducer<OwnerEvidence>, { kind: "loading" });
  const latestInbox = useRef(inbox);
  latestInbox.current = inbox;
  const sequence = useRef(0);
  const load = useCallback(async () => {
    const run = ++sequence.current;
    dispatch({ type: "start" });
    try {
      const owner = await import("@/lib/confidential/ownerCase");
      const files = await owner.listOwnerEvidence(session, latestInbox.current, Date.now());
      if (run === sequence.current) dispatch({ type: "loaded", files });
    } catch { if (run === sequence.current) dispatch({ type: "failed" }); }
    // Re-list when the signed state changes, not on every new inbox object.
  }, [session, inbox.checkpointDigest]);
  useEffect(() => { void load(); }, [load]);
  useEffect(() => () => { sequence.current++; }, []);
  return <OwnerFileList state={state} panel={panel} onRetry={() => void load()} renderDownload={file => file.chunked ? (
    <EvidenceDownloadButton name={file.name ?? "evidence"} size={file.size}
      open={async () => (await import("@/lib/confidential/ownerCase")).openOwnerChunkedEvidence(session, file.objectId, Date.now())} />
  ) : <WholeFileDownload session={session} objectId={file.objectId} />} />;
}

type ListedFile = Pick<OwnerEvidence, "objectId" | "name" | "size" | "original">;

/** Presentational list. Rows are keyed by objectId and stay rendered while a
 * refresh runs or after it fails. */
export function OwnerFileList<F extends ListedFile>({ state, panel, onRetry, renderDownload }: {
  state: OwnerFileListState<F>; panel: string; onRetry: () => void; renderDownload: (file: F) => ReactNode;
}) {
  if (state.kind === "ready" && !state.files.length) return null;
  return (
    <section className={panel} aria-labelledby="owner-files-title">
      <h3 id="owner-files-title" className="mb-2 font-semibold">Your files</h3>
      {state.kind === "loading" && <p role="status" className="text-sm text-black/60">Decrypting the file list on this device…</p>}
      {state.kind === "error" && (
        <p role="alert" className="text-sm">Your files could not be listed. <button type="button" className="underline"
          onClick={onRetry}>Try again</button></p>
      )}
      {state.kind === "ready" && state.refreshFailed && (
        <p role="alert" className="mb-2 text-sm">This list could not be updated, so it may be out of date. <button type="button"
          className="underline" onClick={onRetry}>Try again</button></p>
      )}
      {state.kind === "ready" && (
        <ul aria-busy={state.refreshing || undefined}>
          {state.files.map((file, index) => (
            <li key={file.objectId} className="border-t border-black/10 py-3">
              <div className="mb-2 flex flex-wrap items-baseline gap-3">
                <span className="break-all">{file.name ?? `Evidence file ${index + 1}`}</span>
                {file.size !== undefined && <span className="text-sm text-black/50">{formatBytes(file.size)}</span>}
                <span className="text-sm text-black/50">{file.original ? "Sent with your report" : "Added later"}</span>
              </div>
              {renderDownload(file)}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** Files stored whole by earlier versions (at most 8 MB each). */
function WholeFileDownload({ session, objectId }: { session: OwnerSession; objectId: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  return <div>
    <button type="button" disabled={busy} className="border border-black px-4 py-2 disabled:opacity-50" onClick={() => {
      setBusy(true); setError(false);
      void (async () => {
        const [owner, transfer] = await Promise.all([import("@/lib/confidential/ownerCase"), import("@/lib/confidential/evidenceTransfer")]);
        if (!mounted.current) return;
        const file = await owner.openOwnerWholeEvidence(session, objectId, Date.now());
        try {
          if (!mounted.current) return;
          const sink = transfer.memorySink(file.name);
          await sink.write(file.bytes);
          if (!mounted.current) { await sink.abort(); return; }
          await sink.close();
        } finally { file.bytes.fill(0); }
      })().catch(() => { if (mounted.current) setError(true); }).finally(() => { if (mounted.current) setBusy(false); });
    }}>{busy ? "Decrypting…" : "Download"}</button>
    {error && <p role="alert" className="mt-2 text-sm text-red-800">This file could not be downloaded. Please try again.</p>}
  </div>;
}
