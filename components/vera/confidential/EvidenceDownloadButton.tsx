import { useEffect, useRef, useState } from "react";
import type { OpenedChunkedEvidence } from "@/lib/confidential/evidenceTransfer";
import { formatBytes, percent, type TransferProgress } from "@/lib/confidential/evidence";
import { useParticipantLockHold } from "@/lib/confidential/participantLock";

type Phase =
  | { kind: "idle" }
  | { kind: "running"; progress: TransferProgress }
  | { kind: "stopped"; progress: TransferProgress; message: string; resumable: boolean }
  /** The sign-in expired mid-transfer. The partial file is kept; renewing the
   * sign-in (without leaving the page) resumes where it stopped. */
  | { kind: "sign-in"; progress: TransferProgress; renewing: boolean; error: string | null }
  | { kind: "done" };

/** Streaming, resumable download of one chunked evidence file. Each chunk is
 * fetched through the attested channel, verified against the owner-signed index
 * and decrypted on this device, then written straight to the chosen file (or,
 * where the browser has no save dialog, assembled and offered once complete).
 * The file is never shown or opened in this site. `open` must re-check access
 * every time it is called. A running transfer holds off the automatic idle lock
 * (a long download needs no input); a paused one does not, and an explicit Lock
 * still ends it at once. */
export function EvidenceDownloadButton({ name, size, open, describeError, signIn, buttonClassName, onDone }: {
  name: string; size?: number;
  /** Called after the whole file was verified and saved. */
  onDone?: () => void;
  open: () => Promise<OpenedChunkedEvidence>;
  /** Plain-language text for errors the caller understands (sign-in, access). */
  describeError?: (error: unknown) => string | null;
  /** Legal sign-in renewal. `required` recognizes an expired sign-in; `renew`
   * must renew it without leaving the page (called straight from a click). */
  signIn?: { required: (error: unknown) => boolean; renew: () => Promise<void>; describeRenewalError?: (error: unknown) => string };
  buttonClassName?: string;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  useParticipantLockHold(phase.kind === "running");
  const download = useRef<import("@/lib/confidential/evidenceTransfer").EvidenceDownload | null>(null);
  const abort = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const generation = useRef(0);
  const running = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false; generation.current++; running.current = false;
      abort.current?.abort(); abort.current = null;
      const current = download.current; download.current = null;
      void current?.cancel();
    };
  }, []);

  const run = async (existing: boolean) => {
    if (!mounted.current || running.current) return;
    running.current = true;
    const operation = ++generation.current;
    const controller = new AbortController();
    abort.current = controller;
    const active = () => mounted.current && operation === generation.current;
    let transfer: typeof import("@/lib/confidential/evidenceTransfer") | undefined;
    let current = download.current;
    try {
      transfer = await import("@/lib/confidential/evidenceTransfer");
      if (!active()) return;
      if (!existing) {
        const sink = await transfer.chooseEvidenceSink(name);
        if (!sink) return;
        // Lock/unmount can happen while the native save dialog is open.
        if (!active()) { await sink.abort(); return; }
        current = new transfer.EvidenceDownload(sink, open);
        download.current = current;
      }
      if (!current || !active()) return;
      setPhase({ kind: "running", progress: current.progress });
      await current.run({ signal: controller.signal, onProgress: progress => {
        if (active()) setPhase({ kind: "running", progress });
      } });
      if (!active()) return;
      download.current = null;
      setPhase({ kind: "done" });
      try { onDone?.(); } catch { /* display only */ }
    } catch (error) {
      if (!active()) return;
      if (!current || !transfer) {
        setPhase({ kind: "stopped", progress: { bytesDone: 0, bytesTotal: size ?? 0 },
          message: "The download could not start. Please try again.", resumable: false });
        return;
      }
      if (!controller.signal.aborted && signIn?.required(error)) {
        setPhase({ kind: "sign-in", progress: current.progress, renewing: false, error: null });
        return;
      }
      const known = error instanceof transfer.EvidenceDownloadError ? error : null;
      const resumable = !known || known.reason === "interrupted";
      if (!resumable) download.current = null;
      const message = controller.signal.aborted ? "Download paused." : describeError?.(error) ?? (known ? known.message
        : "The download stopped. Access may have changed, or the secure connection could not be verified.");
      setPhase({ kind: "stopped", progress: current.progress, message, resumable });
    } finally {
      if (operation === generation.current) { abort.current = null; running.current = false; }
    }
  };
  const renewAndResume = () => {
    if (!signIn || phase.kind !== "sign-in" || phase.renewing) return;
    const progress = phase.progress;
    setPhase({ kind: "sign-in", progress, renewing: true, error: null });
    // Opened synchronously inside this click so the browser allows the window.
    signIn.renew().then(() => { if (mounted.current) void run(true); }, error => {
      if (mounted.current) setPhase({ kind: "sign-in", progress, renewing: false,
        error: signIn.describeRenewalError?.(error) ?? "Sign-in did not finish. Try again." });
    });
  };
  const cancel = async () => {
    const operation = ++generation.current;
    abort.current?.abort();
    abort.current = null;
    const current = download.current;
    download.current = null;
    await current?.cancel();
    if (mounted.current && operation === generation.current) { running.current = false; setPhase({ kind: "idle" }); }
  };

  const button = buttonClassName ?? "border border-black px-4 py-2 disabled:opacity-50";
  const progress = phase.kind === "running" || phase.kind === "stopped" || phase.kind === "sign-in" ? phase.progress : null;
  const total = progress?.bytesTotal || size || 0;
  return (
    <div className="w-full">
      <div className="flex flex-wrap items-center gap-3">
        {phase.kind === "idle" || phase.kind === "done" ? (
          <button type="button" className={button} onClick={() => void run(false)} aria-label={`Download ${name}`}>
            {phase.kind === "done" ? "Download again" : "Download"}
          </button>
        ) : phase.kind === "sign-in" ? (
          <button type="button" className={button} disabled={phase.renewing} onClick={renewAndResume}>
            {phase.renewing ? "Waiting for sign-in…" : "Sign in again to continue"}
          </button>
        ) : phase.kind === "running" ? (
          <button type="button" className={button} onClick={() => abort.current?.abort()}>Pause</button>
        ) : (
          <>
            {phase.resumable && <button type="button" className={button} onClick={() => void run(true)}>Resume</button>}
            {!phase.resumable && <button type="button" className={button} onClick={() => void run(false)}>Start again</button>}
          </>
        )}
        {(phase.kind === "running" || phase.kind === "sign-in" || (phase.kind === "stopped" && phase.resumable)) && (
          <button type="button" className="underline underline-offset-4" onClick={() => void cancel()}>Cancel</button>
        )}
        {phase.kind === "done" && <span role="status" className="text-sm text-black/60">Saved. Decrypted on this device.</span>}
      </div>
      {progress && total > 0 && (
        <div className="mt-2 max-w-[420px]">
          <div role="progressbar" aria-label={`Downloading ${name}`} aria-valuemin={0} aria-valuemax={100}
            aria-valuenow={percent({ bytesDone: progress.bytesDone, bytesTotal: total })} className="h-[4px] w-full bg-black/10">
            <div className="h-full bg-black" style={{ width: `${percent({ bytesDone: progress.bytesDone, bytesTotal: total })}%` }} />
          </div>
          <p className="mt-1 text-sm text-black/60">{formatBytes(progress.bytesDone)} of {formatBytes(total)}</p>
        </div>
      )}
      {phase.kind === "stopped" && <p role="alert" className="mt-2 text-sm text-red-800">{phase.message}</p>}
      {phase.kind === "sign-in" && (
        <div role="status" className="mt-2 max-w-[62ch] text-sm">
          <p>Your sign-in expired, so the download is paused. Sign in again in the window that opens to continue.
            The download picks up where it stopped, and nothing already saved is lost.</p>
          {phase.error && <p role="alert" className="mt-1 text-red-800">{phase.error}</p>}
        </div>
      )}
    </div>
  );
}
