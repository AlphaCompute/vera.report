import { useEffect, useId, useRef, useState } from "react";
import { FileUp } from "lucide-react";
import type { RecoveryFile } from "@/lib/confidential/recoveryFile";

type Props = {
  onOpened: (file: RecoveryFile) => void;
  disabled?: boolean;
};

const MESSAGES = {
  unreadable: "That file could not be read. Choose the recovery file you downloaded (vera-private-recovery.txt).",
  notRecovery: "That file does not contain a VERA recovery code. Choose the recovery file you downloaded (vera-private-recovery.txt).",
  many: "Drop one recovery file at a time.",
} as const;

/** Opens a recovery file by drag and drop or the system file picker (works on
 * phones: the button opens Files / Downloads). The file is read on this device
 * and never uploaded. */
export function RecoveryFileDrop({ onOpened, disabled = false }: Props) {
  const input = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState("");
  const hintId = useId(), errorId = useId();

  // A file dropped anywhere else must not make the browser navigate away to it.
  useEffect(() => {
    const stop = (event: DragEvent) => {
      // Other file inputs on the page keep their native drop behaviour.
      if (event.target instanceof HTMLInputElement && event.target.type === "file") return;
      if (event.dataTransfer?.types?.includes("Files")) event.preventDefault();
    };
    window.addEventListener("dragover", stop);
    window.addEventListener("drop", stop);
    return () => { window.removeEventListener("dragover", stop); window.removeEventListener("drop", stop); };
  }, []);

  const open = async (files: File[]) => {
    if (files.length === 0 || disabled) return;
    if (files.length > 1) { setError(MESSAGES.many); return; }
    setReading(true); setError("");
    try {
      const { readRecoveryFile } = await import("@/lib/confidential/recoveryFile");
      const parsed = await readRecoveryFile(files[0]).catch(() => undefined);
      if (parsed === undefined) setError(MESSAGES.unreadable);
      else if (parsed === null) setError(MESSAGES.notRecovery);
      else onOpened(parsed);
    } finally { setReading(false); }
  };

  return (
    <div>
      <div
        onDragEnter={event => { event.preventDefault(); if (!disabled) setDragging(true); }}
        onDragOver={event => { event.preventDefault(); event.dataTransfer.dropEffect = disabled ? "none" : "copy"; }}
        onDragLeave={event => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false); }}
        onDrop={event => { event.preventDefault(); setDragging(false); void open(Array.from(event.dataTransfer.files)); }}
        className="flex flex-col items-start gap-3 p-4 sm:flex-row sm:items-center"
        style={{ border: `1px dashed ${dragging ? "var(--vera-ink)" : "rgba(0,0,0,0.3)"}`,
          background: dragging ? "rgba(0,0,0,0.04)" : "transparent" }}
      >
        <button type="button" disabled={disabled || reading} onClick={() => input.current?.click()}
          aria-describedby={`${hintId}${error ? ` ${errorId}` : ""}`}
          className="inline-flex shrink-0 items-center gap-2 border border-black px-3 py-2 disabled:opacity-50"
          style={{ minHeight: 44 }}>
          <FileUp className="size-[14px]" aria-hidden />{reading ? "Reading file…" : "Open recovery file"}
        </button>
        <p id={hintId} style={{ fontSize: "12px", lineHeight: 1.6, color: "rgba(0,0,0,0.6)" }}>
          <span className="hidden sm:inline">Or drop it here. </span>
          The file is read on this device only. It is never uploaded.
        </p>
        <input ref={input} type="file" accept=".txt,text/plain" className="sr-only" tabIndex={-1} aria-hidden
          onChange={event => { const files = Array.from(event.target.files ?? []); event.target.value = ""; void open(files); }} />
      </div>
      {error && <p id={errorId} role="alert" className="mt-2 text-sm">{error}</p>}
    </div>
  );
}
