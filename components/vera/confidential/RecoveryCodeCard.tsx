import { recoveryQrText } from '@/lib/confidential/recoveryLink';
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { createPortal, flushSync } from "react-dom";
import { Check, Copy, Printer } from "lucide-react";
import { encodeQr, qrSvgPath } from "@/lib/qrCode";
import { createClipboardGuard } from "@/lib/confidential/clipboard";
import type { ClipboardClearState } from "@/lib/confidential/clipboard";
import { formatRecoveryCode, recoveryCodeGroups, recoveryCodeShape } from "@/enclave/src/confidential/recoveryCode";
import { RECOVERY_FILE_NAME } from "@/lib/confidential/recoveryFile";
import { RecoveryFileDownload } from './RecoveryFileDownload';

const button = "inline-flex items-center gap-2 border border-black px-3 py-2 disabled:opacity-50";
export const CLIPBOARD_TEXT: Record<Exclude<ClipboardClearState, "idle">, string> = {
  copied: "Copied. For your safety, we will clear your clipboard in 1 minute while this page stays open.",
  cleared: "Your clipboard was cleared.",
  "clear-failed": "We could not clear your clipboard. Copy something else to replace the recovery code.",
};

/** Local-only QR for the printable recovery sheet: encoded on this device, never sent. */
function RecoveryQr({ text, size = 176, label }: { text: string; size?: number; label: string }) {
  const matrix = useMemo(() => encodeQr(text, "M"), [text]);
  const dim = matrix.size + 8;
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${dim} ${dim}`} width={size} height={size}
      shapeRendering="crispEdges" style={{ background: "#fff", maxWidth: "100%", height: "auto" }}>
      <rect width={dim} height={dim} fill="#fff" />
      <path d={qrSvgPath(matrix)} fill="#000" />
    </svg>
  );
}

/** The code in numbered groups of four, so a typing mistake can be pointed at by group. */
export function RecoveryCodeGroups({ code, large = false }: { code: string; large?: boolean }) {
  const labelId = useId();
  if (recoveryCodeShape(code) === "v1") {
    return <p className="vera-doc-id break-all select-all" style={{ fontSize: large ? "14px" : "13px", color: "#000" }}>{code}</p>;
  }
  const groups = recoveryCodeGroups(code);
  return (
    <div>
      <span id={labelId} className="sr-only">Recovery code, {groups.length} groups of four characters</span>
      <ol aria-labelledby={labelId} className="grid grid-cols-4 gap-x-3 gap-y-2 sm:grid-cols-7" style={{ listStyle: "none", padding: 0, margin: 0 }}>
        {groups.map((value, index) => (
          <li key={index} className="flex flex-col">
            <span aria-hidden className="text-black/50" style={{ fontSize: "10px" }}>{index + 1}</span>
            <span className="vera-doc-id" style={{ fontSize: large ? "18px" : "clamp(0.95rem, 1.2vw, 1.1rem)", color: "#000", letterSpacing: "0.12em" }}>
              {value}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

/** Printable recovery sheet: code, QR code and plain instructions. Rendered only
 * while printing, as a direct child of <body> so print CSS can hide the page. */
function RecoverySheet({ code, statusUrl }: { code: string; statusUrl: string }) {
  const qr = recoveryQrText(statusUrl, code);
  return createPortal(
    <div className="vera-print-sheet" style={{ color: "#000", background: "#fff", padding: "24px", fontSize: "13px", lineHeight: 1.5 }}>
      <h1 style={{ fontSize: "22px", fontWeight: 600, marginBottom: "4px" }}>VERA recovery sheet</h1>
      <p style={{ marginBottom: "16px" }}>Keep this page private. Anyone who has it can open your report and act for you.
        VERA cannot reset or replace your recovery code.</p>
      <h2 style={{ fontSize: "14px", fontWeight: 600, marginBottom: "8px" }}>Recovery code</h2>
      <RecoveryCodeGroups code={code} large />
      <div style={{ display: "flex", gap: "24px", alignItems: "flex-start", marginTop: "20px" }}>
        <div style={{ flex: "0 0 auto" }}><RecoveryQr text={qr.text} size={160} label={qr.link ? "QR code to open your report" : "QR code of your recovery code"} /></div>
        <ol style={{ listStyle: "decimal", paddingLeft: "20px", margin: 0 }}>
          <li>Go to the VERA status page: {statusUrl}</li>
          {qr.link
            ? <li>Scan the QR code with your phone camera to open your report, or enter the recovery code on the status page.</li>
            : <li>Type the recovery code, or scan the QR code with your phone camera to copy it. Do not search for, open or share the scanned text.</li>}
          <li>Your recovery code is checked on your device. It is never sent to VERA.</li>
          <li>If VERA&apos;s online copy of your encrypted backup is ever lost, you also need your recovery file ({RECOVERY_FILE_NAME}).</li>
        </ol>
      </div>
    </div>,
    document.body,
  );
}

type Props = {
  recoveryCode: string;
  /** Prepares the offline recovery file locally. Omit to hide the download. */
  prepareDownload?: () => string | Promise<string>;
  onDownload?: () => void;
  heading?: string;
};

/** Shows a recovery code with copy (auto-cleared), print and download. Everything
 * happens on this device; nothing here makes a network request. */
export function RecoveryCodeCard({ recoveryCode, prepareDownload, onDownload, heading = "Your recovery code" }: Props) {
  const [clipboard, setClipboard] = useState<ClipboardClearState>("idle");
  const [copyError, setCopyError] = useState(false);
  const [printing, setPrinting] = useState(false);
  const [manualCopy, setManualCopy] = useState(false);
  const copyField = useRef<HTMLInputElement>(null);
  const guard = useRef<ReturnType<typeof createClipboardGuard> | null>(null);
  const afterPrint = useRef<(() => void) | null>(null);
  const headingId = useId();
  const code = formatRecoveryCode(recoveryCode);

  useEffect(() => {
    guard.current = createClipboardGuard(setClipboard);
    return () => guard.current?.detach();
  }, []);
  useEffect(() => () => {
    document.body.classList.remove("vera-printing-sheet");
    if (afterPrint.current) window.removeEventListener("afterprint", afterPrint.current);
  }, []);

  const print = () => {
    // Render the sheet synchronously so the print call keeps the click's user activation.
    flushSync(() => setPrinting(true));
    document.body.classList.add("vera-printing-sheet");
    if (afterPrint.current) window.removeEventListener("afterprint", afterPrint.current);
    const done = () => {
      document.body.classList.remove("vera-printing-sheet");
      window.removeEventListener("afterprint", done);
      afterPrint.current = null;
      setPrinting(false);
    };
    afterPrint.current = done;
    window.addEventListener("afterprint", done);
    window.print();
  };

  const copy = async () => {
    setCopyError(false);
    // Keep a clean, selectable code visible even when an embedded browser
    // reports a clipboard write without making it available to other apps.
    flushSync(() => setManualCopy(true));
    copyField.current?.select();
    const ok = await guard.current?.copy(code);
    if (!ok) setCopyError(true);
  };

  return (
    <section aria-labelledby={headingId} className="mb-4">
      <h3 id={headingId} className="mb-2 font-semibold">{heading}</h3>
      <RecoveryCodeGroups code={code} />
      <p className="mt-3 max-w-[62ch] text-sm">Copy this private access key to return without typing it. The code needs VERA’s online encrypted backup; download the recovery file for offline recovery too.</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <button type="button" onClick={() => void copy()} className={button}>
          {clipboard === "copied" ? <Check className="size-[14px]" aria-hidden /> : <Copy className="size-[14px]" aria-hidden />}
          {clipboard === "copied" ? "Copied" : "Copy"}
        </button>
        <button type="button" onClick={print} className={button}>
          <Printer className="size-[14px]" aria-hidden />Print recovery sheet
        </button>
      </div>
      <p aria-live="polite" className="mt-3 text-sm">{clipboard !== "idle" ? CLIPBOARD_TEXT[clipboard] : ""}</p>
      {copyError && <p role="alert" className="mt-1 text-sm">Copy failed. Select the code below and copy it manually, or save the recovery file.</p>}
      <details className="mt-2 text-sm" open={manualCopy} onToggle={event => setManualCopy(event.currentTarget.open)}>
        <summary className="cursor-pointer underline">Copy not working? Select the code</summary>
        <label className="mt-3 block">Recovery code to copy
          <input ref={copyField} readOnly spellCheck={false} autoComplete="off" value={code}
            onFocus={event => event.currentTarget.select()}
            className="mt-2 block w-full border border-black/30 p-3 font-mono text-sm" />
        </label>
        <p className="mt-2">Select this field and press Ctrl+C (Command+C on Mac), then paste into your private saved note.
          It contains only the code, without group numbers or labels. Replace your clipboard afterward.</p>
      </details>
      {prepareDownload && <div className="mt-4"><RecoveryFileDownload prepare={prepareDownload} onDownload={onDownload} className={button} /></div>}
      <p className="mt-2 max-w-[62ch] text-xs text-black/60">
        Print only on a printer you trust: shared or office printers may keep a copy, and &quot;Save as PDF&quot; creates a file on this device.
      </p>
      {printing && <RecoverySheet code={code} statusUrl={`${window.location.origin}/status`} />}
    </section>
  );
}
