import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { AlertDialog, AlertDialogContent, AlertDialogTitle, AlertDialogDescription } from "@/components/ui/alert-dialog";
import { createClipboardGuard } from "@/lib/confidential/clipboard";
import type { ClipboardClearState } from "@/lib/confidential/clipboard";
import { formatRecoveryCode } from "@/enclave/src/confidential/recoveryCode";
import { CLIPBOARD_TEXT, RecoveryCodeGroups } from "./RecoveryCodeCard";

export const RECOVERY_LEAVE_TITLE = "Save your recovery code before leaving";
export const RECOVERY_LEAVE_DESCRIPTION =
  "Leaving or closing this page clears the recovery code shown here. You have not checked a saved recovery file yet. Without a saved code or saved device access, you permanently lose access: you cannot read your report, " +
  "see requests from legal organizations or decide who may access it. VERA cannot reset or recover it.";

type Guard = Pick<ReturnType<typeof createClipboardGuard>, "copy">;

/** Copies through the auto-clearing clipboard guard, never a plain clipboard write. */
export function copyRecoveryCode(guard: Guard | null, recoveryCode: string): Promise<boolean> {
  return guard ? guard.copy(formatRecoveryCode(recoveryCode)) : Promise.resolve(false);
}

type BodyProps = {
  recoveryCode: string;
  clipboard: ClipboardClearState;
  copyError: boolean;
  onCopy: () => void;
  onStay: () => void;
  onLeave: () => void;
};

/** Dialog body: the grouped code, a guarded copy and the two ways out. */
export function RecoveryLeaveBody({ recoveryCode, clipboard, copyError, onCopy, onStay, onLeave }: BodyProps) {
  const copyField = useRef<HTMLInputElement>(null);
  return (
    <>
      <RecoveryCodeGroups code={formatRecoveryCode(recoveryCode)} />
      <label className="block text-sm">Recovery code to copy
        <input ref={copyField} readOnly spellCheck={false} autoComplete="off" value={formatRecoveryCode(recoveryCode)}
          onFocus={event => event.currentTarget.select()} className="mt-2 block w-full border border-black/30 p-3 font-mono text-sm" />
      </label>
      <button type="button" className="inline-flex items-center justify-center gap-2 rounded bg-black px-4 py-3 text-white"
        onClick={() => { copyField.current?.select(); onCopy(); }}>
        {clipboard === "copied" ? <Check className="size-[14px]" aria-hidden /> : <Copy className="size-[14px]" aria-hidden />}
        {clipboard === "copied" ? "Copied" : "Copy recovery code"}
      </button>
      <p aria-live="polite" className="text-sm">{clipboard !== "idle" ? CLIPBOARD_TEXT[clipboard] : ""}</p>
      {copyError && <p role="alert" className="text-sm">Copy failed. Select the field above and press Ctrl+C (Command+C on Mac), or write the code down before leaving.</p>}
      <p className="text-xs text-black/60">Copying alone is not a backup. Write the code down, print the recovery sheet or download the recovery file.</p>
      <button type="button" className="rounded border px-4 py-2" onClick={onStay}>Stay on this page</button>
      <button type="button" className="rounded border px-4 py-2" onClick={onLeave}>I saved my recovery code, leave</button>
    </>
  );
}

type Props = { open: boolean; recoveryCode: string; onStay: () => void; onLeave: () => void };

/** Leave-page warning for a confidential report. It never mentions a Report ID:
 * the recovery code is the only credential on this path. */
export function RecoveryLeaveDialog({ open, recoveryCode, onStay, onLeave }: Props) {
  const [clipboard, setClipboard] = useState<ClipboardClearState>("idle");
  const [copyError, setCopyError] = useState(false);
  const guard = useRef<ReturnType<typeof createClipboardGuard> | null>(null);
  useEffect(() => {
    guard.current = createClipboardGuard(setClipboard);
    // A pending clear still runs after detach while the page stays open.
    return () => guard.current?.detach();
  }, []);
  const copy = async () => {
    setCopyError(false);
    if (!(await copyRecoveryCode(guard.current, recoveryCode))) setCopyError(true);
  };
  return (
    <AlertDialog open={open} onOpenChange={(value) => { if (!value) onStay(); }}>
      <AlertDialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto">
        <AlertDialogTitle className="font-bold text-red-800">{RECOVERY_LEAVE_TITLE}</AlertDialogTitle>
        <AlertDialogDescription className="font-bold text-red-800">{RECOVERY_LEAVE_DESCRIPTION}</AlertDialogDescription>
        <RecoveryLeaveBody recoveryCode={recoveryCode} clipboard={clipboard} copyError={copyError}
          onCopy={() => void copy()} onStay={onStay} onLeave={onLeave} />
      </AlertDialogContent>
    </AlertDialog>
  );
}
