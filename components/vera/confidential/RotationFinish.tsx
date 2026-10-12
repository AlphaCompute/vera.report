import { useEffect, useRef } from "react";
import { primaryButton, secondaryButton } from "@/components/vera/confidential/LegalPortal";

/** Shown when this device's saved workspace could not switch to the new key.
 * The saved copy still holds the old key, so unlocking it again would not work
 * for the new key; the steward must keep the new key file. */
export const WORKSPACE_NOT_UPDATED =
  "This device's saved workspace could not be updated and still holds the old key. Keep the new key file: " +
  "after you lock, unlock with the new key file and its recovery code, not your device passphrase. " +
  "Try again, or download the key file and lock anyway.";

/** Switches this device's saved workspace to the new key, then locks every tab.
 * Returns the message to show when the workspace could not be updated; the tab
 * then stays unlocked so the steward can keep the new key file first. */
export async function finishRotation(replaceWorkspace: () => Promise<unknown>, lock: () => void): Promise<string | null> {
  try { await replaceWorkspace(); }
  catch { return WORKSPACE_NOT_UPDATED; }
  lock();
  return null;
}

/** Last step of a key replacement: Finish and lock, and when the saved
 * workspace could not be updated, the error with the key file and Lock anyway. */
export function RotationFinish({ savedWorkspace, sent, busy, error, onFinish, onDownloadKey, onLockAnyway }: {
  savedWorkspace: boolean; sent: boolean; busy: boolean; error: string | null;
  onFinish: () => void; onDownloadKey: () => void; onLockAnyway: () => void;
}) {
  const alert = useRef<HTMLDivElement | null>(null);
  useEffect(() => { if (error) alert.current?.focus(); }, [error]);
  return (
    <div className="mt-6 border-t border-black/10 pt-4">
      <p className="mb-3 max-w-[62ch] text-sm">When you finish, this device switches to the new key{savedWorkspace ? " in its saved workspace" : ""} and locks.
        {savedWorkspace ? " Unlock it again with your device passphrase." : " Unlock it again with the new key file and its recovery code."}</p>
      {!sent && <p className="mb-3 text-sm text-red-800">Send the new key first, or the other lawyers keep using the old one.</p>}
      <button type="button" className={primaryButton} disabled={busy || !sent} onClick={onFinish}>
        {busy ? "Finishing…" : error ? "Try again" : "Finish and lock"}
      </button>
      {error && <div ref={alert} tabIndex={-1} role="alert" className="mt-4 border border-red-700 p-4 text-sm text-red-800">
        <p className="mb-3 max-w-[62ch]">{error}</p>
        <div className="flex flex-wrap gap-3">
          <button type="button" className={secondaryButton} onClick={onDownloadKey}>Download the key file</button>
          <button type="button" className="underline" disabled={busy} onClick={onLockAnyway}>Lock anyway</button>
        </div>
      </div>}
    </div>
  );
}
