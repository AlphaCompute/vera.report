import { useState } from "react";
import Link from "next/link";
import { RememberWorkspace } from "./DeviceWorkspaces";
import { panel, primaryButton, secondaryButton } from "./LegalPortal";
import type { UnlockedVault } from "@/lib/confidential/deviceVault";

/** An approved device has enrolled automatically. Save its credentials before
 * continuing so a lost tab does not require device approval again. */
export function ApprovedDevice({ notice, vault, onRemembered, getPayload, initiallyBackedUp = false }: {
  notice: string; vault: UnlockedVault | null; onRemembered: (vault: UnlockedVault) => void | Promise<void>;
  getPayload: () => Promise<unknown>; initiallyBackedUp?: boolean;
}) {
  const [backedUp, setBackedUp] = useState(initiallyBackedUp);
  const kept = vault !== null || backedUp;
  return (
    <section className={panel} aria-labelledby="approved-title">
      <h2 id="approved-title" className="mb-3 font-semibold">Your device is approved</h2>
      <p className="mb-3 max-w-[62ch]">{notice}</p>
      {kept ? (
        <p className="mb-4 max-w-[62ch] text-sm" data-step="ready">Your membership is ready. Open your workspace to view submissions and request access.</p>
      ) : (
        <div className="mb-4 max-w-[62ch] text-sm" data-step="keep">
          <h3 className="mb-2 font-semibold">Keep this workspace before you continue</h3>
          <p className="font-bold text-red-800">Your organization key is only open in this tab. Keep this workspace on this device or download a backup first.
            If you close this page without one, you will need your steward to approve this device again.</p>
        </div>
      )}
      {/* Stays after saving: it confirms how the copy opens and offers a portable backup. */}
      <RememberWorkspace role="legal" vault={vault} onRemembered={saved => void onRemembered(saved)}
        onBackedUp={() => setBackedUp(true)} getPayload={getPayload} />
      <div className="mt-4 flex flex-wrap items-center gap-3">
        {kept ? <>
          <Link className={primaryButton} href="/legal">Open workspace</Link>
        </> : <>
          <button type="button" className={secondaryButton} disabled aria-describedby="workspace-locked">Open workspace</button>
          <p id="workspace-locked" className="text-sm text-black/70">Keep this workspace on this device or download a backup to continue.</p>
        </>}
      </div>
    </section>
  );
}
