import { StatusBadge, panel } from "@/components/vera/confidential/LegalPortal";
import { formatDate } from "@/lib/confidential/firmCaseView";
import type { RememberedRequest } from "@/lib/confidential/firmWorkspace";

export const ENDED_REQUEST_STATUS = "Unavailable until your membership is renewed";

/** The organization's requests while its membership has ended. Read-only and
 * offline: it shows only the copy already decrypted on this device, makes no
 * status, directory or open calls (the enclave refuses them without a live
 * membership), and offers no withdraw, remove or renewal controls. */
export function EndedMembershipRequests({ requests }: { requests: readonly RememberedRequest[] }) {
  const ordered = [...requests].sort((a, b) => b.requestedAt - a.requestedAt);
  return (
    <section aria-labelledby="ended-requests-title" className="space-y-4">
      <h2 id="ended-requests-title" className="font-semibold">Your organization&apos;s requests</h2>
      <p className="max-w-[62ch] text-sm text-black/60">
        Your membership has ended (see the notice above), so reports cannot be opened, requested or checked from here.
        {ordered.length > 0
          ? " This is this device's saved copy of your organization's requests. Their current status appears again once you accept a new invitation."
          : " This device has no saved requests for your organization. Your organization's requests appear here again once you accept a new invitation."}
      </p>
      {ordered.length > 0 && (
        <ul className="space-y-4">
          {ordered.map(item => (
            <li key={item.caseId} className={panel}>
              <div className="mb-2"><StatusBadge label={ENDED_REQUEST_STATUS} tone="neutral" /></div>
              <p className="mb-3 whitespace-pre-wrap break-words">{item.summary}</p>
              <p className="text-sm text-black/50">Requested {formatDate(item.requestedAt)}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
