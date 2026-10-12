import { useEffect, useId, useState, useSyncExternalStore } from "react";
import { trustedNow } from "@/lib/confidential/attestedTime";
import { CONFIDENTIAL_RELEASE_MANIFEST } from "@/lib/confidential/config";
import type { ReleaseIdentity } from "@/lib/confidential/releaseIdentity";
import { lastVerification, subscribeVerification } from "@/lib/confidential/verificationRecord";
import type { VerificationRecord } from "@/lib/confidential/verificationRecord";

/** Build-time website commit (NEXT_PUBLIC_SOURCE_COMMIT); literal reference so Next inlines it. */
const WEBSITE_COMMIT = (process.env.NEXT_PUBLIC_SOURCE_COMMIT ?? "").trim();

export type Withdrawals = { configured: false } | { configured: true; checkedAt: number | null; expiresAt: number | null; paused: boolean };

export function formatVerifiedAt(at: number, now: number): string {
  const seconds = Math.max(0, Math.round((now - at) / 1000));
  const relative = seconds < 60 ? "just now" : seconds < 3600 ? `${Math.floor(seconds / 60)} min ago` : `${Math.floor(seconds / 3600)} h ago`;
  return `${new Date(at).toLocaleString()} (${relative})`;
}

/**
 * One "Security details" disclosure for the private screens (/report, /status,
 * /legal/*), per the architecture's UX section: website version and source, the
 * secure service release this device checks, and when this tab last verified it.
 * Shows public release data only: no report, organization or session identifier.
 */
export function SecurityDetails({ className = "" }: { className?: string }) {
  const regionId = useId();
  const [open, setOpen] = useState(false);
  const [identity, setIdentity] = useState<ReleaseIdentity | null | "invalid">(null);
  const [withdrawals, setWithdrawals] = useState<Withdrawals>({ configured: false });
  const [now, setNow] = useState(() => trustedNow());
  const verification = useSyncExternalStore<VerificationRecord | null>(subscribeVerification, lastVerification, () => null);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setNow(trustedNow());
    if (CONFIDENTIAL_RELEASE_MANIFEST) {
      void import("@/lib/confidential/releaseIdentity").then(module => module.releaseIdentity(CONFIDENTIAL_RELEASE_MANIFEST))
        .then(value => { if (!cancelled) setIdentity(value); }, () => { if (!cancelled) setIdentity("invalid"); });
    } else setIdentity("invalid");
    void import("@/lib/confidential/releaseWithdrawals").then(module => {
      if (cancelled) return;
      const state = module.releaseWithdrawalState();
      setWithdrawals(state.configured
        ? { configured: true, checkedAt: state.checkedAt, expiresAt: state.list?.expiresAt ?? null, paused: state.paused !== null }
        : { configured: false });
    }).catch(() => {});
    const timer = setInterval(() => setNow(trustedNow()), 30_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [open, verification]);

  return (
    <div className={`text-xs ${className}`}>
      <button type="button" className="underline underline-offset-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
        aria-expanded={open} aria-controls={regionId} onClick={() => setOpen(value => !value)}>
        Security details
      </button>
      {open && (
        <SecurityDetailsPanel id={regionId} identity={identity} verification={verification} withdrawals={withdrawals}
          websiteCommit={WEBSITE_COMMIT} now={now} />
      )}
    </div>
  );
}

export type SecurityDetailsState = {
  id?: string;
  identity: ReleaseIdentity | null | "invalid";
  verification: VerificationRecord | null;
  withdrawals: Withdrawals;
  websiteCommit: string;
  now: number;
};

/** Pure content of the disclosure (unit-tested with static rendering). */
export function SecurityDetailsPanel({ id, identity, verification, withdrawals, websiteCommit, now }: SecurityDetailsState) {
  const repository = identity && identity !== "invalid" ? identity.sourceUrl.replace(/\/commit\/[0-9a-f]+$/, "") : null;
  const verifiedCurrent = verification && identity && identity !== "invalid" && verification.releaseDigest === identity.digest;
  return (
    <section id={id} aria-label="Security details" className="mt-3 max-w-[62ch] border border-black/10 bg-white/60 p-4 text-left text-sm">
      <dl className="space-y-2">
        <div>
          <dt className="font-semibold">Website version</dt>
          <dd className="break-all">
            {websiteCommit
              ? repository
                ? <a className="underline" href={`${repository}/commit/${websiteCommit}`} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{websiteCommit.slice(0, 12)}</a>
                : <span className="font-mono">{websiteCommit.slice(0, 12)}</span>
              : "Not recorded in this build"}
          </dd>
        </div>
        <div>
          <dt className="font-semibold">Source</dt>
          <dd className="break-all">
            {repository ? <a className="underline" href={repository} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{repository}</a> : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt className="font-semibold">Secure service release</dt>
          <dd className="break-all">
            {identity === null ? "Loading…" : identity === "invalid" ? "This build has no valid release. Nothing can be sent." : (
              <>
                <span className="font-mono">{identity.digest}</span>
                <span className="block">Built from <a className="underline" href={identity.sourceUrl} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{identity.sourceCommit.slice(0, 12)}</a></span>
              </>
            )}
          </dd>
        </div>
        <div>
          <dt className="font-semibold">Last verified on this device</dt>
          <dd>
            {verification
              ? <>{formatVerifiedAt(verification.verifiedAt, now)}{verifiedCurrent ? "" : ` against release ${verification.releaseDigest.slice(0, 12)}…`}</>
              : "Not yet in this tab. The secure service is checked each time something is sent or opened."}
          </dd>
        </div>
        <div>
          <dt className="font-semibold">Release withdrawal check</dt>
          <dd>
            {!withdrawals.configured ? "Not configured for this build."
              : withdrawals.paused ? "Paused: this release is withdrawn or could not be confirmed."
                : withdrawals.checkedAt ? `Current${withdrawals.expiresAt ? ` (list valid until ${new Date(withdrawals.expiresAt).toLocaleDateString()})` : ""}.`
                  : "Checked before the next secure connection."}
          </dd>
        </div>
      </dl>
      <p className="mt-3 text-black/70">
        Each connection checks the secure service&apos;s hardware measurements against this release before anything leaves
        your device. Source links are declared build references; this page itself is still delivered by the VERA website.
      </p>
    </section>
  );
}
