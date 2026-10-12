import type { ReleaseIdentity } from '@/lib/confidential/releaseIdentity';

/** The release a confidential submission is bound to. The exact identifiers sit
 * behind "Technical details" (as in ApproveUpdate): they are for people who want
 * to check the build, not something a reporter must read before submitting. */
export function ConfidentialReleaseIdentity({ identity }: { identity: ReleaseIdentity }) {
  return <div className="mb-4 max-w-[62ch] text-sm">
    <p className="mb-3">Your browser checks VERA’s secure service before sending.</p>
    <details>
      <summary className="cursor-pointer underline">Technical details</summary>
      <p className="mt-3">Submitting authorizes this exact release to process your encrypted report.</p>
      <dl className="mt-3 space-y-2">
        <div><dt className="font-semibold">Release ID</dt><dd className="break-all font-mono">{identity.digest}</dd></div>
        <div><dt className="font-semibold">Source commit</dt><dd className="break-all font-mono">
          <a className="underline" href={identity.sourceUrl} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{identity.sourceCommit}</a>
        </dd></div>
      </dl>
      <p className="mt-3 text-black/60">Your browser checks the secure service’s measurements against this release before
        sending. The source link is a declared build reference; source and build provenance need separate verification.
        The website itself is still delivered by VERA.</p>
    </details>
  </div>;
}
