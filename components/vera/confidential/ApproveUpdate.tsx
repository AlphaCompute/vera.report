import type { ReactNode } from 'react';
import type { ReleaseUpdate } from '@/lib/confidential/releaseUpdate';
import { releaseChangeSentence } from '@/lib/confidential/releaseUpdateCopy';
import { formatDay } from '@/lib/confidential/formatDay';

const shade = (pct: number) => `color-mix(in srgb, currentColor ${pct}%, transparent)`;

/** Contextual consent to one exact backend release (never a standing control). */
export function ApproveUpdate({ update, busy, onApprove, onLater, children }: {
  update: ReleaseUpdate; busy: boolean; onApprove: () => void; onLater: () => void; children?: ReactNode;
}) {
  return (
    <section aria-labelledby="approve-update-title">
      <h2 id="approve-update-title" className="mb-4 text-lg font-semibold">Approve update</h2>
      <h3 className="mb-1 text-sm font-semibold">What changed</h3>
      <p className="mb-1 max-w-[62ch]">{releaseChangeSentence(update)}</p>
      {update.notes && (
        <p className="mb-4 text-sm" style={{ color: shade(60) }}>
          Description from VERA{update.notes.publishedAt ? `, released ${formatDay(Date.parse(`${update.notes.publishedAt}T12:00:00Z`))}` : ''}.
          It is not part of what your browser verifies.
        </p>
      )}
      <h3 className="mb-1 mt-4 text-sm font-semibold">If you don’t approve</h3>
      <p className="mb-4 max-w-[62ch]">
        This new version cannot open your report until you approve it. You and the legal organizations you allowed
        cannot use this version to read the report or requests. Previously approved versions and copies
        already received are unaffected. You can decide later.
      </p>
      {update.previous && (
        <p className="mb-4 text-sm" style={{ color: shade(70) }}>You last approved an update on {formatDay(update.previous.approvedAt)}.</p>
      )}
      <details className="mb-6 max-w-[62ch] text-sm">
        <summary className="cursor-pointer underline">Technical details</summary>
        <dl className="mt-3 space-y-2">
          <div><dt className="font-semibold">Release ID</dt><dd className="break-all font-mono">{update.releaseDigest}</dd></div>
          <div><dt className="font-semibold">Source commit</dt><dd className="break-all font-mono">
            <a className="underline" href={update.sourceUrl} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{update.sourceCommit}</a>
          </dd></div>
          {update.notes?.publishedAt && <div><dt className="font-semibold">Release date (from VERA)</dt><dd>{update.notes.publishedAt}</dd></div>}
          <div><dt className="font-semibold">Enclave measurements</dt><dd className="break-all font-mono text-xs">
            PCR0 {update.measurements.pcr0}<br />PCR1 {update.measurements.pcr1}<br />PCR2 {update.measurements.pcr2}
          </dd></div>
          {update.previous && <div><dt className="font-semibold">Previously approved release</dt>
            <dd className="break-all font-mono">{update.previous.releaseDigest} <span className="font-sans">({formatDay(update.previous.approvedAt)})</span></dd></div>}
        </dl>
        <p className="mt-3" style={{ color: shade(70) }}>
          Your browser checks the secure service’s measurements against this release before it can open your report. The
          source link is a declared build reference; source and build provenance need separate verification. The website
          itself is still delivered by VERA.
        </p>
      </details>
      <div className="flex flex-wrap gap-3">
        <button type="button" disabled={busy} className="border border-current bg-[var(--vera-ink)] px-4 py-2 text-[var(--vera-paper)] disabled:opacity-50"
          onClick={onApprove}>{busy ? 'Approving…' : 'Approve update'}</button>
        <button type="button" disabled={busy} className="border border-current px-4 py-2" onClick={onLater}>Not now</button>
      </div>
      {children}
    </section>
  );
}
