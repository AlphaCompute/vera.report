import type { ReactNode } from 'react';
import { OWNER_FAILURE_COPY } from '@/lib/confidential/failureCopy';
import type { OwnerFailure } from '@/lib/confidential/failureCopy';

const shade = (pct: number) => `color-mix(in srgb, currentColor ${pct}%, transparent)`;

/** One distinct message and next step per failure; a failed verification is
 * visibly different because it may indicate an attack. */
export function ConfidentialFailure({ reason, children }: { reason: OwnerFailure; children?: ReactNode }) {
  const copy = OWNER_FAILURE_COPY[reason];
  return (
    <div role="alert" data-failure={reason} className="p-6"
      style={{ border: `${copy.severity === 'danger' ? 2 : 1}px solid ${shade(copy.severity === 'notice' ? 15 : copy.severity === 'warning' ? 35 : 90)}` }}>
      {copy.severity === 'danger' && (
        <p className="mb-2 text-xs font-semibold uppercase tracking-widest">Possible security problem</p>
      )}
      <h2 className="mb-2 text-lg font-semibold">{copy.title}</h2>
      <p className="mb-3 max-w-[62ch]">{copy.body}</p>
      <h3 className="mb-1 text-sm font-semibold">What to do</h3>
      <ul className="mb-5 max-w-[62ch] list-disc pl-5 text-sm" style={{ color: shade(80) }}>
        {copy.steps.map(step => <li key={step}>{step}</li>)}
      </ul>
      <div className="flex flex-wrap items-center gap-3">{children}</div>
    </div>
  );
}
