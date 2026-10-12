import { useEffect, useState } from 'react';
import { FileText, LockKeyhole } from 'lucide-react';
import type { OwnerInbox, OwnerReport, OwnerSession } from '@/lib/confidential/ownerCase';
import { caseDocument } from '@/lib/confidential/firmCaseView';
import type { DocumentField } from '@/lib/confidential/firmCaseView';

function Fields({ fields }: { fields: DocumentField[] }) {
  return <dl className="grid gap-4 sm:grid-cols-2">
    {fields.map((field, index) => <div key={`${field.label}:${index}`} className="min-w-0">
      <dt className="text-sm text-black/60">{field.label}</dt>
      <dd className="mt-1 whitespace-pre-wrap break-words leading-7">{field.value}</dd>
    </div>)}
  </dl>;
}

export function OwnerReportDocument({ report }: { report: OwnerReport }) {
  const document = caseDocument(report.narrative, report.records);
  const details = [...document.dates, ...document.place, ...document.about, ...document.other];
  const recordTitles: Record<string, string> = {
    'Contact details shared by the reporter': 'Your contact details',
    'Identity shared by the reporter': 'Your identity details',
  };
  return <div className="divide-y divide-[#e2e7df]">
    <section className="py-6" aria-labelledby="your-account-title">
      <h3 id="your-account-title" className="mb-4 text-base font-semibold text-[#243d2e]">What you reported</h3>
      <p className="max-w-[70ch] whitespace-pre-wrap break-words text-base leading-8 text-[#26352c]">
        {document.account || 'You did not include a written account.'}
      </p>
    </section>
    {details.length > 0 && <section className="py-6" aria-labelledby="your-details-title">
      <h3 id="your-details-title" className="mb-4 text-base font-semibold text-[#243d2e]">Report details</h3>
      <Fields fields={details} />
    </section>}
    {document.records.map((record, index) => <details key={index} className="py-5">
      <summary className="cursor-pointer font-semibold text-[#243d2e]">{recordTitles[record.title] ?? record.title}</summary>
      <div className="pt-4"><Fields fields={record.fields} /></div>
    </details>)}
  </div>;
}

/** This reader is independent of sharing controls: an interrupted text read
 * offers a retry without hiding the report's access or recovery controls. */
export function OwnerReportView({ session, inbox }: { session: OwnerSession; inbox: OwnerInbox }) {
  const [state, setState] = useState<{ kind: 'loading' | 'error' } | { kind: 'ready'; report: OwnerReport }>({ kind: 'loading' });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    setState({ kind: 'loading' });
    void import('@/lib/confidential/ownerCase').then(owner => owner.readOwnerReport(session, inbox))
      .then(report => { if (active) setState({ kind: 'ready', report }); }, () => { if (active) setState({ kind: 'error' }); });
    return () => { active = false; };
  }, [session, inbox, attempt]);
  return <article id="your-report" aria-labelledby="your-report-title" className="min-w-0 scroll-mt-24 rounded-lg border border-[#dce3d9] bg-white px-6 pt-6 sm:px-8 sm:pt-8">
    <header className="border-b border-[#e2e7df] pb-6">
      <p className="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-[#526654]">
        <LockKeyhole size={15} aria-hidden="true" />Private report
      </p>
      <h2 id="your-report-title" className="flex items-center gap-3 font-serif text-3xl text-[#203c2c]">
        <FileText size={24} strokeWidth={1.5} aria-hidden="true" />Your submitted report
      </h2>
      <p className="mt-3 max-w-[65ch] text-sm leading-relaxed text-black/65">The details you submitted, opened on this device. Firms can read only what you choose to share.</p>
    </header>
    {state.kind === 'loading' && <p role="status" className="py-8 text-sm">Opening your report…</p>}
    {state.kind === 'error' && <div role="alert" className="py-6">
      <p className="text-sm">Your report details could not be loaded. Your saved report has not changed.</p>
      <button type="button" onClick={() => setAttempt(value => value + 1)} className="mt-3 min-h-11 text-sm font-semibold underline underline-offset-4">Try opening the report again</button>
    </div>}
    {state.kind === 'ready' && <OwnerReportDocument report={state.report} />}
  </article>;
}
