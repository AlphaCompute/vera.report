import { useEffect, useState } from 'react';
import type { FirmSession, OpenedCase } from '@/lib/confidential/firmCase';

/** Mounted only alongside a successfully opened report. Browsing summaries and
 * checking access cannot generate a view confirmation. */
export function ReportOpenAcknowledgement({ session, opened }: { session: FirmSession; opened: OpenedCase }) {
  const [status, setStatus] = useState<'sending' | 'recorded' | 'failed'>('sending');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!opened.narrative) return;
    let active = true;
    setStatus('sending');
    void import('@/lib/confidential/firmCase').then(async client => {
      if (active) await client.acknowledgeReportOpen(session, opened);
    }).then(() => { if (active) setStatus('recorded'); }, () => { if (active) setStatus('failed'); });
    return () => { active = false; };
  }, [session, opened, attempt]);
  if (!opened.narrative || status === 'sending') return null;
  return <p className="text-sm text-black/65" role="status">
    {status === 'recorded' ? 'The reporter can see that your organization opened this report.'
      : <>The report is open, but its opening confirmation could not be saved. <button type="button"
        className="min-h-11 font-semibold underline underline-offset-4" onClick={() => setAttempt(value => value + 1)}>Retry confirmation</button></>}
  </p>;
}
