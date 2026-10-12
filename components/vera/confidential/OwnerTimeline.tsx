import { useState } from 'react';
import { ArrowDown, CheckCircle2, FileText, LockKeyhole, Eye } from 'lucide-react';
import type { OwnerJourney, OwnerTimeline as Timeline, TimelineEvent } from '@/lib/confidential/ownerTimeline';

const shade = (pct: number) => `color-mix(in srgb, currentColor ${pct}%, transparent)`;
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;

/** Separate the public summary from access the reporter has explicitly granted. */
export function OwnerJourneyHeader({ journey, requestsAnchor, closed = false }: { journey: OwnerJourney; requestsAnchor?: string; closed?: boolean }) {
  const steps = [
    { title: 'Your report', label: closed ? 'Closed' : 'Submitted', detail: 'Read the private details you submitted.', href: '#your-report', action: 'Read your report', icon: FileText },
    { title: 'Public summary', label: !closed && journey.visible ? 'Summary published' : 'Hidden from law firms',
      detail: !closed && journey.visible ? 'Legal organizations can see your summary, not your private report.' : 'Your summary is hidden from the directory.', icon: Eye },
    { title: 'Private access', label: !closed && journey.sharedWith ? `Shared with ${plural(journey.sharedWith, 'legal organization')}` : 'Not shared with anyone',
      detail: !closed && journey.sharedWith ? 'Each organization can open only what you allowed.' : 'Only you can open your private report.', icon: LockKeyhole },
  ];
  return (
    <nav aria-label="Your report at a glance" className="space-y-4">
      <ol className="grid gap-3 sm:grid-cols-3">
        {steps.map(({ title, label, detail, href, action, icon: Icon }) => (
          <li key={title} className="min-w-0 border border-black/10 bg-white p-5">
            <p className="mb-4 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-black/60">
              <Icon aria-hidden="true" size={17} strokeWidth={1.6} />{title}
            </p>
            <p className="font-semibold leading-snug">{label}</p>
            <p className="mt-2 text-sm leading-relaxed text-black/60">{detail}</p>
            {href && <a href={href} className="mt-3 inline-flex min-h-11 items-center text-sm font-semibold text-[#243d2e] underline underline-offset-4">{action}</a>}
          </li>
        ))}
      </ol>
      {!closed && journey.requests > 0 ? (
        <div className="flex flex-wrap items-center justify-between gap-4 border border-[#dcc99a] bg-[#fcf8ed] px-5 py-4">
          <div>
            <p className="font-semibold">{plural(journey.requests, 'request')} waiting</p>
            <p className="mt-1 text-sm text-black/70">Review each request before deciding what to share.</p>
          </div>
          {requestsAnchor && <a href={`#${requestsAnchor}`} className="inline-flex items-center gap-2 text-sm font-semibold underline underline-offset-4">
            Review requests <ArrowDown aria-hidden="true" size={16} />
          </a>}
        </div>
      ) : <p className="flex items-center gap-2 text-sm text-black/60"><CheckCircle2 aria-hidden="true" size={17} />{closed ? 'Requests and sharing are stopped.' : 'No requests waiting'}</p>}
    </nav>
  );
}

const INITIAL = 6;

export function OwnerTimeline({ timeline }: { timeline: Timeline }) {
  const [all, setAll] = useState(false);
  const shown = all ? timeline.events : timeline.events.slice(0, INITIAL);
  return (
    <section id="report-activity" className="scroll-mt-24" aria-labelledby="timeline-title">
      <h3 id="timeline-title" className="mb-1 font-semibold">Activity</h3>
      <ol className="relative ml-2 border-l pl-5" style={{ borderColor: shade(15) }}>
        {shown.map(event => (
          <li key={event.id} className="relative pb-5 last:pb-0">
            <span aria-hidden className="absolute -left-[27px] top-1.5 h-2.5 w-2.5 rounded-full"
              style={{ background: event.kind === 'request' || event.kind === 'access-revoked' ? 'currentColor' : shade(45) }} />
            <p className="font-medium">{event.title}</p>
            <p className="text-xs" style={{ color: shade(55) }}>
              <time dateTime={new Date(event.at).toISOString()}>
                {new Date(event.at).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' })}
              </time>

            </p>
            {event.detail && <p className="mt-1 max-w-[62ch] text-sm" style={{ color: shade(75) }}>{event.detail}</p>}
          </li>
        ))}
      </ol>
      {timeline.events.length > INITIAL && (
        <button type="button" className="mt-4 text-sm underline" aria-expanded={all} onClick={() => setAll(value => !value)}>
          {all ? 'Show recent events only' : `Show all ${timeline.events.length} events`}
        </button>
      )}
      {timeline.incomplete && (
        <p className="mt-4 max-w-[62ch] text-sm" style={{ color: shade(70) }}>
          Some details of earlier events could not be verified, so they are not shown.
        </p>
      )}
    </section>
  );
}
