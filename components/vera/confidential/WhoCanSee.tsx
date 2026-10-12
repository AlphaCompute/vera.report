/** "Who can see what" for a confidential report, shown before Submit and on the
 * status page. Static facts from the disclosure boundary in
 * docs/security/README.md#trust-boundaries; nothing here is read from the
 * report. Colors derive from the surrounding text so it works on the dark
 * confirmation card and on the light or dark status page. */
export type Visibility = 'yes' | 'no' | 'if-allowed';
export type WhoCanSeeRow = { label: string; staff: Visibility; organizations: Visibility; you: Visibility };

export const WHO_CAN_SEE_ROWS: readonly WhoCanSeeRow[] = [
  { label: 'Your summary, submission time and whether attachments were included', staff: 'yes', organizations: 'yes', you: 'yes' },
  { label: 'Your full report', staff: 'no', organizations: 'if-allowed', you: 'yes' },
  { label: 'Your files', staff: 'no', organizations: 'if-allowed', you: 'yes' },
  { label: 'Your contact details', staff: 'no', organizations: 'if-allowed', you: 'yes' },
];
const WORDS: Record<Visibility, string> = {
  yes: 'Yes', no: 'No', 'if-allowed': 'Only if you allow',
};
const shade = (pct: number) => `color-mix(in srgb, currentColor ${pct}%, transparent)`;

function Cell({ value }: { value: Visibility }) {
  const mark = value === 'yes' ? '✓' : value === 'no' ? '–' : '◐';
  return (
    <td className="px-2 py-2 align-top sm:px-3">
      <span aria-hidden className="mr-1 inline-block w-3 text-center" style={{ color: shade(value === 'no' ? 40 : 90) }}>{mark}</span>
      <span style={{ color: shade(value === 'no' ? 55 : 85) }}>{WORDS[value]}</span>
    </td>
  );
}

export function WhoCanSee({ allowed, className = '' }: {
  /** Names of legal organizations the reporter allowed; omit before submission. */
  allowed?: readonly string[]; className?: string;
}) {
  return (
    <section aria-labelledby="who-can-see-title" className={className}>
      <h3 id="who-can-see-title" className="mb-3 font-semibold">Who can see what</h3>
      <p className="mb-3 bg-red-50 p-3 text-sm font-bold text-red-800">NOT CONFIDENTIAL: VERA administrators and approved legal organizations can read your summary, submission time and whether attachments were included. Do not include identifying details in the summary. Administrators can also see release approvals, encrypted-data sizes and activity timing.</p>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[17rem] border-collapse text-left text-sm">
          <thead>
            <tr style={{ borderBottom: `1px solid ${shade(25)}` }}>
              <th scope="col" className="py-2 pr-2 font-normal" style={{ color: shade(60) }}><span className="sr-only">Information</span></th>
              <th scope="col" className="px-2 py-2 font-semibold sm:px-3">VERA staff</th>
              <th scope="col" className="px-2 py-2 font-semibold sm:px-3">Legal organizations</th>
              <th scope="col" className="px-2 py-2 font-semibold sm:px-3">You</th>
            </tr>
          </thead>
          <tbody>
            {WHO_CAN_SEE_ROWS.map(row => (
              <tr key={row.label} style={{ borderBottom: `1px solid ${shade(12)}` }}>
                <th scope="row" className="py-2 pr-2 align-top font-normal">{row.label}</th>
                <Cell value={row.staff} /><Cell value={row.organizations} /><Cell value={row.you} />
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 max-w-[62ch] text-sm" style={{ color: shade(70) }}>
        {allowed === undefined
          ? 'Legal organizations are invited and checked by VERA. Each one sees your summary and those submission facts and can ask for more; only you decide.'
          : allowed.length
            ? `You allowed: ${allowed.join(', ')}. Every other legal organization sees only your summary and those submission facts.`
            : 'You have not allowed any legal organization to read more than your summary and those submission facts.'}
        {' '}Your report and files may still contain details that identify you. These protections depend on trusting the website VERA delivers.
        Organizations can keep information you already shared with them.
      </p>
    </section>
  );
}
