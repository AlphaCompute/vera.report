import { CONTACT_LABELS, suppliedContacts, type ReportContacts } from '@/lib/reportContacts';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { EMPTY_SUBMITTER_DISCLOSURE, SUBMITTER_CONSENT_TEXT, type SubmitterDisclosureInput } from '@/src/utils/submitterDisclosure';

export function SubmitterDisclosureFields({ value, onChange, contacts }: {
  value: SubmitterDisclosureInput;
  contacts?: ReportContacts;
  onChange: (updates: Partial<SubmitterDisclosureInput>) => void;
}) {
  const anonymous = value.submitterMode === 'anonymous';
  const inputClass = 'mt-2 block min-h-11 w-full rounded-none border border-white/50 bg-black px-3 py-2 text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white disabled:cursor-not-allowed';
  const radioClass = 'mt-0.5 size-4 shrink-0 appearance-none rounded-full border border-white bg-black checked:bg-white checked:shadow-[inset_0_0_0_3px_#000] focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-white';
  return <fieldset className="min-w-0 space-y-5">
    <legend className="sr-only">Your identity in the report</legend>
    <p className="text-sm">Choose whether authorized recipients can see your name and contact details. Private reward contacts are not included automatically.</p>
    <label className="flex cursor-pointer items-start gap-3 leading-5">
      <input className={radioClass} type="radio" name="submitterMode" value="anonymous" checked={value.submitterMode === 'anonymous'}
        onChange={() => onChange({ ...EMPTY_SUBMITTER_DISCLOSURE })} />
      Keep my name and contact details out of the report
    </label>
    <label className="flex cursor-pointer items-start gap-3 leading-5">
      <input className={radioClass} type="radio" name="submitterMode" value="identified" checked={value.submitterMode === 'identified'}
        onChange={() => onChange({ submitterMode: 'identified', submitterConsent: false, ...(contacts ? { submitterContactMethod: 'multiple', submitterContactValue: Object.entries(suppliedContacts(contacts)).map(([key, value]) => `${CONTACT_LABELS[key as keyof ReportContacts]}: ${value}`).join('; ') } : {}) })} />
      Include my name and contact details
    </label>
    <fieldset disabled={anonymous} className={`min-w-0 space-y-5 transition-opacity ${anonymous ? "opacity-35" : "opacity-100"}`}>
      <legend className="sr-only">Contact details</legend>
      <label className="block" htmlFor="submitter-name">Submitter name
        <input id="submitter-name" className={inputClass} autoComplete="off" maxLength={120} value={value.submitterName}
          onChange={e => onChange({ submitterName: e.target.value })} />
      </label>
      {contacts ? <dl className="space-y-2 text-sm">{Object.entries(suppliedContacts(contacts)).map(([key, contact]) => <div key={key}>
        <dt>{CONTACT_LABELS[key as keyof ReportContacts]}</dt><dd className="break-all">{contact}</dd>
      </div>)}</dl> : <>
      <div>
        <label className="block" htmlFor="submitter-method">Preferred contact method</label>
        <Select disabled={anonymous} value={value.submitterContactMethod}
          onValueChange={method => onChange({ submitterContactMethod: method as SubmitterDisclosureInput['submitterContactMethod'], submitterContactValue: '', submitterConsent: false })}>
          <SelectTrigger id="submitter-method" className="mt-2 min-h-11 rounded-none border-white/50 bg-black text-white focus-visible:border-white focus-visible:ring-white/50 [&_svg]:text-white">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="rounded-none border-white/50 bg-black text-white" style={{ borderColor: 'rgba(255,255,255,0.5)' }}>
            {([
              ['email', 'Email'],
              ['phone', 'Phone'],
              ['encrypted', 'Secure contact (Signal or iMessage)'],
            ] as const).map(([method, label]) => (
              <SelectItem key={method} value={method} className="rounded-none focus:bg-white focus:text-black data-[highlighted]:bg-white data-[highlighted]:text-black [&_svg]:text-current">
                {label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <label className="block" htmlFor="submitter-contact">Contact details to include in the report
        <input id="submitter-contact" className={inputClass} autoComplete="off" maxLength={500}
          type={value.submitterContactMethod === 'email' ? 'email' : value.submitterContactMethod === 'phone' ? 'tel' : 'text'}
          value={value.submitterContactValue} onChange={e => onChange({ submitterContactValue: e.target.value })} />
      </label>
      </>}
      <label className="flex items-start gap-2 text-sm">
        <input className="mt-0.5 size-4 shrink-0 accent-white" type="checkbox" checked={value.submitterConsent} onChange={e => onChange({ submitterConsent: e.target.checked })} />
        {SUBMITTER_CONSENT_TEXT}
      </label>
    </fieldset>
  </fieldset>;
}
