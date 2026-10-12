import { type ListingDraft } from "@/lib/confidential/listingDraft";
import { CONTACT_LABELS, type ReportContacts } from "@/lib/reportContacts";
import { CONFIDENTIAL_SUMMARY_LIMIT } from "@/lib/confidential/config";

/** Editable final review, with the published summary clearly distinguished. */
export function ConfidentialReview({ description, files, contacts, draft, onDescriptionChange, onContactsChange, onDraftChange }: {
  description: string; files: File[]; contacts: ReportContacts; draft: ListingDraft;
  onDescriptionChange: (value: string) => void;
  onContactsChange: (value: ReportContacts) => void;
  onDraftChange: (value: ListingDraft) => void;
}) {
  const field = "mt-2 w-full border border-black/25 bg-white p-3 text-base";
  return (
    <div className="mb-8 space-y-8">
      <label className="block font-semibold">What happened
        <textarea aria-label="What happened, full text" data-testid="review-description" className={`${field} h-48 resize-none overflow-y-auto font-normal`}
          value={description} onChange={event => onDescriptionChange(event.target.value)} spellCheck={false} autoComplete="off" />
      </label>
      <div>
        <h3 className="mb-2 font-semibold">Files</h3>
        {files.length === 0 ? <p>None</p> : <ul className="space-y-1">{files.map((file, index) =>
          <li key={`${file.name}-${index}`} className="break-all">{file.name}</li>)}</ul>}
      </div>
      <fieldset>
        <legend className="mb-2 font-semibold">Contact details</legend>
        <p className="mb-3 text-sm">Add at least one. Encrypted; only you can see them unless you later share them with a specific legal organization.</p>
        <div className="grid gap-4 sm:grid-cols-3">
          {(Object.keys(CONTACT_LABELS) as (keyof ReportContacts)[]).map(method => <label key={method} className="block text-sm">
            {CONTACT_LABELS[method]}
            <input className={field} type={method === 'email' ? 'email' : 'text'} value={contacts[method]}
              maxLength={250} autoComplete="off" autoCapitalize="off" spellCheck={false}
              onChange={event => onContactsChange({ ...contacts, [method]: event.target.value })} />
          </label>)}
        </div>
      </fieldset>
      <div>
        <label className="block text-sm">Summary for legal review
          <span className="mt-2 block text-sm font-bold text-red-800">VERA administrators and legal organizations can read this text.</span>
          <textarea aria-label="Summary for legal review" className={`${field} min-h-36`} value={draft.summary} maxLength={CONFIDENTIAL_SUMMARY_LIMIT}
            spellCheck={false} autoComplete="off" onChange={event => onDraftChange({ ...draft, summary: event.target.value })} />
        </label>
      </div>
    </div>
  );
}
