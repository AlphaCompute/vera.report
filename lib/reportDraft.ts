/** Steps where the reporter has started writing the report and has not yet
 * sent it. Leaving the page on any of them discards the draft, which lives only
 * in this tab's memory. */
const DRAFT_STEPS = new Set(['report', 'files', 'details', 'jurisdiction', 'summary', 'confirm', 'contact', 'rewards-contact', 'category']);

export interface ReportDraftContent {
  description: string;
  typed: string;
  files: number;
  summary: string;
  /** Contact methods typed so far (the legacy flow asks for them first). */
  contacts: Readonly<Record<string, string>>;
}

/** Whether reloading, closing or navigating away would throw away work the
 * reporter typed or attached. An untouched form never prompts. */
export function reportDraftAtRisk(step: string, draft: ReportDraftContent): boolean {
  if (!DRAFT_STEPS.has(step)) return false;
  return draft.description.trim() !== '' || draft.typed.trim() !== '' || draft.files > 0 || draft.summary.trim() !== ''
    || Object.values(draft.contacts).some(value => value.trim() !== '');
}
