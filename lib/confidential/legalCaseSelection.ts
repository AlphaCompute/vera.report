/** Tab-scoped selection of the report the legal portal opens (see
 * ./legalCaseLink.ts). Held in sessionStorage, which is never sent to a server
 * and is cleared when the tab closes; memory only when storage is blocked. Kept
 * free of React and Next imports so it can be used and tested anywhere. */
const CASE_ID = /^[a-f0-9]{64}$/;
const SELECTION_KEY = 'vera-legal-open-case';
let memory: string | null = null;

function tabStorage(): Storage | null {
  try { return typeof window === 'undefined' ? null : window.sessionStorage; } catch { return null; }
}

export function selectLegalCase(caseId: string): void {
  if (!CASE_ID.test(caseId)) throw new Error('Invalid case reference');
  memory = caseId;
  try { tabStorage()?.setItem(SELECTION_KEY, caseId); } catch { /* Memory selection still works in this tab. */ }
}

export function selectedLegalCase(): string | null {
  let stored: string | null = null;
  try { stored = tabStorage()?.getItem(SELECTION_KEY) ?? null; } catch { stored = null; }
  const value = stored ?? memory;
  return value && CASE_ID.test(value) ? value : null;
}

export function clearSelectedLegalCase(): void {
  memory = null;
  try { tabStorage()?.removeItem(SELECTION_KEY); } catch { /* Nothing stored. */ }
}
