import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { selectLegalCase, selectedLegalCase } from './legalCaseSelection';
export { clearSelectedLegalCase, selectLegalCase, selectedLegalCase } from './legalCaseSelection';

/** Which report the legal portal opens.
 *
 * The case ID never travels in a path or query: those reach CDN, load-balancer,
 * WAF and server request logs next to the firm's network address
 * (docs/security/README.md#trust-boundaries: no firm linkage in URLs or
 * logs). The portal's own navigation also keeps it out of fragments, so it is not
 * left in browser history either: the selection is held in tab-scoped
 * sessionStorage (never sent to a server, cleared when the tab closes; memory
 * only when storage is blocked), and `/legal/report` has no identifier at all.
 * A fragment link (`/legal/report#<caseId>`) is still accepted from older
 * bookmarks: it is moved into the selection and removed from the URL at once.
 */
const CASE_ID = /^[a-f0-9]{64}$/;
export const LEGAL_CASE_PATH = '/legal/report';

export function caseIdFromFragment(hash: string): string | null {
  const value = hash.startsWith('#') ? hash.slice(1) : hash;
  return CASE_ID.test(value) ? value : null;
}

/** Opens a report with no identifier in any URL. */
export function openLegalCase(router: { push(url: string): Promise<boolean> }, caseId: string): Promise<boolean> {
  selectLegalCase(caseId);
  return router.push(LEGAL_CASE_PATH);
}

/** The report this tab selected. A fragment link is moved into the tab
 * selection and removed from the URL, so the ID does not stay in the address bar
 * or history or get reloaded. */
export function useLegalCaseId(): { ready: boolean; caseId: string | null } {
  const router = useRouter();
  const [state, setState] = useState<{ ready: boolean; caseId: string | null }>({ ready: false, caseId: null });
  useEffect(() => {
    if (!router.isReady) return;
    const read = () => {
      const linked = caseIdFromFragment(window.location.hash);
      if (linked) {
        selectLegalCase(linked);
        // Drop the fragment from this history entry without a navigation.
        window.history.replaceState(window.history.state, '', LEGAL_CASE_PATH);
      }
      setState({ ready: true, caseId: linked ?? selectedLegalCase() });
    };
    read();
    window.addEventListener('hashchange', read);
    // Next's same-page hash links use pushState, which emits no native hashchange.
    router.events.on('hashChangeComplete', read);
    return () => {
      window.removeEventListener('hashchange', read);
      router.events.off('hashChangeComplete', read);
    };
  }, [router, router.isReady]);
  return state;
}
