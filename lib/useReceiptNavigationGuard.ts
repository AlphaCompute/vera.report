import { useEffect, useRef, useState } from 'react';
import type { NextRouter } from 'next/router';

export const EXPLICIT_PARTICIPANT_DISCARD = 'vera:explicit-participant-discard';
export const BEFORE_PRIVATE_DOCUMENT_NAVIGATION = 'vera:before-private-document-navigation';

/** Receipt capabilities remain in component memory, never in browser storage. */
export function useReceiptNavigationGuard(router: NextRouter, active: boolean) {
  const [pending, setPending] = useState<null | (() => void)>(null);
  const bypass = useRef(false);
  useEffect(() => {
    if (!active) { setPending(null); return; }
    const receiptUrl = window.location.href;
    const receiptState = window.history.state;
    const stays = (href: string) => {
      const url = new URL(href, window.location.href);
      const receipt = new URL(receiptUrl);
      return url.origin === receipt.origin && url.pathname === receipt.pathname && url.search === receipt.search;
    };
    let leavingDocument = false;
    const ask = (leave: () => void) => setPending(() => leave);
    const unload = (event: BeforeUnloadEvent) => {
      if (bypass.current) return;
      event.preventDefault(); event.returnValue = '';
    };
    const route = (url: string) => {
      if (bypass.current || stays(url)) return;
      ask(() => { void router.push(url); });
      const error = Object.assign(new Error('Receipt navigation cancelled'), { cancelled: true });
      router.events.emit('routeChangeError', error, url, { shallow: false });
      throw error;
    };
    const documentNavigation = (event: Event) => {
      const url = (event as CustomEvent<{ url: string }>).detail.url;
      if (stays(url)) return;
      // A confirmed router action can reach this event before its soft route is
      // cancelled. Keep the bypass until the actual document unload completes.
      if (bypass.current) { leavingDocument = true; return; }
      event.preventDefault();
      ask(() => { window.location.assign(url); });
    };
    const click = (event: MouseEvent) => {
      const a = event.target instanceof Element ? event.target.closest<HTMLAnchorElement>('a[href]') : null;
      if (!a || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || a.hasAttribute('download') || (a.target && a.target !== '_self') || stays(a.href) || bypass.current) return;
      event.preventDefault(); event.stopPropagation();
      ask(() => { window.location.assign(a.href); });
    };
    router.beforePopState(({ as }) => {
      if (bypass.current || stays(as)) return true;
      // The browser has moved its history pointer before invoking this callback.
      // Restore the receipt URL while its page remains mounted, then ask.
      window.history.pushState(receiptState, '', receiptUrl);
      ask(() => { void router.replace(as); });
      return false;
    });
    const explicitDiscard = () => { bypass.current = true; leavingDocument = true; setPending(null); };
    window.addEventListener(EXPLICIT_PARTICIPANT_DISCARD, explicitDiscard);
    const resetBypass = () => { if (!leavingDocument) bypass.current = false; };
    router.events.on('routeChangeStart', route);
    router.events.on('routeChangeComplete', resetBypass);
    router.events.on('routeChangeError', resetBypass);
    window.addEventListener(BEFORE_PRIVATE_DOCUMENT_NAVIGATION, documentNavigation);
    window.addEventListener('beforeunload', unload);
    document.addEventListener('click', click, true);
    return () => {
      window.removeEventListener(EXPLICIT_PARTICIPANT_DISCARD, explicitDiscard);
      router.beforePopState(() => true);
      router.events.off('routeChangeStart', route);
      router.events.off('routeChangeComplete', resetBypass);
      router.events.off('routeChangeError', resetBypass);
      window.removeEventListener(BEFORE_PRIVATE_DOCUMENT_NAVIGATION, documentNavigation);
      window.removeEventListener('beforeunload', unload);
      document.removeEventListener('click', click, true);
    };
  }, [router, active]);
  return {
    open: pending !== null,
    stay: () => setPending(null),
    leave: () => { const action = pending; setPending(null); bypass.current = true; action?.(); },
  };
}
