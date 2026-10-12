import { privateRequest } from '../src/utils/requestPrivacy';
/** Aggregate operational signals only: no identity, URLs, messages or report data. */
export function installBrowserTelemetry(): () => void {
  const originalFetch = window.fetch;
  const sendFetch = originalFetch.bind(window);
  let sent = 0;
  let windowStart = Date.now();
  const send = (kind: string, value = 1) => {
    if (privateRequest(location.pathname)) return;
    if (Date.now() - windowStart >= 60000) { sent = 0; windowStart = Date.now(); }
    if (sent >= 10 || !Number.isFinite(value) || value < 0 || value > 300000) return;
    const page = ['/', '/report', '/status', '/admin', '/monitoring'].includes(location.pathname)
      ? location.pathname : '/';
    sent++;
    void sendFetch('/api/monitoring/client', {
      method: 'POST', credentials: 'omit', referrerPolicy: 'no-referrer', keepalive: true,
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind, page, value }),
    }).catch(() => { /* Telemetry failures must not interfere with reporting. */ });
  };
  const onError = () => send('exception');
  const onRejection = () => send('rejection');
  window.addEventListener('error', onError);
  window.addEventListener('unhandledrejection', onRejection);
  const wrappedFetch: typeof window.fetch = async (...args) => {
    // Only count first-party API requests, never inspect bodies or credentials.
    let tracked = false;
    try {
      const input = args[0];
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, location.origin);
      tracked = url.origin === location.origin && url.pathname.startsWith('/api/') && url.pathname !== '/api/monitoring/client' && !privateRequest(url.pathname);
    } catch { /* Leave validation to the original fetch. */ }
    try {
      const response = await originalFetch.apply(window, args);
      if (tracked && !response.ok) send('request_failure');
      return response;
    } catch (error) {
      if (tracked) send('request_failure');
      throw error;
    }
  };
  window.fetch = wrappedFetch;
  const recordLoad = () => {
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
    if (navigation && navigation.loadEventEnd > 0) send('page_load', navigation.loadEventEnd);
  };
  let loadTimer = window.setTimeout(recordLoad, 0);
  const onLoad = () => { window.clearTimeout(loadTimer); loadTimer = window.setTimeout(recordLoad, 0); };
  window.addEventListener('load', onLoad);
  let observer: PerformanceObserver | undefined;
  try {
    observer = new PerformanceObserver(list => {
      const entries = list.getEntries();
      const last = entries[entries.length - 1];
      if (last) send('lcp', last.startTime);
    });
    observer.observe({ type: 'largest-contentful-paint', buffered: true });
  } catch { /* Older browsers can still report errors and navigation timing. */ }
  return () => {
    window.removeEventListener('error', onError);
    window.removeEventListener('unhandledrejection', onRejection);
    window.removeEventListener('load', onLoad);
    window.clearTimeout(loadTimer);
    observer?.disconnect();
    if (window.fetch === wrappedFetch) window.fetch = originalFetch;
  };
}
