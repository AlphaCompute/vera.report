// Etc/GMT uses inverted signs: +5 is fixed EST (UTC−05:00), without DST.
const EST_TIME_ZONE = 'Etc/GMT+5';

export function getBrowserTimeZone(): string {
  if (typeof window === 'undefined') return EST_TIME_ZONE;
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || EST_TIME_ZONE;
  } catch {
    return EST_TIME_ZONE;
  }
}

/** Format timestamp values fetched on the client, consistently across admin. */
export function formatBrowserDateTime(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    timeZoneName: 'short',
  };
  try {
    return date.toLocaleString(undefined, { ...options, timeZone: getBrowserTimeZone() });
  } catch {
    return date.toLocaleString(undefined, { ...options, timeZone: EST_TIME_ZONE });
  }
}
