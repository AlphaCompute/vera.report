import { formatRecoveryCode, recoveryCodeShape } from '../../enclave/src/confidential/recoveryCode';
import { qrFits } from '../qrCode';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** A recovery code is a bearer credential: only put it in a link that opens over
 * HTTPS. Plain HTTP is accepted for a local development host only. */
function secureStatusUrl(origin: string): URL | null {
  let url: URL;
  try { url = new URL('/status', origin); } catch { return null; }
  if (url.protocol === 'https:') return url;
  return url.protocol === 'http:' && LOCAL_HOSTS.has(url.hostname) ? url : null;
}

/** Fragment credentials are consumed locally, never placed in a query or request path. */
export function recoveryLink(origin: string, code: string): string {
  const url = secureStatusUrl(origin);
  if (!url || !recoveryCodeShape(code)) throw new Error('Invalid recovery link');
  url.hash = new URLSearchParams({ recovery: formatRecoveryCode(code) }).toString();
  return url.href;
}

/** What the printed QR code holds: a link that opens the report when the origin
 * is secure and the link fits the local QR encoder, otherwise the code itself. */
export function recoveryQrText(origin: string, code: string): { text: string; link: boolean } {
  const url = secureStatusUrl(origin);
  if (url && recoveryCodeShape(code)) {
    const link = recoveryLink(origin, code);
    if (qrFits(link, 'M')) return { text: link, link: true };
  }
  return { text: formatRecoveryCode(code), link: false };
}

export function takeRecoveryLink(location: Pick<Location, 'hash' | 'pathname' | 'search'>, history: Pick<History, 'replaceState' | 'state'>): string | null {
  const params = new URLSearchParams(location.hash.slice(1));
  if (!params.has('recovery')) return null;
  // Keep the router's state on this entry; only the fragment is removed.
  history.replaceState(history.state, '', location.pathname + location.search);
  if (location.pathname !== '/status' || params.getAll('recovery').length !== 1 || [...params.keys()].some(key => key !== 'recovery')) return '';
  const code = params.get('recovery') ?? '';
  return code.length <= 256 ? code : '';
}
