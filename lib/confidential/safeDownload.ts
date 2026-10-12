/** Hand decrypted evidence to the operating system, never to this origin.
 *
 * The bytes and the file name come from another participant, so both are
 * untrusted. The blob is always `application/octet-stream` behind an `<a download>`
 * (the browser saves it and does not render or sniff it here), and the name is
 * reduced to a plain, portable file name.
 */
export const OPAQUE_DOWNLOAD_TYPE = 'application/octet-stream';
const MAX_NAME = 120;
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;

export function safeDownloadName(name: unknown, fallback = 'download'): string {
  let value = typeof name === 'string' ? name : '';
  // A name, not a path: keep only the last segment of either separator style.
  value = value.split(/[\\/]/).pop() ?? '';
  // ASCII letters, digits, dot, dash, underscore and space only: removes path
  // separators, control and bidirectional-override characters and quotes.
  value = value.normalize('NFKC').replace(/[^\w.\- ]+/g, '_').replace(/\s+/g, ' ');
  // No hidden files, no trailing dots or spaces (Windows strips them, which can
  // change the extension the user sees), no bare "." or "..".
  value = value.replace(/^[\s.]+/, '').replace(/[\s.]+$/, '');
  if (!value || /^_+$/.test(value)) value = fallback;
  if (WINDOWS_RESERVED.test(value)) value = `_${value}`;
  if (value.length > MAX_NAME) {
    const dot = value.lastIndexOf('.');
    const extension = dot > 0 && value.length - dot <= 16 ? value.slice(dot) : '';
    value = value.slice(0, MAX_NAME - extension.length).replace(/[\s.]+$/, '') + extension;
  }
  return value;
}
