/** Day-precision date for participant-facing copy. Kept free of cryptographic
 * imports so pages can use it without bundling openpgp statically. */
export function formatDay(value: number): string {
  return new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}
