/** Show an error's own message only when it reads as plain guidance.
 *
 * Confidential screens surface the messages our code throws deliberately
 * ("This workspace backup is invalid"). Errors from libraries, the network or
 * storage can instead carry key IDs, armored blocks, file paths, URLs, JSON or
 * stack text; those are replaced with the caller's fallback, so no key material,
 * identifier or internal detail is put on screen (where it can be screenshotted,
 * copied into a support request or read by a browser extension).
 */
const MAX_LENGTH = 300;
const PLAIN = /^[A-Z][A-Za-z0-9 ,.;:'’()?!–—-]*$/;
const LONG_TOKEN = /[A-Za-z0-9_-]{24,}/;

export function userFacingMessage(error: unknown, fallback: string): string {
  if (!(error instanceof Error)) return fallback;
  const message = error.message;
  if (typeof message !== 'string' || !message || message.length > MAX_LENGTH ||
      !PLAIN.test(message) || LONG_TOKEN.test(message)) return fallback;
  return message;
}
