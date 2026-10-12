/**
 * Collapse newlines and other control characters in a value before it is written
 * to a log line, so an externally-influenced string (an upstream API response,
 * an error message carrying user input) cannot forge additional log entries —
 * log injection / "log forging" (OWASP A09). Also bounds the length so a large
 * value can't flood the log.
 *
 * Removes C0 controls (including CR, LF and tab), DEL, the C1 controls, and the
 * Unicode line/paragraph separators, collapsing any run of them into one space.
 * Implemented by code point so the source carries no literal control characters.
 */
export function oneLine(value: unknown, max = 500): string {
  let out = '';
  let prevWasControl = false;
  for (const ch of String(value)) {
    const c = ch.codePointAt(0) ?? 0;
    const isControl =
      c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029;
    if (isControl) {
      if (!prevWasControl) out += ' ';
      prevWasControl = true;
    } else {
      out += ch;
      prevWasControl = false;
    }
    // Stop once the log budget is filled; do not copy the rest of an
    // arbitrarily large upstream response just to discard it below.
    if (out.length >= max) break;
  }
  if (out.length <= max) return out;

  // slice() cuts by UTF-16 code unit, so a naive truncation can land between a
  // surrogate pair and leave a lone surrogate, which is not valid text and can
  // render as a replacement character in a log viewer. Drop a trailing unpaired
  // high surrogate so the result stays well formed.
  const cut = out.slice(0, max);
  const last = cut.charCodeAt(cut.length - 1);
  return last >= 0xd800 && last <= 0xdbff ? cut.slice(0, -1) : cut;
}
