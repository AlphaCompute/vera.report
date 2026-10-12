/**
 * Log sanitizer — prevents log forging / log injection (OWASP A09, OX #395).
 * A value that carries CR/LF must not be able to start a new log line.
 * Control characters are built via char code so this source stays clean.
 */
import { oneLine } from '../../../lib/logSanitize';

const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);
const TAB = String.fromCharCode(9);

describe('oneLine', () => {
  it('collapses newlines and tabs to a single space', () => {
    expect(oneLine(`a${LF}b`)).toBe('a b');
    expect(oneLine(`a${CR}${LF}b`)).toBe('a b'); // run collapsed
    expect(oneLine(`a${TAB}b`)).toBe('a b');
  });

  it('defeats a log-forging payload (no newline survives)', () => {
    const forged = `ok${CR}${LF}[Users API] admin deleted by attacker`;
    const cleaned = oneLine(forged);
    expect(cleaned).not.toContain(LF);
    expect(cleaned).not.toContain(CR);
    expect(cleaned).toBe('ok [Users API] admin deleted by attacker');
  });

  it('leaves ordinary text untouched', () => {
    expect(oneLine('hello world 123')).toBe('hello world 123');
  });

  it('bounds the length', () => {
    expect(oneLine('x'.repeat(1000), 10)).toHaveLength(10);
  });

  it('handles non-string input', () => {
    expect(oneLine(null)).toBe('null');
    expect(oneLine(42)).toBe('42');
    expect(oneLine(undefined)).toBe('undefined');
  });
});

describe('oneLine truncation is surrogate-safe', () => {
  it('does not leave a lone high surrogate when the cut lands mid-pair', () => {
    // Each astral character is two UTF-16 code units, so an odd max forces the
    // cut between a surrogate pair.
    const out = oneLine('𝄞'.repeat(10), 5);

    expect(out.length).toBe(4);
    expect(/[\uD800-\uDBFF]$/.test(out)).toBe(false);
    expect([...out]).toHaveLength(2);
  });

  it('still truncates to the bound for plain text', () => {
    expect(oneLine('a'.repeat(100), 10)).toBe('a'.repeat(10));
  });

  it('leaves input shorter than the bound untouched', () => {
    expect(oneLine('short', 500)).toBe('short');
  });
});


describe('oneLine bounded processing', () => {
  it('stops consuming a large response after filling the log budget', () => {
    const originalIterator = String.prototype[Symbol.iterator];
    let consumed = 0;
    const payload = 'x'.repeat(100_000);
    const iterator = jest.spyOn(String.prototype, Symbol.iterator).mockImplementation(function* (this: string) {
      for (const ch of originalIterator.call(this)) {
        consumed++;
        yield ch;
      }
    });
    let result: string;
    try {
      result = oneLine(payload, 500);
    } finally {
      iterator.mockRestore();
    }
    expect(result!).toBe('x'.repeat(500));
    expect(consumed).toBe(500);
  });

  it('preserves control collapsing and a surrogate-safe boundary', () => {
    expect(oneLine('a\r\n𝄞tail', 3)).toBe('a ');
    expect(oneLine('a\r\n𝄞tail', 4)).toBe('a 𝄞');
  });
});
