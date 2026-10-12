/**
 * Minimal leveled logger.
 *
 * Routes to the console under the hood, so CloudWatch (and any stdout/stderr
 * collector) still captures everything — but gates output by `LOG_LEVEL`, so
 * production can silence debug/info noise without losing the ability to turn
 * it back on (set `LOG_LEVEL=debug`).
 *
 * Levels (low → high): debug < info < warn < error. A message prints when its
 * level is >= the configured level. Default: `info` (debug is silent).
 *
 *   logger.debug(...)  // verbose / high-frequency — silent by default
 *   logger.info(...)   // operational milestones — visible by default
 *   logger.warn(...)   // recoverable problems
 *   logger.error(...)  // failures
 *
 * `LOG_LEVEL=silent` disables everything except explicit console usage.
 */

export function redactCapabilities(value: string): string {
  return value.replace(/(?:VRA-[a-f0-9]{16,64}|VRC-[a-f0-9]{64})/gi, '[REPORT-REDACTED]')
    .replace(/\bv[23]\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[CAPABILITY-REDACTED]')
    // Confidential cases: owner and firm recovery codes, OpenPGP ciphertext/keys
    // and bearer tokens (legal/onboarding JWTs) must never reach a log line.
    .replace(/VERA-[A-Z]+-\d+\.[A-Za-z0-9._~+/=-]+/g, '[RECOVERY-REDACTED]')
    // Current short recovery codes: 14 groups of 4 base32 characters (a mistyped
    // code with groups missing or added still counts), or the same run ungrouped.
    .replace(/\b[0-9A-Za-z]{4}(?:-[0-9A-Za-z]{4}){9,17}\b/g, '[RECOVERY-REDACTED]')
    .replace(/\b[0-9A-HJKMNP-TV-Z]{56}\b/g, '[RECOVERY-REDACTED]')
    .replace(/-----BEGIN PGP [A-Z ]+-----[\s\S]*?(?:-----END PGP [A-Z ]+-----|$)/g, '[PGP-REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, '[TOKEN-REDACTED]');
}

function scrub(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value === 'string') return redactCapabilities(value);
  if (value instanceof Error) return { name: value.name, message: redactCapabilities(value.message) };
  if (Buffer.isBuffer(value)) return '[Binary data]';
  if (value && typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
    if (Array.isArray(value)) return value.map(v => scrub(v, seen));
    return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, SENSITIVE_KEY.test(k) ? '[REDACTED]' : scrub(v, seen)]));
  }
  return value;
}

type Level = 'debug' | 'info' | 'warn' | 'error';
type Configured = Level | 'silent';

const ORDER: Record<Configured, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 99,
};

function configuredLevel(): Configured {
  const raw = process.env.LOG_LEVEL?.trim().toLowerCase();
  if (raw && raw in ORDER) return raw as Configured;
  return 'info';
}

function enabled(level: Level): boolean {
  return ORDER[level] >= ORDER[configuredLevel()];
}

const SENSITIVE_KEY = /^(password|secret|token|authorization|cookie|mnemonic|privateKey|contactValue|description|narrative|evidence|buffer|recoveryCode|recoveryPackage|stateKey|ciphertext|accessToken|proof|invitation|passphrase)$/i;

function jsonLine(level: Level, args: unknown[]): string {
  const seen = new WeakSet<object>();
  const message = typeof args[0] === 'string' ? args[0] : 'Log event';
  const context = typeof args[0] === 'string' ? args.slice(1) : args;
  try {
    return JSON.stringify({ timestamp: new Date().toISOString(), level, message, context }, (key, value: unknown) => {
      if (SENSITIVE_KEY.test(key)) return '[REDACTED]';
      if (typeof value === 'bigint') return value.toString();
      if (value && typeof value === 'object') {
        if (seen.has(value)) return '[Circular]';
        seen.add(value);
        if (value instanceof Error) return { name: value.name, message: value.message, stack: value.stack };
        if (Buffer.isBuffer(value) || (value as { type?: string }).type === 'Buffer') return '[Binary data]';
      }
      return value;
    });
  } catch {
    // Logging must not turn an application failure into a second exception.
    return JSON.stringify({ timestamp: new Date().toISOString(), level, message, context: '[Unserializable]' });
  }
}

function write(level: Level, args: unknown[]): void {
  if (!enabled(level)) return;
  args = args.map(value => scrub(value));
  const output = level === 'debug' || level === 'info' ? console.log : console[level];
  if (process.env.LOG_FORMAT === 'json') output(jsonLine(level, args));
  else output(...args);
}

export const logger = {
  debug: (...args: unknown[]): void => write('debug', args),
  info: (...args: unknown[]): void => write('info', args),
  warn: (...args: unknown[]): void => write('warn', args),
  error: (...args: unknown[]): void => write('error', args),
};
