import { importFirmIdentity } from '../../../lib/confidential/firmKey';

// Traffic recording and secret-leak checks for the click-through suite. Kept
// free of Playwright runtime imports so the unit suite can exercise it.

/** The request surface recordTraffic reads (a Playwright Request). */
type SentRequest = { url(): string; headers(): Record<string, string>; postDataBuffer(): Buffer | null };
/** A Playwright Page or BrowserContext: both emit 'request'. */
type RequestSource = { on(event: 'request', listener: (request: SentRequest) => void): unknown };

/**
 * Everything sent from a page or, for a BrowserContext, from every page it has
 * or opens later: URLs, headers and bodies, for sentinel checks. Recording a
 * context covers pages that replace one another (a steward's new tab, a
 * lawyer's invitation tab) without having to remember each one.
 */
export function recordTraffic(source: RequestSource, into: string[] = []): string[] {
  source.on('request', request => {
    into.push(request.url());
    into.push(JSON.stringify(request.headers()));
    const body = request.postDataBuffer();
    if (body) into.push(body.toString('latin1'));
  });
  return into;
}

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const SECRET_BYTES = 32;

/** The 256-bit secret inside a v2 recovery code (Crockford base32, checksum dropped). */
function recoverySecret(code: string): Buffer | null {
  const chars = code.replace(/[\s\-_]+/g, '').toUpperCase();
  if (!/^[0-9A-HJKMNP-TV-Z]{56}$/.test(chars)) return null;
  const out: number[] = [];
  let bits = 0, value = 0;
  for (const char of chars) {
    value = (value << 5) | ALPHABET.indexOf(char); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; value &= (1 << bits) - 1; }
  }
  return Buffer.from(out.slice(0, SECRET_BYTES));
}

/**
 * Every form a recovery code could leave the device in: as shown, upper and
 * lower case, with and without group separators, and the decoded secret as hex,
 * base64, base64url and raw bytes (bodies are recorded as latin1).
 */
export function recoveryCodeForms(code: string): string[] {
  const bare = code.replace(/[\s\-_]+/g, '');
  const forms = new Set<string>();
  for (const value of [code, bare, code.replace(/[\s\-_]+/g, ' ')]) {
    forms.add(value); forms.add(value.toUpperCase()); forms.add(value.toLowerCase());
    forms.add(encodeURIComponent(value));
  }
  const secret = recoverySecret(code);
  if (secret) {
    const hex = secret.toString('hex');
    for (const value of [hex, hex.toUpperCase(), secret.toString('base64'), secret.toString('base64url'), secret.toString('latin1')]) forms.add(value);
  }
  return [...forms].filter(value => value.length >= 16);
}

/**
 * The secrets a recovery file holds: its code in every form, and the file as a
 * whole. The encrypted backup line is the same ciphertext the host already
 * stores, so it is not a secret by itself.
 */
export function recoveryFileSecrets(file: string, code: string): string[] {
  const lines = file.split(/\r?\n/).map(line => line.trim());
  const at = lines.indexOf('Recovery code:');
  const codeLine = at >= 0 ? lines.slice(at + 1).find(Boolean) : undefined;
  return [...new Set([...recoveryCodeForms(code), ...(codeLine ? recoveryCodeForms(codeLine) : []), file.trim()])];
}

/** Check the private key itself as well as its container, including a key sent
 * alone in a JSON request. Public organization metadata is not a secret. Only
 * the encrypted export is a valid organization key file. */
export async function organizationKeyFileSecrets(file: string, code: string): Promise<string[]> {
  // Decrypt on the test driver so leaks of the raw key remain detectable even
  // when the downloaded backup itself contains only ciphertext.
  const firm = await importFirmIdentity(file, code);
  const privateKey = firm.privateKey.armor();
  return [file, ...recoveryCodeForms(code), privateKey, JSON.stringify(privateKey).slice(1, -1), encodeURIComponent(privateKey)];
}

/** The secrets found anywhere in the recorded traffic (empty when none leaked). */
export function leakedSecrets(traffic: string[], secrets: string[]): string[] {
  const sent = traffic.join('\n');
  return [...new Set(secrets.filter(secret => secret && sent.includes(secret)))];
}

// ---------------------------------------------------------------------------
// Teardown sweep of what the host kept: its logs and its database.
//
// Browser traffic checks prove what participants sent. Architecture acceptance
// test 7 also requires that no plaintext, recovery code or key material turns
// up in logs, queues or stored object metadata. Specs register every sentinel
// and device secret they guard (registerHostSecrets); global teardown scans the
// Next log, the API and enclave output and every collection of every database
// (the oplog included, so writes later deleted still count) and fails on a hit.

/**
 * A value the host must never keep, except (when allowedIn is not empty) in the
 * named namespaces: a "database.collection" the architecture assigns that value
 * to. Reporter contact, case contents and participant keys have no exceptions.
 */
export type RegisteredSecret = { secret: string; allowedIn: string[] };
type RegisterLine = string[] | { secrets: string[]; allowedIn: string[] };

/** Append secrets to the register file global teardown sweeps for. */
export function appendSecretRegister(file: string, secrets: readonly string[], append: (file: string, data: string) => void,
  allowedIn: readonly string[] = []): void {
  const values = secrets.filter(value => typeof value === 'string' && value.length > 0);
  if (!values.length) return;
  const line: RegisterLine = allowedIn.length ? { secrets: values, allowedIn: [...allowedIn] } : values;
  append(file, `${JSON.stringify(line)}\n`);
}

const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(item => typeof item === 'string');

/**
 * Every registered secret, deduplicated. A value registered more than once is
 * allowed only where every registration allowed it (a plain registration
 * allows it nowhere). Unreadable lines fail loudly.
 */
export function parseSecretRegister(text: string): RegisteredSecret[] {
  const out = new Map<string, Set<string>>();
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const parsed = JSON.parse(line) as unknown;
    let values: string[], allowedIn: string[] = [];
    if (strings(parsed)) values = parsed;
    else if (parsed && typeof parsed === 'object' && strings((parsed as { secrets?: unknown }).secrets) && strings((parsed as { allowedIn?: unknown }).allowedIn)) {
      ({ secrets: values, allowedIn } = parsed as { secrets: string[]; allowedIn: string[] });
    } else throw new Error('Malformed secret register line');
    for (const value of values) {
      if (!value) continue;
      const before = out.get(value);
      out.set(value, before ? new Set(allowedIn.filter(namespace => before.has(namespace))) : new Set(allowedIn));
    }
  }
  return [...out].map(([secret, allowedIn]) => ({ secret, allowedIn: [...allowedIn] }));
}

const BASE64ISH = /^[A-Za-z0-9+/_-]{16,}={0,2}$/;

/**
 * A stored record as searchable text: every key and value, binary fields as
 * raw bytes (latin1), and base64-looking strings also decoded, so a sentinel
 * kept as bytes or as base64 in a "ciphertext" field is still found.
 */
export function storedRecordText(value: unknown): string {
  const parts: string[] = [];
  const seen = new Set<object>();
  const bytes = (data: Uint8Array) => { parts.push(Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString('latin1')); };
  const walk = (node: unknown): void => {
    if (node === null || node === undefined) return;
    if (typeof node === 'string') {
      parts.push(node);
      if (BASE64ISH.test(node)) parts.push(Buffer.from(node, node.includes('-') || node.includes('_') ? 'base64url' : 'base64').toString('latin1'));
      return;
    }
    if (typeof node !== 'object') { parts.push(String(node)); return; }
    if (node instanceof Uint8Array) return bytes(node);
    if (node instanceof Date) { parts.push(node.toISOString()); return; }
    if (seen.has(node)) return;
    seen.add(node);
    const bson = (node as { _bsontype?: string })._bsontype;
    if (bson === 'Binary') {
      const data = (node as { buffer?: unknown }).buffer;
      if (data instanceof Uint8Array) return bytes(data);
    }
    if (bson === 'ObjectId' || bson === 'ObjectID') { parts.push(String(node)); return; }
    if (Array.isArray(node)) { for (const item of node) walk(item); return; }
    for (const [key, item] of Object.entries(node)) { parts.push(key); walk(item); }
  };
  walk(value);
  return parts.join('\n');
}

/** Searchable host data. namespace ("database.collection") is set for stored records only. */
export type HostRecord = { source: string; text: string; namespace?: string };
export type HostLeak = { source: string; secret: string };

/**
 * Which registered secrets appear in which host record (empty when none). A
 * plain string is allowed nowhere; a RegisteredSecret only in its namespaces.
 */
export function sweepHostRecords(records: Iterable<HostRecord>, secrets: readonly (string | RegisteredSecret)[]): HostLeak[] {
  const wanted = secrets.map(item => (typeof item === 'string' ? { secret: item, allowedIn: [] } : item)).filter(item => item.secret);
  const leaks: HostLeak[] = [];
  for (const { source, text, namespace } of records) {
    for (const { secret, allowedIn } of wanted) {
      if (text.includes(secret) && !(namespace !== undefined && allowedIn.includes(namespace))) leaks.push({ source, secret });
    }
  }
  return leaks;
}

/**
 * A failure message that names each source and which secret matched, without
 * printing device secrets (recovery codes, key files) back into the run's own
 * output: sentinels are shown, anything else only by length and prefix.
 */
export function describeHostLeaks(leaks: readonly HostLeak[]): string {
  const label = (secret: string) => (/sentinel/i.test(secret) && secret.length <= 80
    ? JSON.stringify(secret)
    : `device secret (${secret.length} chars, starts ${JSON.stringify(secret.slice(0, 4))})`);
  return [`Host records hold ${leaks.length} registered secret(s):`,
    ...leaks.map(leak => `  ${leak.source}: ${label(leak.secret)}`)].join('\n');
}
