/** On-device checks for the public summary of a confidential report.
 *
 * The summary is the only plaintext a confidential report publishes, so this
 * looks for things that commonly identify a reporter: names, email addresses,
 * phone numbers, company names, exact dates and addresses. It is a pure
 * function with no I/O: the text is never sent, stored or logged, and results
 * exist only in the page that computed them. It is advice, not a filter: it
 * misses things (a unique job title, a small team) and flags some harmless
 * text, so the copy around it must say so.
 */
export type SummaryWarningKind = 'email' | 'phone' | 'address' | 'company' | 'date' | 'name';
export type SummaryWarning = { kind: SummaryWarningKind; text: string; start: number; end: number };

export const SUMMARY_WARNING_ADVICE: Record<SummaryWarningKind, { label: string; advice: string }> = {
  name: { label: 'Looks like a person’s name', advice: 'Use a role instead, such as “a senior manager”.' },
  email: { label: 'Looks like an email address', advice: 'Remove it. The summary never needs contact details.' },
  phone: { label: 'Looks like a phone number', advice: 'Remove it. The summary never needs contact details.' },
  company: { label: 'Looks like a company or organization name', advice: 'Describe the type instead, such as “a regional hospital”.' },
  date: { label: 'Looks like an exact date', advice: 'Use a broader time, such as “in 2023” or “over several months”.' },
  address: { label: 'Looks like an address', advice: 'Leave it out. Avoid details that identify a workplace or a person.' },
};

const MONTH = '(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)';
const STREET = '(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Highway|Hwy|Parkway|Pkwy|Terrace|Circle|Square|Plaza)';
const COMPANY_SUFFIX = '(?:Inc|Incorporated|LLC|L\\.L\\.C|LLP|Ltd|Limited|Corp|Corporation|Company|Co|Group|Holdings|PLC|GmbH|AG|Partners|Bank|Capital|Technologies|Industries|Labs|Hospital|Clinic|University|College|Foundation|Pharmaceuticals|Systems|Solutions|Enterprises)';
const US_STATES = 'A[LKZR]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY]';

const PATTERNS: { kind: SummaryWarningKind; pattern: RegExp }[] = [
  { kind: 'email', pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g },
  { kind: 'address', pattern: new RegExp(`\\b\\d{1,6}\\s+(?:[NSEW]\\.?\\s+)?(?:[A-Z][A-Za-z]+\\s+){1,3}${STREET}\\b\\.?`, 'g') },
  { kind: 'address', pattern: /\bP\.?\s?O\.?\s+Box\s+\d+/gi },
  { kind: 'address', pattern: /\b(?:Suite|Ste|Apt|Apartment|Unit)\.?\s+#?\d+[A-Za-z]?\b/g },
  { kind: 'address', pattern: new RegExp(`\\b(?:${US_STATES})\\s+\\d{5}(?:-\\d{4})?\\b`, 'g') },
  { kind: 'date', pattern: /\b\d{4}-\d{1,2}-\d{1,2}\b/g },
  { kind: 'date', pattern: /\b\d{1,2}[/.-]\d{1,2}[/.-](?:\d{4}|\d{2})\b/g },
  { kind: 'date', pattern: new RegExp(`\\b${MONTH}\\.?\\s+\\d{1,2}(?:st|nd|rd|th)?\\b(?:,?\\s+\\d{4})?`, 'g') },
  { kind: 'date', pattern: new RegExp(`\\b\\d{1,2}(?:st|nd|rd|th)?\\s+(?:of\\s+)?${MONTH}\\b(?:,?\\s+\\d{4})?`, 'g') },
  { kind: 'phone', pattern: /\+\d{1,3}(?:[\s.-]?\(?\d{1,4}\)?){2,5}\b/g },
  { kind: 'phone', pattern: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3,4}[\s.-]\d{3,4}(?:[\s.-]\d{2,4})?\b/g },
  { kind: 'phone', pattern: /\+?\b\d{10,13}\b/g },
  { kind: 'company', pattern: new RegExp(`\\b(?:[A-Z][\\w&'-]*\\s+){0,3}[A-Z][\\w&'-]*,?\\s+${COMPANY_SUFFIX}\\b\\.?`, 'g') },
  { kind: 'company', pattern: /\b[A-Z][a-z]+(?:[A-Z][a-z]+)+\b/g },
  { kind: 'name', pattern: /\b(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof|Judge|Senator|Sen|Rep|Officer|Sgt|Capt|Lt|Rev)\.?\s+[A-Z][a-z'-]+(?:\s+[A-Z][a-z'-]+)?/g },
  { kind: 'name', pattern: /\b(?:named|called|manager|boss|supervisor|colleague|coworker|co-worker|CEO|CFO|COO|CTO)\s+([A-Z][a-z'-]+(?:\s+[A-Z][a-z'-]+)?)\b/g },
];

/** Capitalized words that begin sentences or name months, days, places,
 * programs or titles. A run of two or more capitalized words is only treated
 * as a possible name once these are stripped from its ends. */
const NOT_NAME = new Set(`a an the this that these those my our their his her its your we i it he she they in on at
by for from to of and or but with without after before during since until when while where because if as last
next every each both several some many most all one two three four five six seven eight nine ten over about
january february march april may june july august september october november december jan feb mar apr jun jul
aug sep sept oct nov dec monday tuesday wednesday thursday friday saturday sunday united states america american
us usa federal state county city national government department agency office bureau program medicare medicaid
chief executive financial operating technology officer director manager senior vice president head board
compliance legal internal external audit team security safety north south east west northern southern eastern
western new early late mid ai crypto covid sec fda epa irs doj ftc osha`.split(/\s+/).filter(Boolean));

function capitalizedRuns(text: string): SummaryWarning[] {
  const found: SummaryWarning[] = [];
  const run = /\b[A-Z][a-z'-]+(?:\s+[A-Z][a-z'-]+)+\b/g;
  for (const match of text.matchAll(run)) {
    const words = match[0].split(/\s+/);
    let first = 0, last = words.length;
    while (first < last && NOT_NAME.has(words[first].toLowerCase())) first++;
    while (last > first && NOT_NAME.has(words[last - 1].toLowerCase())) last--;
    const kept = words.slice(first, last);
    if (kept.length < 2 || kept.some(word => NOT_NAME.has(word.toLowerCase()))) continue;
    const offset = match[0].indexOf(kept[0], words.slice(0, first).join(' ').length);
    const start = match.index! + offset, value = kept.join(' ');
    found.push({ kind: 'name', text: value, start, end: start + value.length });
  }
  return found;
}

const MAX_WARNINGS = 12;

/** Possible identifying details in `text`, in reading order, without overlaps
 * or repeats. Earlier kinds in PATTERNS win an overlap (an address beats the
 * "name" inside it). */
export function findIdentifyingDetails(text: string): SummaryWarning[] {
  if (typeof text !== 'string' || !text.trim()) return [];
  const input = text.slice(0, 2_000);
  const candidates: SummaryWarning[] = [];
  for (const { kind, pattern } of PATTERNS) {
    for (const match of input.matchAll(pattern)) {
      // A pattern with a capture group flags only the captured word.
      const value = (match[1] ?? match[0]).trim().replace(/[.,]$/, '');
      const start = match.index! + match[0].indexOf(value);
      // Year ranges ("2019-2021") and short numbers are not phone numbers.
      if (kind === 'phone' && (value.replace(/\D/g, '').length < 7 || /^(?:19|20)\d{2}\s*[-–.]\s*(?:19|20)?\d{2}$/.test(value))) continue;
      candidates.push({ kind, text: value, start, end: start + value.length });
    }
  }
  candidates.push(...capitalizedRuns(input));
  const accepted: SummaryWarning[] = [];
  for (const item of candidates) {
    if (accepted.some(other => item.start < other.end && other.start < item.end)) continue;
    accepted.push(item);
  }
  const seen = new Set<string>();
  return accepted.sort((a, b) => a.start - b.start).filter(item => {
    const key = `${item.kind}:${item.text.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, MAX_WARNINGS);
}
