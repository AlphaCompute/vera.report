/** Host-side public-intake mirror. Keep validation in sync with enclave/src/confidential/firmProfile.ts; conformance tests exercise both runtimes. */
/** Legal organization public profile, signed into the organization's key
 * submission (see firmKeyBinding.ts). Kept free of OpenPGP imports so pages can show labels
 * without loading the crypto bundle. */
/** Fixed vocabulary so reporters see consistent, comparable labels. */
export const FIRM_PRACTICE_AREAS = {
  whistleblower: 'Whistleblower representation',
  'qui-tam': 'False Claims Act and qui tam',
  securities: 'Securities and financial fraud',
  employment: 'Employment and retaliation',
  government: 'Government contracts and procurement',
  healthcare: 'Healthcare fraud',
  tax: 'Tax fraud',
  environmental: 'Environmental and safety',
  corruption: 'Corruption and bribery',
  privacy: 'Data protection and privacy',
  criminal: 'Criminal defense',
  'human-rights': 'Human rights',
  consumer: 'Consumer protection',
} as const;
export type FirmPracticeArea = keyof typeof FIRM_PRACTICE_AREAS;
export const FIRM_PROFILE_MAX_AREAS = 6;
export const FIRM_JURISDICTION_MAX = 120;
export const FIRM_CONTACT_LABELS = { email: 'Email', phone: 'Phone', imessage: 'iMessage', signal: 'Signal', telegram: 'Telegram' } as const;
export type FirmContacts = Partial<Record<keyof typeof FIRM_CONTACT_LABELS, string>>;
export type FirmProfile = { practiceAreas: FirmPracticeArea[]; jurisdiction: string; website: string; contacts?: FirmContacts };
function contacts(input: unknown): FirmContacts {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  if (!Object.keys(value).length || Object.keys(value).some(key => !Object.prototype.hasOwnProperty.call(FIRM_CONTACT_LABELS, key))) invalid();
  const result: FirmContacts = {};
  for (const key of Object.keys(FIRM_CONTACT_LABELS) as (keyof FirmContacts)[]) {
    if (value[key] === undefined) continue;
    const text = value[key];
    if (typeof text !== 'string' || !text.length || text.length > 200 || text !== text.normalize('NFC').trim() ||
        /[\u0000-\u001f\u007f-\u009f<>]/.test(text)) invalid();
    if (key === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text as string)) invalid();
    // These are displayed as text, never interpreted as arbitrary URI schemes.
    result[key] = text as string;
  }
  return result;
}
function invalid(): never { throw new Error('Invalid firm profile'); }

/** Canonical profile or an error. Values must already be in canonical form so the
 * signed bytes and what reporters see are identical. */
export function firmProfile(input: unknown, firmDomain: string): FirmProfile {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  if (!['jurisdiction,practiceAreas,website', 'contacts,jurisdiction,practiceAreas,website'].includes(Object.keys(value).sort().join(','))) invalid();
  const areas = value.practiceAreas;
  if (!Array.isArray(areas) || !areas.length || areas.length > FIRM_PROFILE_MAX_AREAS ||
      new Set(areas).size !== areas.length ||
      areas.some(area => typeof area !== 'string' || !Object.prototype.hasOwnProperty.call(FIRM_PRACTICE_AREAS, area))) invalid();
  const jurisdiction = value.jurisdiction;
  if (typeof jurisdiction !== 'string' || jurisdiction.length < 2 || jurisdiction.length > FIRM_JURISDICTION_MAX ||
      jurisdiction !== jurisdiction.normalize('NFC').trim().replace(/\s+/g, ' ') || /[\u0000-\u001f\u007f-\u009f<>]/.test(jurisdiction)) invalid();
  const website = value.website;
  if (typeof website !== 'string' || website.length > 200) invalid();
  let url: URL;
  try { url = new URL(website as string); } catch { return invalid(); }
  // The website must sit on the organization's approved domain.
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.href !== website ||
      !(url.hostname === firmDomain || url.hostname.endsWith(`.${firmDomain}`))) invalid();
  return { practiceAreas: [...areas] as FirmPracticeArea[], jurisdiction: jurisdiction as string, website: website as string,
    ...(value.contacts === undefined ? {} : { contacts: contacts(value.contacts) }) };
}


