import type { LegalApplicationInput } from '@/src/utils/legalApplications';

export const APPLICATION_DRAFT_KEY = 'vera-legal-application-draft/v1';
export const APPLICATION_DRAFT_TTL = 30 * 60_000;
export const EMPTY_APPLICATION: LegalApplicationInput = { displayName: '', domain: '', email: '', lawyerName: '', jurisdiction: '', registrationNumber: '' };
export const APPLICATION_LIMITS: Record<keyof LegalApplicationInput, number> = { displayName: 160, domain: 253, email: 254, lawyerName: 160, jurisdiction: 120, registrationNumber: 120 };
type DraftStore = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
/** Only staff-readable application fields, in this tab, for at most 30 minutes. Never keys or invitations. */
export function loadApplicationDraft(store: DraftStore, now = Date.now()): LegalApplicationInput {
  try {
    const raw = store.getItem(APPLICATION_DRAFT_KEY);
    if (!raw) return { ...EMPTY_APPLICATION };
    if (raw.length > 4096) throw new Error('Oversized draft');
    const data = JSON.parse(raw);
    if (!Number.isSafeInteger(data.expires) || data.expires <= now || data.expires > now + APPLICATION_DRAFT_TTL || !data.fields) throw new Error('Expired draft');
    const fields = { ...EMPTY_APPLICATION };
    for (const key of Object.keys(fields) as (keyof LegalApplicationInput)[]) {
      if (typeof data.fields[key] !== 'string' || data.fields[key].length > APPLICATION_LIMITS[key]) throw new Error('Invalid draft');
      fields[key] = data.fields[key];
    }
    return fields;
  } catch { try { store.removeItem(APPLICATION_DRAFT_KEY); } catch { /* storage unavailable */ } return { ...EMPTY_APPLICATION }; }
}
export function saveApplicationDraft(store: DraftStore, fields: LegalApplicationInput, now = Date.now()): boolean {
  const projected = Object.fromEntries((Object.keys(EMPTY_APPLICATION) as (keyof LegalApplicationInput)[]).map(key => [key, fields[key].slice(0, APPLICATION_LIMITS[key])]));
  try { store.setItem(APPLICATION_DRAFT_KEY, JSON.stringify({ expires: now + APPLICATION_DRAFT_TTL, fields: projected })); return true; } catch { return false; }
}
/** Enforces the lifetime while the tab stays open: removes an expired or invalid
 * stored draft. True while a non-empty, unexpired draft remains stored. */
export function expireApplicationDraft(store: DraftStore, now = Date.now()): boolean {
  try { if (store.getItem(APPLICATION_DRAFT_KEY) === null) return false; } catch { return false; }
  return Object.values(loadApplicationDraft(store, now)).some(Boolean);
}
