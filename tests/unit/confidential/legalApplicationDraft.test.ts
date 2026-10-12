import { APPLICATION_DRAFT_KEY, APPLICATION_DRAFT_TTL, EMPTY_APPLICATION, expireApplicationDraft, loadApplicationDraft, saveApplicationDraft } from '../../../lib/legalApplicationDraft';

const draft = { ...EMPTY_APPLICATION, displayName: 'Counsel', email: 'lawyer@counsel.example', domain: 'counsel.example' };
const storage = () => {
  const map = new Map<string, string>();
  return { getItem: (key: string) => map.get(key) ?? null, setItem: (key: string, value: string) => { map.set(key, value); }, removeItem: (key: string) => { map.delete(key); } };
};
test('a partial draft survives Back and return, then expires instead of retaining applicant details indefinitely', () => {
  const store = storage();
  expect(saveApplicationDraft(store, draft, 1000)).toBe(true);
  expect(loadApplicationDraft(store, 2000)).toEqual(draft);
  expect(loadApplicationDraft(store, 1000 + APPLICATION_DRAFT_TTL)).toEqual(EMPTY_APPLICATION);
  expect(store.getItem(APPLICATION_DRAFT_KEY)).toBeNull();
});
test('only the six application fields may be saved or restored', () => {
  const store = storage();
  saveApplicationDraft(store, { ...draft, privateKey: 'never persist this', invitation: 'also private' } as typeof draft, 1000);
  expect(store.getItem(APPLICATION_DRAFT_KEY)).not.toContain('private');
  const raw = JSON.parse(store.getItem(APPLICATION_DRAFT_KEY)!);
  raw.fields.privateKey = 'injected'; store.setItem(APPLICATION_DRAFT_KEY, JSON.stringify(raw));
  expect(loadApplicationDraft(store, 2000)).toEqual(draft);
});
test.each(['broken JSON', JSON.stringify({ expires: 2000, fields: { email: {} } }), 'x'.repeat(4097)])('malformed or oversized drafts are removed safely', raw => {
  const store = storage(); store.setItem(APPLICATION_DRAFT_KEY, raw);
  expect(loadApplicationDraft(store, 1000)).toEqual(EMPTY_APPLICATION);
  expect(store.getItem(APPLICATION_DRAFT_KEY)).toBeNull();
});
test('unavailable storage does not prevent an in-memory application', () => {
  const fail = () => { throw Error('storage blocked'); };
  const store = { getItem: fail, setItem: fail, removeItem: fail };
  expect(saveApplicationDraft(store, draft)).toBe(false);
  expect(loadApplicationDraft(store)).toEqual(EMPTY_APPLICATION);
});
test('an open tab removes the stored draft once it expires', () => {
  const store = storage();
  expect(expireApplicationDraft(store, 1000)).toBe(false);
  saveApplicationDraft(store, draft, 1000);
  expect(expireApplicationDraft(store, 1000 + APPLICATION_DRAFT_TTL - 1)).toBe(true);
  expect(store.getItem(APPLICATION_DRAFT_KEY)).not.toBeNull();
  expect(expireApplicationDraft(store, 1000 + APPLICATION_DRAFT_TTL)).toBe(false);
  expect(store.getItem(APPLICATION_DRAFT_KEY)).toBeNull();
});
