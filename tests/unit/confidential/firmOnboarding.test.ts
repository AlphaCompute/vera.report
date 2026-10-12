import { webcrypto } from 'node:crypto';
import { generateFirmIdentity, firmBindingDocument } from '../../../lib/confidential/firmKey';
import type { FirmIdentity } from '../../../lib/confidential/firmKey';
import {
  EMPTY_ONBOARDING_RECORD, FIRM_ONBOARDING_TERMS, FIRM_ONBOARDING_TERMS_VERSION, MEMBERSHIP_WARNING_MS, checkFirmDomain, domainCheckMessage,
  membershipLease, membershipNotice, onboardingChecklist, portalView, readOnboardingRecord, recordOnboarding,
} from '../../../lib/confidential/firmOnboarding';
import type { DomainCheck, MembershipStatus, OnboardingRecord } from '../../../lib/confidential/firmOnboarding';

let firm: FirmIdentity, other: FirmIdentity;
const profile = { practiceAreas: ['whistleblower' as const], jurisdiction: 'England and Wales', website: 'https://counsel.example/' };
beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  other = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
});
test.each<[DomainCheck, string]>([
  [{ state: 'verified', profile: null, issuedAt: 1 }, 'approved'],
  [{ state: 'different-key' }, 'different organization key'],
  [{ state: 'unreachable' }, 'awaiting approval'],
  [{ state: 'invalid' }, 'awaiting approval'],
])('explains organization approval %j', (check, text) => { expect(domainCheckMessage(check, 'counsel.example')).toContain(text); });

describe('onboarding checklist', () => {
  const verified: DomainCheck = { state: 'verified', profile: null, issuedAt: 1 };
  const enrolled = (members: number | null, keyMatches = true): MembershipStatus =>
    ({ state: 'enrolled', leaseExpiresAt: Date.UTC(2026, 9, 4, 12), members, keyMatches });
  const keyId = 'c'.repeat(64);
  const acknowledged: OnboardingRecord = { custody: { recipientKeyId: keyId, verifiedAt: 1 }, terms: { version: FIRM_ONBOARDING_TERMS_VERSION, acceptedAt: 1 } };
  const run = (keySaved: boolean, domainCheck: DomainCheck | null, membership: MembershipStatus | null, record = acknowledged) =>
    onboardingChecklist({ keySaved, domain: 'counsel.example', domainCheck, membership, recipientKeyId: keyId, record });
  const done = (result: ReturnType<typeof run>) => Object.fromEntries(result.steps.map(step => [step.id, step.done]));

  test('ticks each step from live state and completes once every required step is done', () => {
    expect(done(run(false, null, null, EMPTY_ONBOARDING_RECORD)))
      .toEqual({ key: false, custody: false, terms: false, domain: false, invitation: false, lawyers: false });
    expect(done(run(true, verified, { state: 'not-enrolled' })))
      .toEqual({ key: true, custody: true, terms: true, domain: true, invitation: false, lawyers: false });
    expect(run(true, verified, { state: 'not-enrolled' }).complete).toBe(false);
    const complete = run(true, verified, enrolled(3));
    expect(complete.complete).toBe(true);
    expect(complete.steps.find(step => step.id === 'lawyers')!.detail).toBe('3 people are enrolled for your organization.');
    expect(run(true, { state: 'unreachable' }, enrolled(3)).complete).toBe(false);
  });

  test('explains lapsed memberships, key mismatches and single-member firms', () => {
    const text = (result: ReturnType<typeof run>, id: string) => result.steps.find(step => step.id === id)!.detail;
    expect(text(run(true, verified, { state: 'lapsed' }), 'invitation')).toContain('membership has ended');
    const mismatch = run(true, verified, enrolled(4, false));
    expect(done(mismatch)).toMatchObject({ invitation: false, lawyers: false });
    expect(text(mismatch, 'invitation')).toContain('different organization key');
    expect(text(run(true, verified, enrolled(1)), 'lawyers')).toContain('do not share the organization key file');
    expect(text(run(true, verified, enrolled(1)), 'invitation')).toContain('4 October 2026');
    expect(text(run(true, verified, enrolled(null)), 'lawyers')).toContain('not available');
  });

  test('a one-lawyer organization completes setup; adding lawyers is optional', () => {
    const solo = run(true, verified, enrolled(1));
    expect(done(solo)).toEqual({ key: true, custody: true, terms: true, domain: true, invitation: true, lawyers: true });
    expect(solo.complete).toBe(true);
    const lawyers = solo.steps.find(step => step.id === 'lawyers')!;
    expect(lawyers.optional).toBe(true);
    expect(lawyers.label).toContain('optional');
    expect(lawyers.detail).toContain('Add lawyers any time');
    // An unknown member count never blocks completion either.
    expect(run(true, verified, enrolled(null)).complete).toBe(true);
    // The optional step never makes an incomplete setup complete.
    expect(run(true, verified, enrolled(1, false)).complete).toBe(false);
    expect(run(false, verified, enrolled(1)).complete).toBe(false);
  });
});

describe('key custody and onboarding terms (architecture: organization membership and recovery)', () => {
  const verified: DomainCheck = { state: 'verified', profile: null, issuedAt: 1 };
  const keyId = 'c'.repeat(64), otherKeyId = 'd'.repeat(64);
  const enrolled = (members: number | null): MembershipStatus =>
    ({ state: 'enrolled', leaseExpiresAt: Date.UTC(2026, 9, 4, 12), members, keyMatches: true });
  const terms = { version: FIRM_ONBOARDING_TERMS_VERSION, acceptedAt: 1 };
  const run = (record: OnboardingRecord, members: number | null = 1) =>
    onboardingChecklist({ keySaved: true, domain: 'counsel.example', domainCheck: verified, membership: enrolled(members), recipientKeyId: keyId, record });
  const step = (result: ReturnType<typeof run>, id: string) => result.steps.find(item => item.id === id)!;

  test('a sole key holder completes setup without the optional second custodian', () => {
    const alone = run({ custody: null, terms });
    expect(step(alone, 'custody')).toMatchObject({ done: false });
    expect(step(alone, 'custody').optional).toBe(true);
    expect(step(alone, 'custody').detail).toContain('VERA cannot recover a lost key');
    expect(alone.complete).toBe(true);
    // A copy checked for a previous organization key does not count for the new one.
    expect(step(run({ custody: { recipientKeyId: otherKeyId, verifiedAt: 1 }, terms }), 'custody').done).toBe(false);
    const checked = run({ custody: { recipientKeyId: keyId, verifiedAt: 1 }, terms });
    expect(step(checked, 'custody')).toMatchObject({ done: true });
    expect(checked.complete).toBe(true);
  });

  test('a second enrolled person holding the key on their own device also satisfies custody', () => {
    expect(step(run({ custody: null, terms }, 2), 'custody')).toMatchObject({ done: true, detail: '2 people hold your organization key on their own devices.' });
    expect(run({ custody: null, terms }, 2).complete).toBe(true);
    expect(step(run({ custody: null, terms }, null), 'custody').done).toBe(false);
  });

  test('setup needs the onboarding terms acknowledged, at the current version', () => {
    const custody = { recipientKeyId: keyId, verifiedAt: 1 };
    expect(step(run({ custody, terms: null }), 'terms').done).toBe(false);
    expect(run({ custody, terms: null }).complete).toBe(false);
    expect(run({ custody, terms: { version: FIRM_ONBOARDING_TERMS_VERSION - 1, acceptedAt: 1 } }).complete).toBe(false);
    expect(run({ custody, terms }).complete).toBe(true);
  });

  test('the terms cover every topic the architecture requires', () => {
    expect(FIRM_ONBOARDING_TERMS.map(term => term.title)).toEqual(
      ['Conflict checks', 'Acceptable use', 'Device protection', 'Download handling', 'Member departure', 'Retention']);
    expect(FIRM_ONBOARDING_TERMS.find(term => term.id === 'acceptable-use')!.text).toContain('does not by itself make the reporter your client');
  });

  test('the device record keeps only timestamps and the public key ID, and tolerates bad or missing storage', () => {
    const values = new Map<string, string>();
    const store = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value); } };
    const org = 'a'.repeat(64);
    expect(readOnboardingRecord(store, org)).toEqual(EMPTY_ONBOARDING_RECORD);
    recordOnboarding(store, org, { terms });
    const saved = recordOnboarding(store, org, { custody: { recipientKeyId: keyId, verifiedAt: 2 } });
    expect(saved).toEqual({ custody: { recipientKeyId: keyId, verifiedAt: 2 }, terms });
    expect(readOnboardingRecord(store, org)).toEqual(saved);
    expect(JSON.parse(values.get(`vera-legal-onboarding:${org}`)!)).toEqual(saved);
    values.set(`vera-legal-onboarding:${org}`, '{"custody":{"recipientKeyId":"nothex","verifiedAt":1},"terms":{"version":1,"acceptedAt":-1}}');
    expect(readOnboardingRecord(store, org)).toEqual(EMPTY_ONBOARDING_RECORD);
    values.set(`vera-legal-onboarding:${org}`, 'not json');
    expect(readOnboardingRecord(store, org)).toEqual(EMPTY_ONBOARDING_RECORD);
    expect(readOnboardingRecord(null, org)).toEqual(EMPTY_ONBOARDING_RECORD);
    const failing = { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } };
    expect(recordOnboarding(failing, org, { terms })).toEqual({ custody: null, terms });
  });
});

describe('membership lease warnings', () => {
  // Memberships are seven-day leases; the portal must warn before one ends and say plainly when it has.
  const DAY = 86_400_000, endsAt = Date.UTC(2026, 9, 4, 12);
  const enrolled = (keyMatches = true): MembershipStatus => ({ state: 'enrolled', leaseExpiresAt: endsAt, members: 3, keyMatches });

  test('stays quiet while more than two days are left', () => {
    expect(membershipLease(enrolled(), endsAt - 5 * DAY)).toEqual({ state: 'active', endsAt });
    expect(membershipNotice(enrolled(), endsAt - MEMBERSHIP_WARNING_MS - 1)).toBeNull();
    expect(membershipNotice(null, endsAt)).toBeNull();
    expect(membershipNotice({ state: 'not-enrolled' }, endsAt)).toBeNull();
    expect(membershipNotice(enrolled(false), endsAt + DAY)).toBeNull();
  });

  test('warns from two days before the end, with the end date', () => {
    const soon = membershipNotice(enrolled(), endsAt - MEMBERSHIP_WARNING_MS);
    expect(soon).toMatchObject({ tone: 'attention', title: 'Your membership ends in 2 days' });
    expect(soon!.message).toContain('4 October 2026');
    expect(soon!.message).toContain('Reopen your saved approved device to renew access');
    expect(soon!.message).toMatch(/first key holder without a device approval.*new invitation/);
    expect(membershipNotice(enrolled(), endsAt - DAY / 2)!.title).toBe('Your membership ends within a day');
  });

  test('says the membership ended, when, and how to get it back', () => {
    const ended = membershipNotice(enrolled(), endsAt + 1);
    expect(membershipLease(enrolled(), endsAt)).toEqual({ state: 'ended', endedAt: endsAt });
    expect(ended).toMatchObject({ tone: 'negative', title: 'Your membership has ended' });
    expect(ended!.message).toContain('Your membership ended on 4 October 2026');
    expect(ended!.message).toContain('Reopen your saved approved device to renew access');
    expect(ended!.message).toContain('ask your organization for help');
    expect(ended!.message).toMatch(/First key holders without a device approval.*new VERA invitation/);
    expect(membershipNotice({ state: 'lapsed' }, endsAt)!.message).toMatch(/^Your membership has ended, so reports are not available/);
  });

  test('a lease that ran out on this device no longer counts as an accepted invitation', () => {
    const verified: DomainCheck = { state: 'verified', profile: null, issuedAt: 1 };
    const record: OnboardingRecord = { custody: null, terms: { version: FIRM_ONBOARDING_TERMS_VERSION, acceptedAt: 1 } };
    const at = (now?: number) => onboardingChecklist({ keySaved: true, domain: 'counsel.example', domainCheck: verified, membership: enrolled(), now,
      recipientKeyId: 'c'.repeat(64), record });
    expect(at(endsAt - DAY).complete).toBe(true);
    expect(at().complete).toBe(true);
    const lapsed = at(endsAt + 1);
    expect(lapsed.complete).toBe(false);
    expect(lapsed.steps.find(step => step.id === 'invitation')).toMatchObject({ done: false });
    expect(lapsed.steps.find(step => step.id === 'invitation')!.detail).toContain('membership has ended');
  });
});

describe('portal gating on membership', () => {
  // Reports, the directory and shared requests must not load before membership is known, or a lawyer
  // who is not enrolled sees their errors flash before the blocked panel replaces them.
  const DAY = 86_400_000, endsAt = Date.UTC(2026, 9, 4, 12);
  const enrolled = (keyMatches = true): MembershipStatus => ({ state: 'enrolled', leaseExpiresAt: endsAt, members: 3, keyMatches });

  test('waits while the membership check has not answered yet', () => {
    expect(portalView({ status: null, error: null }, endsAt - DAY)).toBe('checking');
  });

  test('shows reports only once membership is confirmed, or the check itself failed', () => {
    expect(portalView({ status: enrolled(), error: null }, endsAt - 5 * DAY)).toBe('reports');
    expect(portalView({ status: enrolled(), error: null }, endsAt - DAY / 2)).toBe('reports');
    expect(portalView({ status: null, error: 'Your membership could not be checked.' }, endsAt)).toBe('reports');
  });

  test('keeps reports unmounted for a lawyer who is not enrolled, on another key, or lapsed', () => {
    expect(portalView({ status: { state: 'not-enrolled' }, error: null }, endsAt - DAY)).toBe('not-enrolled');
    expect(portalView({ status: enrolled(false), error: null }, endsAt - DAY)).toBe('other-key');
    expect(portalView({ status: { state: 'lapsed' }, error: null }, endsAt - DAY)).toBe('ended');
    expect(portalView({ status: enrolled(), error: null }, endsAt + 1)).toBe('ended');
  });
});
