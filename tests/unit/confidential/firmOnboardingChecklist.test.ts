import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { FirmOnboardingChecklist } from '../../../components/vera/confidential/FirmOnboarding';
import type { DomainCheckState, MembershipState, OnboardingState } from '../../../components/vera/confidential/FirmOnboarding';
import { EMPTY_ONBOARDING_RECORD, FIRM_ONBOARDING_TERMS_VERSION } from '../../../lib/confidential/firmOnboarding';
import type { OnboardingRecord } from '../../../lib/confidential/firmOnboarding';

// Signed onboarding terms remain required; second-key-holder custody is optional.
const firm = { domain: 'counsel.example', organizationId: 'a'.repeat(64), recipientKeyId: 'c'.repeat(64) };
const domain: DomainCheckState = { check: { state: 'verified', profile: null, issuedAt: 1 }, checking: false, checkedAt: null,
  polling: false, checkAgain: () => undefined };
const membership: MembershipState = { status: { state: 'enrolled', leaseExpiresAt: Date.UTC(2026, 9, 4), members: 1, keyMatches: true },
  error: null, loading: false, refresh: () => undefined };
const render = (record: OnboardingRecord, keySaved = true, member: MembershipState = membership) => {
  const onboarding: OnboardingState = { record, confirmCustody: () => undefined, acceptTerms: () => undefined };
  return renderToStaticMarkup(React.createElement(FirmOnboardingChecklist, { firm, keySaved, domain, membership: member, onboarding }));
};

describe('organization setup checklist: key custody and onboarding terms', () => {
  test('a sole key holder sees optional custody separately from the required terms', () => {
    const html = render(EMPTY_ONBOARDING_RECORD);
    expect(html).toContain('3 of 4 required steps done');
    expect(html).not.toContain('Setup complete.');
    expect(html).toContain('Second key holder (optional)');
    expect(html).toContain('Check their copy');
    expect(html).toContain('This copy is kept by a second authorized person, stored apart from mine.');
    expect(html).toContain('Onboarding terms acknowledged');
    for (const topic of ['Conflict checks', 'Acceptable use', 'Device protection', 'Download handling', 'Member departure', 'Retention']) {
      expect(html).toContain(topic);
    }
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Acknowledge<\/button>/);
  });

  test('the custody check waits until the key holder has checked their own copy', () => {
    const html = render(EMPTY_ONBOARDING_RECORD, false);
    expect(html).toContain('Available after you save and check your own copy.');
    expect(html).not.toContain('Check their copy');
  });

  test('once both are recorded for this key, setup is complete and the controls are gone', () => {
    const html = render({ custody: { recipientKeyId: firm.recipientKeyId, verifiedAt: 1 },
      terms: { version: FIRM_ONBOARDING_TERMS_VERSION, acceptedAt: 1 } });
    expect(html).toContain('Setup complete.');
    expect(html).not.toContain('Check their copy');
    expect(html).not.toContain('>Acknowledge<');
  });

  test('custody and terms controls wait for the first membership check, so they never switch under a click', () => {
    const checking = render(EMPTY_ONBOARDING_RECORD, true, { status: null, error: null, loading: true, refresh: () => undefined });
    expect(checking).toMatch(/<input type="checkbox" class="mt-1" disabled=""\/><span>I have read these/);
    expect(checking).not.toContain('Check their copy');
    const unavailable = render(EMPTY_ONBOARDING_RECORD, true, { status: null, error: 'Sign in to check your membership.', loading: false,
      refresh: () => undefined });
    expect(unavailable).toMatch(/<input type="checkbox" class="mt-1"\/><span>I have read these/);
    expect(unavailable).toContain('Check their copy');
    const unchecked = render(EMPTY_ONBOARDING_RECORD, true, { status: null, error: null, loading: false, refresh: () => undefined });
    expect(unchecked).toMatch(/<input type="checkbox" class="mt-1"\/><span>I have read these/);
    expect(unchecked).toContain('Check their copy');
  });

  test('both setup pages pass this device\'s onboarding record to the checklist', () => {
    for (const page of ['enroll.tsx', 'index.tsx']) {
      const source = readFileSync(join(__dirname, '../../../pages/legal', page), 'utf8');
      expect(source).toContain('useOnboardingRecord(');
      expect(source).toMatch(/<FirmOnboardingChecklist[^>]*onboarding=\{onboarding\}/);
    }
  });
});
