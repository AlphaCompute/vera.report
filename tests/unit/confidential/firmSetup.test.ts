import { webcrypto } from 'node:crypto';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import {
  FIRM_ONBOARDING_TERMS, FIRM_ONBOARDING_TERMS_VERSION, firmOnboardingTermsDigest, signFirmSetupStatement, verifyFirmSetupStatement,
} from '../../../enclave/src/confidential/firmSetup';
import { createFirmSetup } from '../../../enclave/src/cases/legalSetup';
import type { OrganizationContext } from '../../../enclave/src/cases/service';
import { parseFirmSetupStatus, parseSetupMissing, setupIncompleteMessage, setupNextSteps } from '../../../lib/confidential/firmSetup';
import type { FirmSetupStatus } from '../../../lib/confidential/firmSetup';
import { EMPTY_ONBOARDING_RECORD, onboardingChecklist, pendingSetupSync } from '../../../lib/confidential/firmOnboarding';
import type { OnboardingRecord } from '../../../lib/confidential/firmOnboarding';
import { userFacingMessage } from '../../../lib/confidential/userFacingError';
import { FirmCaseError } from '../../../lib/confidential/firmCase';
import { FirmOnboardingChecklist } from '../../../components/vera/confidential/FirmOnboarding';
import type { DomainCheckState, FirmSetupState, MembershipState, OnboardingState } from '../../../components/vera/confidential/FirmOnboarding';

// Architecture, "Firm key custody and onboarding terms": the enclave refuses
// requests and case reads until signed onboarding terms are recorded. Recovery
// custody is optional and its evidence still has to be authentic.
const ORG = 'a'.repeat(64), NOW = 1_800_000_000_000;
let key: PrivateKey, other: PrivateKey, keyId: string, otherId: string, context: OrganizationContext;
beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  const make = async (name: string) => (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey;
  [key, other] = [await make('Synthetic organization'), await make('Synthetic other')];
  [keyId, otherId] = [await caseRecipientKeyId(key.toPublic()), await caseRecipientKeyId(other.toPublic())];
  context = { organizationId: ORG, recipientKeyId: keyId, publicKey: key.toPublic().armor() };
});
const custody = (overrides: Record<string, unknown> = {}) => ({ format: 'vera-legal-key-custody/v1' as const, organizationId: ORG,
  recipientKeyId: keyId, method: 'second-custodian-copy' as const, attestedAt: NOW, ...overrides });
const terms = async (overrides: Record<string, unknown> = {}) => ({ format: 'vera-legal-onboarding-terms/v1' as const, organizationId: ORG,
  recipientKeyId: keyId, termsVersion: FIRM_ONBOARDING_TERMS_VERSION, termsDigest: await firmOnboardingTermsDigest(), acknowledgedAt: NOW, ...overrides });
const expected = (kind: 'custody' | 'terms') => ({ kind, organizationId: ORG, recipientKeyId: keyId, publicKey: key.toPublic() }) as const;

describe('organization setup statements (browser and enclave shared module)', () => {
  test('custody and terms statements verify only for the signing organization key, organization and statement kind', async () => {
    const signedCustody = await signFirmSetupStatement(custody(), key);
    await expect(verifyFirmSetupStatement(signedCustody, expected('custody'), NOW)).resolves.toEqual(custody());
    const signedTerms = await signFirmSetupStatement(await terms(), key);
    await expect(verifyFirmSetupStatement(signedTerms, expected('terms'), NOW)).resolves.toMatchObject({ termsVersion: FIRM_ONBOARDING_TERMS_VERSION });
    // Wrong kind, organization, key, or verifying key.
    await expect(verifyFirmSetupStatement(signedCustody, expected('terms'), NOW)).rejects.toThrow('Invalid organization setup statement');
    await expect(verifyFirmSetupStatement(signedCustody, { ...expected('custody'), organizationId: 'b'.repeat(64) }, NOW)).rejects.toThrow();
    await expect(verifyFirmSetupStatement(signedCustody, { ...expected('custody'), recipientKeyId: otherId }, NOW)).rejects.toThrow();
    await expect(verifyFirmSetupStatement(signedCustody, { ...expected('custody'), publicKey: other.toPublic() }, NOW)).rejects.toThrow();
    // Signed by another key but naming this one: refused.
    const forged = JSON.parse(await signFirmSetupStatement(custody({ recipientKeyId: otherId }), other));
    forged.statement.recipientKeyId = keyId;
    await expect(verifyFirmSetupStatement(JSON.stringify(forged), expected('custody'), NOW)).rejects.toThrow();
    // Issued in the future beyond clock skew.
    await expect(verifyFirmSetupStatement(signedCustody, expected('custody'), NOW - 3_600_000)).rejects.toThrow();
    // A different terms version or text digest.
    const tampered = JSON.parse(signedTerms);
    tampered.statement.termsDigest = 'f'.repeat(64);
    await expect(verifyFirmSetupStatement(JSON.stringify(tampered), expected('terms'), NOW)).rejects.toThrow();
    await expect(signFirmSetupStatement(await terms({ termsVersion: FIRM_ONBOARDING_TERMS_VERSION + 1 }), key)).rejects.toThrow();
    await expect(signFirmSetupStatement(await terms({ termsDigest: 'f'.repeat(64) }), key)).rejects.toThrow();
    // The signing key must be the key the statement names.
    await expect(signFirmSetupStatement(custody(), other)).rejects.toThrow();
    // No extra fields.
    await expect(signFirmSetupStatement({ ...custody(), note: 'x' } as never, key)).rejects.toThrow();
  });

  test('the terms digest covers the exact text and version the portal shows', async () => {
    expect(await firmOnboardingTermsDigest()).toMatch(/^[a-f0-9]{64}$/);
    expect(FIRM_ONBOARDING_TERMS.map(item => item.id)).toEqual(['conflicts', 'acceptable-use', 'devices', 'downloads', 'departure', 'retention']);
  });
});

describe('enclave setup gate (legalSetup.ts)', () => {
  function store() {
    const rows = new Map<string, { custody: string | null; terms: string | null }>();
    return { rows,
      async getOrganizationSetup(organizationId: string) { return rows.get(organizationId) ?? null; },
      async putOrganizationSetup(organizationId: string, kind: 'custody' | 'terms', statement: string) {
        rows.set(organizationId, { ...(rows.get(organizationId) ?? { custody: null, terms: null }), [kind]: statement }); return true;
      } };
  }

  test('terms suffice for a sole holder; optional custody remains verifiable and does not gate operations', async () => {
    const backing = store();
    let now = NOW;
    const setup = createFirmSetup({ store: backing, now: () => now });
    const holders = jest.fn(async () => 1);
    await expect(setup.missing(context, holders)).resolves.toEqual(['terms']);
    await setup.record(context, 'terms', await signFirmSetupStatement(await terms(), key));
    await expect(setup.missing(context, holders)).resolves.toBeNull();
    await expect(setup.status(context, holders)).resolves.toMatchObject({ complete: true, custody: null, holders: 1 });
    // Two verified key holders meet custody without an attestation.
    await expect(setup.missing(context, async () => 2)).resolves.toBeNull();
    await expect(setup.status(context, async () => 2)).resolves.toMatchObject({ complete: true, custody: 'members', holders: 2 });
    // An attestation meets it for a sole key holder; the gate then skips counting.
    now += 120_000;
    await setup.record(context, 'custody', await signFirmSetupStatement(custody(), key));
    holders.mockClear();
    await expect(setup.missing(context, holders)).resolves.toBeNull();
    expect(holders).not.toHaveBeenCalled();
    await expect(setup.status(context, holders)).resolves.toMatchObject({ complete: true, custody: 'attested', custodyAttestedAt: NOW });
  });

  test('host rows are verified on every read, and only a complete answer is cached, for one minute', async () => {
    const backing = store();
    let now = NOW;
    const setup = createFirmSetup({ store: backing, now: () => now });
    backing.rows.set(ORG, { custody: await signFirmSetupStatement(custody({ recipientKeyId: otherId }), other),
      terms: 'not a statement' });
    await expect(setup.missing(context, async () => 1)).resolves.toEqual(['terms']);
    backing.rows.set(ORG, { custody: await signFirmSetupStatement(custody(), key), terms: await signFirmSetupStatement(await terms(), key) });
    await expect(setup.missing(context, async () => 1)).resolves.toBeNull();
    backing.rows.delete(ORG);
    await expect(setup.missing(context, async () => 1)).resolves.toBeNull();
    now += 60_001;
    await expect(setup.missing(context, async () => 1)).resolves.toEqual(['terms']);
    // Statements for a replaced key do not carry over.
    backing.rows.set(ORG, { custody: await signFirmSetupStatement(custody(), key), terms: await signFirmSetupStatement(await terms(), key) });
    const replaced = { organizationId: ORG, recipientKeyId: otherId, publicKey: other.toPublic().armor() };
    await expect(setup.missing(replaced, async () => 1)).resolves.toEqual(['terms']);
  });

  test('record refuses a statement the registered key did not sign, and an unknown kind', async () => {
    const backing = store();
    const setup = createFirmSetup({ store: backing, now: () => NOW });
    await expect(setup.record(context, 'custody', await signFirmSetupStatement(custody({ recipientKeyId: otherId }), other))).rejects.toThrow();
    await expect(setup.record(context, 'custody', await signFirmSetupStatement(await terms(), key))).rejects.toThrow();
    await expect(setup.record(context, 'other' as never, await signFirmSetupStatement(custody(), key))).rejects.toThrow();
    expect(backing.rows.size).toBe(0);
    // A storage error is an error, never "complete".
    const broken = createFirmSetup({ store: { ...backing, async getOrganizationSetup() { throw new Error('down'); } }, now: () => NOW });
    await expect(broken.missing(context, async () => 2)).rejects.toThrow();
  });
});

const status = (overrides: Partial<FirmSetupStatus> = {}): FirmSetupStatus => ({ complete: false, missing: ['terms'],
  custody: null, holders: 1, custodyAttestedAt: null, terms: null, termsVersion: FIRM_ONBOARDING_TERMS_VERSION, ...overrides });

describe('portal setup client and messages', () => {
  test('the status reply is parsed strictly; anything inconsistent is an unavailable service', () => {
    expect(parseFirmSetupStatus(status())).toEqual(status());
    const complete = status({ complete: true, missing: [], custody: 'members', holders: 2, terms: { version: 1, acknowledgedAt: NOW } });
    expect(parseFirmSetupStatus(complete)).toEqual(complete);
    for (const bad of [null, [], { ...status(), extra: 1 }, status({ complete: true }), status({ custody: 'attested' }),
      status({ custody: 'members', missing: ['terms'], holders: 1 }), status({ missing: ['custody', 'custody'] as never }),
      status({ missing: ['custody'] }), status({ holders: 3 }), { ...complete, terms: { version: 1 } }]) {
      expect(() => parseFirmSetupStatus(bad)).toThrow();
    }
    expect(parseSetupMissing(['terms', 'custody'])).toBeNull(); // stale required-custody policy is not silently accepted
    expect(parseSetupMissing(['terms'])).toEqual(['terms']);
    expect(parseFirmSetupStatus({ ...complete, custody: null, holders: 1 })).toMatchObject({ complete: true, custody: null });
    expect(parseSetupMissing([])).toBeNull();
    expect(parseSetupMissing(['keys'])).toBeNull();
  });

  test('a refused request or report explains the missing steps in plain, displayable text', () => {
    for (const missing of [['custody', 'terms'], ['custody'], ['terms']] as const) {
      const error = new FirmCaseError('setup-incomplete', missing);
      expect(userFacingMessage(error, 'fallback')).toBe(error.message);
      expect(error.message).toBe(setupIncompleteMessage(missing));
    }
    expect(setupIncompleteMessage(['terms'])).toBe('Your organization has not finished setup, so it cannot request or open reports yet. Acknowledge the onboarding terms under Organization setup on the legal portal home page, then try again.');
    expect(setupNextSteps(['custody', 'terms']).map(item => item.title)).toEqual(['Second key holder', 'Onboarding terms']);
  });
});

describe('organization setup checklist with the enforced status', () => {
  const run = (setup: { status: FirmSetupStatus | null; error?: string | null }, record: OnboardingRecord = EMPTY_ONBOARDING_RECORD) =>
    onboardingChecklist({ keySaved: true, domain: 'counsel.example', domainCheck: { state: 'verified', profile: null, issuedAt: 1 },
      membership: { state: 'enrolled', leaseExpiresAt: NOW + 86_400_000, members: 1, keyMatches: true }, recipientKeyId: 'c'.repeat(64),
      record, setup });
  const step = (result: ReturnType<typeof run>, id: string) => result.steps.find(item => item.id === id)!;
  const localDone: OnboardingRecord = { custody: { recipientKeyId: 'c'.repeat(64), verifiedAt: 1 },
    terms: { version: FIRM_ONBOARDING_TERMS_VERSION, acceptedAt: 1 } };

  test('only what VERA recorded counts: a step finished on this device alone is not done', () => {
    const local = run({ status: status() }, localDone);
    expect(local.complete).toBe(false);
    expect(step(local, 'custody')).toMatchObject({ done: false, detail: expect.stringContaining('not recorded with VERA yet') });
    expect(step(local, 'terms')).toMatchObject({ done: false, detail: expect.stringContaining('not recorded with VERA yet') });
    expect(step(run({ status: status() }), 'custody')).toMatchObject({ optional: true, done: false });
    expect(step(run({ status: status() }), 'custody').detail).not.toContain('VERA will not send requests or open reports');
    expect(run({ status: status({ complete: true, missing: [], terms: { version: 1, acknowledgedAt: NOW } }) }).complete).toBe(true);
    expect(step(run({ status: null }), 'terms')).toMatchObject({ done: false, detail: 'Checking with VERA…' });
    expect(step(run({ status: null, error: 'Unavailable.' }), 'custody').detail).toBe('Unavailable.');
    const recorded = run({ status: status({ complete: true, missing: [], custody: 'members', holders: 2,
      terms: { version: 1, acknowledgedAt: NOW } }) });
    expect(recorded.complete).toBe(true);
    expect(step(recorded, 'custody').detail).toBe('At least two enrolled people hold your organization key on their own devices.');
    expect(step(run({ status: status({ missing: ['terms'], custody: 'attested', custodyAttestedAt: NOW }) }), 'custody'))
      .toMatchObject({ done: true, detail: expect.stringContaining('recorded with VERA on') });
  });

  test('steps done on this device are recorded once the member is enrolled, for this key and terms version only', () => {
    expect(pendingSetupSync(status(), localDone, 'c'.repeat(64))).toEqual(['custody', 'terms']);
    expect(pendingSetupSync(status(), localDone, 'd'.repeat(64))).toEqual(['terms']);
    expect(pendingSetupSync(status({ complete: true, missing: [], terms: { version: 1, acknowledgedAt: 1 } }), localDone, 'c'.repeat(64))).toEqual(['custody']);
    expect(pendingSetupSync(status(), { custody: null, terms: { version: FIRM_ONBOARDING_TERMS_VERSION - 1, acceptedAt: 1 } }, 'c'.repeat(64))).toEqual([]);
  });

  test('the checklist offers "Record with VERA" for a locally finished step and the forms otherwise', () => {
    const firm = { domain: 'counsel.example', organizationId: ORG, recipientKeyId: 'c'.repeat(64) };
    const domain: DomainCheckState = { check: { state: 'verified', profile: null, issuedAt: 1 }, checking: false, checkedAt: null,
      polling: false, checkAgain: () => undefined };
    const membership: MembershipState = { status: { state: 'enrolled', leaseExpiresAt: NOW + 86_400_000, members: 1, keyMatches: true },
      error: null, loading: false, refresh: () => undefined };
    const render = (record: OnboardingRecord, current: FirmSetupStatus | null) => {
      const onboarding: OnboardingState = { record, confirmCustody: () => undefined, acceptTerms: () => undefined };
      const setup: FirmSetupState = { active: true, status: current, error: null, busy: false, record: async () => true, refresh: () => undefined };
      return renderToStaticMarkup(React.createElement(FirmOnboardingChecklist, { firm, keySaved: true, domain, membership, onboarding, setup }));
    };
    const pending = render(localDone, status());
    expect(pending.match(/Record with VERA/g)).toHaveLength(2);
    expect(pending).not.toContain('Check their copy');
    const fresh = render(EMPTY_ONBOARDING_RECORD, status());
    expect(fresh).toContain('Check their copy');
    expect(fresh).toContain('>Acknowledge<');
    expect(render(EMPTY_ONBOARDING_RECORD, null)).toContain('Check again');
    expect(render(EMPTY_ONBOARDING_RECORD, status({ complete: true, missing: [], custody: 'attested', custodyAttestedAt: NOW,
      terms: { version: 1, acknowledgedAt: NOW } }))).toContain('Setup complete.');
  });
});
