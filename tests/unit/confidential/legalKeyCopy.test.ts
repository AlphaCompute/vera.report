import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { KEY_CEREMONY_COPY } from '../../../components/vera/confidential/legalKeyCopy';

const root = resolve(__dirname, '../../..');
const source = (path: string) => readFileSync(resolve(root, path), 'utf8');
const allCopy = (value: unknown): string[] => typeof value === 'string' ? [value] : Object.values(value as object).flatMap(allCopy);

// Legal-facing copy uses one term per concept: legal organization, reporter,
// access, recovery code. Internal words stay out of what the page says.
const forbidden = /\b(firms?|owners?|grants?|granted|epochs?|envelopes?|cases?|rotat\w*)\b/i;

describe('/legal/keys offline ceremony copy', () => {
  it('uses the agreed terms in every string it shows', () => {
    const strings = allCopy(KEY_CEREMONY_COPY);
    expect(strings.length).toBeGreaterThan(20);
    for (const text of strings) expect(text).not.toMatch(forbidden);
    expect(KEY_CEREMONY_COPY.title).toBe('Organization key administration');
    expect(KEY_CEREMONY_COPY.rotated).toMatch(/Every reporter must allow access again for the new key; current access does not move over\./);
    expect(KEY_CEREMONY_COPY.rotateHint).toMatch(/Every reporter must allow access again/);
    expect(KEY_CEREMONY_COPY.failed).not.toMatch(/permission|membership/i);
  });

  it('has no inline string literals or JSX text left in the page markup', () => {
    const page = source('pages/legal/keys.tsx');
    const markup = page.slice(page.indexOf('return <LegalPortalLayout'));
    // JSX text between tags, ignoring expressions and whitespace.
    const text = [...markup.matchAll(/>([^<>{}]+)</g)].map(m => m[1].trim()).filter(t => /[A-Za-z]/.test(t));
    expect(text).toEqual([]);
    const literals = [...markup.matchAll(/'([^'\n]*)'|"([^"\n]*)"/g)].map(m => m[1] ?? m[2]);
    for (const literal of literals.filter(l => /\s/.test(l))) expect(literal).not.toMatch(forbidden);
    expect(page).toContain('<LegalPortalDisabled title="Organization key administration" />');
    for (const line of page.split('\n').filter(l => /field\(/.test(l) && /copy\./.test(l) === false && !/const field/.test(l))) {
      throw new Error(`field label not from copy: ${line}`);
    }
  });

  it('keeps key version detail behind the advanced section', () => {
    const page = source('pages/legal/keys.tsx');
    const details = page.slice(page.indexOf('<details'), page.indexOf('</details>'));
    expect(details).toContain("field('epoch'");
    expect(page.split("field('epoch'").length).toBe(2);
    expect(details).toContain('copy.advancedSummary');
  });

  it('stacks the action select under its label at full width', () => {
    const page = source('pages/legal/keys.tsx');
    const select = page.match(/<select className="([^"]+)"/);
    expect(select).not.toBeNull();
    const classes = select![1].split(/\s+/);
    expect(classes).toEqual(expect.arrayContaining(['block', 'w-full']));
    expect(classes.some(c => /^ml-/.test(c))).toBe(false);
  });
});

describe('/legal/keys browser spec', () => {
  // The Playwright spec in the intake job must follow the page copy instead of
  // hard-coding it, or a copy change fails the job before its security checks run.
  it('reads every label and message from KEY_CEREMONY_COPY', () => {
    const spec = source('qa/local-tests/confidential-administration.spec.ts');
    expect(spec).toContain("import { KEY_CEREMONY_COPY as copy } from '../../components/vera/confidential/legalKeyCopy';");
    for (const text of allCopy(KEY_CEREMONY_COPY)) expect(spec).not.toContain(`'${text}'`);
    expect(spec).not.toMatch(/Firm key administration|Encrypted firm key file|Current key epoch|Each case owner must grant/);
    for (const key of ['title', 'organizationKeyFile', 'keyRecoveryCode', 'currentKeyVersion', 'advancedSummary', 'outputRecoveryCode', 'removedMembers', 'prepared', 'rotated', 'failed']) {
      expect(spec).toContain(`copy.${key}`);
    }
    expect(spec).toContain('copy.modes.rotate');
  });
});

describe('legal workspace backup copy', () => {
  it('describes access in reporter terms, not grants', () => {
    const portal = source('components/vera/confidential/LegalPortal.tsx');
    const tools = portal.slice(portal.indexOf('function FirmDeviceTools'));
    const visible = tools.slice(0, tools.indexOf('<RememberWorkspace'));
    expect(visible).not.toMatch(/\bgrants?\b/i);
    expect(visible).toContain('organization key and reporter access.');
  });
});
