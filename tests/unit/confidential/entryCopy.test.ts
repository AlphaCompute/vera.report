import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { ComponentType } from 'react';
import { entryCopy } from '../../../lib/confidential/entryCopy';
import { WHO_CAN_SEE_ROWS } from '../../../components/vera/confidential/WhoCanSee';

// The home page and the "Before you send" dialog are the first things a
// reporter reads. In confidential mode they must not repeat the legacy claims
// (server-side metadata stripping, administrators reading reports, a Report
// ID): a reporter who trusts them may attach a GPS-tagged photo or look for an
// ID they will never get.

// The home page imports CSS modules, which Jest has no transform for.
jest.mock('../../../components/vera/RisingEdgeMarks.module.css', () => ({}));
jest.mock('next/router', () => ({ useRouter: () => ({ pathname: '/' }) }));

const root = path.join(__dirname, '../../..');
const text = (html: string) =>
    html
        .replace(/<[^>]+>/g, ' ')
        .replace(/&#x27;/g, "'")
        .replace(/&quot;/g, '"')
        .replace(/\s+/g, ' ');
const LEGACY_CLAIMS =
    /report id|stripped on vera|metadata is removed|administrators can (read|access)|authorized review|processes evidence on its servers/i;
const original = process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
afterEach(() => {
    if (original === undefined) delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
    else process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = original;
});

const allText = (confidential: boolean) => {
    const copy = entryCopy(confidential);
    return [
        ...Object.values(copy).filter((v) => typeof v === 'string'),
        ...copy.features.flatMap((f) => [f.title, f.desc]),
    ].join(' ');
};

/** Render with the build flag set, importing fresh so the module-level copy is chosen for that mode. */
function render(
    confidential: boolean,
    load: () => ComponentType<Record<string, unknown>>,
    props: Record<string, unknown> = {},
) {
    process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = confidential ? '1' : '0';
    let html = '';
    jest.isolateModules(() => {
        // React must come from the same isolated registry as the component.
        const { createElement: h } = require('react') as typeof import('react');
        const { renderToStaticMarkup: toHtml } = require('react-dom/server') as typeof import('react-dom/server');
        html = toHtml(h(load(), props));
    });
    return text(html);
}

describe('entry copy in confidential mode', () => {
    test('makes none of the legacy security claims and uses the recovery code', () => {
        const copy = allText(true);
        expect(copy).not.toMatch(LEGACY_CLAIMS);
        expect(copy).toContain(
            'Files are encrypted on your device. Remove hidden details (photo location, document author) before attaching.',
        );
        expect(copy).toMatch(/recovery code/);
        // Keep reporter-facing terminology consistent.
        expect(copy).not.toMatch(/\b(firms?|cases?|owners?|grants?)\b/i);
    });

    test('"Who sees it" matches the Who can see what facts', () => {
        const who = entryCopy(true).whoSeesIt;
        const summary = WHO_CAN_SEE_ROWS[0]!;
        expect(summary.staff).toBe('yes');
        expect(who).toContain('We see your short summary, submission time and whether you included attachments');
        for (const row of WHO_CAN_SEE_ROWS.slice(1)) expect(row.staff).toBe('no');
        expect(who).toMatch(/We cannot read your full report, files or contact details/);
        expect(who).toMatch(/read more only if you allow it/);
    });

    test('legacy mode keeps its own accurate copy', () => {
        expect(allText(false)).toMatch(/Report ID/);
    });

    test('"What you share" promises contact privacy only in confidential mode', () => {
        // Legacy intake lets authorized administrators read contact details.
        expect(entryCopy(false).whatYouShare).toMatch(/administrators can read your contact details/);
        expect(entryCopy(false).whatYouShare).not.toMatch(/only you can see/i);
        expect(entryCopy(true).whatYouShare).toMatch(/Provide at least one contact method/);
        expect(entryCopy(true).whatYouShare).not.toMatch(LEGACY_CLAIMS);
    });

    test('home page renders the confidential copy only in confidential mode', () => {
        const load = () => require('../../../pages/index').default;
        const confidential = render(true, load);
        expect(confidential).not.toMatch(LEGACY_CLAIMS);
        expect(confidential).toContain('Remove hidden details from your files.');
        expect(confidential).toContain('VERA does not remove them for you.');
        expect(confidential).toContain('Save your recovery code');
        expect(confidential).toContain('Your summary is unencrypted and visible on Vera to approved legal organizations, even before you give access.');
        expect(confidential).toContain('A new backend release needs your approval');
        expect(confidential).toContain('Empowered by');
        const legacy = render(false, load);
        expect(legacy).toContain('Save your Report ID');
        expect(legacy).not.toContain('Checked. Signed. Encrypted.');
        expect(legacy).not.toContain('Your browser locks it.');
    });

    test('entry dialog takes its welcome and "Who sees it" copy from the mode switch', () => {
        // The dialog only opens after client-side stages, so check its wiring.
        const source = readFileSync(path.join(root, 'components/vera/EntrySequence.tsx'), 'utf8');
        expect(source).toContain('entryCopy(confidentialCasesEnabled())');
        expect(source).toMatch(/\{COPY\.welcomeDescription\}/);
        expect(source).toMatch(/\{COPY\.whoSeesIt\}/);
        expect(source).toMatch(/\{COPY\.whatYouShare\}/);
        expect(source).not.toMatch(/only you can see/i);
        expect(source).not.toMatch(LEGACY_CLAIMS);
    });

    test('neither entry surface hard-codes legacy claims outside the mode switch', () => {
        for (const file of ['pages/index.tsx', 'components/vera/EntrySequence.tsx']) {
            const source = readFileSync(path.join(root, file), 'utf8');
            expect(source).not.toMatch(LEGACY_CLAIMS);
            expect(source).toContain('entryCopy(confidentialCasesEnabled())');
        }
    });
});
