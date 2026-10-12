import { webcrypto } from 'node:crypto';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { describeReleaseUpdate, readReleaseNotes, releaseChangeSentence } from '../../../lib/confidential/releaseUpdate';
import { OWNER_FAILURE_COPY } from '../../../lib/confidential/failureCopy';
import type { OwnerFailure } from '../../../lib/confidential/failureCopy';
import type { TimelineEvent } from '../../../lib/confidential/ownerTimeline';
import { WhoCanSee, WHO_CAN_SEE_ROWS } from '../../../components/vera/confidential/WhoCanSee';
import { OwnerJourneyHeader, OwnerTimeline } from '../../../components/vera/confidential/OwnerTimeline';
import { ApproveUpdate } from '../../../components/vera/confidential/ApproveUpdate';
import { ConfidentialFailure } from '../../../components/vera/confidential/ConfidentialFailure';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: 'ab'.repeat(20),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const render = (element: Parameters<typeof renderToStaticMarkup>[0]) => renderToStaticMarkup(element);
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, '\'').replace(/&amp;/g, '&').replace(/\s+/g, ' ');

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

describe('who can see what', () => {
  test('matches the disclosure boundary: staff see the summary and submission facts', () => {
    for (const row of WHO_CAN_SEE_ROWS) {
      expect(row.you).toBe('yes');
      expect(row.staff).toBe(row.label.startsWith('Your summary, submission time') ? 'yes' : 'no');
    }
    expect(WHO_CAN_SEE_ROWS.find(row => row.label === 'Your contact details')!.organizations).toBe('if-allowed');
    const html = render(createElement(WhoCanSee));
    expect(html).toContain('<table');
    expect(html).toContain('scope="col"');
    expect(text(html)).toContain('Only if you allow');
    expect(text(html)).toContain('Each one sees your summary and those submission facts and can ask for more');
  });

  test('on the status page it names who was allowed', () => {
    expect(text(render(createElement(WhoCanSee, { allowed: ['Alpha LLP', 'Bravo LLP'] }))))
      .toContain('You allowed: Alpha LLP, Bravo LLP.');
    expect(text(render(createElement(WhoCanSee, { allowed: [] }))))
      .toContain('You have not allowed any legal organization to read more than your summary and those submission facts.');
  });
});

describe('journey header and timeline', () => {
  test('journey separates summary visibility from private grants and links to waiting requests', () => {
    const html = render(createElement(OwnerJourneyHeader, { journey: { submitted: true, visible: true, requests: 2, sharedWith: 1 },
      requestsAnchor: 'access-requests' }));
    expect(text(html)).toMatch(/Submitted .*Summary published .*Shared with 1 legal organization .*2 requests waiting/);
    expect(text(html)).toContain('Legal organizations can see your summary, not your private report.');
    expect(html).toContain('href="#access-requests"');
    const quiet = text(render(createElement(OwnerJourneyHeader, { journey: { submitted: true, visible: false, requests: 0, sharedWith: 0 } })));
    expect(quiet).toContain('Hidden from law firms');
    expect(quiet).toContain('No requests waiting');
    expect(quiet).toContain('Not shared with anyone');
  });

  test('timeline shows the newest six events, and an expand control without cryptographic record labels', () => {
    const events: TimelineEvent[] = Array.from({ length: 8 }, (_, index) => ({ id: `e${index}`, kind: 'files-added',
      at: Date.UTC(2026, 8, 10 - index), title: `Event ${index}`, record: index === 0 ? 'sealed' : 'signed' }));
    const html = render(createElement(OwnerTimeline, { timeline: { events, incomplete: true } }));
    expect(text(html)).toContain('Event 5');
    expect(text(html)).not.toContain('Event 6');
    expect(text(html)).toContain('Show all 8 events');
    expect(html).toContain('aria-expanded="false"');
    expect(text(html)).toContain('Activity');
    expect(text(html)).not.toContain('Signed with your key');
    expect(text(html)).toContain('could not be verified');
    expect(html).toContain('<time dateTime=');
  });
});

describe('approve update', () => {
  test('release notes are used only for the exact bundled release', async () => {
    const { digest } = await readReleaseManifest(MANIFEST);
    const notes = JSON.stringify({ releaseDigest: digest, summary: 'Faster file downloads for legal organizations.', publishedAt: '2026-09-20' });
    expect(readReleaseNotes(notes, digest)).toEqual({ releaseDigest: digest, summary: 'Faster file downloads for legal organizations.', publishedAt: '2026-09-20' });
    expect(readReleaseNotes(notes, hex(9))).toBeNull();
    expect(readReleaseNotes(JSON.stringify({ releaseDigest: digest, summary: 'x', extra: 1 }), digest)).toBeNull();
    expect(readReleaseNotes(JSON.stringify({ releaseDigest: digest, summary: 'x', publishedAt: '2026-02-30' }), digest)).toBeNull();
    expect(readReleaseNotes(JSON.stringify({ releaseDigest: digest, summary: 'a'.repeat(281) }), digest)).toBeNull();
    expect(readReleaseNotes('not json', digest)).toBeNull();
    expect(readReleaseNotes('', digest)).toBeNull();
  });

  test('says what changed, what happens without approval, and hides technical details behind an expander', async () => {
    const { digest } = await readReleaseManifest(MANIFEST);
    const previous = { releaseDigest: hex(0x77), approvedAt: Date.UTC(2026, 7, 1, 12) };
    const bare = await describeReleaseUpdate(MANIFEST, undefined, [previous, { releaseDigest: digest, approvedAt: 1 }]);
    expect(bare.previous).toEqual(previous);
    expect(releaseChangeSentence(bare)).toContain('VERA did not publish a description of this release');
    const update = await describeReleaseUpdate(MANIFEST,
      JSON.stringify({ releaseDigest: digest, summary: 'Faster file downloads for legal organizations.', publishedAt: '2026-09-20' }), [previous]);
    const html = render(createElement(ApproveUpdate, { update, busy: false, onApprove: () => undefined, onLater: () => undefined }));
    const visible = text(html);
    expect(visible).toContain('What changed Faster file downloads for legal organizations.');
    expect(visible).toContain('Description from VERA');
    expect(visible).toContain('If you don’t approve This new version cannot open your report until you approve it.');
    expect(visible).toContain('Previously approved versions and copies already received are unaffected.');
    expect(visible).toContain('You last approved an update on Aug 1, 2026.');
    expect(html).toMatch(/<details[^>]*><summary[^>]*>Technical details<\/summary>/);
    expect(html).toContain(digest);
    expect(html).toContain(`https://github.com/example/vera/commit/${'ab'.repeat(20)}`);
    expect(html).toContain('rel="noopener noreferrer"');
    expect(visible).toContain('Approve update');
    expect(visible).toContain('Not now');
    // One vocabulary for the reporter: no key or backend jargon in the details.
    expect(visible).toContain('before it can open your report');
    expect(visible).not.toMatch(/case keys?|backend release/i);
  });
});

describe('failure states', () => {
  test('each reason renders its own title and next step; only possible attacks are flagged', () => {
    const seen = new Set<string>();
    for (const reason of Object.keys(OWNER_FAILURE_COPY) as OwnerFailure[]) {
      const html = render(createElement(ConfidentialFailure, { reason }));
      expect(html).toContain('role="alert"');
      expect(html).toContain(`data-failure="${reason}"`);
      const visible = text(html);
      expect(visible).toContain('What to do');
      expect(visible.includes('Possible security problem')).toBe(reason === 'verification' || reason === 'rollback');
      seen.add(visible);
    }
    expect(seen.size).toBe(Object.keys(OWNER_FAILURE_COPY).length);
    expect(text(render(createElement(ConfidentialFailure, { reason: 'verification' })))).toContain('different network');
    expect(text(render(createElement(ConfidentialFailure, { reason: 'offline' })))).toContain('Check your internet connection');
    expect(text(render(createElement(ConfidentialFailure, { reason: 'unavailable' })))).toContain('maintenance or an update');
  });
});
