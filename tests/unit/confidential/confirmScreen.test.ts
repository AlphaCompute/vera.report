import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ConfidentialReview } from '../../../components/vera/confidential/ConfidentialReview';
import { ConfidentialReleaseIdentity } from '../../../components/vera/confidential/ConfidentialReleaseIdentity';

const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, '\'').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const report = readFileSync(path.resolve(__dirname, '../../../pages/report.tsx'), 'utf8');

describe('confirm screen', () => {
  test('release identifiers sit behind Technical details, with one plain sentence in front', () => {
    const identity = { digest: 'f'.repeat(64), sourceCommit: 'ab'.repeat(20), sourceUrl: 'https://github.com/example/vera/tree/abab' };
    const html = renderToStaticMarkup(createElement(ConfidentialReleaseIdentity, { identity: identity as never }));
    const [before, inside] = html.split('<details');
    expect(inside).toBeDefined();
    expect(text(before)).toContain('Your browser checks VERA’s secure service before sending.');
    for (const technical of ['Release ID', 'Source commit', identity.digest, identity.sourceCommit, 'measurements', 'provenance']) {
      expect(before).not.toContain(technical);
      expect(inside).toContain(technical);
    }
    expect(inside).toMatch(/<summary[^>]*>Technical details<\/summary>/);
    expect(html).not.toMatch(/<details[^>]*\sopen/);
    // Consent to the exact release is still stated, inside the details.
    expect(inside).toContain('Submitting authorizes this exact release');
  });

  test('the confirm card no longer shows backend release text inline', () => {
    const start = report.indexOf('{step === "confirm"');
    const confirm = report.slice(start, report.indexOf('"Submit Report"', start));
    expect(confirm.length).toBeGreaterThan(0);
    expect(confirm).not.toMatch(/backend release/);
    expect(confirm).not.toMatch(/Source commit|Exact release ID|release identity is unavailable/);
    expect(confirm).toContain('<ConfidentialReleaseIdentity identity={releaseIdentity} />');
    expect(confirm).toContain('<WhoCanSee');
    expect(confirm).toContain('{CONFIDENTIAL_METADATA_NOTICE}');
  });

  test('the review preserves the full narrative in an editable field', () => {
    const description = Array.from({ length: 40 }, (_, i) => `Line ${i + 1} with a detail that may identify me.`).join('\n');
    const html = renderToStaticMarkup(createElement(ConfidentialReview, {
      description, files: [], contacts: { email: 'review@example.test', signal: '', imessage: '' },
      draft: { summary: 'Summary', details: {} } as never,
      onDescriptionChange: () => {}, onContactsChange: () => {}, onDraftChange: () => {},
    }));
    expect(html).not.toContain('line-clamp');
    const box = html.match(/<textarea[^>]*data-testid="review-description"[^>]*>([\s\S]*?)<\/textarea>/);
    expect(box).not.toBeNull();
    expect(box![0]).not.toMatch(/readonly|disabled/);
    expect(html).toContain('review@example.test');
    expect(box![1]).toContain('Line 40 with a detail that may identify me.');
  });
});
