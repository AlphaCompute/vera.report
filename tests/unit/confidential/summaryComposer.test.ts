import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { SummaryComposer } from '../../../components/vera/confidential/SummaryComposer';
import { EMPTY_LISTING_DRAFT } from '../../../lib/confidential/listingDraft';

/** The composer promises "nothing you type is sent until you submit", so the
 * summary field must not opt into browser spell check or autocorrect, which can
 * send field contents to a cloud service. Covers intake and the /status edit. */
describe('summary composer', () => {
  it.each(['submit', 'save'] as const)('keeps the summary out of browser spell check (%s)', commitVerb => {
    const html = renderToStaticMarkup(React.createElement(SummaryComposer, {
      value: { ...EMPTY_LISTING_DRAFT, summary: 'Jane Doe at jane@example.com' }, onChange: () => {}, commitVerb,
    }));
    const textarea = html.match(/<textarea[^>]*>/)?.[0] ?? '';
    expect(textarea).toMatch(/spellcheck="false"/i);
    expect(textarea).toMatch(/autocorrect="off"/i);
    expect(textarea).not.toMatch(/spellcheck="true"|spellcheck=""/i);
    expect(html).toContain(`Nothing you type is sent until you ${commitVerb}.`);
  });
});
