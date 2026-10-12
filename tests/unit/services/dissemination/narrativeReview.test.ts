import { reviewedNarrativeMatches } from '../../../../src/services/dissemination/narrativeReview';

it('does not authorize an old snapshot using the approval for a replacement', () => {
    const override = { narrative: '[REPORTER] observed fraud.', setBy: 'reviewer', setAt: new Date(), notes: [] };
    expect(
        reviewedNarrativeMatches({ narrative: 'My name is Synthetic Alice.' }, { narrativeOverride: override }),
    ).toBe(false);
    expect(reviewedNarrativeMatches({ narrative: override.narrative }, { narrativeOverride: override })).toBe(true);
});

it('requires review for unchanged or files-only narratives', () => {
    expect(reviewedNarrativeMatches({ narrative: '' }, null)).toBe(false);
    expect(reviewedNarrativeMatches({ narrative: '' }, {})).toBe(false);
    expect(reviewedNarrativeMatches({ narrative: '' }, { narrativeReviewedAt: new Date() })).toBe(true);
});
