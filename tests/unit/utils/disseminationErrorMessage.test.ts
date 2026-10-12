import { disseminationErrorMessage } from '../../../lib/disseminationErrorMessage';

it('gives both review paths and requires accepting AI redaction', () => {
  const message = disseminationErrorMessage('narrative_review_required');
  expect(message).toContain('Mark reviewed — no redaction needed');
  expect(message).toContain('accept the reviewed redaction');
});
it('does not suggest routing can supply missing reporter consent', () => {
  const message = disseminationErrorMessage('reporter_consent_missing');
  expect(message).toContain('blocked until valid consent is recorded');
  expect(message).not.toMatch(/run routing/i);
});
it('does not expose configuration names or unknown upstream details', () => {
  expect(disseminationErrorMessage('dryrun_inbox_not_configured')).not.toContain('DISSEMINATION_DRYRUN_INBOX');
  expect(disseminationErrorMessage('dryrun_inbox_invalid')).toBe('The test recipient inbox is invalid. Contact your administrator.');
  for (const error of ['upstream error: private-token-123', '__proto__', 'constructor']) {
    expect(disseminationErrorMessage(error)).toContain('The action could not be completed.');
    expect(disseminationErrorMessage(error)).not.toContain(error);
  }
});
