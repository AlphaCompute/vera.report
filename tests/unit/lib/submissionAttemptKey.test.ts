import { createSubmissionAttemptKey } from '../../../lib/submissionAttemptKey';

describe('memory-only submission attempt key', () => {
  const body = (description = 'synthetic', consent = 'false', file?: File) => {
    const data = new FormData();
    data.append('description', description);
    data.append('consentLegalReview', consent);
    if (file) data.append('files', file);
    return data;
  };
  test('reuses a credential for identical retries, including the same file', () => {
    const random = jest.fn().mockReturnValueOnce('first').mockReturnValueOnce('second');
    const key = createSubmissionAttemptKey(random);
    const file = new File(['synthetic'], 'evidence.csv');
    expect(key(body('synthetic', 'false', file))).toBe('first');
    expect(key(body('synthetic', 'false', file))).toBe('first');
    expect(random).toHaveBeenCalledTimes(1);
  });
  test('changed narrative, consent or file starts a new attempt', () => {
    let count = 0;
    const key = createSubmissionAttemptKey(() => String(++count));
    expect(key(body())).toBe('1');
    expect(key(body('edited'))).toBe('2');
    expect(key(body('edited', 'true'))).toBe('3');
    expect(key(body('edited', 'true', new File(['a'], 'same.csv')))).toBe('4');
    expect(key(body('edited', 'true', new File(['b'], 'same.csv')))).toBe('5');
  });
  test('a new page instance never inherits an earlier key', () => {
    expect(createSubmissionAttemptKey(() => 'first')(body())).toBe('first');
    expect(createSubmissionAttemptKey(() => 'second')(body())).toBe('second');
  });
});
