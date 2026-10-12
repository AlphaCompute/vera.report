import { reportContactError } from '../../../src/utils/reportContact';

describe('required report contact', () => {
  it.each([
    [undefined, undefined], ['', 'person@example.org'], ['fax', '12345678'],
    ['email', ''], ['phone', '   '], ['encrypted', '\t'],
    ['email', 'not-an-email'], ['phone', '-------'], ['phone', '(12)---'],
    ['encrypted', 'x'.repeat(501)], ['email', ['person@example.org']],
  ])('rejects invalid method %p and value %p', (method, value) => {
    expect(reportContactError(method, value)).not.toBe('');
  });

  it.each([
    ['email', 'person@example.org'], ['email', ' person@example.org '],
    ['phone', '+1 (202) 555-0123'], ['encrypted', 'signal-user.123'],
  ])('accepts %s contact', (method, value) => {
    expect(reportContactError(method, value)).toBe('');
  });
});
