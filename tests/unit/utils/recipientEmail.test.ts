import { normalizeRecipientEmail } from '../../../src/utils/recipientEmail';

describe('normalizeRecipientEmail', () => {
  it.each([
    'recipient@example.org', 'Reviewer+Case@Example.ORG', "o'connor@example.org",
    'first.last@example.org', 'person@xn--bcher-kva.org',
    'person@xn--e1afmkfd.xn--p1ai', 'test@sub-domain.example.org',
    `${'a'.repeat(64)}@example.org`, `a@${'b'.repeat(63)}.org`,
    `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`,
  ])('accepts a single ASCII mailbox without rewriting its identity: %s', email => {
    expect(normalizeRecipientEmail(email)).toBe(email);
    expect(normalizeRecipientEmail(`  ${email}  `)).toBe(email);
  });

  it.each([
    undefined, null, 123, {}, [], '', '  ', 'invalid-email', 'a@', '@example.org',
    'a@example', 'a@@example.org', 'a,b@c.org', 'one@example.org,two@example.org',
    'one@example.org;two@example.org', 'Name <person@example.org>', 'a b@example.org',
    'person@b\u00fccher.org', 'r\u00e9cipient@example.org',
    `${'a'.repeat(65)}@example.org`, `a@${'b'.repeat(64)}.org`,
    `${'a'.repeat(64)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`,
    '.a@example.org', 'a.@example.org', 'a..b@example.org',
    'a@-example.org', 'a@example-.org', 'a@exam_ple.org', 'a@example..org',
    'a@example.org.', 'a@[127.0.0.1]', 'a@127.0.0.1',
    'a@example.org\r\n', '\ta@example.org', 'a@example.org\u0000',
    'a\u007f@example.org', 'a\u0085@example.org', '\u00a0a@example.org',
    'a@exam\u200bple.org', 'a@example.org\nBcc:other@example.org',
    '"a,b"@example.org', '"a b"@example.org',
  ])('rejects invalid or unsupported recipient %j', value => {
    expect(normalizeRecipientEmail(value)).toBeNull();
  });
});
