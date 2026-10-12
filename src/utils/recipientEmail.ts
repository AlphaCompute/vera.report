import isEmail from 'validator/lib/isEmail';

/** Browser-safe syntax check for one SES recipient, not a delivery guarantee. */
export function normalizeRecipientEmail(value: unknown): string | null {
  // SES requires ASCII addresses (IDN domains must already be Punycode).
  // Reject controls before trimming so CR/LF cannot become an accepted address.
  if (typeof value !== 'string' || /[^\x20-\x7e]/.test(value)) return null;
  const email = value.trim();
  return isEmail(email, {
    allow_display_name: false,
    allow_utf8_local_part: false,
    allow_ip_domain: false,
    require_tld: true,
    // Match the UI's single, unquoted mailbox contract.
    blacklisted_chars: '"',
  }) ? email : null;
}
