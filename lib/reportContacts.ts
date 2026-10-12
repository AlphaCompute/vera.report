export type ReportContacts = { email: string; signal: string; imessage: string };
export const EMPTY_CONTACTS: ReportContacts = { email: '', signal: '', imessage: '' };
export const CONTACT_LABELS = { email: 'Email', signal: 'Signal', imessage: 'iMessage' } as const;
export function contactProblem(contacts: ReportContacts): string | null {
  const values = Object.values(contacts).map(value => value.trim());
  if (!values.some(Boolean)) return 'Add at least one contact method.';
  if (values.some(value => value.length > 250 || /[\r\n\x00-\x1f]/.test(value))) return 'Use a single contact address of up to 250 characters per field.';
  const email = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  // Same rule as the intake API: allowed phone formatting, and at least 7 digits.
  const isPhone = (value: string) => /^\+?[\d\s().-]{7,20}$/.test(value) && value.replace(/\D/g, '').length >= 7;
  if (contacts.email.trim() && !email.test(contacts.email.trim())) return 'Enter a valid email address.';
  if (contacts.imessage.trim() && !email.test(contacts.imessage.trim()) && !isPhone(contacts.imessage.trim())) return 'Enter an iMessage email address or phone number.';
  if (contacts.signal.trim() && !isPhone(contacts.signal.trim()) && !/^[a-zA-Z_][a-zA-Z0-9_]{2,31}\.\d{2,}$/.test(contacts.signal.trim()) && !/^https:\/\/signal\.me\/#(?:eu|p)\/[A-Za-z0-9_+%=-]+$/.test(contacts.signal.trim())) return 'Enter a Signal username, phone number, or signal.me link.';
  return null;
}
export function suppliedContacts(contacts: ReportContacts): Record<string, string> {
  return Object.fromEntries(Object.entries(contacts).filter(([,value]) => value.trim()).map(([key,value]) => [key,value.trim()]));
}
