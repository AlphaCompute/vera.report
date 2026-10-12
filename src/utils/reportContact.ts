/** Required contact for web intake. Values stay within the existing private contact boundary. */
export function reportContactError(method: unknown, value: unknown): string {
  if (typeof method !== 'string' || !['email', 'phone', 'encrypted', 'multiple'].includes(method)) {
    return 'Choose a contact method';
  }
  if (typeof value !== 'string' || !value.trim()) return 'Contact information is required';
  if (method !== 'multiple' && value.length > 500) return 'Contact information must be 500 characters or fewer';
  if (method === 'multiple' && value.length > 1000) return 'Contact information must be 1000 characters or fewer';
  const contact = value.trim();
  if (method === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact)) {
    return 'Please enter a valid email address';
  }
  if (method === 'phone' && (!/^\+?[\d\s\-().]{7,20}$/.test(contact) || contact.replace(/\D/g, '').length < 7)) {
    return 'Please enter a valid phone number';
  }
  return '';
}
