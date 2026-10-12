/** New public applications cannot choose another key's organization ID. Domain
 * separation also keeps the ID from exposing the independent Key ID readback. */
export async function applicationOrganizationId(recipientKeyId: string): Promise<string> {
  if (!/^[a-f0-9]{64}$/.test(recipientKeyId)) throw new Error('Invalid application key');
  const bytes = new TextEncoder().encode(`vera-application-organization/v1:${recipientKeyId}`);
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
}
