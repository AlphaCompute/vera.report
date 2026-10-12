/** The legal and onboarding clients both use five-minute interactive tokens.
 * Bound the whole exchange, including its body, before retaining any token. */
async function identityResponse(domain: string, clientId: string, body: Record<string, string>) {
  const response = await fetch(`https://${domain}/oauth/token`, { method: 'POST', cache: 'no-store', credentials: 'omit',
    redirect: 'error', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(10_000),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, ...body }).toString() });
  if (!response.ok || !response.body) {
    void response.body?.cancel().catch(() => {});
    throw new Error('Identity exchange failed');
  }
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 64 * 1024) throw new Error('Identity response exceeds limit');
      chunks.push(value);
    }
  } finally {
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
export async function exchangeIdentityToken(domain: string, clientId: string, body: Record<string, string>):
Promise<{ accessToken: string; expiresAt: number }> {
  const value = await identityResponse(domain, clientId, body);
  if (typeof value?.access_token !== 'string' || !value.access_token || value.access_token.length > 16_384 ||
      typeof value.expires_in !== 'number' || !Number.isFinite(value.expires_in) || value.expires_in <= 0 || value.expires_in > 300 ||
      String(value.token_type).toLowerCase() !== 'bearer') throw new Error('Invalid identity response');
  return { accessToken: value.access_token, expiresAt: Date.now() + value.expires_in * 1000 };
}

/** This profile-only exchange is received directly from the pinned issuer over
 * TLS using the one-use PKCE code. It supplies routing, never legal authority.
 * Do not retain its access token or relax the legal API's five-minute limit.
 * Direct TLS issuer validation: OpenID Connect Core 1.0 section 3.1.3.7(6).
 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation */
export async function exchangeLegalEntry(domain: string, clientId: string, nonce: string, body: Record<string, string>): Promise<string> {
  const value = await identityResponse(domain, clientId, body);
  if (typeof value?.id_token !== 'string' || value.id_token.length > 16384) throw new Error('Invalid entry response');
  const parts = value.id_token.split('.');
  if (parts.length !== 3 || parts.some((part: string) => !/^[A-Za-z0-9_-]+$/.test(part))) throw new Error('Invalid entry response');
  const decode = (part: string) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(
    Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))));
  const header = decode(parts[0]), claims = decode(parts[1]), now = Math.floor(Date.now() / 1000);
  if (header.alg !== 'RS256' || claims.iss !== `https://${domain}/` || claims.aud !== clientId ||
      (claims.azp !== undefined && claims.azp !== clientId) || claims.nonce !== nonce ||
      typeof claims.sub !== 'string' || !claims.sub || !Number.isSafeInteger(claims.iat) || claims.iat > now + 30 || now - claims.iat > 600 ||
      !Number.isSafeInteger(claims.exp) || claims.exp <= now || claims.exp <= claims.iat ||
      !/^org_[A-Za-z0-9]{1,64}$/.test(claims['https://vera.app/legal-entry']?.organization || '')) throw new Error('Invalid entry response');
  return claims['https://vera.app/legal-entry'].organization;
}
