import type { NextApiResponse } from 'next';

/** Preserve the server's remaining cooldown through the Next.js proxy. */
export function forwardRetryAfter(response: Response, res: NextApiResponse): void {
  const value = response.headers?.get('retry-after');
  if (response.status === 429 && value) res.setHeader('Retry-After', value);
}
