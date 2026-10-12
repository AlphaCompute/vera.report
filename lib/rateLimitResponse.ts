export class RateLimitError extends Error {
  constructor(public readonly retryAt: number) {
    super(`Too many requests. Automatic refresh will resume after ${new Date(retryAt).toLocaleTimeString()}.`);
  }
}

/** Only numeric cooldown metadata is used; never display private upstream bodies. */
export async function throwIfRateLimited(response: Response): Promise<void> {
  if (response.status !== 429) return;
  const now = Date.now();
  const header = response.headers.get('retry-after');
  let seconds: number | undefined;
  if (header && /^\d+$/.test(header)) seconds = Number(header);
  else if (header && Number.isFinite(Date.parse(header))) seconds = Math.ceil((Date.parse(header) - now) / 1000);
  if (seconds === undefined) {
    const body = await response.clone().json().catch(() => null);
    if (typeof body?.retryAfter === 'number') seconds = body.retryAfter;
  }
  const delay = seconds !== undefined && Number.isFinite(seconds) && seconds >= 0 ? Math.max(1, seconds) : 60;
  throw new RateLimitError(now + delay * 1000);
}
