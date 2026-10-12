/** A log-safe reason: an HTTP status, a timeout, a fixed error code (with its
 * fixed detail tag, e.g. provider_unavailable:auth0_status_404) or an error
 * class, never an error message (those can carry application or identity
 * details). fetch wraps network failures (ECONNREFUSED, Undici timeouts) as a
 * TypeError whose cause carries the code, so the cause chain is checked first. */
export function failureReason(error: unknown): string {
  for (let current = error, depth = 0; current && typeof current === 'object' && depth < 4;
    current = (current as { cause?: unknown }).cause, depth++) {
    const { status, code, detail, codeName, name } = current as { status?: unknown; code?: unknown; detail?: unknown; codeName?: unknown; name?: unknown };
    if (Number.isSafeInteger(status)) return `HTTP ${status}`;
    // Errno, Undici and LegalProvisioningError's fixed codes (provider_unavailable, ...).
    if (typeof code === 'string' && /^(?:E[A-Z]{1,20}|UND_ERR_[A-Z_]{1,40}|[a-z][a-z_]{1,40})$/.test(code))
      return typeof detail === 'string' && /^[a-z][a-z0-9_]{1,40}$/.test(detail) ? `${code}:${detail}` : code;
    // MongoDB server errors (DuplicateKey, NotWritablePrimary, ...).
    if (typeof codeName === 'string' && /^[A-Za-z]{1,40}$/.test(codeName)) return codeName;
    if (name === 'TimeoutError' || name === 'AbortError') return 'timeout';
  }
  const name = (error as { name?: unknown } | null)?.name;
  return typeof name === 'string' && /^[A-Za-z]{1,40}$/.test(name) ? name : 'error';
}
