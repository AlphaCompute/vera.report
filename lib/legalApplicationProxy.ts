import { confidentialListingBackend } from '../pages/api/admin/confidential/listings';
import { confidentialCasesEnabled } from './confidential/config';
import { LEGAL_APPLICATION_INTAKE_CLOSED, legalApplicationIntakeClosedCode, projectLegalApplication, projectLegalApplicationDecision } from '../src/utils/legalApplications';
import { fetchRetryingConnectionError } from './internalBackendFetch';
/** Content-free diagnostics: never the body, headers, URL or error message. */
function failureCode(error: unknown) {
  // Errors raised inside undici (a body parse failure, say) come from another
  // realm, so read the fields rather than relying on instanceof.
  const { name, cause } = error && typeof error === 'object' ? error as { name?: unknown; cause?: unknown } : {};
  const code = cause && typeof cause === 'object' ? (cause as { code?: unknown }).code : undefined;
  return `error=${typeof name === 'string' && /^\w{1,40}$/.test(name) ? name : 'unknown'}${typeof code === 'string' && /^[A-Z0-9_]{1,40}$/.test(code) ? ` code=${code}` : ''}`;
}
/** Only actions the backend treats as idempotent may be resent after a connection
 * failure. A keyed submission has a key-derived ID and an identical resubmission
 * succeeds; a keyless one gets a random ID per request, so a resend could store a
 * duplicate. A decision is never resent. */
function retriesConnectionError(action: 'submit' | 'list' | 'decide' | 'status', body: unknown) {
  if (action === 'status' || action === 'list') return true;
  return action === 'submit' && typeof body === 'object' && body !== null && !!(body as { enrollment?: unknown }).enrollment;
}
/** Fixed paths and projections; never forward arbitrary upstream data. */
export async function legalApplicationRequest(action: 'submit' | 'list' | 'decide' | 'status', body: unknown, headers: Record<string, string> = {}) {
  const backend = confidentialListingBackend();
  if (!backend || !confidentialCasesEnabled()) return { status: 503, data: { error: 'Applications unavailable' } };
  const started = Date.now();
  try {
    const response = await fetchRetryingConnectionError(`${backend.url}/api/admin/confidential/legal-applications/${action}`, {
      method: 'POST', redirect: 'error',
      headers: { ...headers, 'Content-Type': 'application/json', 'x-internal-secret': backend.secret }, body: JSON.stringify(body),
    }, { timeoutMs: 10_000, retry: retriesConnectionError(action, body),
      onRetry: error => console.warn(`[Legal Applications Proxy] retrying action=${action} ${failureCode(error)} elapsedMs=${Date.now() - started}`) });
    if (!response.ok) console.warn(`[Legal Applications Proxy] backend status action=${action} status=${response.status}`);
    const data = await response.json();
    const decision = action === 'decide' ? projectLegalApplicationDecision(data?.decision) : null;
    const matchedDecision = decision && typeof body === 'object' && body && 'id' in body && body.id === decision.id ? decision : null;
    if (action === 'submit' && response.status === 400 && data?.code === 'invalid-application-key') {
      return { status: 400, data: { error: 'Invalid application key', code: 'invalid-application-key' } };
    }
    const closed = action === 'submit' && response.status === 429 ? legalApplicationIntakeClosedCode(data?.code) : null;
    if (closed) return { status: 429, data: { error: LEGAL_APPLICATION_INTAKE_CLOSED[closed], code: closed } };
    if (!response.ok) return { status: [400, 409, 429].includes(response.status) ? response.status : 503,
      data: { error: response.status === 409 ? 'Application already decided or unavailable' : 'Applications unavailable', ...(response.status === 409 && matchedDecision ? { decision: matchedDecision } : {}) } };
    if (data?.success !== true || (action === 'list' && !Array.isArray(data.applications))) {
      return { status: 503, data: { error: 'Applications unavailable' } };
    }
    if (action === 'status') return { status: 200, data: { success: true,
      state: ['pending', 'sign-in-ready', 'ready', 'denied', 'unavailable'].includes(data.state) ? data.state : 'unavailable',
      ...(['ready', 'sign-in-ready'].includes(data.state) && typeof data.providerOrganizationId === 'string' && /^org_[A-Za-z0-9]+$/.test(data.providerOrganizationId)
        ? { providerOrganizationId: data.providerOrganizationId } : {}) } };
    if (action !== 'list') return { status: action === 'submit' ? 202 : 200, data: { success: true, ...(matchedDecision ? { decision: matchedDecision } : {}) } };
    return { status: 200, data: { success: true, provisioningEnabled: data.provisioningEnabled === true, applications: Array.isArray(data.applications) ? data.applications.flatMap((item: unknown) => {
      const result = projectLegalApplication(item); return result ? [result] : [];
    }) : [], next: typeof data.next === 'string' && /^[a-f0-9]{64}$/.test(data.next) ? data.next : null } };
  } catch (error) {
    console.warn(`[Legal Applications Proxy] request failed action=${action} ${failureCode(error)} elapsedMs=${Date.now() - started}`);
    return { status: 503, data: { error: 'Applications unavailable' } };
  }
}
