import { throwIfRateLimited } from './rateLimitResponse';
import { ADMIN_SESSION_EXPIRED_MESSAGE, isAdminSessionExpired, noteAdminResponse } from './adminSession';

/** Keep upstream error bodies (which may contain private data) out of the UI. */
export async function readDashboardResponse(response: Response, label: string): Promise<unknown> {
  await noteAdminResponse(response);
  await throwIfRateLimited(response);
  if (response.status === 401) {
    throw new Error(isAdminSessionExpired() ? ADMIN_SESSION_EXPIRED_MESSAGE : `${label} could not be loaded (HTTP 401). Try again.`);
  }
  if (response.status === 403) throw new Error(`Your account does not have access to ${label.toLowerCase()}.`);
  if (!response.ok) throw new Error(`${label} could not be loaded (HTTP ${response.status}). Try again.`);
  const result = await response.json().catch(() => null);
  if (result?.success !== true || !result.data || typeof result.data !== 'object') {
    throw new Error(`${label} could not be loaded. Try again.`);
  }
  return result.data;
}
