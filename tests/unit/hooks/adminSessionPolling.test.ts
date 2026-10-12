import { useDashboardStats, useDashboardReports } from '../../../hooks/useDashboardData';
import { useDisseminationAlerts, useRelay } from '../../../hooks/useDissemination';
import { isAdminSessionExpired, noteAdminResponse, resetAdminSessionForTests } from '../../../lib/adminSession';
import { readDashboardResponse } from '../../../lib/dashboardResponse';

const setters: jest.Mock[] = [];
jest.mock('react', () => ({
  useState: (initial: unknown) => { const set = jest.fn(); setters.push(set); return [initial, set]; },
  useEffect: jest.fn(),
  useCallback: (callback: unknown) => callback,
  useRef: (current: unknown) => ({ current }),
}));
jest.mock('sonner', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

const originalFetch = global.fetch;
const status = (code: number) => jest.fn().mockImplementation(async () => Response.json(
  code === 401 ? { error: 'not_authenticated' } : { success: false }, { status: code }));
// A 401 forwarded from the backend (internal-secret mismatch) must stay retryable.
const backend401 = () => jest.fn().mockImplementation(async () => Response.json({ success: false, error: 'Unauthorized' }, { status: 401 }));

beforeEach(() => { resetAdminSessionForTests(); jest.clearAllMocks(); setters.length = 0; });
afterAll(() => { global.fetch = originalFetch; });

describe('admin session expiry', () => {
  it('is set only by the session gate 401', async () => {
    for (const code of [200, 403, 429, 500, 502]) await noteAdminResponse(Response.json({ error: 'not_authenticated' }, { status: code }));
    await noteAdminResponse(Response.json({ success: false, error: 'Unauthorized' }, { status: 401 }));
    await noteAdminResponse(new Response('<html>401</html>', { status: 401 }));
    expect(isAdminSessionExpired()).toBe(false);
    await noteAdminResponse(Response.json({ error: 'not_authenticated' }, { status: 401 }));
    expect(isAdminSessionExpired()).toBe(true);
  });

  it('is recorded when a dashboard response is a 401', async () => {
    await expect(readDashboardResponse(Response.json({ error: 'not_authenticated' }, { status: 401 }), 'Reports')).rejects.toThrow('Your session has expired');
    expect(isAdminSessionExpired()).toBe(true);
  });

  const pollers: Array<[string, () => () => Promise<unknown>]> = [
    ['report statistics', () => useDashboardStats().refetch],
    ['report list', () => useDashboardReports().refetch],
    ['dissemination alerts', () => useDisseminationAlerts().refresh],
    ['relay thread', () => useRelay('VRA-0000000000000001').refresh],
  ];

  it.each(pollers)('stops polling %s after a 401', async (_name, poll) => {
    global.fetch = status(401);
    const tick = poll();
    await tick();
    await tick();
    await tick();
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it.each(pollers)('keeps polling %s after a 403 or 500', async (_name, poll) => {
    for (const code of [403, 500]) {
      global.fetch = status(code);
      const tick = poll();
      await tick();
      await tick();
      expect(global.fetch).toHaveBeenCalledTimes(2);
    }
  });

  it.each(pollers)('keeps polling %s after a backend 401', async (_name, poll) => {
    global.fetch = backend401();
    const tick = poll();
    await tick();
    await tick();
    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(isAdminSessionExpired()).toBe(false);
  });

  it('does not tell the admin to sign in again for a backend 401', async () => {
    await expect(readDashboardResponse(Response.json({ success: false, error: 'Unauthorized' }, { status: 401 }), 'Reports'))
      .rejects.toThrow('Reports could not be loaded (HTTP 401). Try again.');
  });

  it('shows the sign-in message on the dashboard when another poller saw the 401', async () => {
    global.fetch = status(401);
    await useDisseminationAlerts().refresh();
    setters.length = 0;
    await useDashboardStats().refetch();
    const shown = setters.flatMap(set => set.mock.calls.map(([value]) => value instanceof Error ? value.message : value));
    expect(shown).toContain('Your session has expired. Reload the page to sign in again.');
    expect(shown).toContain(false);
  });

  it('stops every poller once any one of them sees a 401', async () => {
    global.fetch = status(401);
    await useDisseminationAlerts().refresh();
    global.fetch = status(200);
    await useDashboardStats().refetch();
    await useRelay('VRA-0000000000000001').refresh();
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
