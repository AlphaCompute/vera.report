import { useState } from 'react';
import { useDashboardReports, type DashboardReport } from '../../../hooks/useDashboardData';

jest.mock('react', () => ({
  useState: jest.fn(), useEffect: jest.fn(),
  useCallback: (callback: unknown) => callback,
  useRef: (current: unknown) => ({ current }),
}));

const originalFetch = global.fetch;
const originalActivity = [{ id: 'old', type: 'submit', description: 'Report submitted', timestamp: '2026-09-23T07:00:00Z' }];
const report = { reportId: 'VRA-0000000000000001', status: 'pending', activity: originalActivity } as DashboardReport;
let setReports: jest.Mock;
beforeEach(() => {
  jest.clearAllMocks();
  setReports = jest.fn();
  jest.mocked(useState)
    .mockImplementation((initial: unknown) => [initial, jest.fn()] as any)
    .mockImplementationOnce(() => [[report], setReports] as any);
});
afterAll(() => { global.fetch = originalFetch; });

function response(body: unknown, ok = true) {
  global.fetch = jest.fn().mockResolvedValue({ ok, json: async () => body });
}

it('returns and displays the persisted status with its matching activity', async () => {
  const activity = [{ id: 'status-1', type: 'status', description: 'Status: resolved', timestamp: '2026-09-23T07:01:00Z' }];
  response({ success: true, data: { status: 'resolved', activity } });
  const hook = useDashboardReports();
  expect(await hook.updateReportStatus(report.reportId, 'investigating')).toBe('resolved');
  expect(setReports.mock.calls[0][0]([report])[0]).toMatchObject({ status: 'resolved', activity });
});

it.each(['pending', 'investigating', 'reviewing', 'resolved', 'dismissed'] as const)(
  'accepts persisted %s and preserves activity when omitted', async status => {
    response({ success: true, data: { status } });
    expect(await useDashboardReports().updateReportStatus(report.reportId, 'investigating')).toBe(status);
    expect(setReports.mock.calls[0][0]([report])[0]).toMatchObject({ status, activity: originalActivity });
  },
);

it('preserves the intentionally redacted employee success contract', async () => {
  response({ success: true });
  expect(await useDashboardReports().updateReportStatus(report.reportId, 'investigating')).toBe('investigating');
  expect(setReports.mock.calls[0][0]([report])[0]).toMatchObject({ status: 'investigating', activity: originalActivity });
});

it.each([undefined, null, 'not-a-status', 1, {}])('rejects invalid persisted status %p', async status => {
  response({ success: true, data: { status } });
  expect(await useDashboardReports().updateReportStatus(report.reportId, 'investigating')).toBe(false);
  expect(setReports).not.toHaveBeenCalled();
});

it.each([{ success: false, data: { status: 'resolved' } }, {}, null])('rejects an unconfirmed success response %p', async body => {
  response(body);
  expect(await useDashboardReports().updateReportStatus(report.reportId, 'investigating')).toBe(false);
  expect(setReports).not.toHaveBeenCalled();
});

it('does not update local state on an HTTP failure', async () => {
  response({ success: false }, false);
  expect(await useDashboardReports().updateReportStatus(report.reportId, 'investigating')).toBe(false);
  expect(setReports).not.toHaveBeenCalled();
});

it('does not update local state for malformed JSON or transport failure', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce({ ok: true, json: async () => { throw new Error('synthetic parse error'); } })
    .mockRejectedValueOnce(new Error('synthetic transport failure'));
  const hook = useDashboardReports();
  expect(await hook.updateReportStatus(report.reportId, 'investigating')).toBe(false);
  expect(await hook.updateReportStatus(report.reportId, 'investigating')).toBe(false);
  expect(setReports).not.toHaveBeenCalled();
});
