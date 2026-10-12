import { readDashboardResponse } from '../../../lib/dashboardResponse';

describe('admin dashboard responses', () => {
  it.each([401, 403, 500, 502, 503])('rejects HTTP %s even with a success-looking body', async status => {
    const response = Response.json({ success: true, data: { reports: [] }, error: 'PRIVATE UPSTREAM DETAIL' }, { status });
    await expect(readDashboardResponse(response, 'Reports')).rejects.toThrow();
  });

  it('keeps upstream details out of the visible error', async () => {
    await expect(readDashboardResponse(Response.json({ error: 'PRIVATE UPSTREAM DETAIL' }, { status: 502 }), 'Reports'))
      .rejects.toThrow('Reports could not be loaded (HTTP 502). Try again.');
  });

  it.each([null, { success: false }, { success: true }, { success: true, data: null }])('rejects an invalid response envelope: %j', async body => {
    await expect(readDashboardResponse(Response.json(body), 'Reports')).rejects.toThrow('Reports could not be loaded');
  });

  it('distinguishes an actual empty report list from a failed request', async () => {
    await expect(readDashboardResponse(Response.json({ success: true, data: { reports: [] } }), 'Reports')).resolves.toEqual({ reports: [] });
  });

  it('handles non-JSON gateway responses', async () => {
    await expect(readDashboardResponse(new Response('<html>Unavailable</html>'), 'Reports')).rejects.toThrow('Reports could not be loaded');
  });
});
