import { legalApplicationRequest } from '../../../lib/legalApplicationProxy';
jest.mock('../../../pages/api/admin/confidential/listings', () => ({ confidentialListingBackend: () => ({ url: 'https://backend.example', secret: 'synthetic' }) }));
describe('application proxy acknowledgement', () => {
  const original = process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
  beforeEach(() => { process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '1'; });
  afterEach(() => { jest.restoreAllMocks(); if (original === undefined) delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES; else process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = original; });
  it('uses confidential applications by default and requires explicit legacy opt-out', async () => {
    delete process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES;
    const mock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(Response.json({ success: true }, { status: 202 }));
    expect((await legalApplicationRequest('submit', {})).status).toBe(202);
    process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES = '0';
    expect((await legalApplicationRequest('submit', {})).status).toBe(503);
    expect(mock).toHaveBeenCalledTimes(1);
  });
  it('never tells an applicant their submission was accepted without the backend acknowledgement', async () => {
    const mock = jest.spyOn(global, 'fetch');
    for (const value of [{ success: false }, {}, null]) {
      mock.mockResolvedValueOnce(new Response(JSON.stringify(value), { status: 200 }));
      expect((await legalApplicationRequest('submit', {})).status).toBe(503);
    }
    mock.mockResolvedValueOnce(new Response('<html>wrong upstream</html>', { status: 200 }));
    expect((await legalApplicationRequest('submit', {})).status).toBe(503);
    mock.mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), { status: 202 }));
    expect(await legalApplicationRequest('submit', {})).toEqual({ status: 202, data: { success: true } });
  });
  it('does not turn a malformed roster response into an empty successful list', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce(new Response(JSON.stringify({ success: true }), { status: 200 }));
    expect((await legalApplicationRequest('list', {})).status).toBe(503);
  });
  it('projects a key-validation failure without forwarding upstream diagnostics', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValueOnce(Response.json({ code: 'invalid-application-key',
      error: 'Internal PGP diagnostic', debug: 'not for the browser' }, { status: 400 }));
    expect(await legalApplicationRequest('submit', {})).toEqual({ status: 400,
      data: { code: 'invalid-application-key', error: 'Invalid application key' } });
  });
  it('projects closed intake only for a known code, and keeps rate limiting generic', async () => {
    const fetchMock = jest.spyOn(global, 'fetch');
    fetchMock.mockResolvedValueOnce(Response.json({ code: 'applications-closed', error: 'upstream text', count: 300 }, { status: 429 }));
    expect(await legalApplicationRequest('submit', {})).toEqual({ status: 429,
      data: { code: 'applications-closed', error: 'Applications are temporarily closed. Try again later.' } });
    fetchMock.mockResolvedValueOnce(Response.json({ code: 'domain-applications-pending' }, { status: 429 }));
    expect((await legalApplicationRequest('submit', {})).data).toMatchObject({ code: 'domain-applications-pending' });
    for (const code of [undefined, 'toString', 'other']) {
      fetchMock.mockResolvedValueOnce(Response.json({ code }, { status: 429 }));
      expect(await legalApplicationRequest('submit', {})).toEqual({ status: 429, data: { error: 'Applications unavailable' } });
    }
  });
  it('projects only the matching durable decision for success and conflict', async () => {
    const decision = { id: 'a'.repeat(64), status: 'approved', decidedBy: 'slack:T123:U123', decidedAt: 1800000000000 };
    const fetchMock = jest.spyOn(global, 'fetch');
    for (const status of [200, 409]) {
      fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ success: status === 200, decision: { ...decision, unexpected: 'secret' } }), { status }));
      const result = await legalApplicationRequest('decide', { id: decision.id });
      expect(result.status).toBe(status);
      expect(result.data).toHaveProperty('decision', decision);
    }
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ success: true, decision: { ...decision, id: 'b'.repeat(64) } })));
    expect((await legalApplicationRequest('decide', { id: decision.id })).data).not.toHaveProperty('decision');
  });
  describe('stale pooled connection', () => {
    const reset = () => new TypeError('fetch failed', { cause: Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }) });
    const keyed = { domain: 'firm.example', email: 'counsel@firm.example', enrollment: { organizationId: 'c'.repeat(64) } };
    let warn: jest.SpyInstance;
    beforeEach(() => { warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear(); });
    it('resends an idempotent request once after a connection error and returns the backend answer', async () => {
      for (const [action, body, status] of [['submit', keyed, 202], ['status', { id: 'a'.repeat(64) }, 200]] as const) {
        const mock = jest.spyOn(global, 'fetch').mockRejectedValueOnce(reset())
          .mockResolvedValueOnce(Response.json({ success: true, state: 'pending' }, { status: 200 }));
        expect((await legalApplicationRequest(action, body)).status).toBe(status);
        expect(mock).toHaveBeenCalledTimes(2);
        expect(mock.mock.calls[1]).toEqual(mock.mock.calls[0]);
        mock.mockRestore();
      }
      const mock = jest.spyOn(global, 'fetch').mockRejectedValueOnce(reset())
        .mockResolvedValueOnce(Response.json({ success: true, applications: [], next: null }));
      expect(await legalApplicationRequest('list', {})).toMatchObject({ status: 200, data: { success: true, applications: [] } });
      expect(mock).toHaveBeenCalledTimes(2);
    });
    it('resends only once', async () => {
      const mock = jest.spyOn(global, 'fetch').mockRejectedValueOnce(reset()).mockRejectedValueOnce(reset());
      expect((await legalApplicationRequest('submit', keyed)).status).toBe(503);
      expect(mock).toHaveBeenCalledTimes(2);
    });
    it('does not resend after an HTTP error status', async () => {
      const mock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(Response.json({ success: false }, { status: 503 }));
      expect((await legalApplicationRequest('submit', keyed)).status).toBe(503);
      expect(mock).toHaveBeenCalledTimes(1);
    });
    it('never resends a decision', async () => {
      const mock = jest.spyOn(global, 'fetch').mockRejectedValueOnce(reset());
      expect((await legalApplicationRequest('decide', { id: 'a'.repeat(64), status: 'approved' })).status).toBe(503);
      expect(mock).toHaveBeenCalledTimes(1);
    });
    it('does not resend a keyless submission, which the backend stores under a fresh random ID', async () => {
      const mock = jest.spyOn(global, 'fetch').mockRejectedValueOnce(reset());
      expect((await legalApplicationRequest('submit', { domain: 'firm.example' })).status).toBe(503);
      expect(mock).toHaveBeenCalledTimes(1);
    });
    it('logs only the action, error name, socket code, status and elapsed time', async () => {
      jest.spyOn(global, 'fetch').mockRejectedValueOnce(reset()).mockRejectedValueOnce(reset())
        .mockResolvedValueOnce(Response.json({ success: false }, { status: 500 }));
      await legalApplicationRequest('submit', keyed, { 'x-client': 'client-secret' });
      await legalApplicationRequest('status', { id: 'a'.repeat(64) });
      const lines = warn.mock.calls.map(call => call.join(' '));
      expect(lines[0]).toMatch(/^\[Legal Applications Proxy\] retrying action=submit error=TypeError code=ECONNRESET elapsedMs=\d+$/);
      expect(lines[1]).toMatch(/^\[Legal Applications Proxy\] request failed action=submit error=TypeError code=ECONNRESET elapsedMs=\d+$/);
      expect(lines[2]).toBe('[Legal Applications Proxy] backend status action=status status=500');
      for (const line of lines) for (const secret of ['firm.example', 'counsel', 'client-secret', 'synthetic', 'backend.example', 'c'.repeat(64), 'a'.repeat(64)]) expect(line).not.toContain(secret);
    });
  });
});
