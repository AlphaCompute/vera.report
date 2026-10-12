import { fetchRetryingConnectionError, isConnectionError } from '../../../lib/internalBackendFetch';
const withCode = (code: string) => new TypeError('fetch failed', { cause: Object.assign(new Error(code), { code }) });
describe('fetchRetryingConnectionError', () => {
  afterEach(() => { jest.restoreAllMocks(); });
  it('classifies only socket-level failures as connection errors', () => {
    for (const code of ['ECONNRESET', 'EPIPE', 'UND_ERR_SOCKET', 'UND_ERR_CLOSED']) expect(isConnectionError(withCode(code))).toBe(true);
    expect(isConnectionError(new TypeError('fetch failed', { cause: new Error('unexpected redirect') }))).toBe(false);
    expect(isConnectionError(new DOMException('The operation was aborted due to timeout', 'TimeoutError'))).toBe(false);
    expect(isConnectionError(new Error('read ECONNRESET'))).toBe(false);
  });
  it('shares one abort deadline across both attempts', async () => {
    const onRetry = jest.fn();
    const mock = jest.spyOn(global, 'fetch').mockRejectedValueOnce(withCode('ECONNRESET')).mockResolvedValueOnce(new Response('ok'));
    await fetchRetryingConnectionError('https://backend.example/x', { method: 'POST', body: '{}' }, { timeoutMs: 10_000, retry: true, onRetry });
    expect(mock).toHaveBeenCalledTimes(2);
    expect(mock.mock.calls[1][1]?.signal).toBe(mock.mock.calls[0][1]?.signal);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
  it('does not retry when retry is off or the failure is not a connection error', async () => {
    const mock = jest.spyOn(global, 'fetch').mockRejectedValueOnce(withCode('ECONNRESET'));
    await expect(fetchRetryingConnectionError('https://backend.example/x', {}, { timeoutMs: 10_000, retry: false })).rejects.toThrow('fetch failed');
    mock.mockRejectedValueOnce(new DOMException('aborted', 'AbortError'));
    await expect(fetchRetryingConnectionError('https://backend.example/x', {}, { timeoutMs: 10_000, retry: true })).rejects.toThrow('aborted');
    expect(mock).toHaveBeenCalledTimes(2);
  });
  it('does not retry when too little of the deadline remains', async () => {
    let now = 1_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const mock = jest.spyOn(global, 'fetch').mockImplementationOnce(async () => { now += 9_000; throw withCode('ECONNRESET'); });
    await expect(fetchRetryingConnectionError('https://backend.example/x', {}, { timeoutMs: 10_000, retry: true })).rejects.toThrow('fetch failed');
    expect(mock).toHaveBeenCalledTimes(1);
  });
});
