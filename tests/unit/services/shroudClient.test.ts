jest.mock('../../../src/config/env', () => ({
  env: {
    SHROUD_API_KEY: 'shroud_dev_test',
    SHROUD_BASE_URL: 'https://dev-gateway.shroud.us',
    SHROUD_MODEL: 'nemotron-3-ultra',
  },
}));

import { shroudChat, isShroudConfigured } from '../../../src/services/shroudClient';
import { env } from '../../../src/config/env';

function fakeResponse(
  content: string,
  opts: { ok?: boolean; status?: number; errorBody?: unknown } = {},
): Response {
  return new Response(JSON.stringify(opts.errorBody ?? { choices: [{ message: { content } }] }), {status: opts.status ?? (opts.ok === false ? 500 : 200)});
}

const messages = [{ role: 'user' as const, content: 'score this' }];

describe('shroudChat', () => {
  const originalFetch = global.fetch;
  const originalKey = env.SHROUD_API_KEY;

  afterEach(() => {
    global.fetch = originalFetch;
    (env as { SHROUD_API_KEY?: string }).SHROUD_API_KEY = originalKey;
    jest.useRealTimers();
  });

  it('returns the response content on the happy path', async () => {
    global.fetch = jest.fn().mockResolvedValue(fakeResponse('{"iso":true}'));
    const result = await shroudChat(messages);
    expect(result).toBe('{"iso":true}');
    expect(JSON.parse(result)).toEqual({ iso: true });
  });

  it('POSTs to the gateway chat-completions endpoint with the configured model and bearer key', async () => {
    const fetchMock = jest.fn().mockResolvedValue(fakeResponse('{}'));
    global.fetch = fetchMock;
    await shroudChat(messages);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://dev-gateway.shroud.us/v1/chat/completions');
    expect(init.headers.Authorization).toBe('Bearer shroud_dev_test');
    const sent = JSON.parse(init.body);
    expect(sent.model).toBe('nemotron-3-ultra');
    expect(sent.stream).toBe(false);
    expect(sent.chat_template_kwargs).toEqual({ enable_thinking: false });
  });

  it('strips <think> reasoning and markdown fences so JSON.parse succeeds', async () => {
    global.fetch = jest
      .fn()
      .mockResolvedValue(fakeResponse('<think>reasoning here</think>```json\n{"x":1}\n```'));
    const result = await shroudChat(messages);
    expect(result).not.toContain('<think>');
    expect(result).not.toContain('```');
    expect(JSON.parse(result)).toEqual({ x: 1 });
  });

  it('fails fast on a deterministic 4xx without retrying', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(
        fakeResponse('', { ok: false, status: 400, errorBody: { error: { message: 'bad request' } } }),
      );
    global.fetch = fetchMock;
    await expect(shroudChat(messages)).rejects.toThrow(/bad request|inference request failed/i);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries transient 5xx responses before giving up', async () => {
    jest.useFakeTimers();
    const fetchMock = jest
      .fn()
      .mockResolvedValue(
        fakeResponse('', { ok: false, status: 503, errorBody: { error: { message: 'unavailable' } } }),
      );
    global.fetch = fetchMock;
    const pending = shroudChat(messages);
    const assertion = expect(pending).rejects.toThrow(/unavailable|inference request failed/i);
    await jest.runAllTimersAsync();
    await assertion;
    expect(fetchMock).toHaveBeenCalledTimes(4); // initial + 3 retries
  });

  it('never echoes provider errors containing private report bytes or follows redirects', async () => {
    global.fetch = jest.fn().mockResolvedValue(fakeResponse('', {ok:false,status:401,errorBody:{error:{message:'private-report-canary'}}}));
    await expect(shroudChat(messages)).rejects.not.toThrow('private-report-canary');
    expect(jest.mocked(fetch).mock.calls[0][1]?.redirect).toBe('error');
  });
  it.each(['', ' '.repeat(5), 'x'.repeat(100001)])('rejects empty or oversized output without retrying', async content => {
    global.fetch = jest.fn().mockResolvedValue(fakeResponse(content));
    await expect(shroudChat(messages)).rejects.toThrow('invalid inference response');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([429, 408])('retries transient HTTP %s and recovers', async status => {
    jest.useFakeTimers();
    global.fetch = jest.fn().mockResolvedValueOnce(fakeResponse('', {status})).mockResolvedValueOnce(fakeResponse('{"ok":true}'));
    const result=shroudChat(messages);await jest.runAllTimersAsync();
    await expect(result).resolves.toBe('{"ok":true}');expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('rejects malformed provider JSON without echoing its contents', async()=>{
    global.fetch=jest.fn().mockResolvedValue(new Response('private-malformed-canary'));
    await expect(shroudChat(messages)).rejects.toThrow('[SHROUD] invalid inference response');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('bounds the whole provider response before JSON parsing',async()=>{
    global.fetch=jest.fn().mockResolvedValue(new Response('x'.repeat(256001)));
    await expect(shroudChat(messages)).rejects.toThrow('invalid inference response');expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('throws when SHROUD_API_KEY is not configured', async () => {
    (env as { SHROUD_API_KEY?: string }).SHROUD_API_KEY = '';
    global.fetch = jest.fn();
    await expect(shroudChat(messages)).rejects.toThrow(/not configured/i);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('isShroudConfigured', () => {
  it('is true when SHROUD_API_KEY is set', () => {
    expect(isShroudConfigured()).toBe(true);
  });
});


describe('Shroud private transport failures', () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; jest.restoreAllMocks(); jest.useRealTimers(); });
  it('sanitizes rejected transport errors through retries and final rejection', async () => {
    jest.useFakeTimers();
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    global.fetch = jest.fn().mockRejectedValue(new TypeError('private-report-canary Authorization: private-key'));
    const result = expect(shroudChat(messages)).rejects.toThrow('[SHROUD] inference transport unavailable');
    await jest.runAllTimersAsync(); await result;
    expect(fetch).toHaveBeenCalledTimes(4);
    expect(JSON.stringify(warn.mock.calls)).not.toMatch(/private-report-canary|private-key/);
  });
  it('does not retry invalid credentials even if cancellation fails with private text', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 401, body: { cancel: async () => { throw new Error('private-cancel-canary'); } } });
    await expect(shroudChat(messages)).rejects.toThrow('status 401');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it.each(['<think>private reasoning</think>', '```json\n```'])('rejects content that becomes empty after cleaning', async content => {
    global.fetch = jest.fn().mockResolvedValue(fakeResponse(content));
    await expect(shroudChat(messages)).rejects.toThrow('invalid inference response');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe('cancellation over real HTTP', () => {
  it.each(['headers', 'body'])('aborts while waiting for response %s without sending another request', async stage => {
    const { createServer } = await import('node:http');
    const originalBase = env.SHROUD_BASE_URL;
    const controller = new AbortController();
    let received!: () => void;
    let disconnected!: () => void;
    const started = new Promise<void>(resolve => { received = resolve; });
    const closed = new Promise<void>(resolve => { disconnected = resolve; });
    let requests = 0;
    const server = createServer((req, res) => {
      requests++;
      req.resume();
      res.once('close', disconnected);
      if (stage === 'body') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.write('{"choices":');
      }
      received();
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing local server address');
    (env as { SHROUD_BASE_URL: string }).SHROUD_BASE_URL = `http://127.0.0.1:${address.port}`;
    try {
      const pending = shroudChat(messages, controller.signal);
      const rejected = expect(pending).rejects.toThrow('synthetic caller stop');
      await started;
      controller.abort(new Error('synthetic caller stop'));
      await rejected;
      await closed;
      expect(requests).toBe(1);
    } finally {
      controller.abort();
      (env as { SHROUD_BASE_URL: string }).SHROUD_BASE_URL = originalBase;
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });
});
