import http from 'http';
import request from 'supertest';

function close(server: http.Server): Promise<void> {
  return new Promise(resolve => server.close(() => resolve()));
}

it('binds the same loopback address it requests and closes its ephemeral server', async () => {
  const server = http.createServer((req, res) => res.end(req.url));
  const listen = jest.spyOn(server, 'listen');
  const result = await request(server).get('/status').query({ page: 2 }).expect(200);
  expect(listen).toHaveBeenCalledWith(0, '127.0.0.1');
  expect(result.text).toBe('/status?page=2');
  expect(server.listening).toBe(false);
});

it('does not dispatch to an IPv4 listener owning an IPv6 wildcard port', async () => {
  const foreign = http.createServer((_req, res) => res.writeHead(405).end('foreign'));
  await new Promise<void>(resolve => foreign.listen(0, '127.0.0.1', resolve));
  const port = (foreign.address() as any).port;
  const intended = http.createServer((_req, res) => res.end('intended'));
  const originalListen = intended.listen.bind(intended);
  // Deterministically model the allocator choosing an occupied IPv4 port for
  // an unspecified-address bind. Linux rejects it; macOS accepts both binds.
  jest.spyOn(intended, 'listen').mockImplementation(((...args: any[]) => {
    if (args.length === 1 && args[0] === 0) return originalListen(port);
    return (originalListen as any)(...args);
  }) as any);
  try {
    expect((await request(intended).get('/status')).text).toBe('intended');
  } finally {
    await close(foreign);
    if (intended.listening) await close(intended);
  }
});

it('supports callbacks, chained expectations and agent cookies', async () => {
  const app = (_req: http.IncomingMessage, res: http.ServerResponse) => {
    res.setHeader('Set-Cookie', 'session=ok; Path=/');
    res.end(_req.headers.cookie || 'first');
  };
  const agent = request.agent(app);
  await new Promise<void>((resolve, reject) => {
    agent.get('/').expect(200).end(error => error ? reject(error) : resolve());
  });
  expect((await agent.get('/').expect(200)).text).toBe('session=ok');
});

it('leaves existing listeners and URL targets owned by the caller', async () => {
  const server = http.createServer((_req, res) => res.end('existing'));
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await request(server).get('/').expect(200, 'existing');
    await request(`http://127.0.0.1:${(server.address() as any).port}`).get('/').expect(200, 'existing');
    expect(server.listening).toBe(true);
  } finally { await close(server); }
});

it('reports bind errors through the normal promise rejection', async () => {
  const server = http.createServer();
  jest.spyOn(server, 'listen').mockImplementation((() => {
    process.nextTick(() => server.emit('error', new Error('test bind failure')));
    return server;
  }) as any);
  await expect(request(server).get('/')).rejects.toThrow('test bind failure');
});

it('shares an in-progress bind when requests are constructed together', async () => {
  const server = http.createServer((req, res) => {
    // Closing the first request's owned server must drain the slower request.
    if (req.url === '/second') setTimeout(() => res.end('shared'), 30);
    else res.end('shared');
  });
  const first = request(server).get('/first');
  const second = request(server).get('/second');
  const responses = await Promise.all([first, second]);
  expect(responses.map(response => response.text)).toEqual(['shared', 'shared']);
  expect(server.listening).toBe(false);
});

it('does not start a listener for an unconsumed request', () => {
  const server = http.createServer((_req, res) => res.end('unused'));
  request(server).get('/unused');
  expect(server.listening).toBe(false);
});

it('keeps concurrent requests alive when another request finishes first', async () => {
  let release: () => void = () => undefined;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const server = http.createServer((req, res) => {
    if (req.url === '/slow') void gate.then(() => res.end('slow'));
    else res.end('fast');
  });
  const slow = request(server).get('/slow').then(response => response.text);
  expect((await request(server).get('/fast')).text).toBe('fast');
  expect(server.listening).toBe(true);
  release();
  expect(await slow).toBe('slow');
  expect(server.listening).toBe(false);
});

it('closes owned listeners after assertion failures and can bind them again', async () => {
  const server = http.createServer((_req, res) => res.end('ok'));
  await expect(request(server).get('/').expect(400)).rejects.toThrow();
  expect(server.listening).toBe(false);
  await request(server).get('/').expect(200);
  expect(server.listening).toBe(false);
});

it('reports synchronous bind failures through callbacks without leaving error listeners', async () => {
  const server = http.createServer();
  const errors = server.listenerCount('error');
  const listeners = server.listenerCount('listening');
  jest.spyOn(server, 'listen').mockImplementation((() => { throw new Error('sync bind failure'); }) as any);
  await new Promise<void>((resolve, reject) => request(server).get('/').end(error => {
    try {
      expect(error.message).toBe('sync bind failure');
      expect(server.listenerCount('error')).toBe(errors);
      expect(server.listenerCount('listening')).toBe(listeners);
      resolve();
    } catch (failure) { reject(failure); }
  }));
});

it('rebinds a request constructed before the earlier request closed its listener', async () => {
  const server = http.createServer((req, res) => res.end(req.url));
  const later = request(server).get('/later');
  await request(server).get('/first').expect(200, '/first');
  expect(server.listening).toBe(false);
  await later.expect(200, '/later');
  expect(server.listening).toBe(false);
});

it('preserves a caller listener started after the request was constructed', async () => {
  const server = http.createServer((_req, res) => res.end('caller'));
  const pending = request(server).get('/');
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await pending.expect(200, 'caller');
    expect(server.listening).toBe(true);
  } finally { await close(server); }
});
