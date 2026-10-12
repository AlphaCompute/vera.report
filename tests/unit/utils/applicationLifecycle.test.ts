import express from 'express';
import http from 'node:http';
import { createShutdown, HttpServerLifecycle } from '../../../src/utils/applicationLifecycle';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

test('drains every worker before checkpoint and storage teardown, once across repeated signals', async () => {
  const gate = deferred();
  const entered = deferred();
  const checkpoint = jest.fn(async () => {});
  const disconnect = jest.fn(async () => {});
  const shutdown = createShutdown([
    [async () => { entered.resolve(); await gate.promise; }], [checkpoint], [disconnect],
  ]);
  const first = shutdown();
  expect(shutdown()).toBe(first);
  await entered.promise;
  expect(checkpoint).not.toHaveBeenCalled();
  expect(disconnect).not.toHaveBeenCalled();
  gate.resolve();
  await first;
  expect(checkpoint).toHaveBeenCalledTimes(1);
  expect(disconnect).toHaveBeenCalledTimes(1);
  expect(checkpoint.mock.invocationCallOrder[0]).toBeLessThan(disconnect.mock.invocationCallOrder[0]);
});

test('waits for peers after a drain failure and refuses the checkpoint', async () => {
  const gate = deferred();
  const entered = deferred();
  const checkpoint = jest.fn(async () => {});
  const shutdown = createShutdown([[
    async () => { throw new Error('worker drain failed'); },
    async () => { entered.resolve(); await gate.promise; },
  ], [checkpoint]]);
  let settled = false;
  const result = shutdown().catch(error => { settled = true; return error; });
  await entered.promise;
  expect(settled).toBe(false);
  gate.resolve();
  expect(await result).toEqual(new Error('1 shutdown operations failed'));
  expect(checkpoint).not.toHaveBeenCalled();
});

test('closes a real HTTP listener while allowing an accepted request to finish', async () => {
  const lifecycle = new HttpServerLifecycle();
  const entered = deferred();
  const finish = deferred();
  const app = express();
  app.use(lifecycle.admission);
  app.get('/', async (_req, res) => { entered.resolve(); await finish.promise; res.send('accepted'); });
  const server = http.createServer(app);
  lifecycle.attach(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as import('node:net').AddressInfo;
  const url = `http://127.0.0.1:${address.port}`;
  const request = fetch(url).then(response => response.text());
  try {
    await entered.promise;
    let closed = false;
    const closing = lifecycle.close().then(() => { closed = true; });
    expect(server.listening).toBe(false);
    await Promise.resolve();
    expect(closed).toBe(false);
    finish.resolve();
    expect(await request).toBe('accepted');
    await closing;
    await expect(fetch(url)).rejects.toThrow();

    // Exercise admission denial independently of listener closure.
    const probe = http.createServer(app);
    await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve));
    try {
      const result = await fetch(`http://127.0.0.1:${(probe.address() as import('node:net').AddressInfo).port}`);
      expect(result.status).toBe(503);
      expect(result.headers.get('connection')).toBe('close');
      await result.text();
    } finally { await new Promise<void>((resolve, reject) => probe.close(error => error ? reject(error) : resolve())); }
  } finally {
    finish.resolve();
    await request;
    await lifecycle.close();
  }
});
