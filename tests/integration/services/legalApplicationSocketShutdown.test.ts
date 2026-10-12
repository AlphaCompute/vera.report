import { WebSocket, WebSocketServer } from 'ws';
import { LegalApplicationSocketWorker, legalApplicationSocketSettings } from '../../../src/services/legalApplicationSocket';

/** Real Slack SDK, synthetic token exchange and a loopback WebSocket only. */
it.each(['greeting', 'token response'])('stops while waiting for the Slack %s without requiring hello', async phase => {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve); server.once('error', reject);
  });
  const address = server.address();
  if (typeof address === 'string' || !address) throw new Error('Missing loopback address');
  let peer: WebSocket | undefined;
  const connected = new Promise<void>(resolve => server.once('connection', socket => {
    peer = socket; resolve(); // Deliberately omit Slack's application-level hello.
  }));
  let releaseExchange!: () => void;
  const exchange = new Promise<void>(resolve => { releaseExchange = resolve; });
  let requested!: () => void;
  const requestStarted = new Promise<void>(resolve => { requested = resolve; });
  const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async url => {
    if (String(url) !== 'https://slack.com/api/apps.connections.open') throw new Error('Unexpected network request');
    requested(); await exchange;
    return new Response(JSON.stringify({ ok: true, url: `ws://127.0.0.1:${address.port}` }), {
      headers: { 'Content-Type': 'application/json' },
    });
  });
  const worker = new LegalApplicationSocketWorker({
    settings: legalApplicationSocketSettings({ SLACK_APPLICATION_APP_TOKEN: 'xapp-synthetic-test', SLACK_APPLICATION_BOT_TOKEN: 'xoxb-synthetic-test',
      SLACK_APPLICATION_TEAM_ID: 'T123', SLACK_APPLICATION_APPROVERS: 'U123' })!,
    decide: jest.fn(), getApplication: jest.fn(),
  });
  let deadline: ReturnType<typeof setTimeout> | undefined;
  let stopping: Promise<void> | undefined;
  try {
    worker.start();
    await requestStarted;
    if (phase === 'greeting') { releaseExchange(); await connected; }
    stopping = worker.stop();
    // A token response arriving after stop must not leave a new socket alive.
    releaseExchange();
    const result = await Promise.race([
      stopping.then(() => 'stopped'),
      new Promise<string>(resolve => { deadline = setTimeout(() => resolve('still waiting for hello'), 1000); }),
    ]);
    expect(result).toBe('stopped');
    expect(fetch).toHaveBeenCalledTimes(1);
  } finally {
    clearTimeout(deadline);
    releaseExchange();
    // Also release the pre-fix implementation so a failed assertion cannot leak sockets.
    peer?.terminate();
    await (stopping ?? worker.stop());
    await new Promise<void>(resolve => server.close(() => resolve()));
    fetch.mockRestore();
  }
});
