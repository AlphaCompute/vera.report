import http from 'node:http';
import { EmailAdapter } from '../../../../src/services/dissemination/adapters/emailAdapter';

test('SES transport does not replay a retryable response or fabricate a missing receipt', async () => {
  const env = { ...process.env };
  let calls = 0;
  let status = 503;
  const server = http.createServer((req, res) => {
    calls++;
    req.resume();
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(status === 503 ? JSON.stringify({ message: 'unknown delivery outcome', __type: 'ServiceUnavailableException' }) : '{}');
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    process.env.AWS_ENDPOINT_URL = `http://127.0.0.1:${(server.address() as import('node:net').AddressInfo).port}`;
    process.env.AWS_ACCESS_KEY_ID = 'synthetic';
    process.env.AWS_SECRET_ACCESS_KEY = 'synthetic';
    process.env.AWS_MAX_ATTEMPTS = '5';
    process.env.DISSEMINATION_MODE = 'dryrun';
    process.env.DISSEMINATION_SENDER_EMAIL = 'sender@example.test';
    const adapter = new EmailAdapter({ entityId: 'test', entityName: 'Test', intakeAddress: 'to@example.test', salutation: 'Hello', bodyIntro: 'Synthetic' });
    const prepared = { entityId: 'test', trackingId: 'synthetic', mode: 'email' as const, email: { to: 'to@example.test', subject: 'Synthetic', coverLetter: 'Synthetic', attachments: [], contentFree: true } };
    await expect(adapter.dispatch(prepared)).rejects.toThrow();
    expect(calls).toBe(1);
    status = 200;
    await expect(adapter.dispatch(prepared)).rejects.toThrow('missing message ID');
    expect(calls).toBe(2);
  } finally {
    process.env = env;
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
