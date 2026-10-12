import http from 'node:http';
import { once } from 'node:events';
import { createAttestedEcsCredentials } from '../../../src/services/attestedEcsCredentials';

const role = 'arn:aws:iam::000000000000:role/synthetic-recipient-task';
const relativeUri = '/v2/credentials/00000000-0000-0000-0000-000000000001';
const fixture = () => ({ RoleArn: role, AccessKeyId: 'synthetic-access', SecretAccessKey: 'synthetic-secret',
  Token: 'synthetic-token', Expiration: new Date(Date.now() + 3600000).toISOString() });
let server: http.Server;
let calls: number;
let respond: (response: http.ServerResponse) => void;
beforeEach(async () => {
  calls = 0;
  respond = response => response.end(JSON.stringify(fixture()));
  server = http.createServer((request, response) => {
    calls++;
    expect(request.url).toBe(relativeUri);
    respond(response);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const get = http.get.bind(http);
  jest.spyOn(http, 'get').mockImplementation(((options: http.RequestOptions, listener: (response: http.IncomingMessage) => void) => {
    expect(options).toEqual({ hostname: '169.254.170.2', port: 80, path: relativeUri, agent: false });
    return get({ ...options, hostname: '127.0.0.1', port: (server.address() as { port: number }).port }, listener);
  }) as typeof http.get);
});
afterEach(async () => {
  jest.restoreAllMocks();
  server.closeAllConnections();
  await new Promise<void>(resolve => server.close(() => resolve()));
});
it('loads current temporary credentials over the fixed endpoint without caching', async () => {
  const value = fixture();
  respond = response => response.end(JSON.stringify(value));
  const provider = createAttestedEcsCredentials(relativeUri, role);
  expect(await provider(new AbortController().signal)).toEqual({ accessKeyId: value.AccessKeyId,
    secretAccessKey: value.SecretAccessKey, sessionToken: value.Token, expiration: value.Expiration });
  value.Token = 'rotated-token';
  expect((await provider(new AbortController().signal)).sessionToken).toBe('rotated-token');
  expect(calls).toBe(2);
});
it.each(['redirect', 'role', 'expired', 'token', 'oversize', 'malformed', 'encoding', 'utf8', 'truncated'])('rejects %s with a redacted error', async kind => {
  respond = response => {
    const value = fixture();
    if (kind === 'encoding') { response.setHeader('Content-Encoding', 'gzip'); response.end('not credentials'); return; }
    if (kind === 'utf8') { response.end(Buffer.from([255])); return; }
    if (kind === 'truncated') { response.writeHead(200, { 'Content-Length': '1000' }); response.write('{'); response.destroy(); return; }
    if (kind === 'redirect') { response.writeHead(302, { Location: 'http://example.invalid/' }); response.end(); return; }
    if (kind === 'role') value.RoleArn += '-wrong';
    if (kind === 'expired') value.Expiration = new Date().toISOString();
    if (kind === 'token') value.Token = '';
    response.end(kind === 'oversize' ? 'x'.repeat(32769) : kind === 'malformed' ? 'private provider diagnostic' : JSON.stringify(value));
  };
  await expect(createAttestedEcsCredentials(relativeUri, role)(new AbortController().signal)).rejects.toThrow('Attested task credentials unavailable');
  expect(calls).toBe(1);
});
it('aborts an active request and rejects an already-aborted request without connecting', async () => {
  const controller = new AbortController();
  respond = () => controller.abort();
  const provider = createAttestedEcsCredentials(relativeUri, role);
  await expect(provider(controller.signal)).rejects.toThrow('Attested task credentials unavailable');
  await expect(provider(controller.signal)).rejects.toThrow('Attested task credentials unavailable');
  expect(calls).toBe(1);
});
it('bounds a peer that never responds', async () => {
  respond = () => {};
  await expect(createAttestedEcsCredentials(relativeUri, role)(new AbortController().signal)).rejects.toThrow('Attested task credentials unavailable');
}, 10000);
it('rejects other URLs and accounts before opening a connection', () => {
  for (const uri of ['http://example.invalid/', '//example.invalid/', '/v2/credentials/id?redirect=1', '/other']) {
    expect(() => createAttestedEcsCredentials(uri, role)).toThrow();
  }
  expect(() => createAttestedEcsCredentials(relativeUri, role.replace('000000000000', '123456789012'))).toThrow();
  expect(calls).toBe(0);
});
