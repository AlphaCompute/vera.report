import { generateKey, createMessage, encrypt } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { ChannelClockError, sealChannelRequest, openChannelRequest, sealChannelResponse } from '../../../enclave/src/confidential/channelMessage';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import { setPgpClock } from '../../../enclave/src/confidential/pgpClock';

const nonce = '1'.repeat(64), input = new TextEncoder().encode('SYNTHETIC PRIVATE REQUEST'),
  output = new TextEncoder().encode('SYNTHETIC PRIVATE RESPONSE');
let server: PrivateKey, host: PrivateKey;
beforeAll(async () => {
  [server, host] = await Promise.all(['enclave', 'host'].map(async name => (await generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object',
  })).privateKey));
});
afterEach(() => setPgpClock({ signing: () => Date.now(), verification: () => Date.now() }));

test.each([430, -430, 2_000, -2_000, CLOCK_SKEW_MS, -CLOCK_SKEW_MS])(
  'round trips with the enclave clock %i ms ahead of the browser', async skew => {
    // Cross a whole-second boundary with a sub-second offset, as in #1106.
    const browserTime = Math.floor(Date.now() / 1000) * 1000 + 752;
    let clock = browserTime + skew;
    setPgpClock({ signing: () => clock, verification: () => clock });
    const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Skewed enclave' }], format: 'object' });
    clock = browserTime;
    const pending = await sealChannelRequest(publicKey, nonce, input);
    clock = browserTime + skew;
    const request = await openChannelRequest(pending.ciphertext, nonce, privateKey);
    expect(request.body).toEqual(input);
    const response = await sealChannelResponse(request, output, privateKey);
    clock = browserTime;
    expect(await pending.openResponse(response)).toEqual(output);
  },
);

test('rejects a server key beyond the clock budget with a sanitized clock error', async () => {
  const now = Math.floor(Date.now() / 1000) * 1000;
  setPgpClock({ signing: () => now, verification: () => now });
  const { publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Future enclave' }], date: new Date(now + CLOCK_SKEW_MS + 1_000), format: 'object' });
  await expect(sealChannelRequest(publicKey, nonce, input)).rejects.toBeInstanceOf(ChannelClockError);
});

test('rejects a response signature beyond the clock budget and consumes the pending request', async () => {
  const now = Math.floor(Date.now() / 1000) * 1000;
  setPgpClock({ signing: () => now, verification: () => now });
  const pending = await sealChannelRequest(server.toPublic(), nonce, input);
  const request = await openChannelRequest(pending.ciphertext, nonce, server);
  const forged = await encrypt({ message: await createMessage({ text: JSON.stringify({
    format: 'vera-channel-response/v1', ...request.binding, body: Buffer.from(output).toString('base64'),
  }) }), signingKeys: server, encryptionKeys: request.replyKey, date: new Date(now + CLOCK_SKEW_MS + 1_000) });
  await expect(pending.openResponse(forged)).rejects.toThrow('Invalid confidential channel message');
  await expect(pending.openResponse(forged)).rejects.toThrow();
});

test('enclave rejects a request signature beyond the clock budget', async () => {
  const now = Math.floor(Date.now() / 1000) * 1000;
  setPgpClock({ signing: () => now, verification: () => now });
  const forged = await encrypt({ message: await createMessage({ text: JSON.stringify({
    format: 'vera-channel-request/v1', nonce, requestId: '2'.repeat(64),
    serverKeyId: await caseRecipientKeyId(server.toPublic()),
    replyPublicKey: Buffer.from(host.toPublic().write()).toString('base64'), body: Buffer.from(input).toString('base64'),
  }) }), signingKeys: host, encryptionKeys: server.toPublic(), date: new Date(now + CLOCK_SKEW_MS + 1_000) });
  await expect(openChannelRequest(forged, nonce, server)).rejects.toThrow('Invalid confidential channel message');
});

test('round trips encrypted request and enclave-signed response without exposing keys in serialization', async () => {
  const pending = await sealChannelRequest(server.toPublic(), nonce, input);
  expect(JSON.parse(JSON.stringify(pending))).toEqual({ ciphertext: pending.ciphertext });
  expect(pending.ciphertext).not.toContain('SYNTHETIC PRIVATE');
  await expect(openChannelRequest(pending.ciphertext, nonce, host)).rejects.toThrow();
  const request = await openChannelRequest(pending.ciphertext, nonce, server);
  expect(request.body).toEqual(input);
  const reply = await sealChannelResponse(request, output, server);
  expect(reply).not.toContain('SYNTHETIC PRIVATE');
  expect(await pending.openResponse(reply)).toEqual(output);
  await expect(pending.openResponse(reply)).rejects.toThrow();
});
test('wrong challenge, reply swapping, and explicit close fail', async () => {
  const first = await sealChannelRequest(server.toPublic(), nonce, input);
  const second = await sealChannelRequest(server.toPublic(), nonce, input);
  await expect(openChannelRequest(first.ciphertext, '2'.repeat(64), server)).rejects.toThrow();
  const request = await openChannelRequest(first.ciphertext, nonce, server);
  const reply = await sealChannelResponse(request, output, server);
  await expect(second.openResponse(reply)).rejects.toThrow();
  first.close();
  await expect(first.openResponse(reply)).rejects.toThrow();
});
test('consumes a reply exactly once even for concurrent opens', async () => {
  const pending = await sealChannelRequest(server.toPublic(), nonce, input);
  const request = await openChannelRequest(pending.ciphertext, nonce, server);
  const reply = await sealChannelResponse(request, output, server);
  const results = await Promise.allSettled([pending.openResponse(reply), pending.openResponse(reply)]);
  expect(results.map(result => result.status).sort()).toEqual(['fulfilled', 'rejected']);
});
test.each(['nonce', 'requestId', 'requestDigest', 'serverKeyId'] as const)('rejects response with altered %s', async field => {
  const pending = await sealChannelRequest(server.toPublic(), nonce, input);
  const request = await openChannelRequest(pending.ciphertext, nonce, server);
  // Bypass the safe response helper to simulate malicious signed protocol bytes.
  const forged = await encrypt({ message: await createMessage({ text: JSON.stringify({
    format: 'vera-channel-response/v1', ...request.binding, [field]: 'f'.repeat(64),
    body: Buffer.from(output).toString('base64'),
  }) }), signingKeys: server, encryptionKeys: request.replyKey });
  await expect(pending.openResponse(forged)).rejects.toThrow();
});
test('host cannot sign a response, even when it knows the reply recipient', async () => {
  const pending = await sealChannelRequest(server.toPublic(), nonce, input);
  const request = await openChannelRequest(pending.ciphertext, nonce, server);
  await expect(sealChannelResponse(request, output, host)).rejects.toThrow();
  const forged = await encrypt({ message: await createMessage({ text: JSON.stringify({
    format: 'vera-channel-response/v1', ...request.binding, body: Buffer.from(output).toString('base64'),
  }) }), signingKeys: host, encryptionKeys: request.replyKey });
  await expect(pending.openResponse(forged)).rejects.toThrow();
});
test('request signature must match its encrypted reply key', async () => {
  const { publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'other recipient' }], format: 'object' });
  const forged = await encrypt({ message: await createMessage({ text: JSON.stringify({
    format: 'vera-channel-request/v1', nonce, requestId: '2'.repeat(64), serverKeyId: await caseRecipientKeyId(server.toPublic()),
    replyPublicKey: Buffer.from(publicKey.write()).toString('base64'), body: Buffer.from(input).toString('base64'),
  }) }), signingKeys: host, encryptionKeys: server.toPublic() });
  await expect(openChannelRequest(forged, nonce, server)).rejects.toThrow();
});
test('bounds payloads and ciphertext and fails without emitting raw diagnostics', async () => {
  await expect(sealChannelRequest(server.toPublic(), nonce, new Uint8Array(256 * 1024 + 1))).rejects.toThrow('Invalid confidential channel message');
  await expect(openChannelRequest('x'.repeat(768 * 1024 + 1), nonce, server)).rejects.toThrow('Invalid confidential channel message');
  const pending = await sealChannelRequest(server.toPublic(), nonce, input);
  await expect(pending.openResponse('private failure sentinel')).rejects.toThrow('Invalid confidential channel message');
  const request = await openChannelRequest(pending.ciphertext, nonce, server);
  await expect(pending.openResponse(await sealChannelResponse(request, output, server))).rejects.toThrow();
});
