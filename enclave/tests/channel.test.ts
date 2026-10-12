import * as tls from 'node:tls';
import { createHash, X509Certificate, createPrivateKey } from 'node:crypto';
import { AddressInfo } from 'node:net';
import { createChannelCredentials, createChannelServer } from '../src/channel-server.js';
import { frameMessage } from '../src/server.js';

it('generates a fresh certificate for an internally owned private key', async () => {
  const first = await createChannelCredentials();
  const second = await createChannelCredentials();
  try {
    expect(new X509Certificate(first.cert).checkPrivateKey(createPrivateKey(first.key))).toBe(true);
    expect(first.hash).not.toBe(second.hash);
    expect(first.hash).toBe(createHash('sha256').update(new X509Certificate(first.cert).raw).digest('hex'));
  } finally { first.key.fill(0); second.key.fill(0); }
});

it.each(['valid', 'supplied-binding', 'secret-method', 'bad-nonce'])('TLS channel request: %s', async kind => {
  const attest = jest.fn(async () => ({ document: Buffer.from('synthetic-document').toString('base64') }));
  const server = await createChannelServer(attest);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  let socket: tls.TLSSocket | undefined;
  try {
    const request = { id: 'test', method: kind === 'secret-method' ? 'decrypt' : 'attestChannel',
      params: { nonce: kind === 'bad-nonce' ? 'bad' : '01'.repeat(32), ...(kind === 'supplied-binding' ? { certificate_sha256: '02'.repeat(32) } : {}) } };
    const received = await new Promise<{ data: Buffer; hash: string }>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let hash = '';
      socket = tls.connect({ port: (server.address() as AddressInfo).port, host: '127.0.0.1',
        minVersion: 'TLSv1.3', rejectUnauthorized: false }, () => {
        hash = createHash('sha256').update(socket!.getPeerCertificate().raw).digest('hex');
        socket!.write(frameMessage(request));
      });
      socket.setTimeout(5000, () => { socket!.destroy(); reject(new Error('Channel test timed out')); });
      socket.on('data', chunk => chunks.push(chunk));
      socket.on('error', reject);
      socket.on('close', () => resolve({ data: Buffer.concat(chunks), hash }));
    });
    if (kind === 'valid') {
      expect(attest).toHaveBeenCalledWith('01'.repeat(32), received.hash);
      expect(JSON.parse(received.data.subarray(4).toString())).toEqual({ id: 'test', result: { document: Buffer.from('synthetic-document').toString('base64') } });
    } else {
      expect(attest).not.toHaveBeenCalled();
      expect(received.data.length).toBe(0);
    }
  } finally {
    socket?.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
