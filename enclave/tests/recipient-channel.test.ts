import * as tls from 'node:tls';
import { createHash } from 'node:crypto';
import { createRecipientChannelServer } from '../src/recipient-channel';
import { RecipientSession } from '../src/recipient-session';
import { frameMessage } from '../src/server';
jest.mock('../src/recipient-session', () => ({ RecipientSession: jest.fn() }));
const fixtures: Array<() => Promise<void>> = [];
async function fixture() {
  const session = { beginRead:jest.fn(), appendRead:jest.fn(), authenticateRead:jest.fn(), readChunk:jest.fn(), cancelRead:jest.fn(), generate: jest.fn(async () => ({ handle: 'opaque-handle', wrappedKey: 'wrapped' })),
    bootstrapLegacyPrivate: jest.fn(async () => 'private-handle'), decryptLegacyPrivate: jest.fn(async () => Buffer.from('{}')), bootstrap: jest.fn(async () => 'opaque-handle'), bootstrapLegacyEvidence: jest.fn(async () => 'legacy-handle'), decryptLegacyEvidence: jest.fn(async () => Buffer.from('historical')), encrypt: jest.fn(), decrypt: jest.fn(), close: jest.fn() };
  (RecipientSession as jest.Mock).mockImplementation(() => session);
  const attest = jest.fn(async () => ({ document: 'synthetic-attestation' }));
  const server = await createRecipientChannelServer(attest);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const socket = tls.connect({ host: '127.0.0.1', port: (server.address() as any).port, rejectUnauthorized: false, minVersion: 'TLSv1.3' });
  await new Promise<void>((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', reject); });
  socket.setTimeout(3000, () => socket.destroy());
  const digest = createHash('sha256').update(socket.getPeerCertificate().raw).digest();
  fixtures.push(async () => { socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); });
  function exchange(request: unknown): Promise<any> {
    return new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      const cleanup = () => { socket.off('data', data); socket.off('close', closed); socket.off('error', failed); };
      const closed = () => { cleanup(); resolve(undefined); };
      const failed = (error: Error) => { cleanup(); reject(error); };
      const data = (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (buffer.length >= 4 && buffer.length >= buffer.readUInt32BE() + 4) { cleanup(); resolve(JSON.parse(buffer.subarray(4).toString())); }
      };
      socket.on('data', data); socket.once('close', closed); socket.once('error', failed);
      socket.write(Buffer.isBuffer(request) ? request : frameMessage(request));
    });
  }
  const challenge = () => exchange({ id: 'challenge', method: 'attestChannel', params: { nonce: '01'.repeat(32) } });
  const open = () => exchange({ id: 1, method: 'openRecipient', params: { accessKeyId: 'synthetic', secretAccessKey: 'synthetic', sessionToken: 'synthetic', expiration: new Date(Date.now() + 60000).toISOString() } });
  return { session, attest, digest, socket, exchange, challenge, open };
}
afterEach(async () => { for (const close of fixtures.splice(0)) await close(); jest.clearAllMocks(); });
it('binds its own certificate and carries sequential operations on the same real TLS socket', async () => {
  const f = await fixture();
  expect((await f.challenge()).result).toEqual({ document: 'synthetic-attestation' });
  expect(f.attest).toHaveBeenCalledWith('01'.repeat(32), f.digest.toString('hex'));
  expect((await f.open()).result).toEqual({ kind: 'sessionOpened' });
  expect(RecipientSession).toHaveBeenCalledWith(f.digest, expect.objectContaining({ sessionToken: 'synthetic', expiration: expect.any(Date) }));
  const params = { purpose: 'evidence', record: 'record', keyArn: 'synthetic', context: { purpose: 'evidence', fileKey: 'record' } };
  expect((await f.exchange({ id: 2, method: 'generate', params })).result).toEqual({ handle: 'opaque-handle', wrappedKey: 'wrapped' });
  expect(f.session.generate).toHaveBeenCalledWith(params);
  expect((await f.exchange({ id: 3, method: 'bootstrap', params: { ...params, wrappedKey: 'wrapped' } })).result).toEqual({ handle: 'opaque-handle' });
  f.session.encrypt.mockImplementation(async (_scope, _handle, plaintext) => {
    expect(plaintext.toString()).toBe('synthetic');
    return { iv: Buffer.alloc(12), tag: Buffer.alloc(16), ciphertext: Buffer.from('sealed') };
  });
  const sealed = (await f.exchange({ id: 4, method: 'encrypt', params: { purpose: 'evidence', record: 'record', handle: 'opaque-handle', plaintext: Buffer.from('synthetic').toString('base64') } })).result;
  f.session.decrypt.mockResolvedValue(Buffer.from('synthetic'));
  expect((await f.exchange({ id: 5, method: 'decrypt', params: { purpose: 'evidence', record: 'record', handle: 'opaque-handle', ...sealed } })).result).toEqual({ plaintext: Buffer.from('synthetic').toString('base64') });
});
it('refuses privileged requests before the challenge without constructing a recipient session', async () => {
  const f = await fixture();
  expect(await f.open()).toBeUndefined();
  expect(RecipientSession).not.toHaveBeenCalled();
});
it.each(['replay', 'raw-install', 'extra-field', 'bad-base64'])('closes and releases handles for %s', async kind => {
  const f = await fixture(); await f.challenge(); await f.open();
  const request = { id: kind === 'replay' ? 1 : 2, method: kind === 'raw-install' ? 'install' : 'encrypt',
    params: { purpose: 'evidence', record: 'record', handle: 'opaque', plaintext: kind === 'bad-base64' ? 'YR==' : 'YQ==', ...(kind === 'extra-field' ? { envelope: 'untrusted' } : {}) } };
  expect(await f.exchange(request)).toBeUndefined();
  expect(f.session.encrypt).not.toHaveBeenCalled();
  expect(f.session.close).toHaveBeenCalled();
});
it('closes on KMS denial without returning provider error text', async () => {
  const f = await fixture(); await f.challenge(); await f.open();
  f.session.generate.mockRejectedValue(new Error('sensitive provider detail'));
  expect(await f.exchange({ id: 2, method: 'generate', params: { purpose: 'evidence', record: 'record', keyArn: 'synthetic', context: {} } })).toBeUndefined();
  expect(f.session.close).toHaveBeenCalled();
});
it('cancels the recipient session when a peer closes during a pending operation', async () => {
  const f = await fixture(); await f.challenge(); await f.open();
  let finish!: (value: any) => void;
  let started!: () => void;
  const running = new Promise<void>(resolve => { started = resolve; });
  const closed = new Promise<void>(resolve => f.session.close.mockImplementation(resolve));
  f.session.generate.mockImplementation(() => new Promise(resolve => { finish = resolve; started(); }));
  const pending = f.exchange({ id: 2, method: 'generate', params: { purpose: 'evidence', record: 'record', keyArn: 'synthetic', context: {} } });
  await running;
  f.socket.end();
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([closed, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Session did not cancel on peer EOF')), 1000); })]);
  } finally {
    clearTimeout(timer);
    finish({ handle: 'late-handle', wrappedKey: 'late-wrapper' });
  }
  expect(await pending).toBeUndefined();
});
it.each(['zero-length', 'oversized', 'malformed-json', 'truncated', 'pipelined'])('rejects %s challenge frames before attestation', async mode => {
  const f = await fixture();
  let frame: Buffer;
  if (mode === 'pipelined') {
    frame = Buffer.concat([frameMessage({ id: 'challenge', method: 'attestChannel', params: { nonce: '01'.repeat(32) } }), frameMessage({ id: 1, method: 'openRecipient', params: {} })]);
  } else if (mode === 'malformed-json') {
    frame = Buffer.from([0, 0, 0, 1, 123]);
  } else {
    frame = Buffer.alloc(4); frame.writeUInt32BE(mode === 'zero-length' ? 0 : mode === 'oversized' ? 32769 : 16);
  }
  const pending = f.exchange(frame);
  if (mode === 'truncated') f.socket.end();
  expect(await pending).toBeUndefined();
  expect(f.attest).not.toHaveBeenCalled();
  expect(RecipientSession).not.toHaveBeenCalled();
});

it('routes the explicit historical read methods and never selects them as a fallback', async () => {
  const f = await fixture(); await f.challenge(); await f.open();
  const params = { purpose: 'evidence', record: 'record', keyArn: 'synthetic', context: {purpose:'evidence',fileKey:'record'},
    wrappedKey: 'enc:kms:v2:d3JhcHBlZA==', salt: Buffer.alloc(32,4).toString('base64') };
  expect((await f.exchange({id:2,method:'bootstrapLegacyEvidence',params})).result).toEqual({handle:'legacy-handle'});
  expect(f.session.bootstrapLegacyEvidence).toHaveBeenCalledWith({...params,salt:Buffer.alloc(32,4)});
  expect((await f.exchange({id:3,method:'decryptLegacyEvidence',params:{purpose:'evidence',record:'record',handle:'legacy-handle',
    iv:Buffer.alloc(16).toString('base64'),tag:Buffer.alloc(16).toString('base64'),ciphertext:Buffer.from('legacy').toString('base64')}})).result).toEqual({plaintext:Buffer.from('historical').toString('base64')});
  expect(f.session.bootstrap).not.toHaveBeenCalled(); expect(f.session.decrypt).not.toHaveBeenCalled();
});

it('routes secondary fields through the fixed private-field context interface', async () => {
  const f = await fixture(); await f.challenge(); await f.open();
  const params = {record:'record',field:'contact',keyArn:'synthetic',wrappedKey:'enc:kms:v2:d3JhcHBlZA=='};
  expect((await f.exchange({id:2,method:'bootstrapLegacyPrivate',params})).result).toEqual({handle:'private-handle'});
  expect(f.session.bootstrapLegacyPrivate).toHaveBeenCalledWith(params);
  expect((await f.exchange({id:3,method:'decryptLegacyPrivate',params:{record:'record',field:'contact',handle:'private-handle',
    iv:Buffer.alloc(12).toString('base64'),tag:Buffer.alloc(16).toString('base64'),ciphertext:'YQ=='}})).result).toEqual({plaintext:'e30='});
  expect(f.session.decryptLegacyPrivate).toHaveBeenCalledWith('record','contact','private-handle',{iv:Buffer.alloc(12),tag:Buffer.alloc(16),ciphertext:Buffer.from('a')});
  expect(await f.exchange({id:4,method:'bootstrapLegacyPrivate',params:{...params,context:{purpose:'evidence'}}})).toBeUndefined();
  expect(f.session.bootstrapLegacyPrivate).toHaveBeenCalledTimes(1);
});

it('carries chunked reads on the attested socket and erases the returned plaintext buffer', async () => {
  const f = await fixture(); await f.challenge(); await f.open();
  expect((await f.exchange({id:2,method:'beginRead',params:{purpose:'evidence',record:'record',handle:'opaque',
    iv:Buffer.alloc(16).toString('base64'),size:3,field:null}})).result).toEqual({kind:'readStarted'});
  expect(f.session.beginRead).toHaveBeenCalledWith({purpose:'evidence',record:'record'}, 'opaque', {iv:Buffer.alloc(16),size:3,field:undefined});
  expect((await f.exchange({id:3,method:'appendRead',params:{ciphertext:'YWJj'}})).result).toEqual({kind:'readAccepted'});
  expect((await f.exchange({id:4,method:'authenticateRead',params:{tag:Buffer.alloc(16).toString('base64')}})).result).toEqual({kind:'readAuthenticated'});
  const plaintext = Buffer.from('abc'); f.session.readChunk.mockResolvedValue({plaintext,done:true});
  expect((await f.exchange({id:5,method:'readChunk',params:{}})).result).toEqual({plaintext:'YWJj',done:true});
  expect(plaintext).toEqual(Buffer.alloc(3));
  expect((await f.exchange({id:6,method:'cancelRead',params:{}})).result).toEqual({kind:'readCancelled'});
});
it.each(['extra', 'oversized', 'invalid'])('rejects unsafe chunk framing: %s', async mode => {
  const f = await fixture(); await f.challenge(); await f.open();
  expect(await f.exchange({id:2,method:'appendRead',params:{ciphertext:mode === 'oversized' ? Buffer.alloc(1024*1024+1).toString('base64') : mode === 'invalid' ? 'YR==' : 'YQ==',
    ...(mode === 'extra' ? {stream:0} : {})}})).toBeUndefined();
  expect(f.session.appendRead).not.toHaveBeenCalled();
  expect(f.session.close).toHaveBeenCalled();
});
