import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
const cp = require('node:child_process');
import { RecipientSession } from '../src/recipient-session';
import { encodeRecipientEnvelope } from '../src/recipient-envelope';
import { KmsRecipientClient } from '../src/kms-recipient-client';

const encoded = (size: number) => Buffer.alloc(size, 7).toString('base64');
const scope = { purpose: 'evidence' as const, record: 'synthetic-record' };
const request = () => ({ ...scope, keyArn: 'synthetic-arn', wrappedKey: encodeRecipientEnvelope(Buffer.from('wrapped')), context: { purpose: 'evidence', fileKey: scope.record } });
const sessions: RecipientSession[] = [];
const children: EventEmitter[] = [];
function fixture() {
  const frames: any[] = [];
  let bytes = Buffer.alloc(0);
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(), stderr: new PassThrough(), kill: jest.fn(),
    stdin: new Writable({ write(chunk, _encoding, callback) {
      bytes = Buffer.concat([bytes, chunk]);
      while (bytes.length >= 4 && bytes.length >= 4 + bytes.readUInt32BE()) {
        const size = bytes.readUInt32BE();
        frames.push(JSON.parse(bytes.subarray(4, size + 4).toString()));
        bytes = bytes.subarray(size + 4);
      }
      callback();
    } }),
  });
  children.push(child);
  const spawn = jest.spyOn(cp, 'spawn').mockReturnValue(child as any);
  const kms = jest.spyOn(KmsRecipientClient.prototype, 'decrypt').mockResolvedValue(Buffer.from('authenticated-CMS'));
  const closeKms = jest.spyOn(KmsRecipientClient.prototype, 'close');
  const session = new RecipientSession(Buffer.alloc(32, 2), { accessKeyId: 'synthetic', secretAccessKey: 'synthetic', sessionToken: 'synthetic', expiration: new Date(Date.now() + 60000) });
  sessions.push(session);
  function reply(id: number, result: unknown, fragmented = false) {
    const body = Buffer.from(JSON.stringify({ id, result }));
    const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
    const frame = Buffer.concat([header, body]);
    if (fragmented) { child.stdout.write(frame.subarray(0, 2)); child.stdout.write(frame.subarray(2, 7)); child.stdout.write(frame.subarray(7)); }
    else child.stdout.write(frame);
  }
  return { session, child, frames, reply, kms, spawn, closeKms };
}
const flush = () => new Promise<void>(resolve => setImmediate(resolve));
afterEach(() => { sessions.splice(0).forEach(s => s.close()); children.splice(0).forEach(c => c.emit('exit', 0)); jest.restoreAllMocks(); jest.useRealTimers(); });

it('installs only the internally authenticated KMS response and snapshots the requested scope', async () => {
  const f = fixture();
  expect(f.spawn).toHaveBeenCalledWith('/app/bin/vera-recipient-broker', [], { env: {}, stdio: ['pipe', 'pipe', 'pipe'] });
  expect(f.frames[0].certificate).toBe(Buffer.alloc(32, 2).toString('base64'));
  expect(Buffer.from(f.frames[0].session, 'base64')).toHaveLength(32);
  const input = request();
  const pending = f.session.bootstrap(input);
  input.context.fileKey = 'changed'; input.record = 'changed'; input.wrappedKey = encodeRecipientEnvelope(Buffer.from('changed'));
  expect(f.frames[1].command).toEqual({ method: 'prepare', nonce: expect.any(String), ...scope });
  f.reply(0, { kind: 'attestation', document: Buffer.from('synthetic-NSM').toString('base64') }, true);
  await flush();
  expect(f.kms).toHaveBeenCalledWith({ keyArn: 'synthetic-arn', ciphertext: Buffer.from('wrapped'), context: { purpose: 'evidence', fileKey: scope.record }, attestation: Buffer.from('synthetic-NSM') });
  expect(f.frames[2]).toEqual({ id: 1, command: { method: 'install', envelope: Buffer.from('authenticated-CMS').toString('base64') } });
  f.reply(1, { kind: 'handle', handle: encoded(32) });
  await expect(pending).resolves.toBe(encoded(32));
});
it('refuses concurrent work, closes on KMS failure and never sends install', async () => {
  const f = fixture(); f.kms.mockRejectedValue(new Error('provider detail'));
  const pending = f.session.bootstrap(request());
  const denied = expect(pending).rejects.toThrow('Recipient session unavailable');
  await expect(f.session.bootstrap(request())).rejects.toThrow('unavailable');
  f.reply(0, { kind: 'attestation', document: encoded(32) });
  await denied;
  expect(f.frames).toHaveLength(2);
  expect(f.child.kill).toHaveBeenCalledWith('SIGKILL');
  expect(f.closeKms).toHaveBeenCalledTimes(1);
});
it.each(['wrong-id', 'extra-fields', 'oversize', 'truncated', 'stderr', 'exit'])('closes on invalid helper behavior: %s', async mode => {
  const f = fixture(); const pending = f.session.bootstrap(request());
  const denied = expect(pending).rejects.toThrow('unavailable');
  if (mode === 'wrong-id') f.reply(1, { kind: 'attestation', document: encoded(32) });
  if (mode === 'extra-fields') f.reply(0, { kind: 'attestation', document: encoded(32), key: 'forbidden' });
  if (mode === 'oversize') { const header = Buffer.alloc(4); header.writeUInt32BE(12 * 1024 * 1024 + 1); f.child.stdout.write(header); }
  if (mode === 'truncated') { f.child.stdout.write(Buffer.from([0, 0])); f.child.stdout.end(); }
  if (mode === 'stderr') f.child.stderr.write('untrusted diagnostics');
  if (mode === 'exit') f.child.emit('exit', 1);
  await denied;
  expect(f.kms).not.toHaveBeenCalled();
  expect(f.child.kill).toHaveBeenCalledTimes(1);
});
it('bounds request time and terminates idle native sessions at the absolute deadline', async () => {
  jest.useFakeTimers(); const f = fixture();
  const pending = f.session.bootstrap(request()); const denied = expect(pending).rejects.toThrow('unavailable');
  jest.advanceTimersByTime(15000); await denied;
  expect(f.child.kill).toHaveBeenCalledTimes(1);
  const idle = fixture(); jest.advanceTimersByTime(300000);
  expect(idle.child.kill).toHaveBeenCalledTimes(1);
});
it('validates crypto replies and ignores runtime command injection in scope', async () => {
  const f = fixture();
  const pending = f.session.encrypt({ ...scope, method: 'install', envelope: 'forbidden' } as any, encoded(32), Buffer.from('synthetic'));
  expect(f.frames[1].command.method).toBe('encrypt'); expect(f.frames[1].command.envelope).toBeUndefined();
  f.reply(0, { kind: 'encrypted', iv: encoded(12), tag: encoded(16), ciphertext: encoded(9) });
  const sealed = await pending;
  const decrypted = f.session.decrypt(scope, encoded(32), sealed);
  f.reply(1, { kind: 'decrypted', plaintext: Buffer.from('synthetic').toString('base64') });
  await expect(decrypted).resolves.toEqual(Buffer.from('synthetic'));
  const bad = f.session.encrypt(scope, encoded(32), Buffer.alloc(1));
  f.reply(2, { kind: 'encrypted', iv: encoded(12), tag: encoded(4), ciphertext: encoded(1) });
  await expect(bad).rejects.toThrow('unavailable');
});
it('rejects mismatched context without invoking NSM or KMS', async () => {
  const f = fixture();
  await expect(f.session.bootstrap({ ...request(), context: { purpose: 'evidence', fileKey: 'different' } })).rejects.toThrow('unavailable');
  expect(f.frames).toHaveLength(1); expect(f.kms).not.toHaveBeenCalled();
});
it('exchanges framed messages with a real synthetic child process and reaps it on close', async () => {
  const realSpawn = cp.spawn;
  let child: any;
  const script = `
    let buffer = Buffer.alloc(0), initialized = false;
    process.stdin.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4 && buffer.length >= buffer.readUInt32BE() + 4) {
        const n = buffer.readUInt32BE();
        const frame = JSON.parse(buffer.subarray(4, n + 4)); buffer = buffer.subarray(n + 4);
        if (!initialized) { initialized = true; continue; }
        let result;
        if (frame.command.method === 'prepare') result = {kind:'attestation',document:Buffer.from('synthetic').toString('base64')};
        else if (frame.command.method === 'install' && Buffer.from(frame.command.envelope,'base64').toString() === 'authenticated-CMS') result = {kind:'handle',handle:Buffer.alloc(32,7).toString('base64')};
        else process.exit(2);
        const body = Buffer.from(JSON.stringify({id:frame.id,result}));
        const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
        process.stdout.write(header); process.stdout.write(body);
      }
    });
  `;
  jest.spyOn(cp, 'spawn').mockImplementation(() => (child = realSpawn(process.execPath, ['-e', script], { env: {}, stdio: ['pipe', 'pipe', 'pipe'] })));
  jest.spyOn(KmsRecipientClient.prototype, 'decrypt').mockResolvedValue(Buffer.from('authenticated-CMS'));
  const session = new RecipientSession(Buffer.alloc(32), { accessKeyId: 'synthetic', secretAccessKey: 'synthetic', sessionToken: 'synthetic', expiration: new Date(Date.now() + 60000) });
  sessions.push(session);
  await expect(session.bootstrap(request())).resolves.toBe(encoded(32));
  const exited = new Promise(resolve => child.once('close', resolve));
  session.close(); await exited;
  expect(child.signalCode).toBe('SIGKILL');
});
it('installs generated keys internally and returns only an opaque handle and persistent wrapped key', async () => {
  const f = fixture();
  const generate = jest.spyOn(KmsRecipientClient.prototype, 'generate').mockResolvedValue({ wrappedKey: Buffer.from('persistent-wrapped'), envelope: Buffer.from('recipient-CMS') });
  const pending = f.session.generate(request());
  f.reply(0, { kind: 'attestation', document: encoded(32) });
  await flush();
  expect(generate).toHaveBeenCalledWith({ keyArn: 'synthetic-arn', context: request().context, attestation: Buffer.alloc(32, 7) });
  expect(f.frames[2]).toEqual({ id: 1, command: { method: 'install', envelope: Buffer.from('recipient-CMS').toString('base64') } });
  f.reply(1, { kind: 'handle', handle: encoded(32) });
  await expect(pending).resolves.toEqual({ handle: encoded(32), wrappedKey: encodeRecipientEnvelope(Buffer.from('persistent-wrapped')) });
  expect(f.kms).not.toHaveBeenCalled();
});
it('uses explicit legacy bootstrap with a captured salt and no current-format fallback', async () => {
  const f = fixture();
  const salt = Buffer.alloc(32, 4);
  const pending = f.session.bootstrapLegacyEvidence({ ...request(), wrappedKey: 'enc:kms:v2:d3JhcHBlZA==', salt });
  salt.fill(9);
  expect(f.frames[1].command).toMatchObject({ method: 'prepareLegacyEvidence', salt: Buffer.alloc(32, 4).toString('base64') });
  f.reply(0, { kind: 'attestation', document: encoded(32) }); await flush();
  expect(f.kms).toHaveBeenCalledWith(expect.objectContaining({ ciphertext: Buffer.from('wrapped'), context: request().context }));
  f.reply(1, { kind: 'handle', handle: encoded(32) });
  const handle = await pending;
  const plaintext = f.session.decryptLegacyEvidence(scope, handle, { iv: Buffer.alloc(16), tag: Buffer.alloc(16), ciphertext: Buffer.from('legacy') });
  expect(f.frames[3].command.method).toBe('decryptLegacyEvidence');
  f.reply(2, { kind: 'decrypted', plaintext: Buffer.from('historical').toString('base64') });
  await expect(plaintext).resolves.toEqual(Buffer.from('historical'));
});
it.each([
  { wrappedKey: 'enc:kms:v1:d3JhcHBlZA==' }, { wrappedKey: 'enc:kms:recipient:v1:d3JhcHBlZA==' },
  { salt: Buffer.alloc(16) }, { context: { purpose: 'evidence', record: scope.record } },
  { context: { purpose: 'evidence', fileKey: scope.record, field: 'secondary-field' } },
])('refuses unapproved legacy formats or contexts before bootstrap: %j', async change => {
  const f = fixture();
  await expect(f.session.bootstrapLegacyEvidence({ ...request(), wrappedKey: 'enc:kms:v2:d3JhcHBlZA==', salt: Buffer.alloc(32), ...change })).rejects.toThrow();
  expect(f.frames).toHaveLength(1); expect(f.kms).not.toHaveBeenCalled();
});
it('refuses the new-format IV on the legacy reader', async () => {
  const f = fixture();
  await expect(f.session.decryptLegacyEvidence(scope, encoded(32), { iv: Buffer.alloc(12), tag: Buffer.alloc(16), ciphertext: Buffer.from('legacy') })).rejects.toThrow();
  expect(f.frames).toHaveLength(1);
});
it('constructs private-field context from captured record and field and uses its explicit native reader', async () => {
  const f = fixture();
  const input = { record: 'synthetic-record', field: 'contact', keyArn: 'synthetic-arn', wrappedKey: 'enc:kms:v2:d3JhcHBlZA==' };
  const pending = f.session.bootstrapLegacyPrivate(input);
  input.field = 'changed';
  expect(f.frames[1].command).toMatchObject({ method: 'prepareLegacyPrivate', record: 'synthetic-record', field: 'contact' });
  f.reply(0, { kind: 'attestation', document: encoded(32) }); await flush();
  expect(f.kms).toHaveBeenCalledWith(expect.objectContaining({ context: { purpose: 'narrative', record: 'synthetic-record', field: 'contact' } }));
  f.reply(1, { kind: 'handle', handle: encoded(32) });
  const handle = await pending;
  const plaintext = f.session.decryptLegacyPrivate('synthetic-record', 'contact', handle, { iv: Buffer.alloc(12), tag: Buffer.alloc(16), ciphertext: Buffer.from('private') });
  expect(f.frames[3].command).toMatchObject({ method: 'decryptLegacyPrivate', record: 'synthetic-record', field: 'contact' });
  f.reply(2, { kind: 'decrypted', plaintext: Buffer.from('{"synthetic":true}').toString('base64') });
  await expect(plaintext).resolves.toEqual(Buffer.from('{"synthetic":true}'));
});
it.each(['', 'é'.repeat(129)])('rejects invalid private-field bindings before requesting attestation', async field => {
  const f = fixture();
  await expect(f.session.bootstrapLegacyPrivate({ record: 'record', field, keyArn: 'synthetic', wrappedKey: 'enc:kms:v2:d3JhcHBlZA==' })).rejects.toThrow();
  expect(f.frames).toHaveLength(1); expect(f.kms).not.toHaveBeenCalled();
});

it('streams through authentication before releasing plaintext and validates final length', async () => {
  const f = fixture();
  const beginning = f.session.beginRead(scope, encoded(32), {iv:Buffer.alloc(12), size:3});
  expect(f.frames[1].command).toMatchObject({method:'beginRead', size:3, field:null});
  f.reply(0, {kind:'readStarted', stream:0}); await beginning;
  const appending = f.session.appendRead(Buffer.from('abc'));
  f.reply(1, {kind:'readAccepted'}); await appending;
  const authenticating = f.session.authenticateRead(Buffer.alloc(16));
  f.reply(2, {kind:'readAuthenticated'}); await authenticating;
  const reading = f.session.readChunk();
  f.reply(3, {kind:'readOutput', plaintext:Buffer.from('abc').toString('base64'), done:true});
  await expect(reading).resolves.toEqual({plaintext:Buffer.from('abc'), done:true});
  await expect(f.session.readChunk()).rejects.toThrow('unavailable');
  const next = f.session.beginRead(scope, encoded(32), {iv:Buffer.alloc(16), size:0});
  f.reply(4, {kind:'readStarted', stream:4}); await next;
  const cancelled = f.session.cancelRead();
  f.reply(5, {kind:'cancelled'}); await cancelled;
});
it('holds global memory admission until the native child actually exits', async () => {
  const a = fixture(), b = fixture();
  const beginning = a.session.beginRead(scope, encoded(32), {iv:Buffer.alloc(12), size:3});
  await expect(b.session.beginRead(scope, encoded(32), {iv:Buffer.alloc(12), size:3})).rejects.toThrow('unavailable');
  a.reply(0, {kind:'readStarted', stream:0}); await beginning;
  a.session.close();
  await expect(b.session.beginRead(scope, encoded(32), {iv:Buffer.alloc(12), size:3})).rejects.toThrow('unavailable');
  a.child.emit('exit', 1);
  const next = b.session.beginRead(scope, encoded(32), {iv:Buffer.alloc(12), size:3});
  b.reply(0, {kind:'readStarted', stream:0}); await next;
});
it.each(['early', 'short', 'done', 'extra'])('closes on unsafe streaming behavior: %s', async mode => {
  const f = fixture();
  const beginning = f.session.beginRead(scope, encoded(32), {iv:Buffer.alloc(12), size:3});
  f.reply(0, {kind:'readStarted', stream:0}); await beginning;
  if (mode === 'early') {
    await expect(f.session.readChunk()).rejects.toThrow('unavailable');
    expect(f.frames).toHaveLength(2);
  } else {
    const appending = f.session.appendRead(Buffer.from('abc'));
    f.reply(1, {kind:'readAccepted'}); await appending;
    const authenticating = f.session.authenticateRead(Buffer.alloc(16));
    f.reply(2, {kind:'readAuthenticated'}); await authenticating;
    const reading = f.session.readChunk(); const denied = expect(reading).rejects.toThrow('unavailable');
    f.reply(3, {kind:'readOutput', plaintext:Buffer.from(mode === 'short' ? 'ab' : 'abc').toString('base64'),
      done:mode !== 'done', ...(mode === 'extra' ? {key:'forbidden'} : {})});
    await denied;
  }
  expect(f.child.kill).toHaveBeenCalledWith('SIGKILL');
});
