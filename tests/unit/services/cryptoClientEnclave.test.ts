/**
 * EnclaveCryptoClient host-side transport (ALPHA-096, Phase 1).
 *
 * The wire protocol is a 4-byte big-endian length prefix + JSON RPC over a
 * stream, matching enclave/src/server.ts. These lock in the host client's
 * framing and RPC semantics against an injected fake transport — no Nitro
 * hardware — so the attested decrypt verb can be wired on top in Phase 2:
 * frame reassembly, id correlation, error mapping, timeout, and fail-closed
 * behaviour on a premature close. `health` is the benign verb used to exercise
 * the transport; the at-rest crypto methods stay fail-closed until the attested
 * verb exists.
 */

import { EventEmitter } from 'node:events';
import { EnclaveCryptoClient, FrameDecoder, frameMessage } from '../../../src/services/cryptoClient';

/** Minimal duplex-ish stand-in: captures what the client writes, lets the test push replies. */
class FakeSocket extends EventEmitter {
  writes: Buffer[] = [];
  destroyed = false;
  write(buf: Buffer): boolean {
    this.writes.push(Buffer.from(buf));
    return true;
  }
  destroy(): void {
    this.destroyed = true;
  }
  /** The single framed request the client sent, decoded. */
  request(): any {
    const b = Buffer.concat(this.writes);
    return JSON.parse(b.subarray(4, 4 + b.readUInt32BE(0)).toString('utf-8'));
  }
}

describe('FrameDecoder / frameMessage', () => {
  it('round-trips one message', () => {
    const msgs = new FrameDecoder().push(frameMessage({ a: 1, b: 'x' }));
    expect(msgs).toEqual([{ a: 1, b: 'x' }]);
  });

  it('reassembles a frame split across chunks', () => {
    const framed = frameMessage({ hello: 'world' });
    const d = new FrameDecoder();
    expect(d.push(framed.subarray(0, 3))).toEqual([]); // header not even complete
    expect(d.push(framed.subarray(3, 6))).toEqual([]); // still mid-frame
    expect(d.push(framed.subarray(6))).toEqual([{ hello: 'world' }]);
  });

  it('returns every complete frame coalesced into one chunk', () => {
    const chunk = Buffer.concat([frameMessage({ n: 1 }), frameMessage({ n: 2 }), frameMessage({ n: 3 })]);
    expect(new FrameDecoder().push(chunk)).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }]);
  });

  it('rejects a hostile length prefix rather than allocating', () => {
    const evil = Buffer.alloc(4);
    evil.writeUInt32BE(0xffffffff, 0);
    expect(() => new FrameDecoder().push(evil)).toThrow(/maximum size/);
  });
});

describe('EnclaveCryptoClient — RPC transport (via the benign health verb)', () => {
  function clientWith(sock: FakeSocket, timeoutMs = 500) {
    return new EnclaveCryptoClient(16, 5000, { connect: () => sock, timeoutMs });
  }

  it('sends a framed request and resolves on the correlated reply, then closes', async () => {
    const sock = new FakeSocket();
    const p = clientWith(sock).health();
    const req = sock.request();
    expect(req.method).toBe('health');
    expect(typeof req.id).toBe('string');
    expect(req.params).toEqual({});
    sock.emit('data', frameMessage({ id: req.id, result: { status: 'ok', attested: false } }));
    await expect(p).resolves.toEqual({ status: 'ok', attested: false });
    expect(sock.destroyed).toBe(true); // connection closed after the reply
  });

  it('rejects on an enclave error reply', async () => {
    const sock = new FakeSocket();
    const p = clientWith(sock).health();
    sock.emit('data', frameMessage({ id: sock.request().id, error: { code: -32000, message: 'unavailable' } }));
    await expect(p).rejects.toThrow(/failed \(-32000\): unavailable/);
  });

  it.each([null, [], 'invalid', 17])('rejects malformed JSON replies without throwing out of the socket callback: %p', async reply => {
    const sock = new FakeSocket();
    const p = clientWith(sock).health();
    const rejected = expect(p).rejects.toThrow(/invalid response/);
    expect(() => sock.emit('data', frameMessage(reply))).not.toThrow();
    await rejected;
    expect(sock.destroyed).toBe(true);
  });

  it.each(['missing', 'invalid-error'])('rejects a correlated %s response rather than claiming success', async mode => {
    const sock = new FakeSocket();
    const p = clientWith(sock).health();
    const rejected = expect(p).rejects.toThrow(/missing its result|invalid error response/);
    sock.emit('data', frameMessage({ id: sock.request().id, ...(mode === 'invalid-error' ? { error: 'bad' } : {}) }));
    await rejected;
    expect(sock.destroyed).toBe(true);
  });

  it('reassembles a reply split across two chunks', async () => {
    const sock = new FakeSocket();
    const p = clientWith(sock).health();
    const reply = frameMessage({ id: sock.request().id, result: { ok: true } });
    sock.emit('data', reply.subarray(0, 5));
    sock.emit('data', reply.subarray(5));
    await expect(p).resolves.toEqual({ ok: true });
  });

  it('ignores an uncorrelated reply and resolves on the matching id', async () => {
    const sock = new FakeSocket();
    const p = clientWith(sock).health();
    sock.emit('data', frameMessage({ id: 'someone-elses-id', result: { status: 'stale' } }));
    sock.emit('data', frameMessage({ id: sock.request().id, result: { status: 'mine' } }));
    await expect(p).resolves.toEqual({ status: 'mine' });
  });

  it('fails closed when the connection closes before a reply', async () => {
    const sock = new FakeSocket();
    const p = clientWith(sock).health();
    sock.emit('close');
    await expect(p).rejects.toThrow(/closed before a reply/);
  });

  it('fails closed on timeout when the enclave never answers', async () => {
    const p = clientWith(new FakeSocket(), 30).health();
    await expect(p).rejects.toThrow(/timed out after 30ms/);
  });
  it('sends attestIdentity with a nonce and resolves the document', async () => {
    const sock = new FakeSocket();
    const nonce = 'a'.repeat(64);
    const document = Buffer.from('synthetic-nsm-doc').toString('base64');
    const p = clientWith(sock).attestIdentity(nonce);
    const req = sock.request();
    expect(req.method).toBe('attestIdentity');
    expect(req.params).toEqual({ nonce });
    sock.emit('data', frameMessage({ id: req.id, result: { document } }));
    await expect(p).resolves.toEqual({ document });
  });

  it('rejects attestIdentity with a malformed nonce before connecting', async () => {
    const sock = new FakeSocket();
    await expect(clientWith(sock).attestIdentity('nope')).rejects.toThrow(/nonce/);
    expect(sock.writes).toHaveLength(0);
  });
});

describe('EnclaveCryptoClient — host-key confinement (unchanged)', () => {
  it('keeps every host-secret / key-exporting operation disabled', async () => {
    const c = new EnclaveCryptoClient(16, 5000, { connect: () => new FakeSocket() });
    await expect(c.encrypt(Buffer.from('x'), 's')).rejects.toThrow(/host-secret encryption is disabled/);
    await expect(c.decrypt({ ciphertext: '', iv: '', authTag: '', salt: '' }, 's')).rejects.toThrow(/host-secret decryption is disabled/);
    await expect(c.deriveKey('s', Buffer.alloc(0), { algorithm: 'scrypt', keyLength: 32 })).rejects.toThrow(/cannot be exported/);
    expect(() => c.sign(Buffer.from('x'), Buffer.from('k'))).toThrow(/confined key handle/);
  });
});
