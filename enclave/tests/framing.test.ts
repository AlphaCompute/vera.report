/**
 * Wire protocol for the enclave vsock server.
 *
 * Everything reaching the enclave arrives as a length-prefixed frame over a
 * stream socket, so the framer is the only thing standing between a hostile or
 * merely unlucky byte sequence and the crypto handlers. TCP gives no message
 * boundaries: a caller's single write can arrive split across several `data`
 * events, or several writes can coalesce into one. These lock that behaviour.
 */

import { frameMessage, MessageFramer, MAX_MESSAGE_SIZE } from '../src/server.js';

const framed = (obj: unknown): Buffer => frameMessage(obj);

describe('frameMessage', () => {
  it('prefixes the payload with its big-endian byte length', () => {
    const buf = framed({ id: 1, method: 'health', params: {} });
    const declared = buf.readUInt32BE(0);

    expect(buf.length).toBe(4 + declared);
    expect(JSON.parse(buf.subarray(4).toString('utf-8'))).toEqual({
      id: 1,
      method: 'health',
      params: {},
    });
  });

  it('counts bytes, not characters, for multi-byte payloads', () => {
    // A naive implementation using string .length here under-declares the
    // frame, which desynchronises every subsequent message on the connection.
    const payload = { id: 1, method: 'hash', params: { data: 'sürveillance ☂ 監視' } };
    const buf = framed(payload);

    expect(buf.readUInt32BE(0)).toBe(Buffer.byteLength(JSON.stringify(payload), 'utf-8'));
    expect(JSON.parse(buf.subarray(4).toString('utf-8'))).toEqual(payload);
  });
});

describe('MessageFramer', () => {
  let framer: MessageFramer;

  beforeEach(() => {
    framer = new MessageFramer();
  });

  it('reads a single whole frame', () => {
    const out = framer.feed(framed({ id: 'a', method: 'health', params: {} }));

    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ id: 'a', method: 'health' });
  });

  it('reads several frames coalesced into one chunk', () => {
    const chunk = Buffer.concat([
      framed({ id: 1, method: 'health', params: {} }),
      framed({ id: 2, method: 'hash', params: { data: 'x' } }),
      framed({ id: 3, method: 'generateRandom', params: { length: 8 } }),
    ]);

    expect(framer.feed(chunk).map((m) => m.id)).toEqual([1, 2, 3]);
  });

  it('reassembles a frame split across arbitrary chunk boundaries', () => {
    const whole = framed({ id: 'split', method: 'hash', params: { data: 'a'.repeat(500) } });

    // Feed one byte at a time: the worst case a stream socket can produce.
    const collected = [];
    for (const byte of whole) {
      collected.push(...framer.feed(Buffer.from([byte])));
    }

    expect(collected).toHaveLength(1);
    expect(collected[0]).toMatchObject({ id: 'split', method: 'hash' });
  });

  it('holds a partial frame without emitting, then completes it', () => {
    const whole = framed({ id: 'partial', method: 'health', params: {} });
    const cut = Math.floor(whole.length / 2);

    expect(framer.feed(whole.subarray(0, cut))).toHaveLength(0);
    expect(framer.feed(whole.subarray(cut))).toHaveLength(1);
  });

  it('holds a truncated length header without emitting', () => {
    expect(framer.feed(Buffer.from([0x00, 0x00]))).toHaveLength(0);
  });

  it('does not emit for a declared length whose body has not arrived', () => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(4096, 0);

    expect(framer.feed(header)).toHaveLength(0);
    expect(framer.feed(Buffer.alloc(100))).toHaveLength(0);
  });

  it('drops a frame declaring more than MAX_MESSAGE_SIZE instead of buffering it', () => {
    // Memory-exhaustion guard: the enclave runs with a fixed 512 MB, so an
    // attacker-declared 4 GB frame must not be accumulated.
    const header = Buffer.alloc(4);
    header.writeUInt32BE(MAX_MESSAGE_SIZE + 1, 0);

    expect(() => framer.feed(Buffer.concat([header, Buffer.alloc(64)]))).toThrow('RPC frame limit exceeded');
  });

  it('accepts a frame exactly at MAX_MESSAGE_SIZE', () => {
    // Boundary check: the guard is > not >=, so the limit itself is legal.
    const body = Buffer.from(
      JSON.stringify({ id: 'big', method: 'hash', params: { data: '' } }),
      'utf-8'
    );
    const header = Buffer.alloc(4);
    header.writeUInt32BE(body.length, 0);

    expect(framer.feed(Buffer.concat([header, body]))).toHaveLength(1);
  });

  it('skips a frame whose body is not JSON but keeps the connection usable', () => {
    const bad = Buffer.from('{not json', 'utf-8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(bad.length, 0);

    const chunk = Buffer.concat([header, bad, framed({ id: 9, method: 'health', params: {} })]);
    const out = framer.feed(chunk);

    // The malformed frame is discarded, the well-formed one behind it survives.
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe(9);
  });

  it('skips a frame missing method', () => {
    expect(framer.feed(framed({ id: 5, params: {} }))).toHaveLength(0);
  });

  it('reset() discards buffered partial input', () => {
    const whole = framed({ id: 'x', method: 'health', params: {} });
    framer.feed(whole.subarray(0, 6));
    framer.reset();

    // Without the reset the leftover bytes would corrupt the next frame.
    expect(framer.feed(whole)).toHaveLength(1);
  });

  it('should accept a request with id 0', () => {
    expect(framer.feed(framed({ id: 0, method: 'health', params: {} }))).toHaveLength(1);
  });
});

it('does not log source bytes from malformed JSON parser diagnostics', () => {
  const stderr = jest.spyOn(process.stderr, 'write').mockReturnValue(true);
  try {
    const payload = Buffer.from('PRIVATE-PARSER-CANARY');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length);
    expect(new MessageFramer().feed(Buffer.concat([header, payload]))).toEqual([]);
    expect(JSON.stringify(stderr.mock.calls)).not.toContain('PRIVATE-PARSER-CANARY');
  } finally { stderr.mockRestore(); }
});


it.each([null, [], {id: {secret: 'private'}, method: 'health', params: {}},
  {id: 'x'.repeat(129), method: 'health', params: {}},
  {id: 1, method: 'health', params: []}, {id: 1, method: {}, params: {}}])(
  'rejects invalid RPC envelope %j', (value) => {
    expect(new MessageFramer().feed(frameMessage(value))).toEqual([]);
  });

it('bounds a coalesced batch including malformed frames', () => {
  const chunk = Buffer.concat(Array.from({length: 33}, () => frameMessage({id: 1, method: 'health', params: {}})));
  expect(() => new MessageFramer().feed(chunk)).toThrow('RPC batch limit exceeded');
});

it('bounds buffered bytes before copying attacker input', () => {
  expect(() => new MessageFramer().feed(Buffer.alloc(MAX_MESSAGE_SIZE + 5))).toThrow('RPC buffer limit exceeded');
});
