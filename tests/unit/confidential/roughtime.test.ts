import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import dgram from 'node:dgram';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import {
  ROUGHTIME_VERSIONS, createRoughtimeRequest, decodeRoughtimeMessage, encodeRoughtimeMessage, roughtimeServerId, roughtimeTag,
  sampleRoughtime, verifyRoughtimeResponse,
} from '../../../enclave/src/cases/roughtime';
import type { RoughtimeServer } from '../../../enclave/src/cases/roughtime';
import { createTrustedClock } from '../../../enclave/src/cases/trustedClock';
import { measuredRoughtimePolicy, parseRoughtimePolicy } from '../../../enclave/src/cases/measuredConfiguration';
import { roughtimeExchange } from '../../../enclave/src/cases/storageRpc';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { createConfidentialStorageServer } from '../../../src/services/confidentialStorageRpc';
import { parseRoughtimeAllowlist, udpRoughtimeRelay } from '../../../src/services/confidentialRoughtime';

const tag = roughtimeTag;
const u32 = (value: number) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value >>> 0, 0); return bytes; };
const u64 = (value: number) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(value), 0); return bytes; };
const h = (...parts: Uint8Array[]) => createHash('sha512').update(Buffer.concat(parts)).digest().subarray(0, 32);
const raw = (key: KeyObject) => Buffer.from(key.export({ format: 'jwk' }).x as string, 'base64url');
const packet = (message: Buffer) => { const length = Buffer.alloc(4); length.writeUInt32LE(message.length, 0); return Buffer.concat([Buffer.from('ROUGHTIM'), length, message]); };

/** Synthetic Roughtime server (draft-19 wire format) with its own long-term and online keys. */
function syntheticServer() {
  const root = generateKeyPairSync('ed25519'), online = generateKeyPairSync('ed25519');
  const publicKey = raw(root.publicKey);
  return {
    publicKey,
    /** Answers `request` the way a server would; `tamper` lets a test change one field. */
    respond(request: Uint8Array, options: { seconds: number; radius?: number; mint?: number; maxt?: number;
      sibling?: boolean; signer?: KeyObject; rootSigner?: KeyObject; nonce?: Buffer; type?: number } ) {
      const message = decodeRoughtimeMessage(Buffer.from(request).subarray(12));
      const nonce = options.nonce ?? message.get(tag('NONC'))!;
      const dele = encodeRoughtimeMessage(new Map([[tag('PUBK'), raw(online.publicKey)],
        [tag('MINT'), u64(options.mint ?? options.seconds - 3600)], [tag('MAXT'), u64(options.maxt ?? options.seconds + 3600)]]));
      const cert = encodeRoughtimeMessage(new Map([[tag('DELE'), dele],
        [tag('SIG'), sign(null, Buffer.concat([Buffer.from('RoughTime v1 delegation signature\0'), dele]), options.rootSigner ?? root.privateKey)]]));
      // Batched with one other request when `sibling`: this request is leaf 1.
      const leaf = h(Buffer.from([0]), request), other = randomBytes(32);
      const rootHash = options.sibling ? h(Buffer.from([1]), other, leaf) : leaf;
      const srep = encodeRoughtimeMessage(new Map([[tag('VER'), u32(1)], [tag('RADI'), u32(options.radius ?? 1)],
        [tag('MIDP'), u64(options.seconds)], [tag('VERS'), Buffer.concat(ROUGHTIME_VERSIONS.map(u32))], [tag('ROOT'), rootHash]]));
      const sig = sign(null, Buffer.concat([Buffer.from('RoughTime v1 response signature\0'), srep]), options.signer ?? online.privateKey);
      return packet(encodeRoughtimeMessage(new Map([[tag('SIG'), sig], [tag('NONC'), nonce], [tag('TYPE'), u32(options.type ?? 1)],
        [tag('PATH'), options.sibling ? other : Buffer.alloc(0)], [tag('SREP'), srep], [tag('CERT'), cert],
        [tag('INDX'), u32(options.sibling ? 1 : 0)]])));
    },
  };
}

const T = Date.UTC(2026, 8, 29, 12), SECONDS = T / 1000;

describe('Roughtime client (draft-ietf-ntp-roughtime-19)', () => {
  const server = syntheticServer();

  test('a request is a padded, framed, sorted tag map with a fresh nonce bound to the pinned server', () => {
    const { packet: request, nonce } = createRoughtimeRequest(server.publicKey);
    expect(request.length).toBeGreaterThanOrEqual(1024);
    expect(request.subarray(0, 8).toString('ascii')).toBe('ROUGHTIM');
    const message = decodeRoughtimeMessage(request.subarray(12));
    expect([...message.keys()]).toEqual(['VER', 'SRV', 'NONC', 'TYPE', 'ZZZZ'].map(tag));
    expect(message.get(tag('NONC'))).toEqual(nonce);
    expect(message.get(tag('TYPE'))!.readUInt32LE(0)).toBe(0);
    expect(message.get(tag('SRV'))).toEqual(roughtimeServerId(server.publicKey));
    expect(createRoughtimeRequest(server.publicKey).nonce.equals(nonce)).toBe(false);
    expect(tag('NONC')).toBe(0x434e4f4e);
    expect(tag('VER')).toBe(0x00524556);
  });

  test('accepts a good response, including a batched one with a Merkle path', () => {
    for (const sibling of [false, true]) {
      const { packet: request, nonce } = createRoughtimeRequest(server.publicKey);
      const response = server.respond(request, { seconds: SECONDS, radius: 2, sibling });
      expect(verifyRoughtimeResponse({ response, request, nonce, publicKey: server.publicKey })).toEqual({ midpoint: T, radius: 2000 });
    }
  });

  test('refuses a response for another nonce or request (replay, or host substitution)', () => {
    const first = createRoughtimeRequest(server.publicKey), second = createRoughtimeRequest(server.publicKey);
    const old = server.respond(first.packet, { seconds: SECONDS - 86_400 });
    // Replaying yesterday's valid answer to today's request.
    expect(() => verifyRoughtimeResponse({ response: old, request: second.packet, nonce: second.nonce, publicKey: server.publicKey }))
      .toThrow('Roughtime response invalid');
    // Echoing the right nonce does not help: the signed Merkle root commits to the first request.
    const swapped = server.respond(first.packet, { seconds: SECONDS, nonce: second.nonce });
    expect(() => verifyRoughtimeResponse({ response: swapped, request: second.packet, nonce: second.nonce, publicKey: server.publicKey }))
      .toThrow('Roughtime response invalid');
  });

  test('refuses bad signatures: tampered response, wrong online key, delegation not by the pinned key', () => {
    const { packet: request, nonce } = createRoughtimeRequest(server.publicKey);
    const good = server.respond(request, { seconds: SECONDS });
    const verifyWith = (response: Buffer, publicKey = server.publicKey) => () => verifyRoughtimeResponse({ response, request, nonce, publicKey });
    expect(verifyWith(good)).not.toThrow();
    const flipped = Buffer.from(good); flipped[flipped.length - 200] ^= 1;
    expect(verifyWith(flipped)).toThrow('Roughtime response invalid');
    expect(verifyWith(server.respond(request, { seconds: SECONDS, signer: generateKeyPairSync('ed25519').privateKey }))).toThrow();
    expect(verifyWith(server.respond(request, { seconds: SECONDS, rootSigner: generateKeyPairSync('ed25519').privateKey }))).toThrow();
    // A different pinned key (another server) never verifies this server's answer.
    expect(verifyWith(good, syntheticServer().publicKey)).toThrow();
    expect(verifyWith(server.respond(request, { seconds: SECONDS, type: 0 }))).toThrow();
    expect(verifyWith(Buffer.alloc(64))).toThrow();
  });

  test('refuses a stale answer: midpoint outside the delegation window, or zero radius', () => {
    const { packet: request, nonce } = createRoughtimeRequest(server.publicKey);
    const check = (options: Parameters<typeof server.respond>[1]) => () =>
      verifyRoughtimeResponse({ response: server.respond(request, options), request, nonce, publicKey: server.publicKey });
    expect(check({ seconds: SECONDS, mint: SECONDS - 7200, maxt: SECONDS - 3600 })).toThrow();
    expect(check({ seconds: SECONDS, mint: SECONDS + 60, maxt: SECONDS + 3600 })).toThrow();
    expect(check({ seconds: SECONDS, radius: 0 })).toThrow();
  });

  test('samples through a relay; the interval is widened by the measured round trip', async () => {
    let mono = 0;
    const servers: RoughtimeServer[] = [{ name: 'a', address: 'a.example:2002', publicKey: server.publicKey },
      { name: 'b', address: 'b.example:2002', publicKey: syntheticServer().publicKey }];
    const samples = await sampleRoughtime(servers, async (address, request) => {
      mono += 250;
      return address === 'a.example:2002' ? server.respond(request, { seconds: SECONDS, radius: 1 }) : null;
    }, () => mono);
    expect(samples).toEqual([{ earliest: T - 1000, latest: T + 1000 + 250, receivedAt: 250 }, null]);
  });
});

describe('trusted clock with a Roughtime bound', () => {
  const encodeCbor = (value: unknown): Buffer => {
    const head = (major: number, n: number) => {
      if (n < 24) return Buffer.from([major * 32 + n]);
      if (n < 256) return Buffer.from([major * 32 + 24, n]);
      if (n < 65536) return Buffer.from([major * 32 + 25, n >> 8, n & 255]);
      const out = Buffer.alloc(9); out[0] = major * 32 + 27; out.writeBigUInt64BE(BigInt(n), 1); return out;
    };
    if (typeof value === 'number') return head(0, value);
    if (typeof value === 'string') { const data = Buffer.from(value); return Buffer.concat([head(3, data.length), data]); }
    if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
    if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encodeCbor)]);
    if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)])]);
    throw new Error('unsupported');
  };
  const nsm = (timestamp: number) => new Uint8Array(encodeCbor([encodeCbor(new Map([[1, 35]])), new Map(),
    encodeCbor(new Map<string, unknown>([['module_id', 'synthetic'], ['timestamp', timestamp]])), Buffer.alloc(96)]));

  function harness(roughtimeOffsetMs: number, servers = 1, quorum = 1) {
    const synthetic = Array.from({ length: servers }, () => syntheticServer());
    const state = { nsm: T, mono: 1_000, host: T, offsets: Array(servers).fill(roughtimeOffsetMs) as number[],
      reachable: Array(servers).fill(true) as boolean[] };
    const configured: RoughtimeServer[] = synthetic.map((item, index) => ({ name: `s${index}`, address: `s${index}.example:2002`, publicKey: item.publicKey }));
    const external = { quorum, toleranceMs: 5_000,
      sample: (monotonic: () => number) => sampleRoughtime(configured, async (address, request) => {
        const index = Number(address.slice(1, address.indexOf('.')));
        if (!state.reachable[index]) return null;
        // True time: T advanced with the monotonic clock (the NSM clock is right here).
        const trueTime = T + (state.mono - 1_000);
        return synthetic[index].respond(request, { seconds: Math.round((trueTime + state.offsets[index]) / 1000), radius: 1 });
      }, monotonic) };
    const options = { attest: async () => nsm(state.nsm), monotonic: () => state.mono, hostClock: () => state.host,
      toleranceMs: 30_000, maxAnchorAgeMs: 600_000, refreshMs: 0, external };
    return { state, options };
  }

  test('starts when NSM time and Roughtime agree', async () => {
    const { options } = harness(0);
    const clock = await createTrustedClock(options);
    expect(clock.now()).toBe(T);
  });

  test('refuses to start when they disagree beyond tolerance (a wrong hypervisor clock, or wrong NSM time)', async () => {
    await expect(createTrustedClock(harness(10 * 60_000).options)).rejects.toThrow('Trusted time unavailable');
    await expect(createTrustedClock(harness(-10 * 60_000).options)).rejects.toThrow('Trusted time unavailable');
    // Within tolerance plus radius: accepted.
    await expect(createTrustedClock(harness(4_000).options)).resolves.toBeDefined();
  });

  test('a later disagreement fails closed until a refresh agrees again', async () => {
    const { state, options } = harness(0);
    const clock = await createTrustedClock(options);
    state.mono += 60_000; state.host += 60_000; state.nsm += 60_000;
    state.offsets[0] = 3_600_000;
    await clock.refresh();
    expect(() => clock.now()).toThrow('Trusted time unavailable');
    state.offsets[0] = 0;
    await clock.refresh();
    expect(clock.now()).toBe(T + 60_000);
  });

  test('servers that do not answer: the last agreement stays usable for a bounded time', async () => {
    const { state, options } = harness(0);
    const clock = await createTrustedClock(options);
    state.reachable[0] = false;
    state.mono += 300_000; state.host += 300_000; state.nsm += 300_000;
    await clock.refresh();
    expect(clock.now()).toBe(T + 300_000);
    state.mono += 400_000; state.host += 400_000; state.nsm += 400_000;
    await clock.refresh();
    expect(() => clock.now()).toThrow('Trusted time unavailable');
    // And a clock never starts without a first agreement.
    const silent = harness(0);
    silent.state.reachable[0] = false;
    await expect(createTrustedClock(silent.options)).rejects.toThrow('Trusted time unavailable');
  });

  test('a quorum decides: one wrong server of three does not stop the clock, two do', async () => {
    const one = harness(0, 3, 2);
    one.state.offsets[1] = 3_600_000;
    await expect(createTrustedClock(one.options)).resolves.toBeDefined();
    const two = harness(0, 3, 2);
    two.state.offsets[1] = 3_600_000; two.state.offsets[2] = -3_600_000;
    await expect(createTrustedClock(two.options)).rejects.toThrow('Trusted time unavailable');
  });

  test('not configured: behaves exactly as the NSM-only clock', async () => {
    const { state, options } = harness(3_600_000);
    const { external: _unused, ...plain } = options;
    const clock = await createTrustedClock(plain);
    state.mono += 5_000;
    expect(clock.now()).toBe(T + 5_000);
  });
});

describe('measured Roughtime policy and host relay', () => {
  const server = syntheticServer();
  const key = server.publicKey.toString('base64');
  const policy = { servers: [{ name: 'synthetic', address: '127.0.0.1:2002', publicKey: key }], quorum: 1, toleranceMs: 10_000 };

  test('only exact public Ed25519 keys, bounded quorum and tolerance are accepted', () => {
    expect(parseRoughtimePolicy(null)).toBeNull();
    expect(parseRoughtimePolicy(undefined)).toBeNull();
    expect(parseRoughtimePolicy(policy)).toEqual({ servers: [{ name: 'synthetic', address: '127.0.0.1:2002', publicKey: new Uint8Array(server.publicKey) }],
      quorum: 1, toleranceMs: 10_000 });
    for (const invalid of [
      { ...policy, quorum: 2 }, { ...policy, quorum: 0 }, { ...policy, toleranceMs: 10 }, { ...policy, extra: true }, [],
      { ...policy, servers: [] }, { ...policy, servers: [{ ...policy.servers[0], publicKey: key.slice(0, -2) + '==' }] },
      { ...policy, servers: [{ ...policy.servers[0], address: 'http://x:1' }] },
      { ...policy, servers: [{ ...policy.servers[0], address: 'x.example:70000' }] },
      { ...policy, servers: [policy.servers[0], { ...policy.servers[0], name: 'again' }] },
    ]) expect(() => parseRoughtimePolicy(invalid)).toThrow('Invalid measured Roughtime policy');
  });

  test('comes only from exact measured configuration bytes', async () => {
    const fixture = (roughtime: unknown) => {
      const bytes = Buffer.from(JSON.stringify({ format: 'vera-confidential-configuration/v1',
        protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
        channelAudience: 'vera-confidential-cases', legalIdentityPolicySha256: null, roughtime }));
      const wire = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
        sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
        eifSha256: '1'.repeat(64), imageSha256: '2'.repeat(64), provenanceSha256: '3'.repeat(64),
        configurationSha256: createHash('sha256').update(bytes).digest('hex'),
        protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
        measurements: { pcr0: '1'.repeat(96), pcr1: '2'.repeat(96), pcr2: '3'.repeat(96) } });
      return { bytes, wire };
    };
    const pinned = fixture(policy), disabled = fixture(null);
    await expect(measuredRoughtimePolicy(pinned.wire, pinned.bytes)).resolves.toMatchObject({ quorum: 1 });
    await expect(measuredRoughtimePolicy(disabled.wire, disabled.bytes)).resolves.toBeNull();
    // The host cannot swap in other bytes (for example with its own server key).
    await expect(measuredRoughtimePolicy(pinned.wire, disabled.bytes)).rejects.toThrow();
  });

  test('end to end: enclave RPC -> host storage server -> UDP -> synthetic server; host allowlist enforced', async () => {
    const udp = dgram.createSocket('udp4');
    udp.on('message', (message, remote) => {
      udp.send(server.respond(message, { seconds: SECONDS, radius: 1 }), remote.port, remote.address);
    });
    await new Promise<void>(resolve => udp.bind(0, '127.0.0.1', () => resolve()));
    const address = `127.0.0.1:${(udp.address() as AddressInfo).port}`;
    expect(parseRoughtimeAllowlist(` ${address} ,`)).toEqual([address]);
    expect(() => parseRoughtimeAllowlist('not an address')).toThrow();
    const storage = createConfidentialStorageServer({}, { roughtime: udpRoughtimeRelay(parseRoughtimeAllowlist(address)) });
    await new Promise<void>(resolve => storage.listen(0, '127.0.0.1', () => resolve()));
    const rpc = { port: (storage.address() as AddressInfo).port };
    try {
      const configured: RoughtimeServer[] = [{ name: 'synthetic', address, publicKey: server.publicKey }];
      const [sample] = await sampleRoughtime(configured, (target, request) => roughtimeExchange(rpc, target, request));
      expect(sample).toMatchObject({ earliest: T - 1000 });
      expect(sample!.latest).toBeGreaterThanOrEqual(T + 1000);
      // A server that is not on the host allowlist is never contacted.
      const { packet: request } = createRoughtimeRequest(server.publicKey);
      await expect(roughtimeExchange(rpc, '127.0.0.1:9', request)).resolves.toBeNull();
      // Without a configured relay the method answers null (the enclave then fails closed).
      const bare = createConfidentialStorageServer({});
      await new Promise<void>(resolve => bare.listen(0, '127.0.0.1', () => resolve()));
      try { await expect(roughtimeExchange({ port: (bare.address() as AddressInfo).port }, address, request)).resolves.toBeNull(); }
      finally { await new Promise<void>(resolve => bare.close(() => resolve())); }
    } finally {
      udp.close();
      await new Promise<void>(resolve => storage.close(() => resolve()));
    }
  });

  test('the checked-in configuration pins no Roughtime server by default', async () => {
    const config = JSON.parse(readFileSync('enclave/confidential-config.json', 'utf8'));
    expect(config.roughtime).toBeNull();
  });
});
