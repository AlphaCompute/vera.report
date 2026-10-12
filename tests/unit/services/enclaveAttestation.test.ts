import {
  extractPcr0FromAttestationDocument,
  synthesizeAttestationDocumentForTests,
} from '../../../src/utils/nsmAttestationPcr0';
import {
  fetchLiveEnclaveAttestation,
  getCachedEnclaveAttestation,
  resetEnclaveAttestationCache,
  type EnclaveAttestationResult,
} from '../../../src/services/enclaveAttestation';
import { EventEmitter } from 'node:events';
import { frameMessage } from '../../../src/services/cryptoClient';
import { logger } from '../../../src/utils/logger';

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
  request(): { id: string; method: string; params: Record<string, unknown> } {
    const b = Buffer.concat(this.writes);
    return JSON.parse(b.subarray(4, 4 + b.readUInt32BE(0)).toString('utf-8'));
  }
}

describe('extractPcr0FromAttestationDocument', () => {
  it('reads PCR0 from a synthetic COSE_Sign1 document', () => {
    const pcr0 = Buffer.from('cc83ee92729a475abe41b9983e2b655f7787ca4732910557bc82f91050ce9a77a39b5b417b270f77f0835f644ad20292', 'hex');
    const document = synthesizeAttestationDocumentForTests(pcr0);
    expect(extractPcr0FromAttestationDocument(document)).toBe(pcr0.toString('hex'));
  });

  it('rejects unsafe 64-bit integers and mismatched challenges', () => {
    const pcr0 = Buffer.alloc(48, 1);
    expect(() => extractPcr0FromAttestationDocument(synthesizeAttestationDocumentForTests(pcr0, 'a'.repeat(64), 2n ** 63n))).toThrow(/Unsafe/);
    expect(() => extractPcr0FromAttestationDocument(synthesizeAttestationDocumentForTests(pcr0), 'b'.repeat(64))).toThrow(/nonce mismatch/);
  });

  it('requires the enclave identity context when asked', () => {
    const pcr0 = Buffer.alloc(48, 1);
    const nonce = 'a'.repeat(64);
    const context = 'VERA-ENCLAVE-IDENTITY-v1';
    expect(extractPcr0FromAttestationDocument(
      synthesizeAttestationDocumentForTests(pcr0, nonce), nonce, context,
    )).toBe(pcr0.toString('hex'));
    expect(() => extractPcr0FromAttestationDocument(
      synthesizeAttestationDocumentForTests(pcr0, nonce, BigInt(Date.now()), Buffer.from('other')), nonce, context,
    )).toThrow(/context mismatch/);
  });

  it('rejects invalid base64 / empty documents', () => {
    expect(() => extractPcr0FromAttestationDocument('')).toThrow(/Invalid/);
    expect(() => extractPcr0FromAttestationDocument('!!!')).toThrow();
  });
});

describe('fetchLiveEnclaveAttestation', () => {
  async function start(timeoutMs = 500) {
    const sock = new FakeSocket();
    const pending = fetchLiveEnclaveAttestation({ connect: () => sock as any, timeoutMs });
    // Wait a tick for the client to write
    await new Promise((r) => setImmediate(r));
    return { sock, pending, req: sock.request() };
  }

  it('returns only pcr0 from the attestIdentity RPC, never the raw document', async () => {
    const pcr0 = Buffer.alloc(48, 0xab);
    const { sock, pending, req } = await start();
    expect(req.method).toBe('attestIdentity');
    expect(req.params.nonce).toMatch(/^[0-9a-f]{64}$/);
    const document = synthesizeAttestationDocumentForTests(pcr0, req.params.nonce as string);
    sock.emit('data', frameMessage({ id: req.id, result: { document } }));
    await expect(pending).resolves.toEqual({ available: true, pcr0: pcr0.toString('hex') });
  });

  it('reports unavailable when the bridge refuses the connection', async () => {
    const { sock, pending } = await start();
    sock.emit('error', Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));
    await expect(pending).resolves.toEqual({ available: false });
  });

  it('reports unavailable when the enclave closes without replying', async () => {
    const { sock, pending } = await start();
    sock.emit('close');
    await expect(pending).resolves.toEqual({ available: false });
  });

  it('reports unavailable when the enclave does not answer in time', async () => {
    const { pending } = await start(20);
    await expect(pending).resolves.toEqual({ available: false });
  });

  it('reports unavailable when the running enclave lacks attestIdentity (-32601)', async () => {
    const { sock, pending, req } = await start();
    sock.emit('data', frameMessage({ id: req.id, error: { code: -32601, message: 'Method not found' } }));
    await expect(pending).resolves.toEqual({ available: false });
  });

  it('reports unavailable for the prod EIF refusal (-32000 "Enclave operation unavailable")', async () => {
    // Exact reply from enclave/src/server.ts in the EIF prod runs (65f78e51):
    // every method but health is refused on Nitro hardware.
    const { sock, pending, req } = await start();
    sock.emit('data', frameMessage({ id: req.id, error: { code: -32000, message: 'Enclave operation unavailable' } }));
    await expect(pending).resolves.toEqual({ available: false });
  });

  it('reports unavailable, not a fault, for any enclave RPC error reply', async () => {
    const { sock, pending, req } = await start();
    sock.emit('data', frameMessage({ id: req.id, error: { code: -32603, message: 'NSM failure' } }));
    await expect(pending).resolves.toEqual({ available: false });
  });

  it('rejects a document answering a different challenge', async () => {
    const { sock, pending, req } = await start();
    const document = synthesizeAttestationDocumentForTests(Buffer.alloc(48, 0xab), 'b'.repeat(64));
    sock.emit('data', frameMessage({ id: req.id, result: { document } }));
    await expect(pending).rejects.toThrow(/nonce mismatch/);
  });

  it('rejects a malformed document', async () => {
    const { sock, pending, req } = await start();
    sock.emit('data', frameMessage({ id: req.id, result: { document: 'not base64!' } }));
    await expect(pending).rejects.toThrow(/invalid document/);
  });
});

describe('getCachedEnclaveAttestation', () => {
  const result: EnclaveAttestationResult = { available: true, pcr0: 'ab'.repeat(48) };
  let clock = 0;
  const now = () => clock;
  let logError: jest.SpyInstance;

  beforeEach(() => {
    resetEnclaveAttestationCache();
    clock = 1_000_000;
    logError = jest.spyOn(logger, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    logError.mockRestore();
  });

  it('shares one in-flight request between concurrent callers', async () => {
    let resolve!: (r: EnclaveAttestationResult) => void;
    const fetchLive = jest.fn(() => new Promise<EnclaveAttestationResult>((r) => { resolve = r; }));
    const a = getCachedEnclaveAttestation(fetchLive, now);
    const b = getCachedEnclaveAttestation(fetchLive, now);
    resolve(result);
    await expect(Promise.all([a, b])).resolves.toEqual([result, result]);
    expect(fetchLive).toHaveBeenCalledTimes(1);
  });

  it('reuses a success for 30s, then refreshes', async () => {
    const fetchLive = jest.fn(async () => result);
    await getCachedEnclaveAttestation(fetchLive, now);
    clock += 29_999;
    await getCachedEnclaveAttestation(fetchLive, now);
    expect(fetchLive).toHaveBeenCalledTimes(1);
    clock += 2;
    await getCachedEnclaveAttestation(fetchLive, now);
    expect(fetchLive).toHaveBeenCalledTimes(2);
  });

  it('caches an unavailable enclave briefly so public traffic cannot hammer it', async () => {
    const fetchLive = jest.fn(async (): Promise<EnclaveAttestationResult> => ({ available: false }));
    await expect(getCachedEnclaveAttestation(fetchLive, now)).resolves.toEqual({ available: false });
    clock += 4_999;
    await expect(getCachedEnclaveAttestation(fetchLive, now)).resolves.toEqual({ available: false });
    expect(fetchLive).toHaveBeenCalledTimes(1);
    clock += 2;
    fetchLive.mockImplementationOnce(async () => result);
    await expect(getCachedEnclaveAttestation(fetchLive, now)).resolves.toEqual(result);
    expect(fetchLive).toHaveBeenCalledTimes(2);
    expect(logError).not.toHaveBeenCalled();
  });

  it('caches and logs genuine faults briefly', async () => {
    const fetchLive = jest.fn(async (): Promise<EnclaveAttestationResult> => {
      throw new Error('Attestation nonce mismatch');
    });
    await expect(getCachedEnclaveAttestation(fetchLive, now)).rejects.toThrow('nonce mismatch');
    await expect(getCachedEnclaveAttestation(fetchLive, now)).rejects.toThrow('nonce mismatch');
    expect(fetchLive).toHaveBeenCalledTimes(1);
    expect(logError).toHaveBeenCalledTimes(1);
    clock += 5_001;
    fetchLive.mockImplementationOnce(async () => result);
    await expect(getCachedEnclaveAttestation(fetchLive, now)).resolves.toEqual(result);
    expect(fetchLive).toHaveBeenCalledTimes(2);
  });
});
