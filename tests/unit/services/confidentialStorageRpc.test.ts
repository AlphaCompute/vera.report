import { readFileSync } from 'node:fs';
import { CASE_STORE_RPC_METHODS as enclaveMethods } from '../../../enclave/src/cases/storageRpc';
import { CASE_STORE_RPC_METHODS as hostMethods } from '../../../src/services/confidentialStorageRpc';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CASE_STORE_RPC_METHODS, createConfidentialStorageServer, listenConfidentialStorage, storageRpcArgumentsSafe } from '../../../src/services/confidentialStorageRpc';
import { socketEnclaveTransport } from '../../../src/api/confidentialChannel';
import { createRemoteCaseStore, createRemoteLegalMembershipStore, fetchLegalIdentityPolicy } from '../../../enclave/src/cases/storageRpc';

async function rawCall(port: number, payload: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    const body = Buffer.from(JSON.stringify(payload)), header = Buffer.alloc(4);
    header.writeUInt32BE(body.length, 0);
    let data = Buffer.alloc(0);
    socket.on('data', chunk => { data = Buffer.concat([data, chunk]); });
    socket.on('end', () => resolve(JSON.parse(data.subarray(4).toString())));
    socket.on('error', reject);
    socket.write(Buffer.concat([header, body]));
  });
}

describe('confidential storage RPC boundary', () => {
  const calls: string[] = [];
  const store = {
    async getCase(caseId: string) { calls.push(`getCase:${caseId}`); return { caseId }; },
    async stageObject() { calls.push('stageObject'); },
    async close() { calls.push('close'); },
    // Even a stale host adapter must not expose contact custody through RPC.
    async getOwnerNotification() { calls.push('getOwnerNotification'); return { address: 'private@example.org' }; },
    async setOwnerNotification() { calls.push('setOwnerNotification'); },
    async queueOwnerNotification() { calls.push('queueOwnerNotification'); },
  };
  let server: net.Server, port: number;
  beforeAll(async () => {
    server = createConfidentialStorageServer(store);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => server.close());

  test('allowlisted methods round-trip through the enclave client', async () => {
    const remote = createRemoteCaseStore({ port });
    await expect(remote.getCase('a'.repeat(64))).resolves.toEqual({ caseId: 'a'.repeat(64) });
  });

  test.each(['stageObject', 'close', '__proto__', 'constructor', 'toString',
    'getOwnerNotification', 'setOwnerNotification', 'queueOwnerNotification'])('refuses non-allowlisted method %s', async method => {
    const before = calls.length;
    await expect(rawCall(port, { method, args: [] })).resolves.toEqual({ error: 'unavailable' });
    expect(calls.length).toBe(before);
  });

  test('refuses Mongo operator keys anywhere in the arguments before dispatch', async () => {
    const before = calls.length;
    await expect(rawCall(port, { method: 'getCase', args: [{ $ne: null }] })).resolves.toEqual({ error: 'unavailable' });
    await expect(rawCall(port, { method: 'getCase', args: ['a'.repeat(64), [{ nested: { $exists: true } }]] }))
      .resolves.toEqual({ error: 'unavailable' });
    expect(calls.length).toBe(before);
    expect(storageRpcArgumentsSafe(['a', 1, null, [{ statements: { ['b'.repeat(64)]: 'wire' } }]])).toBe(true);
  });

  test('refuses malformed requests and extra fields', async () => {
    await expect(rawCall(port, { method: 'getCase', args: [], admin: true })).resolves.toEqual({ error: 'unavailable' });
    await expect(rawCall(port, ['getCase'])).resolves.toEqual({ error: 'unavailable' });
  });

  test('the enclave client rejects an error or malformed host reply', async () => {
    const hostile = net.createServer(socket => socket.end(Buffer.from([0, 0, 0, 2, 0x7b, 0x7d])));
    await new Promise<void>(resolve => hostile.listen(0, '127.0.0.1', resolve));
    const remote = createRemoteCaseStore({ port: (hostile.address() as AddressInfo).port, timeoutMs: 2000 });
    await expect(remote.getCase('a'.repeat(64))).rejects.toThrow('Confidential storage unavailable');
    hostile.close();
  });

  test('legal identity policy is null unless configured, and shape-checked by the enclave', async () => {
    await expect(fetchLegalIdentityPolicy({ port })).resolves.toBeNull();
    const policy = { issuer: 'https://identity.example/', audience: 'https://api.example/legal', clientId: 'legal-client', jwks: { keys: [] } };
    for (const [served, expected] of [[policy, policy], [{ ...policy, admin: true }, null]] as const) {
      const configured = createConfidentialStorageServer(store, { legalIdentityPolicy: served });
      await new Promise<void>(resolve => configured.listen(0, '127.0.0.1', resolve));
      const result = fetchLegalIdentityPolicy({ port: (configured.address() as AddressInfo).port });
      if (expected) await expect(result).resolves.toEqual(expected);
      else await expect(result).rejects.toThrow('Confidential storage unavailable');
      configured.close();
    }
  });

  test('a large reply split into many small chunks decodes exactly, in both directions', async () => {
    const big = 'x'.repeat(3 * 1024 * 1024);
    const rows = { async getStagedObject(digest: string) { return `${digest}:${big}`; } };
    const host = createConfidentialStorageServer(rows);
    await new Promise<void>(resolve => host.listen(0, '127.0.0.1', resolve));
    // A relay that forwards in 1 KiB pieces, like a vsock bridge under load.
    const hostPort = (host.address() as AddressInfo).port;
    const bridge = net.createServer(client => {
      const upstream = net.connect(hostPort, '127.0.0.1');
      const drip = (from: net.Socket, to: net.Socket) => from.on('data', (chunk: Buffer) => {
        for (let offset = 0; offset < chunk.length; offset += 1024) to.write(chunk.subarray(offset, offset + 1024));
      });
      drip(client, upstream); drip(upstream, client);
      upstream.on('end', () => client.end()); client.on('end', () => upstream.end());
      upstream.on('error', () => client.destroy()); client.on('error', () => upstream.destroy());
    });
    await new Promise<void>(resolve => bridge.listen(0, '127.0.0.1', resolve));
    try {
      const remote = createRemoteCaseStore({ port: (bridge.address() as AddressInfo).port, timeoutMs: 20_000 });
      await expect(remote.getStagedObject!('d'.repeat(64))).resolves.toBe(`${'d'.repeat(64)}:${big}`);
    } finally { bridge.close(); host.close(); }
  });

  test('the enclave client refuses a reply longer than its declared frame', async () => {
    const hostile = net.createServer(socket => socket.end(Buffer.from([0, 0, 0, 2, 0x7b, 0x7d, 0x20])));
    await new Promise<void>(resolve => hostile.listen(0, '127.0.0.1', resolve));
    const remote = createRemoteCaseStore({ port: (hostile.address() as AddressInfo).port, timeoutMs: 2000 });
    await expect(remote.getCase('a'.repeat(64))).rejects.toThrow('Confidential storage unavailable');
    hostile.close();
  });

  test('membership lookups use only the allowlisted methods', async () => {
    const rows = { async getMember(subject: string) { return { subject }; }, async getOrganization(id: string) { return { organizationId: id }; } };
    const membership = createConfidentialStorageServer(rows);
    await new Promise<void>(resolve => membership.listen(0, '127.0.0.1', resolve));
    const remote = createRemoteLegalMembershipStore({ port: (membership.address() as AddressInfo).port });
    await expect(remote.getMember('auth0|a', 'org_a')).resolves.toEqual({ subject: 'auth0|a' });
    await expect(remote.getOrganization('b'.repeat(64))).resolves.toEqual({ organizationId: 'b'.repeat(64) });
    membership.close();
  });
});

describe('confidential storage RPC over the host Unix socket bridge', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vcs-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  test('serves on an owner-only socket and replaces only a stale socket', async () => {
    const socketPath = path.join(dir, 'storage.sock');
    const store = { async getCase(caseId: string) { return { caseId }; } };
    const first = createConfidentialStorageServer(store);
    await listenConfidentialStorage(first, { path: socketPath });
    expect(fs.statSync(socketPath).mode & 0o777).toBe(0o600);
    const remote = createRemoteCaseStore({ connect: () => net.connect(socketPath) });
    await expect(remote.getCase('b'.repeat(64))).resolves.toEqual({ caseId: 'b'.repeat(64) });
    // Simulate a crashed task leaving the socket file behind.
    await new Promise<void>(resolve => { first.close(() => resolve()); });
    fs.closeSync(fs.openSync(socketPath + '.x', 'w'));
    const regular = createConfidentialStorageServer(store);
    await expect(listenConfidentialStorage(regular, { path: socketPath + '.x' })).rejects.toThrow('not a socket');
    const second = createConfidentialStorageServer(store);
    await listenConfidentialStorage(second, { path: socketPath });
    await expect(remote.getCase('c'.repeat(64))).resolves.toEqual({ caseId: 'c'.repeat(64) });
    await new Promise<void>(resolve => { second.close(() => resolve()); });
    await expect(listenConfidentialStorage(createConfidentialStorageServer(store), { path: 'relative.sock' })).rejects.toThrow();
  });

  test('session transport frames requests over a Unix socket', async () => {
    const socketPath = path.join(dir, 'session.sock');
    const server = net.createServer(socket => {
      let data = Buffer.alloc(0);
      socket.on('data', chunk => {
        data = Buffer.concat([data, chunk]);
        if (data.length < 4 || data.length < data.readUInt32BE(0) + 4) return;
        const request = JSON.parse(data.subarray(4).toString());
        const body = Buffer.from(JSON.stringify({ echoed: request.op })), header = Buffer.alloc(4);
        header.writeUInt32BE(body.length, 0);
        socket.end(Buffer.concat([header, body]));
      });
    });
    await new Promise<void>(resolve => server.listen(socketPath, resolve));
    try {
      await expect(socketEnclaveTransport(socketPath)({ op: 'open', nonce: 'a'.repeat(64) })).resolves.toEqual({ echoed: 'open' });
      expect(() => socketEnclaveTransport('session.sock')).toThrow();
    } finally { await new Promise<void>(resolve => { server.close(() => resolve()); }); }
  });
});

test('measured storage inventory matches both runtime allowlists exactly', () => {
  const config = JSON.parse(readFileSync('enclave/confidential-config.json', 'utf8'));
  expect(config.vsock.storage.methods).toEqual([...enclaveMethods]);
  expect([...hostMethods]).toEqual([...enclaveMethods]);
  expect(new Set(config.vsock.storage.methods).size).toBe(enclaveMethods.length);
});

test('admin onboarding methods are never reachable over the enclave storage RPC', () => {
  // Creating, listing and revoking roster records is a host admin action; the enclave
  // (and anything that can speak on its socket) must not be able to call them.
  for (const method of ['createLegalOrganization', 'listLegalOrganizationRecords', 'getLegalOrganizationRecord', 'countLegalOnboarding',
    'listLegalInvitationRecords', 'listLegalMemberRecords', 'revokeLegalInvitation', 'revokeLegalOrganization', 'removeLegalMember',
    'listLegalAudit', 'upsertLegalMember', 'queueLegalAuth0Membership', 'provisionLegalAuth0Membership']) {
    expect(CASE_STORE_RPC_METHODS as readonly string[]).not.toContain(method);
  }
});
