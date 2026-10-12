import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import request from 'supertest';
import { generateKey, readPrivateKey } from '../../../enclave/src/confidential/pgp';
import * as pgp from '../../../enclave/src/confidential/pgp';
import {
  ConfidentialReleaseWithdrawnError, MAX_WITHDRAWAL_VALIDITY_MS, createWithdrawalMonitor, readWithdrawalPublicKey,
  signReleaseWithdrawalList, verifyReleaseWithdrawalList,
} from '../../../enclave/src/confidential/releaseWithdrawals';
import type { ReleaseWithdrawalList } from '../../../enclave/src/confidential/releaseWithdrawals';
import { createReleaseWithdrawalGuard } from '../../../enclave/src/cases/releaseWithdrawalGuard';
import { measuredReleaseWithdrawalKey } from '../../../enclave/src/cases/measuredConfiguration';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { fetchReleaseWithdrawals } from '../../../enclave/src/cases/storageRpc';
import { createConfidentialStorageServer } from '../../../src/services/confidentialStorageRpc';
import { releaseWithdrawalsSource } from '../../../src/services/confidentialReleaseWithdrawals';
import { createConfidentialReleaseWithdrawalsRouter } from '../../../src/api/confidentialReleaseWithdrawals';
import {
  WITHDRAWAL_FLOOR_PREFIX, assertReleaseNotWithdrawn, browserWithdrawalFloorStore, configureReleaseWithdrawals, releaseWithdrawalState,
} from '../../../lib/confidential/releaseWithdrawals';
import { verifiedSession } from '../../../lib/confidential/client';
import type { ChannelRelay } from '../../../lib/confidential/client';

const NOW = 1_800_000_000_000;
const DAY = 24 * 60 * 60 * 1000;
const RELEASE = 'a'.repeat(64), OTHER = 'b'.repeat(64);
const SCRIPT = path.join(__dirname, '../../../scripts/security/confidential-release-withdrawals.cjs');

let signer: Awaited<ReturnType<typeof readPrivateKey>>, publicArmored: string, otherSigner: typeof signer;
beforeAll(async () => {
  const generated = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'withdrawals' }], format: 'armored' });
  signer = await readPrivateKey({ armoredKey: generated.privateKey });
  publicArmored = generated.publicKey;
  const other = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'other' }], format: 'armored' });
  otherSigner = await readPrivateKey({ armoredKey: other.privateKey });
});
afterEach(() => configureReleaseWithdrawals(undefined));

const list = (overrides: Partial<ReleaseWithdrawalList> = {}): ReleaseWithdrawalList => ({
  format: 'vera-confidential-withdrawals/v1', sequence: 2, issuedAt: NOW - DAY, expiresAt: NOW + 2 * DAY, withdrawn: [], ...overrides });
const signed = (overrides: Partial<ReleaseWithdrawalList> = {}, key = signer) => signReleaseWithdrawalList(list(overrides), key);

describe('signed release withdrawal list', () => {
  test('verifies a current list and exposes withdrawn releases', async () => {
    const wire = await signed({ withdrawn: [{ releaseDigest: RELEASE, reason: 'security', withdrawnAt: NOW - DAY }] });
    const verified = await verifyReleaseWithdrawalList(wire, await readWithdrawalPublicKey(publicArmored), { now: NOW });
    expect(verified.withdrawn).toEqual([{ releaseDigest: RELEASE, reason: 'security', withdrawnAt: NOW - DAY }]);
  });

  test.each<[string, (key: Awaited<ReturnType<typeof readWithdrawalPublicKey>>) => Promise<unknown>]>([
    ['expired', async key => verifyReleaseWithdrawalList(await signed({ expiresAt: NOW }), key, { now: NOW })],
    ['issued in the future', async key => verifyReleaseWithdrawalList(await signed({ issuedAt: NOW + 10 * 60_000, expiresAt: NOW + DAY }), key, { now: NOW })],
    ['older than one already seen', async key => verifyReleaseWithdrawalList(await signed(), key, { now: NOW, minimumSequence: 3 })],
    ['signed by another key', async key => verifyReleaseWithdrawalList(await signed({}, otherSigner), key, { now: NOW })],
    ['valid for longer than 72 hours', async key => verifyReleaseWithdrawalList(await signed({ expiresAt: NOW - DAY + MAX_WITHDRAWAL_VALIDITY_MS + 1 }), key, { now: NOW })],
    ['tampered', async key => {
      const wire = JSON.parse(await signed());
      wire.list.withdrawn = [{ releaseDigest: RELEASE, reason: 'security', withdrawnAt: NOW - DAY }];
      return verifyReleaseWithdrawalList(JSON.stringify(wire), key, { now: NOW });
    }],
    ['not canonical', async key => {
      const wire = JSON.parse(await signed());
      return verifyReleaseWithdrawalList(JSON.stringify({ list: { sequence: wire.list.sequence, ...wire.list }, signature: wire.signature }), key, { now: NOW });
    }],
  ])('refuses a list that is %s', async (_name, attempt) => {
    await expect(attempt(await readWithdrawalPublicKey(publicArmored))).rejects.toThrow('Invalid release withdrawal list');
  });

  test('a private key is never accepted as the pinned verification key', async () => {
    await expect(readWithdrawalPublicKey(signer.armor())).rejects.toThrow();
  });

  test('monitor pauses a withdrawn release without enabling any other', async () => {
    const monitor = createWithdrawalMonitor(await readWithdrawalPublicKey(publicArmored));
    const withdrawn = await signed({ sequence: 3, withdrawn: [{ releaseDigest: RELEASE, reason: 'security', withdrawnAt: NOW - DAY }] });
    await expect(monitor.check(withdrawn, RELEASE, NOW)).rejects.toMatchObject({
      code: 'release-withdrawn', withdrawal: { releaseDigest: RELEASE, reason: 'security' } });
    await expect(monitor.check(withdrawn, OTHER, NOW)).resolves.toMatchObject({ sequence: 3 });
    // A replayed older list that does not mention the withdrawal is ignored.
    await expect(monitor.check(await signed({ sequence: 2 }), RELEASE, NOW)).rejects.toBeInstanceOf(ConfidentialReleaseWithdrawnError);
  });

  test('lists are valid for at most 72 hours', () => {
    expect(MAX_WITHDRAWAL_VALIDITY_MS).toBe(3 * DAY);
  });

  test.each([false, true])('late older verification cannot undo a newer withdrawal (persisted: %s)', async persistedOnly => {
    const key = await readWithdrawalPublicKey(publicArmored);
    const older = await signed({ sequence: 2 });
    const newer = await signed({ sequence: 3, withdrawn: [{ releaseDigest: RELEASE, reason: 'security', withdrawnAt: NOW - DAY }] });
    let saved: { sequence: number; wire: string } | null = null;
    const store = { load: () => saved, save: jest.fn((sequence: number, wire: string) => { saved = { sequence, wire }; }) };
    const monitor = createWithdrawalMonitor(key, { store });
    let resume!: () => void, entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    const realVerify = pgp.verify;
    let first = true;
    const spy = jest.spyOn(pgp, 'verify').mockImplementation((async options => {
      const delay = first; first = false;
      const result = await realVerify(options);
      if (delay) { entered(); await gate; }
      return result;
    }) as typeof realVerify);
    try {
      const pending = monitor.check(older, RELEASE, NOW);
      const rejected = expect(pending).rejects.toBeInstanceOf(ConfidentialReleaseWithdrawnError);
      await started;
      if (persistedOnly) saved = { sequence: 3, wire: newer };
      else await expect(monitor.check(newer, RELEASE, NOW)).rejects.toMatchObject({ withdrawal: { releaseDigest: RELEASE } });
      resume();
      await rejected;
      expect(saved).toEqual({ sequence: 3, wire: newer });
      expect(store.save.mock.calls.some(([sequence]) => sequence === 2)).toBe(false);
      await expect(monitor.check(older, RELEASE, NOW)).rejects.toBeInstanceOf(ConfidentialReleaseWithdrawnError);
      expect(monitor.highestSequence()).toBe(3);
    } finally { resume(); spy.mockRestore(); }
  });

  test('a persisted floor refuses an older unexpired list after a reload or restart', async () => {
    const key = await readWithdrawalPublicKey(publicArmored);
    let saved: { sequence: number; wire: string | null } | null = null;
    const store = { load: () => saved, save: jest.fn((sequence: number, wire: string) => { saved = { sequence, wire }; }) };
    const older = await signed({ sequence: 2 });
    const newer = await signed({ sequence: 3, withdrawn: [{ releaseDigest: RELEASE, reason: 'security', withdrawnAt: NOW - DAY }] });
    await createWithdrawalMonitor(key, { store }).check(older, RELEASE, NOW);
    await expect(createWithdrawalMonitor(key, { store }).check(newer, RELEASE, NOW)).rejects.toMatchObject({ withdrawal: { releaseDigest: RELEASE } });
    expect(saved).toEqual({ sequence: 3, wire: newer });
    // A new monitor (page reload, new tab, process restart) served list 2 keeps
    // the withdrawal from the persisted list 3 instead of accepting the replay.
    const reloaded = createWithdrawalMonitor(key, { store });
    await expect(reloaded.check(older, RELEASE, NOW)).rejects.toMatchObject({ withdrawal: { releaseDigest: RELEASE } });
    expect(reloaded.highestSequence()).toBe(3);
    // Once the persisted list expires the floor still holds: pause, never list 2.
    const expiredStored = createWithdrawalMonitor(key, { store });
    const late = NOW + 2 * DAY + 1;
    await expect(expiredStored.check(await signed({ sequence: 2, issuedAt: late - DAY, expiresAt: late + DAY }), RELEASE, late))
      .rejects.toMatchObject({ withdrawal: null });
    expect(store.save).toHaveBeenCalledTimes(2);
  });

  test('monitor pauses when the list is missing or expires', async () => {
    const monitor = createWithdrawalMonitor(await readWithdrawalPublicKey(publicArmored));
    await expect(monitor.check(null, RELEASE, NOW)).rejects.toMatchObject({ withdrawal: null });
    const wire = await signed();
    await monitor.check(wire, RELEASE, NOW);
    // Host stops delivering: the verified list is reused until it expires.
    await expect(monitor.check(null, RELEASE, NOW + DAY)).resolves.toMatchObject({ sequence: 2 });
    await expect(monitor.check(null, RELEASE, NOW + 2 * DAY)).rejects.toMatchObject({ withdrawal: null });
  });
});

describe('offline signing tool interoperates with the verifier', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vrw-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
  const run = (...args: string[]) => JSON.parse(execFileSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' }));

  test('keygen, sign, carry forward and verify', async () => {
    const privateFile = path.join(dir, 'private.asc'), publicFile = path.join(dir, 'public.asc');
    const { publicKeyBase64 } = run('keygen', '--name', 'Vera release withdrawals', '--private', privateFile, '--public', publicFile);
    expect(Buffer.from(publicKeyBase64, 'base64').toString()).toBe(fs.readFileSync(publicFile, 'utf8'));
    expect(fs.statSync(privateFile).mode & 0o077).toBe(0);
    const first = path.join(dir, 'list-1.json'), second = path.join(dir, 'list-2.json');
    run('sign', '--private', privateFile, '--withdraw', `${OTHER}:defect`, '--withdraw', `${RELEASE}:security`, '--now', String(NOW), '--out', first);
    run('sign', '--private', privateFile, '--previous', first, '--restore', OTHER, '--now', String(NOW + 1000), '--valid-hours', '24', '--out', second);
    const key = await readWithdrawalPublicKey(fs.readFileSync(publicFile, 'utf8'));
    const one = await verifyReleaseWithdrawalList(fs.readFileSync(first, 'utf8'), key, { now: NOW });
    expect(one.withdrawn.map(entry => entry.releaseDigest)).toEqual([RELEASE, OTHER]);
    const two = await verifyReleaseWithdrawalList(fs.readFileSync(second, 'utf8'), key, { now: NOW + 1000, minimumSequence: one.sequence });
    expect(two).toMatchObject({ sequence: 2, expiresAt: NOW + 1000 + DAY, withdrawn: [{ releaseDigest: RELEASE, withdrawnAt: NOW }] });
    expect(run('verify', '--public', publicFile, '--in', second, '--release', OTHER, '--now', String(NOW + 2000))).toMatchObject({ sequence: 2 });
    expect(() => execFileSync(process.execPath, [SCRIPT, 'verify', '--public', publicFile, '--in', second, '--release', RELEASE,
      '--now', String(NOW + 2000)], { stdio: 'pipe' })).toThrow();
    // A TypeScript-signed list verifies with the tool too.
    const tsFile = path.join(dir, 'ts.json');
    fs.writeFileSync(tsFile, await signed());
    const tsPublic = path.join(dir, 'ts-public.asc');
    fs.writeFileSync(tsPublic, publicArmored);
    expect(run('verify', '--public', tsPublic, '--in', tsFile, '--now', String(NOW))).toMatchObject({ sequence: 2 });
  });
});

describe('enclave self-check', () => {
  test('without a pinned key nothing is paused', async () => {
    const guard = await createReleaseWithdrawalGuard({ publicKey: null, releaseDigest: RELEASE, fetchList: async () => null, clock: () => NOW });
    const dispatch = jest.fn(async () => new Uint8Array([1]));
    await expect(guard.wrap(dispatch)(new Uint8Array(), {} as never)).resolves.toEqual(new Uint8Array([1]));
  });

  test('pauses every operation while withdrawn or unconfirmed, and resumes on a current list', async () => {
    let served: string | null = null, now = NOW;
    const guard = await createReleaseWithdrawalGuard({ publicKey: publicArmored, releaseDigest: RELEASE,
      fetchList: async () => served, clock: () => now, refreshMs: 60 * 60_000 });
    const dispatch = jest.fn(async () => new Uint8Array([1]));
    const wrapped = guard.wrap(dispatch);
    await expect(wrapped(new Uint8Array(), {} as never)).rejects.toThrow('paused');
    served = await signed();
    await guard.refresh();
    await expect(wrapped(new Uint8Array(), {} as never)).resolves.toBeDefined();
    served = await signed({ sequence: 3, withdrawn: [{ releaseDigest: RELEASE, reason: 'security', withdrawnAt: NOW - DAY }] });
    await guard.refresh();
    await expect(wrapped(new Uint8Array(), {} as never)).rejects.toThrow('paused');
    served = await signed({ sequence: 4 });
    await guard.refresh();
    await expect(wrapped(new Uint8Array(), {} as never)).resolves.toBeDefined();
    now = NOW + 3 * DAY; // The list expired and was not refreshed.
    await expect(wrapped(new Uint8Array(), {} as never)).rejects.toThrow('paused');
    expect(dispatch).toHaveBeenCalledTimes(2);
    guard.stop();
  });

  test('the withdrawal key comes only from exact measured configuration bytes', async () => {
    const fixture = (releaseWithdrawal: unknown) => {
      const bytes = Buffer.from(JSON.stringify({ format: 'vera-confidential-configuration/v1',
        protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
        channelAudience: 'vera-confidential-cases', legalIdentityPolicySha256: null, legalAdministration: null, releaseWithdrawal }));
      const wire = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
        sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
        eifSha256: '1'.repeat(64), imageSha256: '2'.repeat(64), provenanceSha256: '3'.repeat(64),
        configurationSha256: createHash('sha256').update(bytes).digest('hex'),
        protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
        measurements: { pcr0: '1'.repeat(96), pcr1: '2'.repeat(96), pcr2: '3'.repeat(96) } });
      return { bytes, wire };
    };
    const pinned = fixture({ publicKey: publicArmored });
    await expect(measuredReleaseWithdrawalKey(pinned.wire, pinned.bytes)).resolves.toBe(publicArmored);
    const disabled = fixture(null);
    await expect(measuredReleaseWithdrawalKey(disabled.wire, disabled.bytes)).resolves.toBeNull();
    const privateKey = fixture({ publicKey: signer.armor() });
    await expect(measuredReleaseWithdrawalKey(privateKey.wire, privateKey.bytes)).rejects.toThrow();
    const extra = fixture({ publicKey: publicArmored, allowUnsigned: true });
    await expect(measuredReleaseWithdrawalKey(extra.wire, extra.bytes)).rejects.toThrow();
    await expect(measuredReleaseWithdrawalKey(pinned.wire, disabled.bytes)).rejects.toThrow();
  });
});

describe('host delivery', () => {
  let dir: string;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vrh-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  test('the host re-reads the refreshed file and serves it to the enclave and browsers unchanged', async () => {
    const file = path.join(dir, 'release-withdrawals.json');
    let clock = 0;
    const source = releaseWithdrawalsSource(file, () => clock);
    expect(source()).toBeNull();
    const wire = await signed();
    fs.writeFileSync(file, wire);
    clock += 31_000;
    expect(source()).toBe(wire);
    const server = createConfidentialStorageServer({}, { releaseWithdrawals: source });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    await expect(fetchReleaseWithdrawals({ port: (server.address() as AddressInfo).port })).resolves.toBe(wire);
    server.close();
    const app = express().use('/api/confidential', createConfidentialReleaseWithdrawalsRouter(source));
    const response = await request(app).get('/api/confidential/release-withdrawals');
    expect(response.status).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.text).toBe(wire);
    const empty = express().use('/api/confidential', createConfidentialReleaseWithdrawalsRouter(() => null));
    expect((await request(empty).get('/api/confidential/release-withdrawals')).status).toBe(404);
  });

  test('without a published list the enclave RPC returns null', async () => {
    const server = createConfidentialStorageServer({});
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    await expect(fetchReleaseWithdrawals({ port: (server.address() as AddressInfo).port })).resolves.toBeNull();
    server.close();
    void net;
  });
});

describe('participant devices', () => {
  const manifest = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
    sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
    eifSha256: '1'.repeat(64), imageSha256: '2'.repeat(64), provenanceSha256: '3'.repeat(64), configurationSha256: '4'.repeat(64),
    protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
    measurements: { pcr0: '1'.repeat(96), pcr1: '2'.repeat(96), pcr2: '3'.repeat(96) } });
  const digest = createHash('sha256').update(manifest).digest('hex');
  const relay = (withdrawals?: () => Promise<string | null>) => {
    const opened = jest.fn(async () => { throw new Error('attestation not reached in this test'); });
    return { opened, relay: { stage: jest.fn(), open: opened, call: jest.fn(), withdrawals } as unknown as ChannelRelay };
  };

  test('not configured: sessions proceed to attestation and the state says so', async () => {
    configureReleaseWithdrawals(null);
    const { relay: unconfigured, opened } = relay();
    await expect(verifiedSession(unconfigured, manifest, Date.now())).rejects.toThrow('attestation not reached');
    expect(opened).toHaveBeenCalled();
    expect(releaseWithdrawalState()).toEqual({ configured: false });
  });

  test('a withdrawn release is refused before the relay sees any session', async () => {
    configureReleaseWithdrawals(publicArmored);
    const now = Date.now();
    const wire = await signReleaseWithdrawalList(list({ issuedAt: now - DAY, expiresAt: now + DAY,
      withdrawn: [{ releaseDigest: digest, reason: 'security', withdrawnAt: now - DAY }] }), signer);
    const { relay: paused, opened } = relay(async () => wire);
    await expect(verifiedSession(paused, manifest, now)).rejects.toBeInstanceOf(ConfidentialReleaseWithdrawnError);
    expect(opened).not.toHaveBeenCalled();
    expect(releaseWithdrawalState()).toMatchObject({ configured: true, paused: { releaseDigest: digest } });
  });

  test('a pinned key with no list available pauses (fail closed)', async () => {
    configureReleaseWithdrawals(publicArmored);
    const { relay: silent, opened } = relay(async () => null);
    await expect(verifiedSession(silent, manifest, Date.now())).rejects.toMatchObject({ withdrawal: null });
    expect(opened).not.toHaveBeenCalled();
    expect(releaseWithdrawalState()).toMatchObject({ paused: 'unconfirmed' });
  });

  test('the highest verified list survives a reload, so the host cannot replay an older one', async () => {
    const data = new Map<string, string>();
    const localStorage = { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value); } };
    const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
    Object.defineProperty(globalThis, 'window', { value: { localStorage }, configurable: true });
    try {
      configureReleaseWithdrawals(publicArmored);
      const now = Date.now();
      const at = (overrides: Partial<ReleaseWithdrawalList>) => signReleaseWithdrawalList(list({ issuedAt: now - DAY, expiresAt: now + DAY, ...overrides }), signer);
      const older = await at({ sequence: 4 });
      const newer = await at({ sequence: 5, withdrawn: [{ releaseDigest: digest, reason: 'security', withdrawnAt: now - DAY }] });
      await expect(assertReleaseNotWithdrawn(digest, now, async () => newer)).rejects.toBeInstanceOf(ConfidentialReleaseWithdrawnError);
      const [[slot, stored]] = [...data.entries()];
      expect(slot).toMatch(/^vera-confidential-withdrawals\/v1:[a-f0-9]{40,64}$/);
      expect(JSON.parse(stored)).toEqual({ sequence: 5, wire: newer });
      // Fresh module state, as after a page reload; the host now serves list 4.
      configureReleaseWithdrawals(publicArmored);
      await expect(assertReleaseNotWithdrawn(digest, now, async () => older)).rejects.toMatchObject({ withdrawal: { releaseDigest: digest } });
      expect(releaseWithdrawalState()).toMatchObject({ paused: { releaseDigest: digest }, list: { sequence: 5 } });
      // The stored floor is never lowered.
      browserWithdrawalFloorStore(slot.slice(WITHDRAWAL_FLOOR_PREFIX.length)).save(4, older);
      expect(JSON.parse(data.get(slot)!).sequence).toBe(5);
    } finally {
      if (originalWindow) Object.defineProperty(globalThis, 'window', originalWindow); else delete (globalThis as { window?: unknown }).window;
    }
  });

  test('a current list that does not withdraw the release lets the session continue and is reused briefly', async () => {
    configureReleaseWithdrawals(publicArmored);
    const now = Date.now();
    const source = jest.fn(async () => signReleaseWithdrawalList(list({ issuedAt: now - DAY, expiresAt: now + DAY,
      withdrawn: [{ releaseDigest: OTHER, reason: 'retired', withdrawnAt: now - DAY }] }), signer));
    await assertReleaseNotWithdrawn(digest, now, source);
    await assertReleaseNotWithdrawn(digest, now + 1000, source);
    expect(source).toHaveBeenCalledTimes(1);
    expect(releaseWithdrawalState()).toMatchObject({ configured: true, checkedAt: now, paused: null, list: { sequence: 2 } });
  });
});
