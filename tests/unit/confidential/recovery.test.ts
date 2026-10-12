import { webcrypto } from 'node:crypto';
import { createCaseOwner, createOwnerRecovery, recoveryCaseLocator, restoreOwnerRecovery,
  advanceOwnerCheckpoint, refreshOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { parseRecoveryCode } from '../../../enclave/src/confidential/recoveryCode';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import { sealCaseObject, openOwnerCaseObject } from '../../../enclave/src/confidential/caseObject';
import type { CaseCheckpoint } from '../../../enclave/src/confidential/authorization';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
let owner: Awaited<ReturnType<typeof createCaseOwner>>;
let checkpoint: string, receipt: Awaited<ReturnType<typeof createOwnerRecovery>>;
let initial: CaseCheckpoint;
beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  owner = await createCaseOwner();
  initial = { kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1, keyEpoch: 1, previousDigest: null,
    listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: now };
  checkpoint = await signOwnerStatement(initial, owner.privateKey);
  receipt = await createOwnerRecovery(owner, checkpoint);
});

describe('participant-only recovery', () => {
  test('new cases have independent random identifiers and owner keys without personal user IDs', async () => {
    const second = await createCaseOwner();
    expect(second.trust.caseId).toMatch(/^[a-f0-9]{64}$/);
    expect(second.trust.caseId).not.toBe(owner.trust.caseId);
    expect(second.trust.ownerFingerprint).not.toBe(owner.trust.ownerFingerprint);
    expect(second.privateKey.getUserIDs()).toEqual(['Vera case owner']);
  });

  test('restores the original private key, checkpoint and explicitly unverified freshness state', async () => {
    const restored = await restoreOwnerRecovery(receipt.recoveryCode, receipt.encryptedPackage);
    expect(restored.privateKey.getFingerprint()).toBe(owner.trust.ownerFingerprint);
    expect(restored.checkpoint).toBe(checkpoint);
    expect(restored.pin).toEqual(receipt.pin);
    expect(restored.freshness).toBe('requires-current-state-verification');
    const signed = await signOwnerStatement({ kind: 'listing', caseId: owner.trust.caseId,
      revision: 2, summary: 'Owner-approved public preview.' }, restored.privateKey);
    expect((await verifyOwnerStatement(signed, owner.trust)).statement.kind).toBe('listing');
  });

  test('a separately restored browser key can decrypt an existing private object', async () => {
    const ctx = { caseId: owner.trust.caseId, objectId: hex(2), scope: 'evidence' as const, keyEpoch: 1, objectRevision: 1 };
    const evidence = new TextEncoder().encode('PRIVATE-RECOVERY-SENTINEL');
    const object = await sealCaseObject(ctx, evidence, owner.privateKey);
    const restored = await restoreOwnerRecovery(receipt.recoveryCode, receipt.encryptedPackage);
    expect(await openOwnerCaseObject(object, ctx, restored.privateKey)).toEqual(evidence);
  });

  test('the code is only the secret: 14 groups of 4, no locator or fingerprint inside', async () => {
    expect(receipt.recoveryCode).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){13}$/);
    expect(receipt.recoveryCode.length).toBe(69);
    const compact = receipt.recoveryCode.replace(/-/g, '').toLowerCase();
    expect(compact).not.toContain(owner.trust.caseId.slice(0, 8));
    expect(receipt.recoveryCode).not.toContain(owner.trust.ownerFingerprint.slice(0, 8).toUpperCase());
    const parsed = await parseRecoveryCode(receipt.recoveryCode);
    expect(parsed.version).toBe('v2');
    expect(parsed.secret).toHaveLength(32);
  });

  test('the owner secret derives the public case locator; the locator does not reveal the package key', async () => {
    const fresh = await createCaseOwner();
    expect(fresh.recoverySecret).toHaveLength(32);
    const freshCheckpoint = await signOwnerStatement({ ...initial, caseId: fresh.trust.caseId }, fresh.privateKey);
    const freshReceipt = await createOwnerRecovery(fresh, freshCheckpoint);
    expect(await recoveryCaseLocator(freshReceipt.recoveryCode)).toBe(fresh.trust.caseId);
    // A mismatched secret (so the derived locator differs from the case ID) is refused.
    const forged = { ...fresh, recoverySecret: new Uint8Array(32).fill(7) };
    await expect(createOwnerRecovery(forged, freshCheckpoint)).rejects.toThrow('Unable to restore confidential case recovery');
    // The package is encrypted under a key derived with a different label than the
    // locator: using the locator bytes as that key does not open it.
    const value = JSON.parse(freshReceipt.encryptedPackage);
    const locatorKey = await globalThis.crypto.subtle.importKey('raw', Buffer.from(fresh.trust.caseId, 'hex'), 'AES-GCM', false, ['decrypt']);
    const b64 = (text: string) => Buffer.from(text, 'base64url');
    await expect(globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(value.nonce),
      additionalData: new TextEncoder().encode(JSON.stringify({ format: value.format, caseId: fresh.trust.caseId })) },
      locatorKey, b64(value.ciphertext))).rejects.toThrow();
  });

  test('only the public locator is exposed for routing; the saved package is opaque', async () => {
    expect(await recoveryCaseLocator(receipt.recoveryCode)).toBe(owner.trust.caseId);
    expect(await recoveryCaseLocator(`  ${receipt.recoveryCode}\n`)).toBe(owner.trust.caseId);
    // Typed forms of the same code: lower case, spaces, no separators, O for 0 and L for 1.
    const typed = receipt.recoveryCode.toLowerCase().replace(/-/g, ' ');
    expect(await recoveryCaseLocator(typed)).toBe(owner.trust.caseId);
    expect(await recoveryCaseLocator(receipt.recoveryCode.replace(/-/g, ''))).toBe(owner.trust.caseId);
    expect(await recoveryCaseLocator(receipt.recoveryCode.replace(/0/g, 'O').replace(/1/g, 'l'))).toBe(owner.trust.caseId);
    expect(JSON.parse(receipt.encryptedPackage).format).toBe('vera-owner-recovery/v2');
    expect(Object.keys(JSON.parse(receipt.encryptedPackage)).sort()).toEqual(['ciphertext', 'format', 'nonce']);
    for (const value of [owner.trust.caseId, owner.trust.ownerFingerprint, owner.privateKey.armor(),
      receipt.recoveryCode, 'PRIVATE KEY', checkpoint]) {
      expect(receipt.encryptedPackage).not.toContain(value);
    }
  });

  test('another report\'s valid code cannot unlock this package', async () => {
    const other = await createCaseOwner();
    const otherReceipt = await createOwnerRecovery(other, await signOwnerStatement({ ...initial, caseId: other.trust.caseId }, other.privateKey));
    expect(otherReceipt.recoveryCode).not.toBe(receipt.recoveryCode);
    await expect(restoreOwnerRecovery(otherReceipt.recoveryCode, receipt.encryptedPackage)).rejects.toThrow('Unable to restore confidential case recovery');
    // Swapping packages across reports fails too, even though both are authentic.
    await expect(restoreOwnerRecovery(receipt.recoveryCode, otherReceipt.encryptedPackage)).rejects.toThrow('Unable to restore confidential case recovery');
  });

  test('a mistyped code (checksum) fails before any key is derived', async () => {
    const chars = receipt.recoveryCode.split('');
    chars[5] = chars[5] === 'A' ? 'B' : 'A';
    await expect(recoveryCaseLocator(chars.join(''))).rejects.toThrow('Unable to restore confidential case recovery');
    await expect(restoreOwnerRecovery(chars.join(''), receipt.encryptedPackage)).rejects.toThrow('Unable to restore confidential case recovery');
    await expect(recoveryCaseLocator(receipt.recoveryCode.slice(0, -5))).rejects.toThrow();
  });

  test.each(['', 'password', 'VRC-old-server-recovery', 'VERA-OWNER-2.' + 'a'.repeat(160), 'x'.repeat(257),
    'U'.repeat(56), '0'.repeat(55)])(
    'does not accept password/legacy/version/oversized recovery input %#', async code => {
      await expect(recoveryCaseLocator(code)).rejects.toThrow('Unable to restore confidential case recovery');
      await expect(restoreOwnerRecovery(code, receipt.encryptedPackage)).rejects.toThrow('Unable to restore confidential case recovery');
    });

  test('tampered, oversized, truncated, unknown-version and extended packages fail closed', async () => {
    const value = JSON.parse(receipt.encryptedPackage);
    const change = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
    for (const packageValue of [
      { ...value, ciphertext: change(value.ciphertext) }, { ...value, nonce: change(value.nonce) },
      { ...value, nonce: '' }, { ...value, ciphertext: value.ciphertext + '=' },
      { ...value, format: 'vera-owner-recovery/v1' }, { ...value, format: 'vera-owner-recovery/v3' },
      { ...value, adminRecoveryKey: 'PRIVATE-SENTINEL' },
    ]) {
      await expect(restoreOwnerRecovery(receipt.recoveryCode, JSON.stringify(packageValue)))
        .rejects.toThrow('Unable to restore confidential case recovery');
    }
    await expect(restoreOwnerRecovery(receipt.recoveryCode, 'x'.repeat(132 * 1024 + 1))).rejects.toThrow();
    await expect(restoreOwnerRecovery(receipt.recoveryCode, 'PRIVATE-SENTINEL')).rejects.toThrow('Unable to restore confidential case recovery');
  });

  test('recovery requires an owner-signed checkpoint for this case', async () => {
    const other = await createCaseOwner();
    const forged = await signOwnerStatement(initial, other.privateKey);
    const otherCase = await signOwnerStatement({ ...initial, caseId: other.trust.caseId }, owner.privateKey);
    const listing = await signOwnerStatement({ kind: 'listing', caseId: owner.trust.caseId, revision: 1, summary: 'Preview' }, owner.privateKey);
    for (const invalid of [forged, otherCase, listing]) {
      await expect(createOwnerRecovery(owner, invalid)).rejects.toThrow();
    }
  });

  test('refresh preserves the participant code while advancing the saved checkpoint', async () => {
    const nextWire = await signOwnerStatement({ ...initial, revision: 2, keyEpoch: 2,
      previousDigest: receipt.pin.digest }, owner.privateKey);
    const updated = await refreshOwnerRecovery(receipt.recoveryCode, owner.privateKey, nextWire, receipt.pin);
    expect(updated.encryptedPackage).not.toBe(receipt.encryptedPackage);
    const restored = await restoreOwnerRecovery(receipt.recoveryCode, updated.encryptedPackage, receipt.pin);
    expect(restored.pin).toEqual(updated.pin);
    expect(restored.pin.revision).toBe(2);
    expect(restored.pin.keyEpoch).toBe(2);
    // The old blob is authentic, but cannot roll back a device with the newer pin.
    await expect(restoreOwnerRecovery(receipt.recoveryCode, receipt.encryptedPackage, updated.pin)).rejects.toThrow();
    await expect(refreshOwnerRecovery(receipt.recoveryCode, owner.privateKey, checkpoint, updated.pin)).rejects.toThrow();
  });

  test('a fresh device restoring an old export is never told it knows the latest state', async () => {
    const restored = await restoreOwnerRecovery(receipt.recoveryCode, receipt.encryptedPackage);
    expect(restored.freshness).toBe('requires-current-state-verification');
  });

  test('accepts an identical checkpoint but rejects a signed fork at the same revision', async () => {
    expect(await advanceOwnerCheckpoint(checkpoint, owner.trust, receipt.pin)).toEqual(receipt.pin);
    const fork = await signOwnerStatement({ ...initial, grantDigests: [hex(9)] }, owner.privateKey);
    await expect(advanceOwnerCheckpoint(fork, owner.trust, receipt.pin)).rejects.toThrow();
  });

  test('rejects lowering the key epoch even if the policy revision increases', async () => {
    const newer = await signOwnerStatement({ ...initial, revision: 2, keyEpoch: 2,
      previousDigest: receipt.pin.digest }, owner.privateKey);
    const newerPin = await advanceOwnerCheckpoint(newer, owner.trust, receipt.pin);
    const rollback = await signOwnerStatement({ ...initial, revision: 3, keyEpoch: 1,
      previousDigest: newerPin.digest }, owner.privateKey);
    await expect(advanceOwnerCheckpoint(rollback, owner.trust, newerPin)).rejects.toThrow();
  });

  test('checkpoint advancement follows the hash chain and refuses spliced or skipped history', async () => {
    const second = await signOwnerStatement({ ...initial, revision: 2, previousDigest: receipt.pin.digest }, owner.privateKey);
    const secondPin = (await verifyOwnerStatement(second, owner.trust));
    const third = await signOwnerStatement({ ...initial, revision: 3, previousDigest: secondPin.digest }, owner.privateKey);
    // A full chain from the device pin advances; the tip alone skips history and fails.
    expect((await advanceOwnerCheckpoint([second, third], owner.trust, receipt.pin)).revision).toBe(3);
    await expect(advanceOwnerCheckpoint(third, owner.trust, receipt.pin)).rejects.toThrow();
    // A higher-revision successor that does not link to the pin is a fork.
    const unlinked = await signOwnerStatement({ ...initial, revision: 4, previousDigest: hex(9) }, owner.privateKey);
    await expect(advanceOwnerCheckpoint(unlinked, owner.trust, receipt.pin)).rejects.toThrow();
    await expect(advanceOwnerCheckpoint([third, second], owner.trust, receipt.pin)).rejects.toThrow();
  });

  test('does not accept malformed, unrelated or mismatched device pins', async () => {
    for (const pin of [
      { ...receipt.pin, caseId: hex(99) }, { ...receipt.pin, digest: hex(99) },
      { ...receipt.pin, revision: 1.5 }, { ...receipt.pin, keyEpoch: 0 }, { ...receipt.pin, adminOverride: true },
    ]) {
      await expect(restoreOwnerRecovery(receipt.recoveryCode, receipt.encryptedPackage, pin)).rejects.toThrow();
    }
  });
});

/** Builds a report exactly as the v1 client did: random case ID, long
 * `VERA-OWNER-1.` code carrying locator and fingerprint, AES key = raw secret. */
async function legacyV1Report() {
  const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
  const caseId = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString('hex');
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Vera case owner' }], format: 'object' });
  const ownerFingerprint = publicKey.getFingerprint();
  const trust = { caseId, ownerFingerprint, ownerPublicKey: publicKey };
  const legacyCheckpoint = await signOwnerStatement({ ...initial, caseId }, privateKey);
  const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const code = `VERA-OWNER-1.${caseId}.${ownerFingerprint}.${b64(secret)}`;
  const key = await globalThis.crypto.subtle.importKey('raw', secret, 'AES-GCM', false, ['encrypt']);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify({ format: 'vera-owner-recovery-payload/v1', caseId, ownerFingerprint,
    privateKey: privateKey.armor(), checkpoint: legacyCheckpoint }));
  const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128,
    additionalData: new TextEncoder().encode(JSON.stringify({ format: 'vera-owner-recovery/v1', caseId, ownerFingerprint })) }, key, plaintext));
  const pkg = JSON.stringify({ format: 'vera-owner-recovery/v1', nonce: b64(nonce), ciphertext: b64(ciphertext) });
  return { code, pkg, caseId, ownerFingerprint, privateKey, trust, checkpoint: legacyCheckpoint };
}

describe('backward compatibility with v1 (long) recovery codes', () => {
  test('existing v1 codes and packages still restore, route and refresh in v1 format', async () => {
    const legacy = await legacyV1Report();
    expect(await recoveryCaseLocator(legacy.code)).toBe(legacy.caseId);
    const restored = await restoreOwnerRecovery(legacy.code, legacy.pkg);
    expect(restored.privateKey.getFingerprint()).toBe(legacy.ownerFingerprint);
    expect(restored.trust.caseId).toBe(legacy.caseId);
    expect(restored.checkpoint).toBe(legacy.checkpoint);
    const next = await signOwnerStatement({ ...initial, caseId: legacy.caseId, revision: 2, previousDigest: restored.pin.digest },
      legacy.privateKey);
    const refreshed = await refreshOwnerRecovery(legacy.code, legacy.privateKey, next, restored.pin);
    expect(JSON.parse(refreshed.encryptedPackage).format).toBe('vera-owner-recovery/v1');
    expect((await restoreOwnerRecovery(legacy.code, refreshed.encryptedPackage, restored.pin)).pin.revision).toBe(2);
  });

  test('v1 still binds the locator and owner fingerprint named in the code', async () => {
    const legacy = await legacyV1Report();
    const other = await createCaseOwner();
    const locatorSwap = legacy.code.replace(legacy.caseId, other.trust.caseId);
    const ownerSwap = legacy.code.replace(legacy.ownerFingerprint, other.trust.ownerFingerprint);
    await expect(restoreOwnerRecovery(locatorSwap, legacy.pkg)).rejects.toThrow();
    await expect(restoreOwnerRecovery(ownerSwap, legacy.pkg)).rejects.toThrow();
    // A v1 refresh with a different owner key is refused.
    const restored = await restoreOwnerRecovery(legacy.code, legacy.pkg);
    await expect(refreshOwnerRecovery(legacy.code, other.privateKey, legacy.checkpoint, restored.pin)).rejects.toThrow();
  });

  test('versions never cross: a v1 code cannot open a v2 package, nor a v2 code a v1 package', async () => {
    const legacy = await legacyV1Report();
    await expect(restoreOwnerRecovery(legacy.code, receipt.encryptedPackage)).rejects.toThrow('Unable to restore confidential case recovery');
    await expect(restoreOwnerRecovery(receipt.recoveryCode, legacy.pkg)).rejects.toThrow('Unable to restore confidential case recovery');
    // Relabelling the v1 package as v2 does not help either (the version is bound into the AES-GCM data).
    const relabelled = JSON.stringify({ ...JSON.parse(legacy.pkg), format: 'vera-owner-recovery/v2' });
    await expect(restoreOwnerRecovery(legacy.code, relabelled)).rejects.toThrow();
  });
});
