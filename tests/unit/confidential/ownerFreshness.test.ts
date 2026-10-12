import { webcrypto } from 'node:crypto';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint } from '../../../enclave/src/confidential/authorization';
import { createCaseOwner, createOwnerRecovery, restoreOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { refreshedRecoveryPackage, restoreOwnerSession } from '../../../lib/confidential/ownerCase';
import type { ChannelRelay } from '../../../lib/confidential/client';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const now = Date.now();
// The recovery file path never touches the relay.
const relay = (() => { throw new Error('relay must not be used'); }) as unknown as ChannelRelay;

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

describe('owner freshness: refreshed recovery packages and pin-less devices', () => {
  async function setup() {
    const owner = await createCaseOwner();
    const genesis: CaseCheckpoint = { kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1, keyEpoch: 1, previousDigest: null,
      listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: now };
    const genesisWire = await signOwnerStatement(genesis, owner.privateKey);
    const recovery = await createOwnerRecovery(owner, genesisWire);
    const next = await signOwnerStatement({ ...genesis, revision: 2,
      previousDigest: (await verifyOwnerStatement(genesisWire, owner.trust)).digest, issuedAt: now + 1 }, owner.privateKey);
    return { owner, genesis, genesisWire, recovery, next };
  }

  test('a session restored only from the package is marked unconfirmed; a retained device pin confirms it', async () => {
    const { recovery } = await setup();
    const unpinned = await restoreOwnerSession({ code: recovery.recoveryCode, recoveryPackage: recovery.encryptedPackage,
      relay, releaseManifest: MANIFEST, now });
    expect(unpinned.freshness).toBe('unconfirmed');
    expect(unpinned.recoveryCode).toBe(recovery.recoveryCode);
    const pinned = await restoreOwnerSession({ code: recovery.recoveryCode, recoveryPackage: recovery.encryptedPackage,
      relay, releaseManifest: MANIFEST, now, rememberedPin: recovery.pin });
    expect(pinned.freshness).toBe('device-pinned');
  });

  test('each commit carries a package that restores the new checkpoint on a fresh device', async () => {
    const { recovery, next } = await setup();
    const session = await restoreOwnerSession({ code: recovery.recoveryCode, recoveryPackage: recovery.encryptedPackage,
      relay, releaseManifest: MANIFEST, now });
    const refreshed = await refreshedRecoveryPackage(session, next);
    const restored = await restoreOwnerRecovery(recovery.recoveryCode, refreshed);
    expect(restored.checkpoint).toBe(next);
    expect(restored.pin.revision).toBe(2);
    // A device holding the newer pin accepts the older package only as a starting
    // point: the newer pin becomes a floor the served chain must contain.
    const floored = await restoreOwnerSession({ code: recovery.recoveryCode, recoveryPackage: recovery.encryptedPackage,
      relay, releaseManifest: MANIFEST, now, rememberedPin: restored.pin });
    expect(floored.minimumPin).toEqual(restored.pin);
    expect(floored.freshness).toBe('device-pinned');
  });

  test('refresh refuses a checkpoint that does not directly extend the session pin', async () => {
    const { owner, genesis, recovery, next } = await setup();
    const session = await restoreOwnerSession({ code: recovery.recoveryCode, recoveryPackage: recovery.encryptedPackage,
      relay, releaseManifest: MANIFEST, now });
    const forked = await signOwnerStatement({ ...genesis, revision: 2, previousDigest: hex(9), issuedAt: now + 1 }, owner.privateKey);
    await expect(refreshedRecoveryPackage(session, forked)).rejects.toThrow();
    const other = await createCaseOwner();
    await expect(refreshedRecoveryPackage({ ...session, owner: other.privateKey }, next)).rejects.toThrow();
  });
});
