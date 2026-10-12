import { webcrypto } from 'node:crypto';
import { enums, generateKey, readMessage } from '../../../enclave/src/confidential/pgp';
import {
  caseMailboxTag, findCaseStateKey, generateCaseStateKey, openCaseDelta, padStateEnvelopes, paddedStateEnvelopeCount,
  sealCaseDelta, unwrapCaseStateKey, wrapCaseStateKey,
} from '../../../enclave/src/confidential/caseStateKey';

const hex = (n: number) => n.toString(16).padStart(64, '0');
beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

describe('participant-held case state key', () => {
  test('sealed deltas are bound to case, epoch and position', async () => {
    const state = generateCaseStateKey(1), bytes = new TextEncoder().encode('PRIVATE-SENTINEL grant metadata');
    const wire = await sealCaseDelta(hex(1), state, 3, bytes);
    expect(wire).not.toContain('PRIVATE-SENTINEL');
    expect(new TextDecoder().decode(await openCaseDelta(hex(1), state, 3, wire))).toBe('PRIVATE-SENTINEL grant metadata');
    await expect(openCaseDelta(hex(2), state, 3, wire)).rejects.toThrow();
    await expect(openCaseDelta(hex(1), state, 4, wire)).rejects.toThrow();
    await expect(openCaseDelta(hex(1), { ...state, stateEpoch: 2 }, 3, wire)).rejects.toThrow();
    await expect(openCaseDelta(hex(1), generateCaseStateKey(1), 3, wire)).rejects.toThrow();
  });

  test('wrapped keys open only for the recipient and only with the owner signature', async () => {
    const [owner, firm, other] = await Promise.all(['owner', 'firm', 'other'].map(async name =>
      (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
    const state = generateCaseStateKey(1);
    const envelope = await wrapCaseStateKey(hex(1), state, firm.toPublic(), owner);
    expect((await unwrapCaseStateKey(envelope, hex(1), firm, owner.toPublic())).key).toEqual(state.key);
    await expect(unwrapCaseStateKey(envelope, hex(1), other, owner.toPublic())).rejects.toThrow();
    await expect(unwrapCaseStateKey(envelope, hex(2), firm, owner.toPublic())).rejects.toThrow();
    const forged = await wrapCaseStateKey(hex(1), state, firm.toPublic(), other);
    await expect(unwrapCaseStateKey(forged, hex(1), firm, owner.toPublic())).rejects.toThrow();
  });

  test('mailbox tags are keyed: storage cannot map them to firm key IDs', async () => {
    const a = generateCaseStateKey(1).key, b = generateCaseStateKey(1).key;
    expect(await caseMailboxTag(a, hex(1), hex(9))).not.toBe(await caseMailboxTag(b, hex(1), hex(9)));
    expect(await caseMailboxTag(a, hex(1), hex(9))).not.toBe(hex(9));
  });

  test('state-key envelope lists are padded with decoys that look like real envelopes', async () => {
    expect([1, 2, 16, 17, 64, 65, 128].map(paddedStateEnvelopeCount)).toEqual([16, 16, 16, 32, 64, 128, 128]);
    expect(paddedStateEnvelopeCount(0)).toBe(16);
    expect(() => paddedStateEnvelopeCount(-1)).toThrow();
    expect(() => paddedStateEnvelopeCount(129)).toThrow();
    const [owner, firm, other] = await Promise.all(['owner', 'firm', 'other'].map(async name =>
      (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
    const state = generateCaseStateKey(3);
    const real = await Promise.all([owner, firm].map(key => wrapCaseStateKey(hex(1), state, key.toPublic(), owner)));
    const padded = await padStateEnvelopes(real, hex(1), 3);
    // The count no longer tracks the owner plus each grantee.
    expect(padded).toHaveLength(16);
    expect(padded.filter(item => real.includes(item))).toHaveLength(2);
    const shape = async (wire: string) => {
      const message = await readMessage({ armoredMessage: wire });
      return { length: wire.length, tags: message.packets.map(packet => (packet.constructor as { tag?: number }).tag),
        wildcard: message.getEncryptionKeyIDs().every(id => id.isWildcard()),
        pkesk: message.packets.filterByTag(enums.packet.publicKeyEncryptedSessionKey).write().length,
        data: message.packets.filterByTag(enums.packet.symEncryptedIntegrityProtectedData).write().length };
    };
    const expected = await shape(real[0]);
    for (const item of padded) expect(await shape(item)).toEqual(expected);
    // Real participants still find their own key; nobody else opens anything.
    expect((await findCaseStateKey(padded, hex(1), firm, owner.toPublic())).key).toEqual(state.key);
    expect((await findCaseStateKey(padded, hex(1), owner, owner.toPublic())).key).toEqual(state.key);
    await expect(findCaseStateKey(padded, hex(1), other, owner.toPublic())).rejects.toThrow();
    // Shuffled: the real envelopes are not simply kept at the front.
    const positions = new Set<string>();
    for (let round = 0; round < 6; round++) {
      const again = await padStateEnvelopes(real, hex(1), 3);
      positions.add(real.map(item => again.indexOf(item)).join(','));
    }
    expect(positions.size).toBeGreaterThan(1);
  }, 60_000);
});
