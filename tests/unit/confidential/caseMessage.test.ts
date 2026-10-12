import { webcrypto } from 'node:crypto';
import { generateKey, readMessage } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { openCaseMessage, sealCaseMessage } from '../../../enclave/src/confidential/caseMessage';
import type { MessageParticipants } from '../../../enclave/src/confidential/caseMessage';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const none = { owner: 0, organization: 0 };
let owner: PrivateKey, firm: PrivateKey, intruder: PrivateKey, participants: MessageParticipants;

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [owner, firm, intruder] = await Promise.all(['owner', 'firm', 'platform-admin'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }],
      format: 'object' })).privateKey));
  participants = {
    owner: { caseId: hex(1), ownerFingerprint: owner.getFingerprint(), ownerPublicKey: owner.toPublic() },
    organization: { organizationId: hex(2), publicKey: firm.toPublic() },
  };
});

describe('end-to-end encrypted case messages', () => {
  test('both participants read a message; the relay sees ciphertext with hidden recipients', async () => {
    const wire = await sealCaseMessage({ sender: 'organization', sequence: 1, sentAt: now,
      body: 'PRIVATE-SENTINEL question from counsel' }, participants, firm);
    expect(wire).not.toContain('PRIVATE-SENTINEL');
    const message = await readMessage({ armoredMessage: wire });
    expect(message.getEncryptionKeyIDs().every(id => /^0+$/.test(id.toHex()))).toBe(true);
    for (const reader of [owner, firm]) {
      const opened = await openCaseMessage(wire, participants, reader, none);
      expect(opened).toMatchObject({ sender: 'organization', sequence: 1, body: 'PRIVATE-SENTINEL question from counsel' });
    }
    await expect(openCaseMessage(wire, participants, intruder, none)).rejects.toThrow('Invalid confidential case message');
  });

  test('a sender cannot claim the other direction or use an unpinned key', async () => {
    await expect(sealCaseMessage({ sender: 'owner', sequence: 1, sentAt: now, body: 'x' }, participants, firm)).rejects.toThrow();
    await expect(sealCaseMessage({ sender: 'organization', sequence: 1, sentAt: now, body: 'x' }, participants, intruder)).rejects.toThrow();
    // An intruder that encrypts to both real keys still fails signature verification.
    const substituted = { ...participants, organization: { ...participants.organization, publicKey: intruder.toPublic() } };
    const forged = await sealCaseMessage({ sender: 'organization', sequence: 1, sentAt: now, body: 'forged' }, substituted, intruder);
    await expect(openCaseMessage(forged, participants, owner, none)).rejects.toThrow();
  });

  test('messages cannot be replayed into another case, organization or older sequence', async () => {
    const wire = await sealCaseMessage({ sender: 'owner', sequence: 5, sentAt: now, body: 'Owner reply' }, participants, owner);
    await expect(openCaseMessage(wire, { ...participants, owner: { ...participants.owner, caseId: hex(9) } }, firm, none)).rejects.toThrow();
    await expect(openCaseMessage(wire, { ...participants,
      organization: { ...participants.organization, organizationId: hex(9) } }, firm, none)).rejects.toThrow();
    await expect(openCaseMessage(wire, participants, firm, { owner: 5, organization: 0 })).rejects.toThrow();
    await expect(openCaseMessage(wire, participants, firm, { owner: 4, organization: 99 })).resolves.toMatchObject({ sequence: 5 });
  });

  test.each([
    { body: '' }, { body: ' ' }, { body: 'x'.repeat(10_001) }, { body: 'bad\u0000byte' }, { sequence: 0 }, { sequence: 1.5 },
  ])('rejects malformed message %#', async change => {
    await expect(sealCaseMessage({ sender: 'owner', sequence: 1, sentAt: now, body: 'ok', ...change }, participants, owner))
      .rejects.toThrow();
  });

  test('corrupt or oversized relay input fails without echoing it', async () => {
    await expect(openCaseMessage('PRIVATE-SENTINEL', participants, owner, none)).rejects.toThrow('Invalid confidential case message');
    await expect(openCaseMessage('x'.repeat(48 * 1024 + 1), participants, owner, none)).rejects.toThrow();
  });
});
