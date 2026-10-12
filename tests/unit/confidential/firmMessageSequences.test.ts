jest.mock('../../../lib/confidential/client', () => ({
  ...jest.requireActual('../../../lib/confidential/client'),
  channelSessionsFor: jest.fn(() => ({})),
  authenticatedOperation: jest.fn(),
}));
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import { openCaseMessage, sealCaseMessage } from '../../../enclave/src/confidential/caseMessage';
import { generateFirmIdentity } from '../../../lib/confidential/firmKey';
import { readFirmMessages, sendFirmMessage } from '../../../lib/confidential/firmCase';
import type { FirmSession } from '../../../lib/confidential/firmCase';
import { authenticatedOperation } from '../../../lib/confidential/client';

async function fixture() {
  const owner = await createCaseOwner();
  const firm = await generateFirmIdentity({ organizationId: '33'.repeat(32), domain: 'firm.example' });
  const caseId = owner.trust.caseId;
  const session = { firm, owners: new Map([[caseId, owner.trust]]), pins: new Map(), sequences: new Map(),
    accessToken: async () => 'synthetic', relay: {}, releaseManifest: 'synthetic' } as unknown as FirmSession;
  const participants = { owner: owner.trust, organization: { organizationId: firm.organizationId, publicKey: firm.privateKey.toPublic() } };
  const sent: string[] = [];
  let messages: unknown[] = [];
  jest.mocked(authenticatedOperation).mockImplementation(async (_sessions, input) => {
    const body = input.request('synthetic-proof') as { operation: string; body?: string };
    if (body.operation === 'legal.read-messages') return { messages, next: null };
    if (body.operation === 'legal.send-message') {
      sent.push(JSON.parse(Buffer.from(body.body!, 'base64').toString('utf8')).ciphertext);
      return { sent: true };
    }
    throw new Error('Unexpected operation');
  });
  return { owner, firm, caseId, session, participants, sent, setMessages: (value: unknown[]) => { messages = value; } };
}
test('restored sequence floors never regress when the store omits history', async () => {
  const f = await fixture();
  f.session.sequences.set(f.caseId, { owner: 9, organization: 7 });
  const ciphertext = await sealCaseMessage({ sender: 'owner', sequence: 2, sentAt: Date.now(), body: 'Older visible message' },
    f.participants, f.owner.privateKey);
  f.setMessages([{ caseId: f.caseId, organizationId: f.firm.organizationId, sender: 'owner', ciphertext }]);
  expect((await readFirmMessages(f.session, f.caseId, Date.now())).messages).toHaveLength(1);
  expect(f.session.sequences.get(f.caseId)).toEqual({ owner: 9, organization: 7 });
  f.setMessages([]);
  await readFirmMessages(f.session, f.caseId, Date.now());
  await sendFirmMessage(f.session, f.caseId, 'New message', Date.now());
  expect((await openCaseMessage(f.sent[0], f.participants, f.owner.privateKey, { owner: 0, organization: 7 })).sequence).toBe(8);
});
test('concurrent sends reserve distinct sequences before awaiting crypto or transport', async () => {
  const f = await fixture();
  f.session.sequences.set(f.caseId, { owner: 0, organization: 7 });
  await Promise.all([sendFirmMessage(f.session, f.caseId, 'First', Date.now()), sendFirmMessage(f.session, f.caseId, 'Second', Date.now())]);
  const sequences = await Promise.all(f.sent.map(async ciphertext =>
    (await openCaseMessage(ciphertext, f.participants, f.owner.privateKey, { owner: 0, organization: 0 })).sequence));
  expect(sequences.sort()).toEqual([8, 9]);
  expect(f.session.sequences.get(f.caseId)?.organization).toBe(9);
});
