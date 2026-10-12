jest.mock('../../../../src/services/dissemination/packetEvidence', () => ({ exportPacketArchive: jest.fn().mockResolvedValue(Buffer.from('ZIP-with-private-evidence')) }));
/**
 * Dryrun skips the narrative review gate, so the email adapter must never send
 * report content to the dryrun inbox in cleartext (audit B-047). Without a
 * pinned key for the inbox it sends a content-free notice; with one it sends
 * the full packet encrypted. Live mode is unchanged. Encryption and policy
 * failures happen before SES and must be classified as not sent (audit B-041).
 */

import { SESv2Client } from '@aws-sdk/client-sesv2';
import { generateKey, readKey, readMessage, readPrivateKey, decrypt } from 'openpgp';
import { EmailAdapter } from '../../../../src/services/dissemination/adapters/emailAdapter';
import { encryptForRecipient } from '../../../../src/services/dissemination/recipientEncryption';
import { DispatchNotSentError, type DisseminationView, type Packet } from '../../../../src/services/dissemination/types';

const NARRATIVE = 'The CFO falsified invoices in the Springfield office.';
const INBOX = 'internal@vera.test';
const INTAKE = 'intake@agency.test';
const ZIP_B64 = Buffer.from('ZIP-with-private-evidence').toString('base64');

function makeView(): DisseminationView {
  return {
    trackingId: 'CASE-0123456789ABCDEF',
    categories: ['cyber-security'],
    rawCategories: ['cyber-security'],
    narrative: NARRATIVE,
    urgency: 'high',
    location: 'Springfield',
    evidence: { evidenceHash: 'e'.repeat(64), files: [{ name: 'cfo-ledger-scan.pdf', cid: 'QmFileCid' }] },
  };
}

function makePacket(): Packet {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    entityId: 'synthetic',
    packetVersion: 1,
    pdf: Buffer.from('%PDF-1.7 synthetic'),
    sidecar: {
      schema: 'vera-packet/1.0',
      trackingId: 'CASE-0123456789ABCDEF',
      entityId: 'synthetic',
      packetVersion: 1,
      generatedAt: new Date().toISOString(),
      categories: [{ slug: 'cyber-security', label: 'Cyber security' }],
      narrative: NARRATIVE,
      evidenceManifest: { files: [], escrowStatement: 'escrowed' },
      transmittalStatement: 'transmitted with consent',
    },
    packetHash: 'f'.repeat(64),
    generatedAt: new Date(),
  };
}

const adapter = () => new EmailAdapter({
  entityId: 'synthetic', entityName: 'Synthetic Agency', intakeAddress: INTAKE, salutation: 'Hello', bodyIntro: 'Intro',
});

/** The raw MIME SES received, with quoted-printable soft breaks and escapes decoded. */
function rawOf(send: jest.SpyInstance): string {
  const raw = Buffer.from((send.mock.calls[0][0] as { input: { Content: { Raw: { Data: Uint8Array } } } }).input.Content.Raw.Data).toString('utf8');
  return raw.replace(/=\r\n/g, '').replace(/=([0-9A-F]{2})/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

describe('dryrun never sends report content in cleartext', () => {
  const env = { ...process.env };
  let publicKey: string, privateKey: string, fingerprint: string;
  let send: jest.SpyInstance;

  beforeAll(async () => {
    const pair = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ email: INBOX }], format: 'armored' });
    publicKey = pair.publicKey; privateKey = pair.privateKey;
    fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  });
  beforeEach(() => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    process.env.DISSEMINATION_DRYRUN_INBOX = INBOX;
    process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';
    delete process.env.DISSEMINATION_EMAIL_POLICIES;
    send = jest.spyOn(SESv2Client.prototype, 'send').mockImplementation(async () => ({ MessageId: 'synthetic' }) as never);
  });
  afterEach(() => { send.mockRestore(); process.env = { ...env }; });

  it('sends a content-free notice when the dryrun inbox has no policy', async () => {
    const a = adapter();
    const prep = await a.prepare(makeView(), makePacket());
    expect(prep.email).toMatchObject({ to: INBOX, attachments: [], contentFree: true });
    expect(prep.email!.subject).toContain('[DRYRUN]');
    expect(prep.email!.subject).toContain('no report content');

    const result = await a.dispatch({ ...prep, auditTrackingId: 'VRA-ABCDEF0123456789' });
    expect(result.outcome).toBe('sent');
    const raw = rawOf(send);
    // What would be sent, by size only.
    expect(raw).toContain('Synthetic Agency (synthetic)');
    expect(raw).toContain('CASE-0123456789ABCDEF');
    expect(raw).toContain(INTAKE);
    expect(raw).toContain('vera-report-CASE-0123456789ABCDEF.zip');
    expect(raw).toContain(`${Buffer.from('ZIP-with-private-evidence').length} bytes`);
    // No narrative, evidence, file names, location, or attachment parts.
    expect(raw).not.toContain('CFO');
    expect(raw).not.toContain('Springfield');
    expect(raw).not.toContain('cfo-ledger-scan');
    expect(raw).not.toContain('QmFileCid');
    expect(raw).not.toContain(ZIP_B64);
    expect(raw).not.toContain('Content-Disposition: attachment');
  });

  it('treats a plaintext exception for the dryrun inbox like no policy', async () => {
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [INBOX]: { allowUnencrypted: true, reason: 'Internal inbox' } });
    const prep = await adapter().prepare(makeView(), makePacket());
    expect(prep.email).toMatchObject({ attachments: [], contentFree: true });
    expect(prep.email!.coverLetter).not.toContain('CFO');
  });

  it('encrypts the full packet when the dryrun inbox has a pinned key', async () => {
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [INBOX]: { publicKey, fingerprint } });
    const a = adapter();
    const prep = await a.prepare(makeView(), makePacket());
    expect(prep.email!.contentFree).toBeUndefined();
    expect(prep.email!.attachments.map(x => x.filename)).toContain('vera-report-CASE-0123456789ABCDEF.zip');

    await a.dispatch({ ...prep, auditTrackingId: 'VRA-ABCDEF0123456789' });
    const raw = rawOf(send);
    expect(raw).toContain('multipart/encrypted');
    expect(raw).not.toContain('Springfield');
    expect(raw).not.toContain('cfo-ledger-scan');
    expect(raw).not.toContain(ZIP_B64);
    const armoredMessage = raw.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/)![0];
    const plain = await decrypt({ message: await readMessage({ armoredMessage }), decryptionKeys: await readPrivateKey({ armoredKey: privateKey }), format: 'utf8' });
    expect(plain.data).toContain(ZIP_B64);
  });

  it('refuses a content email to an inbox without a pinned key before calling SES', async () => {
    const a = adapter();
    const prep = { entityId: 'synthetic', trackingId: 'CASE-x', mode: 'email' as const,
      email: { to: INBOX, subject: 'x', coverLetter: NARRATIVE, attachments: [] } };
    await expect(a.dispatch(prep)).rejects.toBeInstanceOf(DispatchNotSentError);
    expect(send).not.toHaveBeenCalled();
  });

  it('fails as not sent, without SES, when the inbox key is broken', async () => {
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [INBOX]: { publicKey, fingerprint: '0'.repeat(40) } });
    const a = adapter();
    const prep = await a.prepare(makeView(), makePacket());
    expect(prep.email!.contentFree).toBeUndefined();
    await expect(a.dispatch(prep)).rejects.toBeInstanceOf(DispatchNotSentError);
    expect(send).not.toHaveBeenCalled();
  });
});

describe('live mode is unchanged', () => {
  const env = { ...process.env };
  let publicKey: string, privateKey: string, fingerprint: string;
  let send: jest.SpyInstance;

  beforeAll(async () => {
    const pair = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ email: INTAKE }], format: 'armored' });
    publicKey = pair.publicKey; privateKey = pair.privateKey;
    fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  });
  beforeEach(() => {
    process.env.DISSEMINATION_MODE = 'live';
    process.env.DISSEMINATION_DRYRUN_INBOX = INBOX;
    process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';
    send = jest.spyOn(SESv2Client.prototype, 'send').mockImplementation(async () => ({ MessageId: 'synthetic' }) as never);
  });
  afterEach(() => { send.mockRestore(); process.env = { ...env }; });

  it('sends the full packet to the intake address, encrypted to its pinned key', async () => {
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [INTAKE]: { publicKey, fingerprint } });
    const a = adapter();
    const prep = await a.prepare(makeView(), makePacket());
    expect(prep.email!.to).toBe(INTAKE);
    expect(prep.email!.contentFree).toBeUndefined();
    expect(prep.email!.subject).not.toContain('[DRYRUN]');
    expect(prep.email!.coverLetter).toContain('cfo-ledger-scan.pdf');
    expect(prep.email!.attachments.map(x => x.filename)).toEqual([
      'vera-report-CASE-0123456789ABCDEF.zip', 'vera-packet-CASE-0123456789ABCDEF.json',
    ]);

    await a.dispatch({ ...prep, auditTrackingId: 'VRA-ABCDEF0123456789' });
    const raw = rawOf(send);
    expect(raw).toContain('multipart/encrypted');
    const armoredMessage = raw.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/)![0];
    const plain = await decrypt({ message: await readMessage({ armoredMessage }), decryptionKeys: await readPrivateKey({ armoredKey: privateKey }), format: 'utf8' });
    expect(plain.data).toContain(ZIP_B64);
  });

  it('refuses live email without a policy, as not sent and without SES', async () => {
    delete process.env.DISSEMINATION_EMAIL_POLICIES;
    const a = adapter();
    const prep = await a.prepare(makeView(), makePacket());
    expect(prep.email!.to).toBe(INTAKE);
    await expect(a.dispatch(prep)).rejects.toThrow('required');
    await expect(a.dispatch(prep)).rejects.toBeInstanceOf(DispatchNotSentError);
    expect(send).not.toHaveBeenCalled();
  });
});

describe('encryption failures are classified as not sent (B-041)', () => {
  const env = { ...process.env };
  afterEach(() => { process.env = { ...env }; });

  it.each([
    ['malformed policy JSON', '{invalid', true],
    ['missing live policy', JSON.stringify({}), true],
    ['key without fingerprint', JSON.stringify({ [INTAKE]: { publicKey: 'x' } }), false],
    ['unparseable key', JSON.stringify({ [INTAKE]: { publicKey: 'not a key', fingerprint: 'a'.repeat(40) } }), false],
  ])('%s', async (_label, policies, live) => {
    process.env.DISSEMINATION_EMAIL_POLICIES = policies;
    await expect(encryptForRecipient(INTAKE, Buffer.from('secret'), live)).rejects.toBeInstanceOf(DispatchNotSentError);
  });
});
