import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import { SESv2Client } from '@aws-sdk/client-sesv2';
import { generateKey, readKey, readPrivateKey, readMessage, decrypt, revokeKey } from 'openpgp';
import { encryptForRecipient } from '../../../../src/services/dissemination/recipientEncryption';
import { EmailAdapter } from '../../../../src/services/dissemination/adapters/emailAdapter';

describe('recipient encryption', () => {
  let publicKey: string, privateKey: string, fingerprint: string;
  const env = { ...process.env };
  const to = 'agency@example.test';
  beforeAll(async () => {
    const pair = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic recipient', email: to }], format: 'armored' });
    publicKey = pair.publicKey; privateKey = pair.privateKey;
    fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  });
  beforeEach(() => {
    process.env.DISSEMINATION_MODE = 'live';
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [to]: { publicKey, fingerprint } });
  });
  afterEach(() => { process.env = { ...env }; });
  it('encrypts the full MIME body and only the pinned private key can recover its attachments', async () => {
    const adapter = new EmailAdapter({ entityId: 'test', entityName: 'Test', intakeAddress: to, salutation: 'Hello', bodyIntro: 'Test' });
    const raw = Buffer.from(await adapter.buildMime('sender@example.test', { to, subject: 'VRA-secret', coverLetter: 'Secret narrative', attachments: [{ filename: 'VRA-secret.pdf', contentType: 'application/pdf', content: Buffer.from('private evidence') }] })).toString();
    expect(raw).toContain('multipart/encrypted');
    expect(raw).not.toContain('VRA-secret'); expect(raw).not.toContain('Secret narrative');
    expect(raw).not.toContain(Buffer.from('private evidence').toString('base64'));
    const armoredMessage = raw.match(/-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/)![0];
    const result = await decrypt({ message: await readMessage({ armoredMessage }), decryptionKeys: await readPrivateKey({ armoredKey: privateKey }), format: 'utf8' });
    expect(result.data).toContain('Secret=20narrative');
    expect(result.data).toContain('filename="VRA-secret.pdf"');
    expect(result.data).toContain(Buffer.from('private evidence').toString('base64'));
  });
  it('is readable by GnuPG and an independent MIME parser without corrupting Unicode or attachment bytes', async () => {
    const home = mkdtempSync(path.join(tmpdir(), 'vera-pgp-client-'));
    try {
      const adapter = new EmailAdapter({ entityId: 'test', entityName: 'Test', intakeAddress: to, salutation: 'Hello', bodyIntro: 'Test' });
      const narrative = 'Confidential café 🛡️ '.repeat(12) + 'end ';
      const attachment = Buffer.from([0, 1, 2, 128, 255]);
      const raw = Buffer.from(await adapter.buildMime('sender@example.test', { to, subject: 'VRA-secret', coverLetter: narrative, attachments: [{ filename: 'evidence.pdf', contentType: 'application/pdf', content: attachment }] }));
      const extract = 'import sys,email,email.policy; m=email.message_from_bytes(sys.stdin.buffer.read(),policy=email.policy.default); assert m.get_content_type()=="multipart/encrypted"; assert m.get_param("protocol")=="application/pgp-encrypted"; sys.stdout.buffer.write(list(m.iter_parts())[1].get_payload(decode=True))';
      const encrypted = execFileSync('python3', ['-c', extract], { input: raw });
      execFileSync('gpg', ['--homedir', home, '--batch', '--import'], { input: privateKey, stdio: ['pipe', 'pipe', 'pipe'] });
      const decrypted = execFileSync('gpg', ['--homedir', home, '--batch', '--decrypt'], { input: encrypted, stdio: ['pipe', 'pipe', 'pipe'] });
      const parse = 'import sys,email,email.policy,json,base64; m=email.message_from_bytes(sys.stdin.buffer.read(),policy=email.policy.default); print(json.dumps({"text":m.get_body().get_content(),"attachment":base64.b64encode(list(m.iter_attachments())[0].get_payload(decode=True)).decode()}))';
      const result = JSON.parse(execFileSync('python3', ['-c', parse], { input: decrypted, encoding: 'utf8' }));
      expect(result.text.trimEnd()).toBe(narrative.trimEnd());
      expect(Buffer.from(result.attachment, 'base64')).toEqual(attachment);
    } finally {
      execFileSync('gpgconf', ['--homedir', home, '--kill', 'gpg-agent'], { stdio: 'ignore' });
      rmSync(home, { recursive: true, force: true });
    }
  });
  it('requires an exact recipient policy for live dispatch', async () => {
    await expect(encryptForRecipient('other@example.test', Buffer.from('secret'), true)).rejects.toThrow('required');
    delete process.env.DISSEMINATION_EMAIL_POLICIES;
    await expect(encryptForRecipient(to, Buffer.from('secret'), true)).rejects.toThrow('required');
  });
  it('never falls back when a fingerprint is wrong, even with an exception', async () => {
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [to]: { publicKey, fingerprint: '0'.repeat(40), allowUnencrypted: true, reason: 'test' } });
    await expect(encryptForRecipient(to, Buffer.from('secret'), true)).rejects.toThrow('no plaintext');
  });
  it('never calls SES when live policy is missing', async () => {
    delete process.env.DISSEMINATION_EMAIL_POLICIES;
    process.env.DISSEMINATION_SENDER_EMAIL = 'sender@example.test';
    const send = jest.spyOn(SESv2Client.prototype, 'send');
    const adapter = new EmailAdapter({ entityId: 'blocked-test', entityName: 'Test', intakeAddress: to, salutation: 'Hello', bodyIntro: 'Test' });
    try {
      await expect(adapter.dispatch({ entityId: 'blocked-test', trackingId: 'VRA-test', mode: 'email', email: { to, subject: 'test', coverLetter: 'secret', attachments: [] } })).rejects.toThrow('required');
      expect(send).not.toHaveBeenCalled();
    } finally { send.mockRestore(); }
  });
  it('rejects an expired encryption key', async () => {
    const expired = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ email: to }], date: new Date('2000-01-01'), keyExpirationTime: 1, format: 'armored' });
    const pin = (await readKey({ armoredKey: expired.publicKey })).getFingerprint();
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [to]: { publicKey: expired.publicKey, fingerprint: pin } });
    await expect(encryptForRecipient(to, Buffer.from('secret'), true)).rejects.toThrow('no plaintext');
  });
  it('rejects revoked public keys' , async () => {
    const revoked = await revokeKey({ key: await readPrivateKey({ armoredKey: privateKey }), format: 'armored' });
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [to]: { publicKey: revoked.publicKey, fingerprint } });
    await expect(encryptForRecipient(to, Buffer.from('secret'), true)).rejects.toThrow('no plaintext');
  });
  it('rejects malformed policies and private keys', async () => {
    process.env.DISSEMINATION_EMAIL_POLICIES = '{invalid';
    await expect(encryptForRecipient(to, Buffer.from('secret'), false)).rejects.toThrow('Invalid');
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [to]: { publicKey: privateKey, fingerprint } });
    await expect(encryptForRecipient(to, Buffer.from('secret'), true)).rejects.toThrow('no plaintext');
  });
  it('allows plaintext only in unconfigured dryrun or an explicit reasoned per-address exception', async () => {
    delete process.env.DISSEMINATION_EMAIL_POLICIES;
    expect(await encryptForRecipient(to, Buffer.from('synthetic'), false)).toBeNull();
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ [to]: { allowUnencrypted: true, reason: 'Recipient publishes no encryption key; approved TLS-only route.' } });
    const audit = jest.fn().mockResolvedValue(undefined);
    expect(await encryptForRecipient(to, Buffer.from('secret'), true, audit)).toBeNull();
    expect(audit).toHaveBeenCalledWith({ recipient: to, reason: 'Recipient publishes no encryption key; approved TLS-only route.' });
    await expect(encryptForRecipient(to, Buffer.from('secret'), true)).rejects.toThrow('audit record');
  });
});


test('audits each live plaintext attempt before SES and blocks sending if the audit fails', async () => {
  const saved = { ...process.env };
  process.env.DISSEMINATION_MODE = 'live';
  process.env.DISSEMINATION_SENDER_EMAIL = 'sender@example.test';
  process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({ 'intake@example.test': { allowUnencrypted: true, reason: 'Approved no-key channel' } });
  const audit = jest.spyOn(disseminationPersistence, 'appendAudit').mockResolvedValue(undefined);
  const send = jest.spyOn(SESv2Client.prototype, 'send').mockImplementation(async () => ({ MessageId: 'synthetic' }) as any);
  const adapter = new EmailAdapter({ entityId: 'audit-test', entityName: 'Test', intakeAddress: 'intake@example.test', salutation: 'Hello', bodyIntro: 'Test' });
  const prep = { entityId: 'audit-test', trackingId: 'CASE-test', auditTrackingId: 'VRA-test', mode: 'email' as const, email: { to: 'intake@example.test', subject: 'test', coverLetter: 'private narrative', attachments: [] } };
  try {
    await adapter.dispatch(prep);
    expect(audit).toHaveBeenCalledWith({ trackingId: 'VRA-test', entityId: 'audit-test', actor: 'system', event: 'email_plaintext_exception_attempted', detail: { recipient: 'intake@example.test', reason: 'Approved no-key channel' } });
    expect(audit.mock.invocationCallOrder[0]).toBeLessThan(send.mock.invocationCallOrder[0]);
    expect(JSON.stringify(audit.mock.calls)).not.toContain('private narrative');
    audit.mockRejectedValue(new Error('audit unavailable'));
    await expect(adapter.dispatch(prep)).rejects.toThrow('audit unavailable');
    expect(send).toHaveBeenCalledTimes(1);
  } finally { audit.mockRestore(); send.mockRestore(); process.env = saved; }
});
