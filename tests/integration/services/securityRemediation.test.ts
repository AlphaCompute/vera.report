import crypto from 'node:crypto';
import { MongoClient } from 'mongodb';
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
import { disseminationPersistence as store } from '../../../src/services/dissemination/disseminationPersistence';
import { reportPersistenceService as reports } from '../../../src/services/reportPersistence';
import { createReporterAccess, receiptCode } from '../../../src/services/reporterAccess';
import { openPrivateValue, sealPrivateValue } from '../../../src/services/privateRecord';
import { issueRecipientCapability, recipientCapabilityActive } from '../../../src/services/dissemination/recipientCapability';
import { makeSecureLinkToken, verifySecureLinkToken } from '../../../src/services/dissemination/secureLink';
useDisseminationMongo();

it('encrypts correspondence at the real database boundary and restores after reconnect', async () => {
  const trackingId = 'VRA-1111111111111111';
  await store.insertRelayMessage({ trackingId, messageId: 'private-message', body: 'PRIVATE NAME AND ALLEGATION', direction: 'from-reporter', createdAt: new Date() });
  await store.insertInboundMail({ inboundId: 'private-mail', recipient: 'agency@example.invalid', from: 'source@example.invalid', subject: 'PRIVATE SUBJECT', body: 'PRIVATE MAIL', status: 'pending_review', autoParsed: false, createdAt: new Date(), receivedAt: new Date() });
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  try {
    const db = client.db(process.env.MONGODB_DB_NAME);
    const relay = await db.collection('relay_threads').findOne({ messageId: 'private-message' });
    const mail = await db.collection('dissemination_inbound').findOne({ inboundId: 'private-mail' });
    expect(JSON.stringify([relay, mail])).not.toMatch(/PRIVATE NAME|PRIVATE MAIL|PRIVATE SUBJECT|source@example/);
    await store.disconnect();
    expect((await store.getRelayThread(trackingId))[0].body).toBe('PRIVATE NAME AND ALLEGATION');
    expect((await store.getInboundMail('private-mail'))?.subject).toBe('PRIVATE SUBJECT');
    await store.patchInboundMail('private-mail', { body: 'PRIVATE CHANGED BODY' });
    expect((await store.getInboundMail('private-mail'))?.body).toBe('PRIVATE CHANGED BODY');
  } finally { await client.close(); }
});
it('rejects transplanted or corrupted private field ciphertext; legacy remains readable', async () => {
  const sealed = await sealPrivateValue('PRIVATE', 'record-a', 'body');
  await expect(openPrivateValue(sealed, 'record-b', 'body')).rejects.toThrow();
  await expect(openPrivateValue(sealed, 'record-a', 'subject')).rejects.toThrow();
  await expect(openPrivateValue(sealed.slice(0,-8), 'record-a', 'body')).rejects.toThrow();
  expect(await openPrivateValue('legacy text', 'record-a', 'body')).toBe('legacy text');
  const downgraded = JSON.parse(sealed.slice('private:v1:'.length));
  downgraded.key = '11'.repeat(32);
  await expect(openPrivateValue('private:v1:' + JSON.stringify(downgraded), 'record-a', 'body')).rejects.toThrow('Invalid private-record key envelope');
});
it('separates the reporter credential, protects it at rest, and rotates with compare-and-set', async () => {
  const trackingId = 'VRA-2222222222222222';
  const access = await createReporterAccess(trackingId);
  const report = { trackingId, reporterAccess: access, status: 'pending' as const, createdAt: new Date(), updatedAt: new Date() };
  await reports.upsert(report);
  const code = await receiptCode(report);
  expect(code).toMatch(/^VRC-[A-F0-9]{64}$/);
  expect(JSON.stringify(await reports.get(trackingId))).not.toContain(code);
  expect(await reports.getForReporter(trackingId)).toBeNull();
  expect((await reports.getForReporter(code))?.trackingId).toBe(trackingId);
  const next = await createReporterAccess(trackingId);
  expect(await reports.rotateReporterAccess(trackingId, access.hash, next)).toBe(true);
  expect(await reports.rotateReporterAccess(trackingId, access.hash, access)).toBe(false);
  expect(await reports.getForReporter(code)).toBeNull();
  expect(await reports.getForReporter(await receiptCode({ trackingId, reporterAccess: next }))).not.toBeNull();
});
it('requires durable issuance, rejects revoked grants across restart and does not reactivate on reissue', async () => {
  const token = makeSecureLinkToken('VRA-3333333333333333');
  expect(verifySecureLinkToken(token)).not.toBeNull();
  expect(await recipientCapabilityActive(token)).toBe(false);
  await issueRecipientCapability(token, 'securelink');
  await store.disconnect();
  expect(await recipientCapabilityActive(token)).toBe(true);
  await store.revokeRecipientGrant(crypto.createHash('sha256').update(token).digest('hex'));
  await issueRecipientCapability(token, 'securelink');
  expect(await recipientCapabilityActive(token)).toBe(false);
});
it('webhook-secret compromise cannot mint recipient tokens; old v2 tokens are rejected', () => {
  const original = process.env.RECIPIENT_CAPABILITY_SECRET;
  const token = makeSecureLinkToken('VRA-4444444444444444');
  try {
    process.env.RECIPIENT_CAPABILITY_SECRET = process.env.DISSEMINATION_WEBHOOK_SECRET;
    expect(() => makeSecureLinkToken('VRA-4444444444444444')).toThrow();
    expect(verifySecureLinkToken(token)).toBeNull();
  } finally { process.env.RECIPIENT_CAPABILITY_SECRET = original; }
  expect(verifySecureLinkToken(token.replace(/^v3/, 'v2'))).toBeNull();
});

it('migrates historical plaintext idempotently and dry-run does not write', async () => {
  const { migratePrivateRecords } = await import('../../../scripts/migrate-private-records');
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  try {
    const db = client.db(process.env.MONGODB_DB_NAME);
    await db.collection('relay_threads').insertOne({ trackingId: 'VRA-5555555555555555', messageId: 'legacy-migration', body: 'LEGACY PRIVATE', direction: 'from-reporter', createdAt: new Date() });
    expect((await migratePrivateRecords(client, process.env.MONGODB_DB_NAME!)).eligible).toBeGreaterThan(0);
    expect((await db.collection('relay_threads').findOne({ messageId: 'legacy-migration' }))?.body).toBe('LEGACY PRIVATE');
    const result = await migratePrivateRecords(client, process.env.MONGODB_DB_NAME!, true);
    expect(result.migrated).toBeGreaterThan(0);
    expect((await db.collection('relay_threads').findOne({ messageId: 'legacy-migration' }))?.body).not.toContain('LEGACY PRIVATE');
    expect((await store.getRelayThread('VRA-5555555555555555'))[0].body).toBe('LEGACY PRIVATE');
    expect((await migratePrivateRecords(client, process.env.MONGODB_DB_NAME!, true)).migrated).toBe(0);
  } finally { await client.close(); }
});
