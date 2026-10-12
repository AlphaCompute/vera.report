import { BSON, MongoClient } from 'mongodb';
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
import { migratePrivateRecords } from '../../../scripts/migrate-private-records';
import { keyEnvelope } from '../../../src/services/keyEnvelope';
import { openPrivateValue } from '../../../src/services/privateRecord';
useDisseminationMongo();
test('migrated records survive BSON backup, independent restore and reconnect with their original keys', async () => {
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  const source = client.db('synthetic_migration_source');
  const fixtures = [
    { collection:'relay_threads', doc:{ trackingId:'VRA-SYNTHETIC', messageId:'m', body:'PRIVATE RELAY' }, binding:'relay:VRA-SYNTHETIC:m', field:'body', value:'PRIVATE RELAY' },
    { collection:'dissemination_inbound', doc:{ inboundId:'i', body:'PRIVATE MAIL', subject:'PRIVATE SUBJECT', from:'private@example.test', s3Key:'private/mail' }, binding:'inbound:i', field:'body', value:'PRIVATE MAIL' },
    { collection:'dispositions', doc:{ trackingId:'VRA-SYNTHETIC', narrativeOverride:{ narrative:'PRIVATE REVIEW' } }, binding:'disposition:VRA-SYNTHETIC', field:'narrativeOverride', value:{ narrative:'PRIVATE REVIEW' } },
    { collection:'whistleblower_reports', doc:{ trackingId:'VRA-SYNTHETIC', verification:{ contentAnalysis:'PRIVATE ANALYSIS' } }, binding:'report:VRA-SYNTHETIC', field:'verification', value:{ contentAnalysis:'PRIVATE ANALYSIS' } },
  ];
  try {
    for (const fixture of fixtures) await source.collection(fixture.collection).insertOne(fixture.doc);
    expect((await migratePrivateRecords(client, source.databaseName)).eligible).toBe(7);
    expect((await migratePrivateRecords(client, source.databaseName, true)).migrated).toBe(7);
    const backup: Array<{collection:string, bytes:Buffer}> = [];
    for (const fixture of fixtures) {
      const raw = await source.collection(fixture.collection).findOne({});
      const bytes = BSON.serialize(raw!);
      expect(bytes.toString()).not.toMatch(/PRIVATE|private@example|private\/mail/);
      backup.push({collection:fixture.collection, bytes:Buffer.from(bytes)});
    }
    // Restore into a separate database, preserving BSON identifiers and ciphertext.
    const restored = client.db('synthetic_migration_restore');
    for (const entry of backup) await restored.collection(entry.collection).insertOne(BSON.deserialize(entry.bytes));
    await client.close();
    const reader = await new MongoClient(process.env.MONGODB_URI!).connect();
    try {
      for (const fixture of fixtures) {
        const raw = await reader.db(restored.databaseName).collection(fixture.collection).findOne({});
        const fields = fixture.collection === 'dissemination_inbound' ? ['body', 'subject', 'from', 's3Key'] : [fixture.field];
        for (const field of fields) {
          expect(await openPrivateValue(raw![field], fixture.binding, field)).toEqual((fixture.doc as any)[field]);
          const originalKey = process.env.AT_REST_LOCAL_KEY;
          try {
            process.env.AT_REST_LOCAL_KEY = 'd'.repeat(64);
            await expect(openPrivateValue(raw![field], fixture.binding, field)).rejects.toThrow();
          } finally {
            if (originalKey === undefined) delete process.env.AT_REST_LOCAL_KEY;
            else process.env.AT_REST_LOCAL_KEY = originalKey;
          }
          expect(await openPrivateValue(raw![field], fixture.binding, field)).toEqual((fixture.doc as any)[field]);
        }
      }
      expect((await migratePrivateRecords(reader, restored.databaseName, true)).migrated).toBe(0);
    } finally { await reader.close(); }
  } finally { await client.close(); }
});


test('migration preserves a concurrent writer and reports a conflict for operator retry', async () => {
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  try {
    const database = 'synthetic_migration_race';
    const db = client.db(database);
    const collection = db.collection('relay_threads');
    await collection.insertOne({ trackingId:'VRA-RACE', messageId:'m', body:'ORIGINAL' });
    let raced = false;
    const proxy = { db: () => ({ collection: (name: string) => {
      const actual = db.collection(name);
      if (name !== 'relay_threads') return actual;
      return { find: (...args: any[]) => (actual.find as any)(...args), updateOne: async (filter: any, update: any) => {
        if (!raced) { raced = true; await actual.updateOne({ _id: filter._id }, { $set: { body:'CONCURRENT UPDATE' } }); }
        return actual.updateOne(filter, update);
      } };
    } }) } as unknown as MongoClient;
    const outcome = await migratePrivateRecords(proxy, database, true);
    expect(outcome.conflicts).toBe(1); expect(outcome.migrated).toBe(0);
    expect((await collection.findOne({}))?.body).toBe('CONCURRENT UPDATE');
    expect((await migratePrivateRecords(client, database, true)).migrated).toBe(1);
    expect(await openPrivateValue((await collection.findOne({}))?.body, 'relay:VRA-RACE:m', 'body')).toBe('CONCURRENT UPDATE');
  } finally { await client.close(); }
});

// Change only the authenticated identity between the migration read and write.
// The value predicate alone would succeed and leave undecryptable ciphertext.
test.each([
  ['relay_threads', { trackingId: 'old', messageId: 'm', body: 'PRIVATE' }, 'trackingId', 'body', 'relay:new:m'],
  ['relay_threads', { trackingId: 'old', messageId: 'm', body: 'PRIVATE' }, 'messageId', 'body', 'relay:old:new'],
  ['dissemination_inbound', { inboundId: 'old', body: 'PRIVATE' }, 'inboundId', 'body', 'inbound:new'],
  ['dispositions', { trackingId: 'old', narrativeOverride: { narrative: 'PRIVATE' } }, 'trackingId', 'narrativeOverride', 'disposition:new'],
  ['whistleblower_reports', { trackingId: 'old', verification: { contentAnalysis: 'PRIVATE' } }, 'trackingId', 'verification', 'report:new'],
] as const)('migration fences changes to %s binding %s', async (name, fixture, identity, field, binding) => {
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  const database = `binding_${name}_${identity}`;
  const db = client.db(database);
  try {
    const collection = db.collection(name);
    await collection.insertOne({ ...fixture });
    let raced = false;
    const proxy = { db: () => ({ collection: (collectionName: string) => {
      const actual = db.collection(collectionName);
      if (collectionName !== name) return actual;
      return { find: (...args: any[]) => (actual.find as any)(...args), updateOne: async (filter: any, update: any) => {
        if (!raced) { raced = true; await actual.updateOne({ _id: filter._id }, { $set: { [identity]: 'new' } }); }
        return actual.updateOne(filter, update);
      } };
    } }) } as unknown as MongoClient;
    expect(await migratePrivateRecords(proxy, database, true)).toMatchObject({ conflicts: 1, migrated: 0 });
    expect((await collection.findOne({}))![field]).toEqual((fixture as any)[field]);
    expect((await migratePrivateRecords(client, database, true)).migrated).toBe(1);
    const encrypted = (await collection.findOne({}))![field];
    expect(await openPrivateValue(encrypted, binding, field)).toEqual((fixture as any)[field]);
    await expect(openPrivateValue(encrypted, 'wrong-owner', field)).rejects.toThrow();
    expect(await migratePrivateRecords(client, database, true)).toMatchObject({ eligible: 0, conflicts: 0 });
  } finally { await client.close(); }
});

test.each([undefined, null, '', { $ne: 'x' }])('migration refuses missing or non-string binding %p', async (trackingId) => {
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  const db = client.db('invalid_binding');
  try {
    await db.dropDatabase();
    await db.collection('relay_threads').insertOne({ trackingId, messageId: 'm', body: 'PRIVATE' });
    await expect(migratePrivateRecords(client, db.databaseName, true)).rejects.toThrow('Invalid migration binding');
    expect((await db.collection('relay_threads').findOne({}))!.body).toBe('PRIVATE');
  } finally { await client.close(); }
});

// KMS is synthetic here; MongoDB executes the real compare-and-set predicates.
test.each([
  ['evidence_decryption_params', 'fileKey', 'encryptionKey'],
  ['whistleblower_reports', 'trackingId', 'encryptedNarrative.encryptionKey'],
])('KMS rewrap fences %s identity changes', async (name, identity, field) => {
  const client = await new MongoClient(process.env.MONGODB_URI!).connect();
  const db = client.db(`kms_binding_${name}`);
  const old = 'enc:kms:v1:synthetic';
  const unwrap = jest.spyOn(keyEnvelope, 'unwrap').mockResolvedValue('synthetic-data-key');
  const wrap = jest.spyOn(keyEnvelope, 'wrap').mockResolvedValue('enc:kms:v2:synthetic');
  try {
    const collection = db.collection(name);
    await collection.insertOne({ [identity]: 'old', ...(field.includes('.') ? { encryptedNarrative: { encryptionKey: old } } : { [field]: old }) });
    let raced = false;
    const proxy = { db: () => ({ collection: (collectionName: string) => {
      const actual = db.collection(collectionName);
      if (collectionName !== name) return actual;
      return { find: (...args: any[]) => (actual.find as any)(...args), updateOne: async (filter: any, update: any) => {
        if (!raced) { raced = true; await actual.updateOne({ _id: filter._id }, { $set: { [identity]: 'new' } }); }
        return actual.updateOne(filter, update);
      } };
    } }) } as unknown as MongoClient;
    expect(await migratePrivateRecords(proxy, db.databaseName, true)).toMatchObject({ migrated: 0, conflicts: 1 });
    const raw = await collection.findOne({});
    expect(field.split('.').reduce((value: any, part) => value[part], raw)).toBe(old);
    expect(await migratePrivateRecords(client, db.databaseName, true)).toMatchObject({ migrated: 1, conflicts: 0 });
  } finally { unwrap.mockRestore(); wrap.mockRestore(); await client.close(); }
});
