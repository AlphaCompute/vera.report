#!/usr/bin/env ts-node
/** Dry-run by default. Compare-and-set encrypts secondary content without logging content or identifiers. */
import { MongoClient } from 'mongodb';
import { sealPrivateValue, openPrivateValue } from '../src/services/privateRecord';
import { keyEnvelope } from '../src/services/keyEnvelope';

// Include every identity used by encryption in the write predicate. A concurrent
// identity change must not commit ciphertext authenticated for the previous owner.
function bindingFilter(doc: any, fields: string[]): Record<string, { $eq: string }> {
  const filter: Record<string, { $eq: string }> = {};
  for (const field of fields) {
    if (typeof doc[field] !== 'string' || !doc[field].length) throw new Error('Invalid migration binding');
    filter[field] = { $eq: doc[field] };
  }
  return filter;
}

export async function migratePrivateRecords(client: MongoClient, database: string, apply = false) {
  const db = client.db(database);
  const counts = { scanned: 0, eligible: 0, migrated: 0, conflicts: 0 };
  const specs = [
    { collection: 'relay_threads', fields: ['body'], bindings: ['trackingId', 'messageId'], record: (d: any) => `relay:${d.trackingId}:${d.messageId}` },
    { collection: 'dissemination_inbound', fields: ['body', 'subject', 'from', 's3Key'], bindings: ['inboundId'], record: (d: any) => `inbound:${d.inboundId}` },
    { collection: 'dispositions', fields: ['narrativeOverride'], bindings: ['trackingId'], record: (d: any) => `disposition:${d.trackingId}` },
    { collection: 'whistleblower_reports', fields: ['verification'], bindings: ['trackingId'], record: (d: any) => `report:${d.trackingId}` },
  ];
  for (const spec of specs) {
    const collection = db.collection(spec.collection);
    for await (const doc of collection.find({})) {
      counts.scanned++;
      for (const field of spec.fields) {
        const value = doc[field];
        if (value === undefined || (typeof value === 'string' && value.startsWith('private:v1:'))) continue;
        counts.eligible++;
        const binding = bindingFilter(doc, spec.bindings);
        if (!apply) continue;
        const encrypted = await sealPrivateValue(value, spec.record(doc), field);
        if (JSON.stringify(await openPrivateValue(encrypted, spec.record(doc), field)) !== JSON.stringify(value)) throw new Error('Migration round-trip failed');
        const result = await collection.updateOne({ _id: { $eq: doc._id }, ...binding, [field]: { $eq: value } }, { $set: { [field]: encrypted } });
        if (!result.acknowledged) throw new Error('Migration write not acknowledged');
        result.modifiedCount ? counts.migrated++ : counts.conflicts++;
      }
    }
  }
  // Existing KMS v1 blobs must be decrypted with their original context, then rewrapped.
  // This one-time read still writes the old context to CloudTrail; restrict legacy logs.
  for (const spec of [
    { collection: 'evidence_decryption_params', field: 'encryptionKey', bindings: ['fileKey'], context: (d: any) => ({ fileKey: d.fileKey, purpose: 'evidence' }) },
    { collection: 'whistleblower_reports', field: 'encryptedNarrative.encryptionKey', bindings: ['trackingId'], context: (d: any) => ({ trackingId: d.trackingId, purpose: 'narrative' }) },
  ]) {
    const collection = db.collection(spec.collection);
    for await (const doc of collection.find({ [spec.field]: { $regex: '^enc:kms:v1:' } })) {
      counts.eligible++;
      const binding = bindingFilter(doc, spec.bindings);
      if (!apply) continue;
      const old = spec.field.split('.').reduce((value: any, field) => value[field], doc);
      const context = spec.context(doc);
      const plain = await keyEnvelope.unwrap(old, context);
      const updated = await keyEnvelope.wrap(plain, context);
      if (!updated.startsWith('enc:kms:v2:') || await keyEnvelope.unwrap(updated, context) !== plain) throw new Error('Key migration verification failed');
      const result = await collection.updateOne({ _id: { $eq: doc._id }, ...binding, [spec.field]: { $eq: old } }, { $set: { [spec.field]: updated } });
      if (!result.acknowledged) throw new Error('Key migration not acknowledged');
      result.modifiedCount ? counts.migrated++ : counts.conflicts++;
    }
  }
  return counts;
}
if (require.main === module) {
  void (async () => {
    if (!process.env.MONGODB_URI || !process.env.MONGODB_DB_NAME) throw new Error('Database configuration required');
    if (process.argv.includes('--apply') && !process.env.KMS_AT_REST_KEY_ID) throw new Error('KMS configuration required to apply migration');
    const client = new MongoClient(process.env.MONGODB_URI, { writeConcern: { w: 'majority', j: true }, ...(process.env.MONGODB_TLS_CA_FILE ? { tlsCAFile: process.env.MONGODB_TLS_CA_FILE } : {}) });
    try {
      await client.connect();
      const result = await migratePrivateRecords(client, process.env.MONGODB_DB_NAME, process.argv.includes('--apply'));
      console.log(JSON.stringify(result));
      if (process.argv.includes('--apply') && result.conflicts) process.exitCode = 2;
    }
    finally { await client.close(); }
  })().catch(() => { console.error('Private-record migration failed; no sensitive diagnostics emitted'); process.exitCode = 1; });
}
