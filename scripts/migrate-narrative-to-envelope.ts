#!/usr/bin/env ts-node
/**
 * One-time migration: move report narratives from the retired app-key scheme
 * onto the KMS envelope scheme.
 *
 * Two narrative-at-rest schemes exist across branches. Records written by the
 * pre-envelope code (and by the ALPHA-024 Eliza backfill, which ran against
 * staging) store the narrative in `encryptedDescription`: a single
 * `iv:authTag:ciphertext` hex string, AES-256-GCM under a key derived from the
 * app-held REWARD_ENCRYPTION_KEY. The envelope code stores it in
 * `encryptedNarrative`: AES-256-GCM under a random per-record data key, with
 * that key wrapped by keyEnvelope (KMS in production).
 *
 * Readers support both formats during rollout. This migration must be verified
 * before REWARD_ENCRYPTION_KEY is de-provisioned, since unmigrated narratives
 * still depend on that key.
 *
 * SAFETY
 *  - DRY-RUN by default. Nothing is written unless you pass `--apply`.
 *  - Idempotent: only touches records that have `encryptedDescription` and no
 *    `encryptedNarrative`. Safe to re-run.
 *  - Every record is round-tripped before it is written: the freshly encrypted
 *    narrative is decrypted back (unwrapping through KMS) and compared to the
 *    legacy plaintext. A mismatch fails that record instead of persisting it.
 *  - `encryptedDescription` is intentionally LEFT IN PLACE. It is the only
 *    other copy once ElizaOS is gone, so it stays until the migration is
 *    verified in the environment; dropping it is a separate follow-up.
 *  - Journaled majority writes compare the legacy ciphertext and absence of an
 *    envelope again at update time, so concurrent changes are not overwritten.
 *
 * SEQUENCING: this must run BEFORE REWARD_ENCRYPTION_KEY is dropped from the
 * task definitions. It needs the legacy key to read and KMS to re-wrap, so run
 * it while both are available:
 *   ts-node scripts/migrate-narrative-to-envelope.ts          # dry run
 *   ts-node scripts/migrate-narrative-to-envelope.ts --apply  # writes changes
 *
 * ENV: MONGODB_URI, MONGODB_DB_NAME, REWARD_ENCRYPTION_KEY, KMS_AT_REST_KEY_ID.
 */
import { MongoClient } from 'mongodb';
import { encryptReportNarrative } from '../src/services/reportNarrative';
import 'dotenv/config';
import { keyEnvelope } from '../src/services/keyEnvelope';
import { evidenceEncryptionService } from '../src/services/evidenceEncryption';
// The retired narrative scheme derived its key exactly as legacy reward
// contacts did (scrypt over REWARD_ENCRYPTION_KEY with the same salt, same
// iv:authTag:ciphertext wire format), so this decrypt is byte-compatible.
// Reusing it also inherits its fail-loud-in-production guard, which is what we
// want: deriving the dev fallback here would silently mis-decrypt real records.
import { decryptLegacyRewardContact } from '../src/services/rewardContact';

/** Rebuild the envelope-scheme narrative for one record, via the shared submit-path helper. */
async function toEnvelopeNarrative(plaintext: string, trackingId: string) {
  return encryptReportNarrative(trackingId, plaintext);
}

/** Decrypt what we just built, the same way getReportContext will. */
async function readBackNarrative(
  narrative: { encryptedData: string; encryptionKey: string; salt: string; iv: string; authTag: string },
  trackingId: string,
): Promise<string> {
  const dataKey = await keyEnvelope.unwrap(narrative.encryptionKey, { trackingId, purpose: 'narrative' });
  const result = await evidenceEncryptionService.decryptEvidence(
    {
      encryptedData: narrative.encryptedData,
      encryptionMetadata: {
        algorithm: 'aes-256-gcm',
        salt: narrative.salt,
        iv: narrative.iv,
        authTag: narrative.authTag,
        keyVersion: 'v1.0',
      },
      contentMetadata: { originalType: 'text/plain' },
      privacyMetadata: {
        metadataStripped: false,
        exifRemoved: false,
        deviceInfoCleaned: false,
        ipObfuscated: false,
      },
    },
    dataKey,
  );
  return result.content.toString('utf8');
}

async function main() {
  const apply = process.argv.includes('--apply');
  const uri = process.env.MONGODB_URI;
  const dbName = process.env.MONGODB_DB_NAME || 'vera';

  if (!uri) {
    console.error('❌ MONGODB_URI not set');
    process.exit(1);
  }
  if (!process.env.REWARD_ENCRYPTION_KEY) {
    console.error(
      '❌ REWARD_ENCRYPTION_KEY not set. Refusing to run. It is required to decrypt the legacy ' +
      'narratives; without it every record fails and an operator could read that as "nothing to do".',
    );
    process.exit(1);
  }
  if (apply && !process.env.KMS_AT_REST_KEY_ID) {
    console.warn(
      '⚠️  KMS_AT_REST_KEY_ID not set. Keys will be wrapped by the local dev fallback, not KMS. ' +
      'This is only correct outside production.',
    );
  }

  console.log(`[NARRATIVE-MIGRATE] mode=${apply ? 'APPLY (writing)' : 'DRY-RUN (no writes)'} db=${dbName}`);

  if (!process.env.KMS_AT_REST_KEY_ID && !process.env.AT_REST_LOCAL_KEY) {
    throw new Error('Configure KMS_AT_REST_KEY_ID or an explicit AT_REST_LOCAL_KEY; migration must not use a development constant');
  }
  const client = new MongoClient(uri, {
    ...(process.env.MONGODB_TLS_CA_FILE ? { tlsCAFile: process.env.MONGODB_TLS_CA_FILE } : {}),
    writeConcern: { w: 'majority', j: true },
    serverSelectionTimeoutMS: 10000,
  });
  await client.connect();
  const col = client.db(dbName).collection('whistleblower_reports');

  const cursor = col.find({
    encryptedDescription: { $exists: true, $ne: null },
    encryptedNarrative: { $exists: false },
  });

  let scanned = 0;
  let migrated = 0;
  let failed = 0;
  let empty = 0;

  for await (const doc of cursor) {
    scanned++;
    const trackingId: string = doc.trackingId;
    try {
      const plaintext = decryptLegacyRewardContact(doc.encryptedDescription);
      if (!plaintext.trim()) {
        empty++;
        continue;
      }

      const narrative = await toEnvelopeNarrative(plaintext, trackingId);

      const readBack = await readBackNarrative(narrative, trackingId);
      if (readBack !== plaintext) {
        failed++;
        console.error(`⚠️  ${trackingId}: round-trip mismatch (len ${plaintext.length} -> ${readBack.length}), not written`);
        continue;
      }

      if (apply) {
        const res = await col.updateOne({ _id: { $eq: doc._id }, encryptedDescription: { $eq: doc.encryptedDescription }, encryptedNarrative: { $exists: false } }, { $set: { encryptedNarrative: narrative } });
        if (!res.acknowledged || res.modifiedCount !== 1) {
          failed++;
          console.error(`⚠️  ${trackingId}: update matched ${res.matchedCount}, modified ${res.modifiedCount}, not migrated`);
          continue;
        }
      }
      migrated++;
      console.log(`[NARRATIVE-MIGRATE] ${trackingId}: ${apply ? 'migrated' : 'would migrate'}`);
    } catch (err) {
      failed++;
      console.error(`⚠️  ${trackingId}: ${(err as Error).message}`);
    }
  }

  console.log(
    `\n[NARRATIVE-MIGRATE] ${apply ? 'Applied' : 'Dry run'}: scanned ${scanned}, ` +
    `${apply ? 'migrated' : 'would migrate'} ${migrated}, empty(skipped) ${empty}, failed ${failed}`,
  );
  if (!apply && migrated > 0) console.log('[NARRATIVE-MIGRATE] Re-run with --apply to write changes.');
  if (failed > 0) console.log('[NARRATIVE-MIGRATE] Failures above were NOT written; legacy encryptedDescription is untouched.');

  await client.close();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
