import { MongoClient, Db, MongoClientOptions } from 'mongodb';
import { existsSync } from 'fs';

let client: MongoClient | null = null;
let db: Db | null = null;

export async function getDb(): Promise<Db | null> {
  // If we have a cached client, verify it's still alive
  if (db && client) {
    try {
      await client.db('admin').command({ ping: 1 });
      return db;
    } catch {
      console.warn('[MongoDB] Stale connection detected, reconnecting...');
      client = null;
      db = null;
    }
  }

  const uri = process.env.MONGODB_URI?.trim();
  if (!uri) {
    console.warn('[MongoDB] MONGODB_URI not set');
    return null;
  }

  try {
    const dbName = process.env.MONGODB_DB_NAME || 'vera';
    const tlsCAFile = process.env.MONGODB_TLS_CA_FILE;
    const opts: MongoClientOptions = {
      readPreference: 'primary',
      maxPoolSize: 10,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 30000,
      heartbeatFrequencyMS: 10000,
      retryWrites: false, // DocumentDB doesn't support retryWrites
      retryReads: true,
    };
    if (tlsCAFile && existsSync(tlsCAFile)) {
      opts.tlsCAFile = tlsCAFile;
    }
    client = new MongoClient(uri, opts);
    await client.connect();
    db = client.db(dbName);
    console.log('[MongoDB] Connected successfully');
    return db;
  } catch (err) {
    console.error('[MongoDB] Connection failed:', err);
    client = null;
    db = null;
    return null;
  }
}
