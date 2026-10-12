// What the local stack's host kept, for the teardown leak sweep (stack.ts):
// the output of this process (where the confidential API and the enclave run)
// and every stored record. Kept free of the stack's other imports so the unit
// suite can exercise it against an in-memory MongoDB.
import { MongoClient } from 'mongodb';
import { storedRecordText } from '../support/leaks';
import type { HostRecord } from '../support/leaks';

/**
 * Tee this process's stdout and stderr: the confidential API and the enclave
 * run here, so whatever they (or a library they call) print is captured for
 * the teardown sweep. Returns the captured text and a restore function.
 */
export function captureProcessOutput(): { text: () => string; restore: () => void } {
  const chunks: string[] = [];
  const streams = [process.stdout, process.stderr];
  const originals = streams.map(stream => stream.write);
  streams.forEach((stream, index) => {
    const original = originals[index];
    stream.write = function write(this: NodeJS.WriteStream, chunk: unknown, ...rest: unknown[]) {
      chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk as Uint8Array).toString('latin1'));
      return (original as (...args: unknown[]) => boolean).call(this, chunk, ...rest);
    } as typeof stream.write;
  });
  return { text: () => chunks.join(''), restore: () => streams.forEach((stream, index) => { stream.write = originals[index]; }) };
}

type OplogEntry = { ns?: unknown; op?: unknown; o?: { applyOps?: OplogEntry[] } };

/**
 * An oplog entry as records attributed to the namespace each write touched:
 * a transaction's applyOps is split into its operations, so a value the
 * architecture allows in one collection is still caught in any other.
 */
function oplogRecords(entry: OplogEntry, source: string): HostRecord[] {
  const nested = entry.op === 'c' && Array.isArray(entry.o?.applyOps) ? entry.o!.applyOps! : undefined;
  if (nested) return nested.flatMap(operation => oplogRecords(operation, source));
  const namespace = typeof entry.ns === 'string' ? entry.ns : undefined;
  return [{ source: namespace ? `${source} (${namespace})` : source, text: storedRecordText(entry), namespace }];
}

/**
 * Every document of every collection of every database, collection options and
 * indexes included, and the oplog, so a record written and later deleted still
 * counts. Each document is attributed to its "database.collection".
 */
export async function* storedRecords(mongoUri: string): AsyncGenerator<HostRecord> {
  const client = await MongoClient.connect(mongoUri, { directConnection: true });
  try {
    const { databases } = await client.db('admin').admin().listDatabases({ nameOnly: true });
    for (const { name } of databases) {
      const db = client.db(name);
      for (const info of await db.listCollections({}, { nameOnly: false }).toArray()) {
        if (info.type === 'view') continue;
        const source = `mongo ${name}.${info.name}`;
        yield { source: `${source} (options)`, text: storedRecordText(info) };
        for (const index of await db.collection(info.name).indexes().catch(() => [])) yield { source: `${source} (index)`, text: storedRecordText(index) };
        const oplog = name === 'local' && info.name === 'oplog.rs';
        for await (const document of db.collection(info.name).find({})) {
          if (oplog) yield* oplogRecords(document as OplogEntry, source);
          else yield { source, text: storedRecordText(document), namespace: `${name}.${info.name}` };
        }
      }
    }
  } finally { await client.close(); }
}
