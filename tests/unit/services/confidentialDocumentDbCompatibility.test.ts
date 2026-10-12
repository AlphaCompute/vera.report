import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { Db } from 'mongodb';
import { MongoClient } from 'mongodb';
import { MongoConfidentialCaseStore, confidentialMongoClientOptions } from '../../../src/services/confidentialCaseStore';

/** Production runs the confidential store on Amazon DocumentDB 5.0 (instance
 * based). This guard pins the MongoDB features the store may use to ones AWS
 * lists as supported for 5.0:
 * https://docs.aws.amazon.com/documentdb/latest/developerguide/mongo-apis.html
 * https://docs.aws.amazon.com/documentdb/latest/developerguide/partial-index.html
 * https://docs.aws.amazon.com/documentdb/latest/developerguide/transactions.html
 * Adding an operator means checking it there first, then adding it here. */
const SOURCE = ['confidentialCaseStore.ts', 'weeklySubmissionSummary.ts']
  .map(file => readFileSync(path.join(__dirname, '../../../src/services', file), 'utf8')).join('\n');

const DOCUMENTDB_50 = {
  query: ['$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$exists', '$type', '$and', '$or', '$nor', '$not'],
  update: ['$set', '$setOnInsert', '$inc', '$unset', '$push', '$addToSet', '$pull'],
  stages: ['$match', '$project', '$sort', '$limit', '$skip', '$group'],
  /** $group accumulators. */
  accumulators: ['$sum'],
  expressions: ['$arrayElemAt', '$filter', '$objectToArray', '$ifNull', '$substrBytes', '$strLenBytes', '$literal', '$cond'],
  /** partialFilterExpression on 5.0: no implicit or array forms. */
  partialIndex: ['$eq', '$exists', '$and', '$gt', '$gte', '$lt', '$lte'],
};
const ALLOWED = new Set([...DOCUMENTDB_50.query, ...DOCUMENTDB_50.update, ...DOCUMENTDB_50.stages, ...DOCUMENTDB_50.accumulators, ...DOCUMENTDB_50.expressions]);

/** Operator keys (`$name:`), not quoted field paths such as '$ciphertext'. */
function operatorKeys(source: string): string[] {
  return [...source.matchAll(/(?<!['"\w$])(\$[a-zA-Z]+)\s*:/g)].map(match => match[1]);
}
/** The text of every `projection: { ... }` object literal. */
function projections(source: string): string[] {
  const found: string[] = [];
  for (const match of source.matchAll(/projection:\s*\{/g)) {
    let depth = 0, index = match.index! + match[0].length - 1;
    const start = index;
    for (; index < source.length; index++) {
      if (source[index] === '{') depth++;
      if (source[index] === '}' && --depth === 0) break;
    }
    found.push(source.slice(start, index + 1));
  }
  return found;
}

test('the confidential store uses only operators DocumentDB 5.0 supports', () => {
  const used = new Set(operatorKeys(SOURCE));
  expect(used.size).toBeGreaterThan(5); // The scan found the operators.
  expect([...used].filter(operator => !ALLOWED.has(operator))).toEqual([]);
});

test('find projections are inclusion/exclusion only; expressions stay in aggregation stages', () => {
  const found = projections(SOURCE);
  expect(found.length).toBeGreaterThan(5);
  for (const projection of found) {
    // `$project` stages are matched by a different key; `projection:` is a find/findOneAndUpdate option.
    expect(projection).not.toMatch(/\$[a-zA-Z]+/);
  }
  // The byte-range read that used $substrBytes in a find projection now runs in $project.
  expect(SOURCE).toMatch(/\$project: \{[^}]*totalBytes: \{ \$strLenBytes/);
});

test('client options disable retryable writes, which DocumentDB does not support', () => {
  expect(confidentialMongoClientOptions()).toMatchObject({ retryWrites: false, readPreference: 'primary' });
});

test('a failed connection closes its client before a later startup retry', async () => {
  const failure = new Error('synthetic connection failure');
  const connect = jest.spyOn(MongoClient.prototype, 'connect').mockRejectedValue(failure);
  const close = jest.spyOn(MongoClient.prototype, 'close').mockResolvedValue(undefined);
  try {
    await expect(MongoConfidentialCaseStore.connect('mongodb://127.0.0.1:1', 'synthetic'))
      .rejects.toBe(failure);
    expect(connect).toHaveBeenCalledTimes(1);
    expect(close).toHaveBeenCalledTimes(1);
  } finally { connect.mockRestore(); close.mockRestore(); }
});

test('transactions request only snapshot reads and majority writes, which DocumentDB supports', () => {
  const levels = [...SOURCE.matchAll(/readConcern: \{ level: '(\w+)' \}/g)].map(match => match[1]);
  expect(levels.length).toBeGreaterThan(5);
  expect(new Set(levels)).toEqual(new Set(['snapshot']));
  expect(SOURCE).not.toMatch(/linearizable/);
  // Finds inside a transaction return one batch: DocumentDB has no getMore there.
  for (const match of SOURCE.matchAll(/\.find\([^;]*\{ session,[^;]*\}\)\.toArray\(\)/g)) {
    if (/limit:/.test(match[0])) expect(match[0]).toMatch(/batchSize:/);
  }
});

test('indexes are plain, compound, unique, TTL or partial with supported filter operators', async () => {
  const created: { collection: string; keys: Record<string, unknown>; options: Record<string, unknown> }[] = [];
  const db = { collection: (name: string) => ({
    createIndex: async (keys: Record<string, unknown>, options: Record<string, unknown> = {}) => { created.push({ collection: name, keys, options }); return 'ok'; },
    // Startup backfills (legal application retention) on an empty database.
    updateMany: async () => ({ matchedCount: 0, modifiedCount: 0 }),
    updateOne: async () => ({ matchedCount: 0, modifiedCount: 0 }),
    find: () => ({ toArray: async () => [], async *[Symbol.asyncIterator]() { /* no rows */ } }),
  }) } as unknown as Db;
  await MongoConfidentialCaseStore.fromDatabase(db);
  expect(created.length).toBeGreaterThan(5);
  for (const index of created) {
    expect(Object.values(index.keys).every(direction => direction === 1 || direction === -1)).toBe(true); // No text/hashed/wildcard.
    for (const option of Object.keys(index.options)) expect(['unique', 'name', 'partialFilterExpression', 'expireAfterSeconds']).toContain(option);
    const filter = index.options.partialFilterExpression as Record<string, unknown> | undefined;
    if (!filter) continue;
    for (const [field, condition] of Object.entries(filter)) {
      if (field === '$and') continue;
      // Equality must be spelled $eq; DocumentDB rejects array and logical forms.
      expect(condition && typeof condition === 'object' && !Array.isArray(condition)).toBe(true);
      for (const operator of Object.keys(condition as object)) expect(DOCUMENTDB_50.partialIndex).toContain(operator);
    }
  }
});
