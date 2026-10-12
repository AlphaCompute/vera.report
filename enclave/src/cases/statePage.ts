/** Transport paging only: participants still verify every signed checkpoint and
 * statement after assembling the full result. The latest digest pins all pages. */
export type StateCursor = { checkpointDigest: string; checkpointOffset: number; statementOffset: number };
export function statePage(checkpointDigest: string, checkpoints: string[], statements: Record<string, string>, cursor?: unknown) {
  let checkpointOffset = 0, statementOffset = 0;
  if (cursor !== undefined && cursor !== null) {
    const value = cursor as StateCursor;
    if (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'checkpointDigest,checkpointOffset,statementOffset' ||
        value.checkpointDigest !== checkpointDigest || [value.checkpointOffset, value.statementOffset]
          .some(item => !Number.isSafeInteger(item) || item < 0)) throw new Error('Invalid confidential state cursor');
    checkpointOffset = value.checkpointOffset; statementOffset = value.statementOffset;
  }
  const entries = Object.entries(statements).sort(([a], [b]) => a.localeCompare(b));
  if (checkpointOffset > checkpoints.length || statementOffset > entries.length) throw new Error('Invalid confidential state cursor');
  let budget = 64 * 1024;
  const pageCheckpoints: string[] = [], pageStatements: Record<string, string> = {};
  while (checkpointOffset < checkpoints.length) {
    const wire = checkpoints[checkpointOffset], bytes = new TextEncoder().encode(JSON.stringify(wire)).length + 1;
    if (bytes > budget) break;
    pageCheckpoints.push(wire); checkpointOffset++; budget -= bytes;
  }
  while (statementOffset < entries.length) {
    const [digest, wire] = entries[statementOffset], bytes = new TextEncoder().encode(JSON.stringify({ [digest]: wire })).length;
    if (bytes > budget) break;
    pageStatements[digest] = wire; statementOffset++; budget -= bytes;
  }
  const more = checkpointOffset < checkpoints.length || statementOffset < entries.length;
  if (more && !pageCheckpoints.length && !Object.keys(pageStatements).length) throw new Error('Confidential statement exceeds page capacity');
  return { checkpoints: pageCheckpoints, statements: pageStatements,
    stateNext: more ? { checkpointDigest, checkpointOffset, statementOffset } : null };
}
