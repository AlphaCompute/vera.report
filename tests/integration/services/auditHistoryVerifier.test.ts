import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { auditCommitmentRoot } from '../../../src/services/dissemination/auditAnchor';

const script = 'scripts/verify-audit-history.py';
const batchRoot = createHash('sha256').update('independent history fixture').digest('hex');
const genesis = { commitmentVersion: 2, batchRoot, eventCount: 1, root: auditCommitmentRoot(batchRoot, 1) };
const next = { ...genesis, prevRoot: genesis.root, root: auditCommitmentRoot(batchRoot, 1, genesis.root) };
const run = (anchors: unknown, head = next.root, tail = 'genesis') => runInput(JSON.stringify({ anchors }), head, tail);
const runInput = (input: string, head = next.root, tail = 'genesis') => {
  const result = spawnSync('python3', [script, '--head', head, '--tail', tail], {
    cwd: process.cwd(), input, encoding: 'utf8', timeout: 10_000, maxBuffer: 8192,
  });
  if (result.error) throw result.error;
  expect(result.stderr).toBe('');
  return { status: result.status, output: JSON.parse(result.stdout) };
};

it('independently verifies TypeScript commitments through the real Python CLI', () => {
  expect(run([next, genesis])).toEqual({ status: 0, output: {
    consistent: true, trust: 'caller-supplied endpoints', anchorCount: 2, head: next.root, checkpoint: null,
  } });
  expect(run([next], next.root, genesis.root).output.anchorCount).toBe(1);
  expect(run([], next.root, next.root).output.anchorCount).toBe(0);
});

it.each([
  [next], [genesis, next], [next, next, genesis], [next, genesis, genesis],
  [{ ...next, prevRoot: batchRoot }, genesis], [{ ...next, eventCount: 2 }, genesis],
  [{ ...next, batchRoot: genesis.root }, genesis], [{ ...next, commitmentVersion: 3 }, genesis],
  [{ ...next, prevRoot: next.root }, genesis],
  [{ ...next, prevRoot: null }, genesis], [{ ...next, eventCount: true }, genesis],
])('rejects missing, reordered, duplicated or changed history (%#)', (...anchors) => {
  const result = run(anchors);
  expect(result.status).toBe(1);
  expect(result.output.consistent).toBe(false);
});

it('requires an explicit checkpoint at the legacy trust boundary', () => {
  const legacy = { root: batchRoot, eventCount: 1, prevRoot: genesis.root };
  const transition = { ...genesis, prevRoot: legacy.root, root: auditCommitmentRoot(batchRoot, 1, legacy.root) };
  expect(run([transition], transition.root, legacy.root).status).toBe(0);
  const result = run([transition, legacy], transition.root);
  expect(result.status).toBe(1);
  expect(result.output.reason).toBe('legacy_boundary');
});

it('bounds input and rejects duplicate keys and malformed endpoints', () => {
  expect(run(Array(1001).fill(next)).output.reason).toBe('invalid_history_length');
  expect(runInput(' '.repeat(1024 * 1024 + 1)).output.reason).toBe('invalid_input');
  expect(runInput('{"anchors":[],"anchors":[]}').output.reason).toBe('invalid_input');
  expect(run([], 'not-a-root').output.reason).toBe('invalid_endpoint');
  expect(run([next, genesis], next.root, batchRoot).output.reason).toBe('missing_anchors');
  expect(runInput('{').output.reason).toBe('invalid_input');
});
