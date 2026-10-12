import { statePage } from '../../../enclave/src/cases/statePage';
const digest = '11'.repeat(32);
test('bounded state pages reconstruct long checkpoint history and all statements without truncation', () => {
  const checkpoints = Array.from({ length: 600 }, (_, index) => `checkpoint-${index}-` + 'x'.repeat(1500));
  const statements = Object.fromEntries(Array.from({ length: 400 }, (_, index) => [index.toString(16).padStart(64, '0'), `statement-${index}-` + 'x'.repeat(2000)]));
  let page = statePage(digest, checkpoints, statements);
  const reconstructed = { checkpoints: [...page.checkpoints], statements: { ...page.statements } };
  let count = 1;
  while (page.stateNext) {
    expect(Buffer.byteLength(JSON.stringify(page))).toBeLessThan(65 * 1024);
    page = statePage(digest, checkpoints, statements, page.stateNext);
    reconstructed.checkpoints.push(...page.checkpoints);
    Object.assign(reconstructed.statements, page.statements);
    count++;
  }
  expect(count).toBeGreaterThan(10);
  expect(reconstructed).toEqual({ checkpoints, statements });
});
test('state pages reject changed checkpoint, malformed offsets and an individually oversized statement', () => {
  const cursor = { checkpointDigest: digest, checkpointOffset: 0, statementOffset: 0 };
  expect(() => statePage('22'.repeat(32), [], {}, cursor)).toThrow();
  expect(() => statePage(digest, [], {}, { ...cursor, statementOffset: -1 })).toThrow();
  expect(() => statePage(digest, [], {}, { ...cursor, checkpointOffset: 1 })).toThrow();
  expect(() => statePage(digest, [], { [digest]: 'x'.repeat(100000) })).toThrow('page capacity');
});
