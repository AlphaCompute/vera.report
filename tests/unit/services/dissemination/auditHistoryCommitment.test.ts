import { auditCommitmentRoot, verifyAuditInclusion, type AuditCommitment } from '../../../../src/services/dissemination/auditAnchor';

// Generated independently with Python hashlib.sha256 and compact JSON arrays.
const a = '06ada57c26aa5cf429e9f2c0a99e3e4a42daecd45fc4c955d7c1399ab4227ae8';
const b = 'e0ef56d6eb603d9ffe87e74c28b8210b0ea93839e2ea4fb64f1fc2c66e95e391';
const batch = '4c466c3e972f4ae01f4a192f131901e63ab1042ef318e80836ae864029b5c529';
const root = 'ecb6e6fcbe1722eaef6feeb277c48936c6716244cf26dbfd43fdb71bb6ad5a56';
const nextRoot = '6584452b0e0e23946ade34e278f92ccf89a028f9f95c6942303d5c2061133501';
const genesis: AuditCommitment = { commitmentVersion: 2, batchRoot: batch, eventCount: 2, root };
const next: AuditCommitment = { commitmentVersion: 2, batchRoot: a, eventCount: 1, prevRoot: root, root: nextRoot };

it('matches independent genesis and linked-history encodings', () => {
  expect(auditCommitmentRoot(batch, 2)).toBe(root);
  expect(auditCommitmentRoot(a, 1, root)).toBe(nextRoot);
  expect(verifyAuditInclusion(a, [{ hash: b, position: 'right' }], genesis)).toBe(true);
  expect(verifyAuditInclusion(a, [], next)).toBe(true);
});

it.each([
  { prevRoot: b }, { eventCount: 2 }, { batchRoot: b }, { root: b },
  { commitmentVersion: 3 }, { commitmentVersion: undefined }, { prevRoot: undefined },
])('rejects changed history metadata %j', change => {
  expect(verifyAuditInclusion(a, [], { ...next, ...change } as AuditCommitment)).toBe(false);
});

it('rejects malformed paths and excessive counts', () => {
  expect(verifyAuditInclusion(a, [{ hash: b, position: 'left' }], genesis)).toBe(false);
  expect(verifyAuditInclusion(b, [], next)).toBe(false);
  expect(() => auditCommitmentRoot(batch, 0)).toThrow();
  expect(() => auditCommitmentRoot(batch, 2049)).toThrow();
  expect(() => auditCommitmentRoot(batch, 1, 'invalid')).toThrow();
});

it('retains legacy inclusion without claiming that its predecessor is authenticated', () => {
  const legacy = { root: batch, eventCount: 2, prevRoot: a };
  expect(verifyAuditInclusion(a, [{ hash: b, position: 'right' }], legacy)).toBe(true);
  expect(verifyAuditInclusion(a, [{ hash: b, position: 'right' }], { ...legacy, prevRoot: b })).toBe(true);
  expect(verifyAuditInclusion(a, [], { ...next, commitmentVersion: undefined })).toBe(false);
});
