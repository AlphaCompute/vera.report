const { summarizeAudit } = require('../../../scripts/dependency-audit-report.cjs');
const report = (severity?: string) => ({
  auditReportVersion: 2,
  vulnerabilities: severity ? { example: { name: 'example', severity, via: [{ title: 'Synthetic advisory' }], fixAvailable: true } } : {},
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: severity ? 1 : 0, ...(severity ? { [severity]: 1 } : {}) } },
});
it('recognizes complete clean and low-severity reports', () => {
  expect(summarizeAudit(report(), 0)).toMatchObject({ blocking: 0 });
  expect(summarizeAudit(report('moderate'), 0)).toMatchObject({ blocking: 0 });
});
it.each(['high', 'critical'])('keeps a completed %s finding open despite npm exit 1', severity => {
  expect(summarizeAudit(report(severity), 1)).toMatchObject({ blocking: 1, body: expect.stringContaining('Synthetic advisory') });
});
it.each([
  [{ error: { code: 'ENOAUDIT', summary: 'Registry unavailable' } }, 1],
  [{}, 0], [null, 0], [{ ...report(), metadata: undefined }, 0],
  [report(), 1], [report(), 2], [report('high'), 0],
  [{ ...report(), auditReportVersion: 3 }, 0],
  [{ ...report(), vulnerabilities: [] }, 0],
  [{ ...report(), vulnerabilities: { missing: null } }, 0],
  [{ ...report(), metadata: { vulnerabilities: { ...report().metadata.vulnerabilities, high: '0' } } }, 0],
  [{ ...report(), metadata: { vulnerabilities: { ...report().metadata.vulnerabilities, total: 1 } } }, 0],
  [{ ...report('high'), vulnerabilities: {} }, 1],
])('never treats an unavailable, unsupported, or inconsistent audit as clean (%#)', (input, status) => {
  expect(() => summarizeAudit(input, status)).toThrow();
});
