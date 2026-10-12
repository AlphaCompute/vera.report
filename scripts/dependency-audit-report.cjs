#!/usr/bin/env node
const fs = require('node:fs');

function summarizeAudit(report, status) {
  const severities = ['info', 'low', 'moderate', 'high', 'critical'];
  const counts = report?.metadata?.vulnerabilities;
  if (!report || report.error || report.auditReportVersion !== 2 || !counts ||
      !report.vulnerabilities || Array.isArray(report.vulnerabilities) ||
      typeof report.vulnerabilities !== 'object' ||
      ![0, 1].includes(status) ||
      [...severities, 'total'].some(key => !Number.isSafeInteger(counts[key]) || counts[key] < 0)) {
    throw new Error('Dependency audit did not produce a complete supported report');
  }
  const entries = Object.values(report.vulnerabilities);
  if (entries.some(entry => !entry || typeof entry.name !== 'string' ||
      !severities.includes(entry.severity) || !Array.isArray(entry.via)) ||
      severities.some(severity => entries.filter(entry => entry.severity === severity).length !== counts[severity]) ||
      counts.total !== entries.length) {
    throw new Error('Dependency audit vulnerability counts are inconsistent');
  }
  const blocking = counts.high + counts.critical;
  // With --audit-level=high, only a completed nonblocking audit exits zero.
  if (status !== (blocking > 0 ? 1 : 0)) throw new Error('Dependency audit exit status is inconsistent');
  const lines = entries.filter(v => v.severity === 'high' || v.severity === 'critical').map(v => {
    const via = v.via.map(entry => typeof entry === 'string' ? entry : entry?.title).filter(Boolean);
    const fix = v.fixAvailable === true ? 'fix available'
      : v.fixAvailable && v.fixAvailable.name
        ? `fix available: ${v.fixAvailable.name}@${v.fixAvailable.version}${v.fixAvailable.isSemVerMajor ? ' (semver-major)' : ''}`
        : 'NO fix available';
    return `- **${v.name}** (${v.severity}) — ${fix}` +
      (via.length ? '\n  - ' + [...new Set(via)].join('\n  - ') : '');
  });
  return { blocking, summary: `critical ${counts.critical} / high ${counts.high} / moderate ${counts.moderate} / low ${counts.low}`,
    body: lines.join('\n') || '_No high or critical advisories._' };
}

if (require.main === module) {
  try {
    const result = summarizeAudit(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')), Number(process.argv[3]));
    fs.writeFileSync('audit-body.md', result.body);
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `blocking=${result.blocking}\nsummary=${result.summary}\n`);
    console.log(result.summary);
  } catch {
    console.error('Dependency audit unavailable or incomplete; existing drift issues must remain open.');
    process.exitCode = 1;
  }
}
module.exports = { summarizeAudit };
