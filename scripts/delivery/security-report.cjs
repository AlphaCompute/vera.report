// Generate a sanitized engineering evidence PDF, never a pentest certification.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { chromium } = createRequire(path.resolve(__dirname, '../../qa/package.json'))('@playwright/test');
const escape = (value) =>
    String(value).replace(
        /[&<>"']/g,
        (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
    );
exports.generate = async (directory) => {
    const evidence = JSON.parse(fs.readFileSync(path.join(directory, 'measurements.json')));
    const batches = JSON.parse(fs.readFileSync(path.join(directory, 'concurrency.json')));
    const browser = await chromium.launch({ headless: true });
    try {
        const page = await browser.newPage();
        const html = `<!doctype html><html><head><meta charset="utf-8"><style>
      @page{size:A4;margin:19mm}body{font:11px/1.5 Arial,sans-serif;color:#172635}h1{font-size:29px;line-height:1.15}h2{font-size:19px;color:#165c66}h3{font-size:13px}p{margin:10px 0}table{border-collapse:collapse;width:100%;font-size:10px}td,th{padding:8px;border-bottom:1px solid #ccd5db;text-align:left}th{background:#edf3f5}.page{break-after:page}.page:last-child{break-after:auto}.label{font-size:10px;letter-spacing:1px;color:#526b77}.box{background:#edf3f5;padding:12px;margin:18px 0}code{font-size:10px;overflow-wrap:anywhere}li{margin:7px 0}
      </style></head><body>
      <section class="page"><p class="label">VERA / ENGINEERING DELIVERY EVIDENCE</p><h1>Security scope and<br>local verification</h1><p>${escape(evidence.recordedAt)}</p>
      <div class="box"><strong>Local synthetic evidence. This is not an independent penetration test or a security certification.</strong><p>No production acceptance or Shroud attestation is established by this run.</p></div>
      <h2>Source and reproducibility</h2><p>Commit: <code>${escape(evidence.commit)}</code><br>Dirty checkout: ${escape(evidence.dirty)}<br>Command: <code>npm run demo:record</code></p><p>Node ${escape(evidence.runtime.node)}; ${escape(evidence.runtime.platform)} / ${escape(evidence.runtime.architecture)}; ${escape(evidence.runtime.cpu)}; ${escape(evidence.runtime.cpuCount)} logical CPUs; ${escape(Math.round(evidence.runtime.memoryBytes / 1024 ** 3))} GiB RAM.</p>
      <h2>Evidence boundaries</h2><p>The encrypted-browser video records current confidential reporter intake. The measurements and controls below exercise retained legacy API endpoints; they do not describe current browser plaintext handling. Nitro attestation and identity-provider responses in the browser stack are synthetic.</p><h2>Legacy API threat boundaries</h2><ul><li>Intake servers process plaintext before storage encryption. Metadata removal does not remove identifying visible content.</li><li>Admin and counsel authorization is required for restricted access. A report ID is not permission to download evidence.</li><li>Single-use packet links are bearer capabilities. GET does not consume them; explicit reveal does. Independently issued links have separate lifetimes.</li><li>Evidence commitments establish implemented cryptographic bindings, not factual truth, source anonymity or legal sufficiency.</li></ul></section>
      <section class="page"><p class="label">CONTROLS / REVIEW SCOPE</p><h2>Implemented controls</h2><table><tr><th>Area</th><th>Control and evidence</th></tr><tr><td>Transport boundaries</td><td>Bounded evidence uploads; trusted API origin; per-IP intake limiter; backend authorization remains required for evidence.</td></tr><tr><td>Shroud handling</td><td>No redirects or echoed provider error bodies; bounded response; strict result schema; deterministic rejection and transient retry tests.</td></tr><tr><td>Legal workflow</td><td>Connected intake-to-counsel tests exercise consent gate, reviewed disclosure, evidence decryption, dossier, filing status and revoked access.</td></tr><tr><td>Operations</td><td>Minimized events use the configured authenticated notification channel; local test recipients are disabled.</td></tr></table>
      <h2>Local versus external dependencies</h2><p><strong>Real:</strong> ${escape(evidence.real.join(', '))}.</p><p><strong>Substituted:</strong> ${escape(evidence.substituted.join(', '))}.</p><h2>Limitations and review follow-up</h2><p>A lost submission response remains locked for idempotent recovery. Production privacy depends on deployed keys, storage, logs, network boundaries and access control.</p><p>Security model and verification: <code>docs/security/README.md</code>. Deployment and independent review trackers: #608, #611, #562, #564. Findings and source changes are reviewable in the matching Git revision.</p></section>
      <section class="page"><p class="label">MEASUREMENTS / ACCEPTANCE</p><h2>Observed local timings</h2><table><tr><th>Stage</th><th>Source</th><th>Milliseconds</th></tr>${evidence.timings.map((t) => `<tr><td>${escape(t.stage)}</td><td>${escape(t.source)}</td><td>${escape(t.milliseconds)}</td></tr>`).join('')}</table>
      <h2>Small concurrency probe</h2><table><tr><th>Concurrent attempts</th><th>Rejected attempts</th><th>Batch ms</th></tr>${batches.map((b) => `<tr><td>${escape(b.concurrency)}</td><td>${escape(b.failures)}</td><td>${escape(b.totalMilliseconds.toFixed(2))}</td></tr>`).join('')}</table><p>Concurrency workload: synthetic narrative and ${escape(evidence.workload.fileBytes)}-byte CSV. Seven total requests, no stable percentile claim. The separate legacy API intake includes tagged image and PDF fixtures; metadata-checks.json records before/after validation. The default upload budget can reject excess requests with 503; these remain counted as failures. Acknowledgment is not finality.</p>
      <h2>Unmeasured and pending</h2><p>${escape(evidence.unmeasured.join('; '))}. No contractual thresholds have been invented.</p><p>Before launch: complete independent review, actual Shroud request and failure-mode acceptance, Nitro/storage cutover checks, designated QA and stakeholder approval. See <code>docs/security/README.md</code>.</p><p>The accompanying SHA256SUMS covers this PDF and the recorded artifacts. Hash integrity does not establish the correctness or completeness of a security assessment.</p></section></body></html>`;
        fs.writeFileSync(path.join(directory, 'security-report.html'), html);
        await page.setContent(html);
        await page.pdf({
            path: path.join(directory, 'security-report.pdf'),
            format: 'A4',
            printBackground: true,
            displayHeaderFooter: true,
            headerTemplate: '<span></span>',
            footerTemplate:
                '<div style="font-size:9px;width:100%;text-align:center;color:#647480">VERA / Synthetic local evidence · <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
        });
    } finally {
        await browser.close();
    }
};
if (require.main === module)
    exports.generate(path.resolve(process.argv[2])).catch((error) => {
        console.error(error.message);
        process.exitCode = 1;
    });
