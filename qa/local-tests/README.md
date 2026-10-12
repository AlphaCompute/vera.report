# Local browser regressions

These tests run real Next.js pages/components with synthetic service responses. They never establish a successful deployed report, hosted Auth0 or Nitro acceptance. Use the [full local journey](../e2e/README.md) for a real local service stack, and [development setup](../../docs/development.md) for dependencies.

From the repository root, run one configuration at a time with no other Next process in this checkout:

```sh
npm --prefix qa run test:local
node qa/node_modules/@playwright/test/cli.js test --config qa/playwright.intake.config.ts
node qa/node_modules/@playwright/test/cli.js test --config qa/playwright.vault.config.ts
node qa/node_modules/@playwright/test/cli.js test --config qa/playwright.participant.config.ts
node qa/node_modules/@playwright/test/cli.js test --config qa/playwright.onboarding.config.ts
```

`test:local` selects `playwright.local.config.ts` (default port 3100, override `VERA_QA_PORT`) and starts its own Webpack dev server. Its report tests now use confidential intake: narrative validation, draft/file retention, mobile layout, unavailable service and failed-attestation handling. A fabricated legacy success/proof response must not produce a confidential receipt. Historical proof-status fixtures only exercise rendering of old records.

The separate intake, vault, participant and onboarding configs select their own subsets and settings. Read the config before narrowing by filename; an ignored spec will not run through `test:local`. Coverage includes:

- Encrypted IndexedDB transactions, stale-tab refusal, offline backup/export/import and cross-tab forgetting.
- Recovery files/codes remaining on-device, saved-backup verification and failed-load retention.
- Firm key/device enrollment, Auth0 fixture binding, optional second-holder custody and mandatory current terms.
- Report directory/status batching, cancelled/failed passes, release approval, direct grants and ended/revoked access.
- Refusal of conversation controls even for historical message permissions; safe download of decrypted evidence.
- Invitation validation, renewal, cooldown and uncertain-delivery feedback.
- Private page headers/CSP, fragment removal and no organization-website key fetches.

Component fixtures bundle real code through `support/fixtureBundle.ts`; only explicitly mapped I/O modules are stubbed. Unmapped imports, stale stubs and unexpected network modules fail. They verify UI behavior, not remote authorization. Jest and the compiled-runtime suite separately exercise protocol and service enforcement.

For a matching existing production frontend build, `VERA_QA_PRODUCTION=1 npm --prefix qa run test:local` starts `next start`. The build must contain the same confidential fixture settings expected by the config; read `qa/playwright.local.config.ts` for the matching public fixture variables. Confidential and legacy build modes are not interchangeable. In PowerShell set the variable before invoking npm; in POSIX shells inline assignment is supported.
