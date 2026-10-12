# VERA

VERA accepts whistleblower reports and supports reporter-controlled disclosure to approved legal organizations. This repository contains application source, the confidential enclave runtime, integrations and local tests.

`main` contains the maintained source; `staging` is the integration branch. This is a clean source import: private repository history, Terraform, cloud provisioning and production identity configuration are not included. GitHub Actions runs typechecking and unit/service tests for pushes and pull requests to both branches. There are no deployment workflows.

## Local development

Use Node.js 22 or later, npm and OpenSSL. Root, enclave and browser QA packages have separate lockfiles:

```sh
npm ci --legacy-peer-deps
npm ci --prefix enclave --ignore-scripts
npm ci --prefix qa
npm run build:enclave
node qa/node_modules/@playwright/test/cli.js install chromium
npm run dev:review
```

Open `http://127.0.0.1:3000`. The review stack runs disposable MongoDB, the confidential API and enclave composition with synthetic attestation and test identities. It downloads a MongoDB test binary when needed. Use synthetic data only; state is discarded when the stack stops. Hosted legal sign-in requires separate configuration; the browser harness supplies synthetic identity-provider behavior.

For environment variables, Docker profiles, native media tools and legacy mode, read [local development](docs/development.md). Example environment files contain placeholders, not working credentials. The checked-in enclave configuration disables confidential services and contains no production identity policy. The local review harness generates its own synthetic configuration.

## Application

- `pages/`, `components/`, `hooks/`, `lib/`, `styles/`, `public/`: Next.js routes, UI and browser clients.
- `src/`: APIs, persistence, authorization, evidence processing and workers.
- `enclave/`: measured runtime, shared confidential protocol, native NSM code and attestation verification tools.
- `auth0/actions/`, `auth0/templates/`: identity-provider application logic and email templates.
- `integrations/`, `aws/lambda/`: IPFS transports and the inbound email relay. AWS application adapters remain; infrastructure provisioning does not.
- `tests/`, `qa/`: regression tests, synthetic fixtures and local browser journeys.
- `scripts/`: build helpers, local verification, approval-worker code and application data migration.

Confidential reporting encrypts private contents in the browser. Reporters retain recovery material and control which organizations can access particular report contents through a verified enclave channel. The operator-readable public listing is separate. Legacy reporting remains for compatibility and processes plaintext before sanitization and encryption; select it explicitly only for that development path.

Encryption and attestation do not establish a report's truth or guarantee anonymity. See the [security architecture](docs/security/README.md) and [confidential protocol](enclave/src/confidential/README.md).

## Verification

GitHub Actions runs the enclave compilation, typecheck and Jest unit/service suite. You can also run these checks locally, plus the separate runtime and browser suites:

```sh
npm run typecheck
npm test -- --runInBand --watchAll=false
npm run test:runtime
npm run test:e2e:confidential
node --test auth0/actions/*.test.cjs
```

The full media suite requires Linux, FFmpeg, Poppler and `util-linux`. A frontend build requires either a matching confidential release manifest or explicit legacy mode. Local doubles do not establish live Auth0, Nitro, S3 or DocumentDB acceptance. See [verification prerequisites](docs/development.md#verification).

Read [CONTRIBUTING.md](CONTRIBUTING.md) before sending a change. Report vulnerabilities privately using [SECURITY.md](SECURITY.md). The source is licensed under [MIT](LICENSE); bundled dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
