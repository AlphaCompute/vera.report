# Local development

Run commands from the repository root unless a directory is stated. Use Node.js 22 or later and the committed npm lockfiles. Linux is the reference environment for the full native media suite; Windows users can use WSL for those checks and POSIX shell scripts.

## Install

```sh
npm ci --legacy-peer-deps
npm ci --prefix enclave --ignore-scripts
npm ci --prefix qa
npm run build:enclave
node qa/node_modules/@playwright/test/cli.js install chromium
```

Root and enclave packages are separate runtimes. Do not exchange live OpenPGP objects between them; use serialized keys/messages. Next.js conventions are documented in `node_modules/next/dist/docs/`; read the applicable guide before changing framework code, as required by [AGENTS.md](../AGENTS.md).

## Confidential local review

With OpenSSL on `PATH`, run:

```sh
npm run dev:review
```

Open `http://127.0.0.1:3000`. This starts disposable MongoDB, the confidential API, enclave composition and Next development stack with synthetic attestation. Stop other Next processes in this checkout first. Data disappears when the stack stops. The browser fixture supplies legal identity-provider behavior; interactive review alone does not provide a hosted legal sign-in. See [the E2E guide](../qa/e2e/README.md).

## Configured legacy web and API

Copy `.env.example` to `.env.local` and replace placeholders with development configuration. Explicitly set both switches for legacy work:

```dotenv
NEXT_PUBLIC_CONFIDENTIAL_CASES=0
CONFIDENTIAL_CASES_ENABLED=false
```

Leave `CONFIDENTIAL_INTAKE_REQUIRED` unset. Set `NEXT_PUBLIC_CONFIDENTIAL_CASES=0` in the backend runtime as well as the frontend build; a separately built frontend flag is not visible to Express. Either server-side confidential flag overrides legacy selection. Provide MongoDB, independent encryption/internal secrets, `IPFS_STORAGE_BACKEND=local-enclave` and `ENCLAVE_IPFS_URL`; follow the [IPFS local setup](../integrations/ipfs/README.md). Production-mode storage also requires the S3 ciphertext archive. Never copy production secrets into a local env file or expose backend secrets as `NEXT_PUBLIC_*`.

Do not leave example Shroud, SES or webhook credentials enabled for local submissions. Missing Shroud configuration leaves legacy scoring pending; confidential private contents do not use that scorer. Hosted Auth0 and external delivery need their own approved development configuration.

In separate POSIX terminals:

```sh
# API, port 3001
RUN_MODE=api npm run start:dev
# Frontend, port 3000
npm run dev
```

In PowerShell, the API equivalent avoids the POSIX assignment in `start:dev`:

```powershell
$env:RUN_MODE = 'api'
$env:NODE_OPTIONS = '--max-old-space-size=8192'
npx ts-node src/index.ts
```

Set `BACKEND_URL` to the API origin. The trusted frontend/backend must share `INTERNAL_API_SECRET`; it is not a browser credential. `src/index.ts` starts only the legacy API. The confidential service has its own `src/confidentialServer.ts` entrypoint and strictly separate configuration; do not start it with the legacy environment file.

For a local legacy production build, keep the explicit frontend setting in `.env.local`, then run `npm run build` and `npm start`. A confidential build instead needs the canonical `NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST` and matching backend/release configuration. Public variables are compiled into the frontend; changing runtime environment alone does not replace them.

## Docker profiles

`docker-compose.yml` has no default application profile. Copy the split templates to `.env.backend.local` and `.env.frontend.local`, select legacy mode explicitly, and provide reachable development MongoDB/storage services. Compose does not provision the confidential stack or a complete database/IPFS backend.

```sh
docker compose --profile development up --build
```

The `split` profile builds a production frontend. Its build settings must be supplied at build time; `env_file` applies only to running containers. For a legacy split build, prepare a local override:

```yaml
# /private/path/vera-compose-legacy.yml
services:
  frontend:
    build:
      args:
        NEXT_PUBLIC_CONFIDENTIAL_CASES: "0"
```

```sh
docker compose -f docker-compose.yml -f /private/path/vera-compose-legacy.yml --profile split up --build
```

Use an appropriate private path for your OS. The [IPFS](../integrations/ipfs/README.md) Compose file is a separate storage harness.

## Verification

| Check | Command | Boundary |
| --- | --- | --- |
| Environment | `npm run env:validate` | Selected process configuration; does not provision dependencies |
| Types | `npm run typecheck` | Root TypeScript |
| Supported Jest suite | `npm test -- --runInBand --watchAll=false` | `jest.local.config.ts`: unit, enclave and connected service tests |
| Compiled enclave | `npm run test:runtime` | Builds enclave and runs `tests/confidential-runtime/*.test.cjs` |
| Confidential journey | `npm run test:e2e:confidential` | Synthetic identity/attestation, real local pages and services |
| Local UI | `npm --prefix qa run test:local` | Browser fixtures; see [local coverage](../qa/local-tests/README.md) |
| Production build | `npm run build` | Requires the chosen frontend build configuration |
| Legacy delivery recording | `npm run demo:record` | Synthetic local package written to `artifacts/delivery/`; not live acceptance |

Jest loads `.env.test`; database suites use disposable `mongodb-memory-server` instances, which may download their MongoDB binary. Do not point tests at an existing application database. Browser packages and binaries require their separate install above. On Windows junction-based worktrees, the E2E harness supports `VERA_E2E_WEBPACK=1`.

The full native sanitizer suite needs FFmpeg, Poppler and `util-linux`. On Debian/Ubuntu:

```sh
sudo apt-get install -y --no-install-recommends poppler-utils util-linux ffmpeg curl
ffmpeg -encoders
```

Confirm `libvorbis` and `libtheora` are available. Missing binaries can produce the intentionally sanitized error `Document could not be safely sanitized`. Run tests without `--forceExit` so lifecycle failures remain visible. Local doubles do not establish live delivery, Nitro attestation or DocumentDB compatibility.

## Deployment configuration boundary

No production tenant policies, infrastructure or deployment workflows ship in this repository. GitHub Actions runs typechecking and unit/service tests with synthetic configuration. The legacy recipient-bound KMS readers use the non-operational AWS account pin `000000000000`; it must be deliberately configured and reviewed for your own deployment together with the enclave measurement. The confidential local review stack uses synthetic policies and does not need AWS credentials.

The application database defaults to `vera`. When using an existing database, set `MONGODB_DB_NAME` to its current name before starting the application or workers; changing the default does not migrate data. `CONFIDENTIAL_MONGODB_DB_NAME` must select a separate database.

Set `CORS_ALLOWED_ORIGINS` to a comma-separated list of your frontend origins, including any staging frontend. Production accepts only HTTPS origins. Custom staging hostnames are never allowed by default.
