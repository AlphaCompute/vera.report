# Contributing

Thanks for your interest in contributing to Vera. This guide covers the process for submitting changes.

## Getting Started

1. Fork the repository
2. Clone your fork and create a branch from `staging`
3. Install dependencies with `npm ci --legacy-peer-deps`
4. Follow [local development](docs/development.md) to choose the confidential simulation or explicitly configured legacy stack
5. Install the separate enclave/QA dependencies for the checks you will run; use `npm run env:validate` for a configured application environment

> **Branch strategy:** Base feature and fix branches on `staging`. Reviewed changes move from `staging` to `main`. GitHub Actions checks types and runs unit/service tests on pushes and pull requests to either branch. Deployment remains outside this repository.

## Development Workflow

### Before making changes

```bash
npm run env:validate   # Verify environment
npm run typecheck      # Confirm types are clean
npm test               # Confirm tests pass
```

### While developing

- Follow the existing TypeScript strict-mode conventions (no `any` types in vault/security modules)
- All sensitive data must be encrypted — never store plaintext secrets

### Before submitting

```bash
npm run typecheck      # No type errors
npm test               # All tests green
npm run test:runtime   # Compiled enclave checks, when affected
npm run build          # Production build succeeds
```

Tests use `mongodb-memory-server` for database tests and `nock` for HTTP mocking. Test-suite environment config lives in **`.env.test`** (separate from `.env.local` / `.env`). Coverage thresholds apply when running with `--coverage`; the default local test gate does not collect coverage. Browser checks require their own setup; see the README.

Choose checks for the affected behavior and report commands actually run. The full application sequence is `env:validate` → `typecheck` → `test` → `build`; confidential changes additionally need the compiled runtime and browser checks. Documentation-only changes need link/path and whitespace checks, not a fabricated application test result. Build mode and native runtime prerequisites are in [development setup](docs/development.md#verification).

## Pull Request Process

1. Write a clear PR description explaining **what** changed and **why**
2. Reference any related issues
3. Run the relevant checks locally and include their results
4. Keep PRs focused — one logical change per PR
5. Update documentation if your change affects public APIs or configuration

## Commit Messages

Use conventional-style messages in the form `<type>(<scope>): <description>`:

```
feat(legal): add a report access filter
fix(intake): handle expired session gracefully
docs: update environment variable table
test(intake): cover receipt recovery after restart
```

## Code Style

- TypeScript strict mode throughout
- 120 character line width, 4 space indentation, single quotes
- Prettier handles formatting — run it before committing
- Avoid comments that restate what the code does; comment the *why* when it isn't obvious

## Reporting Issues

When opening an issue, include:

- Steps to reproduce
- Expected vs actual behavior
- Node.js version and OS
- Relevant environment details (without exposing secrets)

## Security

If you discover a security vulnerability, **do not open a public issue**. Use GitHub's [Report a vulnerability](https://github.com/AlphaCompute/vera.report/security/advisories/new) form when available, or email [ir@alphacompute.ai](mailto:ir@alphacompute.ai) with the subject `Vera security vulnerability`, as directed by Alpha Compute's [security.txt](https://www.alphacompute.ai/.well-known/security.txt). See the [Security Policy](SECURITY.md) for details.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Repository layout

- Keep standalone maintenance and diagnostic scripts in `scripts/`.
- Keep application routes in `pages/` and backend services/API under `src/`.
- Keep current setup, architecture, and operational guidance in `docs/`; use issues and PRs for temporary plans and implementation reports.
- Delete unused code rather than keeping archive directories. Check imports, dynamic entry points, CI, and operational consumers before removal; Git retains historical versions.
- Check consumers before removing tools, migrations or infrastructure. Remove obsolete test/CI references with their tools; historical source and documentation remain in Git.
- Link new durable documentation from [the documentation index](docs/README.md); label dated observations and distinguish legacy intake from confidential reporting.
