# Security architecture

## Trust boundaries

Confidential reporting encrypts private report contents in the browser. The browser verifies the enclave release and attestation before opening the encrypted application channel. Enclave code checks participant signatures, grants, identities and release approvals. Host storage holds ciphertext; participants retain the recovery and authorization material required to use it.

The public listing is a separate, explicitly published summary. Legal applications and organization contact details are intentionally available to onboarding staff. Legacy intake processes plaintext before sanitization and encryption and must not be described as confidential browser-to-enclave reporting.

Browser-delivered code, participant devices, account authentication, availability and operational metadata remain part of the trust boundary. Encryption, metadata removal and attestation do not guarantee anonymity or prove a report true. Synthetic tests cannot establish hardware or hosted-service acceptance.

## Authorization and legal access

Auth0 sign-in, organization membership and staff approval do not grant access to a private report. The reporter authorizes the organization, report sections, files, duration and any optional contact disclosure. Firm and device keys are independently approved; a matching email domain alone is insufficient. See the [legal enrollment protocol](../../enclave/src/legal/README.md).

The approval worker runs separately from the API. Its signing key and private journal belong only to that process. Configure your own identity provider, audiences, clients and authority keys. The source distribution includes Auth0 action logic, but no hosted tenant configuration or production authority material.

## Recovery and release approval

Recovery material stays with the reporter. A changed private-processing release requires approval of its exact manifest. Updating source or changing measured configuration creates a different release identity; a locally built image must not be represented as the hosted production release.

`enclave/confidential-config.json` is deliberately unconfigured: confidential services are disabled, the legal identity policy pin is null and no administration authority is embedded. Use `npm run dev:review` for a synthetic local configuration. Enable a real measured runtime only after configuring and verifying your own policies and release manifest.

## Storage and metadata

The application includes IPFS/Kubo, S3, KMS, SES and Auth0 adapters. Their presence does not provision those services. Production-mode storage requires the configured durable ciphertext archive; local test storage is disposable. Never point automated tests at an existing application database.

Notifications and firm onboarding have separate data boundaries from confidential report contents. Never put private report contents, recovery material, signing keys or credentials into logs, analytics, issue reports or screenshots. Backend credentials must never be exposed through `NEXT_PUBLIC_*` settings.

## Publication and incident handling

This source repository has no private upstream Git history, deployment workflows or infrastructure configuration. Scan proposed changes before sharing them. The repository-specific prepublication scanner supplements a general secret scanner:

```sh
node scripts/security/prepublication-scan.cjs --head-only --allow scripts/security/prepublication-allowlist.json
```

The command examines the committed tree. Review uncommitted files before committing, and review every exception; a passing scan cannot prove the absence of every possible secret. Tests generate synthetic keys and identities for local use.

Report vulnerabilities privately through [SECURITY.md](../../SECURITY.md). For an incident, preserve restricted evidence, contain affected credentials, correct the emitting or authorization path and validate recovery. Removing a file does not revoke a credential or purge already shared copies.
