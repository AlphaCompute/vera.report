# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **please do not open a public issue**.

Report it privately using one of these routes:

1. If GitHub's [Report a vulnerability](https://github.com/AlphaCompute/vera.report/security/advisories/new) form is available, submit a private advisory there.
2. If that form is unavailable, email [ir@alphacompute.ai](mailto:ir@alphacompute.ai) with the subject `Vera security vulnerability`. This is the contact published in Alpha Compute's [security.txt](https://www.alphacompute.ai/.well-known/security.txt).

Include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues. We coordinate disclosure with you privately and credit you in it unless you ask us not to.

Please do not include real whistleblower reports, reporter identities or other people's personal data in a report. Use synthetic data to demonstrate the issue.

## Scope

This policy covers:

- Encryption and key management in vault operations
- Confidential browser encryption, attestation, report grants and recovery
- Historical receipt integrity (new blockchain proofs are no longer issued)
- Website reporter credentials and administrator session handling
- API authentication and authorization
- Evidence storage and decryption flows

## Supported Versions

The latest source on `main` is supported. Integration changes can be reviewed on `staging`; this repository does not deploy services.
