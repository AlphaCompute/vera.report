# Enclave runtime

This package contains the confidential report runtime, shared protocol, Nitro NSM bridge and attestation verification tools. It is a separate Node package with its own lockfile; `nsm/` contains the native Rust bridge.

From the repository root:

```sh
npm ci --prefix enclave --ignore-scripts
npm run build:enclave
npm run test:runtime
```

Use `npm run dev:review` for a local application stack with synthetic attestation. See the [browser harness](../qa/e2e/README.md), [confidential protocol](src/confidential/README.md), [legal enrollment protocol](src/legal/README.md) and [application channel verification](verification/APPLICATION-CHANNEL.md).

The Dockerfile packages the runtime and native bridge for Nitro. `confidential-config.json` is a disabled, unconfigured template; it contains no production identity policy or administration authority. Its exact bytes contribute to the enclave measurement. Configure your own policies before building an enabled image, and generate a matching release manifest using `scripts/security/` from the repository root. A changed configuration or source build has its own release identity.

AWS's public Nitro root certificate is included for verification. Private signing keys, credentials, production policies, cloud provisioning and publishing workflows are not included. Hardware smoke and verification tools require a separately configured Nitro host; local tests do not establish hardware acceptance.
