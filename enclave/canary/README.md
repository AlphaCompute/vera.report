# Nitro hardware canary

Use this only for the isolated canary boundary. Current confidential report acceptance is documented in the [deployment runbook](../../docs/security/README.md); [the enclave index](../README.md) maps the separate interfaces. The canary remains a reusable hardware test, not an application runtime.

This is an isolated synthetic-data test, not VERA's production cryptographic service. It has no KMS integration, persistence, record authorization, migration or production routing. Never send reports, credentials or real keys to it. A plaintext digest is returned solely to verify random synthetic input; this interface is unsuitable for confidential low-entropy content.

The verifier runs on the trusted client. The parent forwards framed ciphertext over vsock; it cannot supply a replacement recipient key without failing verification. The client pins the AWS root, validates the COSE signature and certificate chain, checks a fresh nonce and approved non-debug PCR0, and encrypts to the attested ephemeral X25519 key. Sessions expire after 60 seconds and are consumed on confirmation attempts, including failures. The parent can still observe timing, size and availability, deny service, and call the canary itself. This is not an anonymity mechanism.

## Build on an authenticated, idle Nitro builder

Use verified SSH host identity. Inventory existing enclaves and allocator state first. Reserve 2 CPUs and 2048 MiB only if free; record the original allocator file/service state and restore them after the test. Do not terminate other enclaves. Do not run with `--debug-mode`.

Build the AWS NSM library from the SDK revision used in this review:

```sh
git clone https://github.com/aws/aws-nitro-enclaves-sdk-c.git sdk
cd sdk
git checkout cd61b6187c8b20867ba4368d1ae62c5790c0269a
python3 - <<'PY'
from pathlib import Path
source = Path('containers/Dockerfile.al2').read_text()
source = source.replace('amazonlinux:2', 'amazonlinux:2023')
source = source.replace('cmake3', 'cmake').replace('yum install', 'dnf install')
source = source.replace('\tgo ', '\tgolang ').replace('$(nproc)', '4')
source = '\n'.join(line for line in source.splitlines() if not line.startswith('RUN rpm -e')) + '\n'
Path('containers/Dockerfile.canary').write_text(source)
PY
sudo docker build --target kmstool-enclave-cli -t vera-review-kmstool:canary -f containers/Dockerfile.canary .
sudo docker create --name vera-review-library-export vera-review-kmstool:canary
sudo docker cp vera-review-library-export:/usr/lib64/libnsm.so ../canary/libnsm.so
sudo docker rm vera-review-library-export
cd ../canary
sudo docker build -t vera-nitro-canary:v1 .
sudo nitro-cli build-enclave --docker-uri vera-nitro-canary:v1 --output-file canary.eif > measurements.json
sudo nitro-cli run-enclave --eif-path canary.eif --cpu-count 2 --memory 2048 --enclave-cid 36 --enclave-name vera-review-canary > run.json
```

Place this directory at `~/vera-nitro-review/canary` on the builder, and clone the SDK into its sibling `sdk` directory. The proxy is invoked through SSH, without a public listener. CID 36 is an example: choose an unused CID. The build uses package repositories and a mutable base tag: inspect each build and explicitly approve its new PCR0. It is not a reproducible production supply chain or an audited SDK release. Do not silently trust a measurement supplied by an untrusted parent; establish image provenance independently.

## Verify from the trusted client

Use Python 3.13, the pinned `requirements.txt`, and OpenSSL with `verify -trusted` support. Obtain the AWS Nitro root ZIP from the [official AWS location](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip), verify ZIP SHA256 `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`, then extract `root.pem`. The verifier also pins its DER fingerprint. See [AWS attestation verification guidance](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

```sh
python -m unittest discover -s enclave/canary -p 'test_*.py'
python enclave/canary/verify.py --ssh-config /path/to/verified-ssh-config \
  --host ec2-user@ENCLAVE_BUILDER_HOST --cid 36 \
  --pcr0 APPROVED_96_HEX_PCR0 --root /path/to/root.pem
```

Keep the JSON result and image measurements as evidence. Never commit generated keys, documents, libraries, images or EIFs. Terminate only the recorded canary enclave ID; then restore the allocator if no other workload has started. Production acceptance additionally requires KMS recipient-policy negative tests, purpose-bound operations, caller/record authorization, migration, deployed intake verification and independent review.
