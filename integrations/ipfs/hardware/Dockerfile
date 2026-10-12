# Build the repository's enclave/Dockerfile first and pass its recorded local tag.
ARG VERA_ENCLAVE_IMAGE
FROM ${VERA_ENCLAVE_IMAGE}
# Nitro does not accept Docker runtime environment overrides at run-enclave.
ENV ENCLAVE_IPFS_ENABLED=1
# Never enable ENCLAVE_LOCAL_IPFS_TEST on actual hardware.
