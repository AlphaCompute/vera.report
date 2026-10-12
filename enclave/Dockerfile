# Multi-stage Dockerfile for VERA Nitro Enclave
# Used with nitro-cli build-enclave to create the EIF

# The source distribution ships an unconfigured, disabled confidential service.
# Configure your own measured identity policies before building an enabled EIF.

# ============================================
# Stage 1: Build the TypeScript application
# ============================================
# Kubo is built from source: upstream release images lag the Go toolchain
# (v0.43.1 ships Go 1.26.5, carrying CVE-2026-39821) and Shipyard ends Kubo
# maintenance on 2026-09-30, so the toolchain has to be ours to bump.
FROM golang:1.26.8@sha256:3c3e25a4da13fd0478eed2df1eb35a0e667094a7124d3993a6a1d30f71c17e79 AS kubo
ARG KUBO_VERSION=v0.43.1
ARG KUBO_COMMIT=acc53c093810a8fe9a4bc2f023f0b1e0c1d629b5
# Kubo 0.43.1 still carries grpc 1.83.1; upstream patch fixes CVE-2026-84445.
# Keep the source commit and this narrow dependency override reviewable.
ARG GRPC_VERSION=v1.83.2
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN git clone --depth 1 --branch ${KUBO_VERSION} https://github.com/ipfs/kubo.git /src && \
    cd /src && \
    test "$(git rev-parse HEAD)" = "${KUBO_COMMIT}" && \
    go get google.golang.org/grpc@${GRPC_VERSION} && \
    test "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" = "${GRPC_VERSION}" && \
    make build && \
    go version -m cmd/ipfs/ipfs | awk -v expected="${GRPC_VERSION}" '$1 == "dep" && $2 == "google.golang.org/grpc" && $3 == expected { found = 1 } END { exit !found }'

# Pinned repository release 2023.12.20260928 includes the curl, libpcap, Node,
# pcre2, RPM and systemd security updates, plus the earlier expat/OpenSSL fixes.
# Pinned base and explicit repository upgrade remain separate requirements.
# Base images are pinned by digest so the published PCR0 maps to known inputs.
FROM amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8 AS builder
ARG AL2023_RELEASE=2023.12.20260928

# Install Node.js 22
RUN dnf upgrade -y --releasever=${AL2023_RELEASE} && \
    dnf install -y --releasever=${AL2023_RELEASE} nodejs22 npm tar gzip rust cargo gcc openssl openssl-devel pkg-config && \
    dnf clean all

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY tsconfig.json ./
COPY src/ ./src/
COPY nsm/ ./nsm/

RUN npx tsc && npm prune --omit=dev --ignore-scripts
RUN cargo test --locked --manifest-path nsm/Cargo.toml && \
    cargo build --locked --release --manifest-path nsm/Cargo.toml

# These exact bytes contribute to the enclave measurement.
FROM scratch AS confidential-config
COPY confidential-config.json /confidential-config.json

# ============================================
# Stage 2: Production runtime
# ============================================
FROM amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8 AS runtime
ARG AL2023_RELEASE=2023.12.20260928

RUN dnf upgrade -y --releasever=${AL2023_RELEASE} && \
    dnf install -y --releasever=${AL2023_RELEASE} nodejs22 openssl shadow-utils socat iproute util-linux && \
    dnf clean all && \
    rm -rf /var/cache/dnf

RUN useradd -r -s /sbin/nologin enclave

COPY --from=kubo /src/cmd/ipfs/ipfs /usr/local/bin/ipfs
ENV IPFS_PATH=/app/ipfs
ENV XDG_CONFIG_HOME=/app/.config
WORKDIR /app

COPY --from=builder /build/dist ./dist
COPY --from=builder /build/package.json ./
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/nsm/target/release/vera-nsm /app/bin/vera-nsm
COPY --from=builder /build/nsm/target/release/vera-nsm-seed /app/bin/vera-nsm-seed
COPY --from=builder /build/nsm/target/release/vera-nsm-channel /app/bin/vera-nsm-channel
COPY --from=builder /build/nsm/target/release/vera-nsm-application-channel /app/bin/vera-nsm-application-channel
COPY --from=builder /build/nsm/target/release/vera-recipient-broker /app/bin/vera-recipient-broker

# Configuring this template creates a new measured release identity.
COPY --from=confidential-config confidential-config.json /app/confidential-config.json
# Init script: bridges vsock to TCP and starts the Node.js server
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Service processes may write runtime data, but cannot replace executable code.
RUN mkdir -p /app/ipfs /app/.config && \
    chown enclave:enclave /app/ipfs /app/.config && \
    chmod 0700 /app/ipfs /app/.config

# Root initializes loopback, NSM entropy and data ownership before dropping
# every service process to enclave.

ENTRYPOINT ["/app/entrypoint.sh"]

# Explicit isolated-hardware acceptance target. Never the default image.
FROM runtime AS recipient-acceptance
COPY recipient-acceptance-entrypoint.sh /app/recipient-acceptance-entrypoint.sh
RUN chmod 0755 /app/recipient-acceptance-entrypoint.sh
ENTRYPOINT ["/app/recipient-acceptance-entrypoint.sh"]

# Kubo sidecar for the API ECS task (ECR repository vera-ipfs). It is not an
# enclave target and never contributes to PCR measurements: the same pinned
# Kubo build and add/cat/rm proxy run next to the API container, offline, with
# S3 as the durable copy. Build with:
#   docker build --target ipfs-sidecar -t vera-ipfs enclave
FROM amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8 AS ipfs-sidecar-builder
ARG AL2023_RELEASE=2023.12.20260928
RUN dnf upgrade -y --releasever=${AL2023_RELEASE} && \
    dnf install -y --releasever=${AL2023_RELEASE} nodejs22 npm && dnf clean all
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

FROM amazonlinux:2023@sha256:5b29412077a463b4a3a8fbc99a8cdf4b929f38a3ecc8dac10328d8f36b0099b8 AS ipfs-sidecar
ARG AL2023_RELEASE=2023.12.20260928
RUN dnf upgrade -y --releasever=${AL2023_RELEASE} && \
    dnf install -y --releasever=${AL2023_RELEASE} nodejs22 shadow-utils && \
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    groupadd -r -g 1000 ipfs && \
    useradd -r -u 1000 -g ipfs -s /sbin/nologin ipfs
COPY --from=kubo /src/cmd/ipfs/ipfs /usr/local/bin/ipfs
COPY --from=ipfs-sidecar-builder /build/dist/ipfs-proxy.js /app/dist/ipfs-proxy.js
COPY --from=ipfs-sidecar-builder /build/dist/fatal.js /app/dist/fatal.js
COPY ipfs-sidecar-entrypoint.sh /app/ipfs-sidecar-entrypoint.sh
RUN chmod 0755 /app/ipfs-sidecar-entrypoint.sh && \
    mkdir -p /data/ipfs && chown ipfs:ipfs /data/ipfs && chmod 0700 /data/ipfs
# Ephemeral container storage; the node is rebuilt from the archive on demand.
ENV IPFS_PATH=/data/ipfs IPFS_PROXY_PORT=15002 IPFS_PROXY_BIND=127.0.0.1
USER ipfs
EXPOSE 15002
# ECS ignores image health checks; the task definition repeats this command.
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD ["node", "/app/dist/ipfs-proxy.js", "healthcheck"]
ENTRYPOINT ["/app/ipfs-sidecar-entrypoint.sh"]

# Keep ordinary builds on the existing fail-closed production entrypoint.
FROM runtime AS production
# Nitro does not accept environment overrides at run-enclave, so the measured
# image itself turns on the offline Kubo node that stores evidence ciphertext
# (vsock 5002). Its repo is a tmpfs capped at ENCLAVE_IPFS_REPO_MIB so a full
# repo fails the add instead of taking memory from the crypto services; S3
# holds the durable copy and refills it on demand.
ENV ENCLAVE_IPFS_ENABLED=1 ENCLAVE_IPFS_REPO_MIB=1024
