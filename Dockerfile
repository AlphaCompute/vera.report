# Multi-stage Dockerfile for VERA
# Dual Server Architecture: Next.js (3000) + Express (3001)
# Runs the web API

ARG NODE_VERSION=22

# ============================================
# Stage 1: Base image with common dependencies
# ============================================
FROM public.ecr.aws/docker/library/node:${NODE_VERSION}-trixie-slim AS base
LABEL org.opencontainers.image.title="VERA"

# Bump this build argument when rebuilding to refresh cached system packages.
# An existing image does not receive package updates until it is rebuilt.
ARG APT_SECURITY_REFRESH=0

# The slim image has no system CA bundle, and on trixie OpenSSL rejects a
# bundle synthesised from Node's roots. Fetch Debian's own ca-certificates
# over plain HTTP first, where apt's GPG signatures provide the integrity
# guarantee, then pin the sources to HTTPS for everything after. The Debian
# CDN occasionally resets connections, so every stage retries fetches.
COPY scripts/ci/apt-retry.sh /usr/local/bin/apt-retry
RUN echo "apt security refresh: ${APT_SECURITY_REFRESH}" && \
    printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/80-retries && \
    apt-retry update && \
    apt-retry install -y --no-install-recommends ca-certificates && \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && \
    apt-retry update && \
    apt-retry upgrade -y && \
    apt-retry install -y --no-install-recommends \
        dumb-init \
        tini \
        curl \
        ca-certificates \
        poppler-utils \
        util-linux \
        openssl \
        stunnel4 && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1001 nodejs && \
    useradd -u 1001 -g nodejs -s /bin/sh -m appuser

WORKDIR /app
COPY --chown=appuser:nodejs scripts/start-tls.cjs /app/start-tls.cjs

# FFmpeg is only needed by the API/development evidence pipeline.
FROM base AS media-runtime
RUN apt-retry update && apt-retry install -y --no-install-recommends ffmpeg python3 && rm -rf /var/lib/apt/lists/*

COPY scripts/media-memfd.py /app/scripts/media-memfd.py

# The disabled attested reader uses this fixed, root-owned Python runtime.
FROM media-runtime AS attestation-runtime
COPY enclave/canary/requirements.txt /opt/vera-attestation/enclave/canary/requirements.txt
COPY enclave/verification/requirements.txt /opt/vera-attestation/enclave/verification/requirements.txt
RUN apt-retry update && apt-retry install -y --no-install-recommends python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m venv /opt/vera-attestation/venv && \
    /opt/vera-attestation/venv/bin/pip install --no-cache-dir -r /opt/vera-attestation/enclave/verification/requirements.txt
COPY enclave/verification/verify_identity.py enclave/verification/verify_channel.py enclave/verification/recipient_client.py enclave/verification/read_report_verification.py enclave/verification/narrative.py enclave/verification/aws-nitro-root.pem /opt/vera-attestation/enclave/verification/

# Synthetic signed documents and loopback TLS; no AWS credentials or external network.
FROM attestation-runtime AS attestation-verification
COPY enclave/verification/test_*.py enclave/verification/accept_recipient.py /opt/vera-attestation/enclave/verification/
COPY enclave/verification/fixtures/ /opt/vera-attestation/enclave/verification/fixtures/
WORKDIR /opt/vera-attestation
USER appuser
ENTRYPOINT ["/opt/vera-attestation/venv/bin/python", "-E", "-s", "-B", "-m", "unittest"]
CMD ["enclave.verification.test_identity", "enclave.verification.test_transport", "enclave.verification.test_channel", "enclave.verification.test_recipient_client", "enclave.verification.test_read_report_verification", "enclave.verification.test_narrative", "enclave.verification.test_accept_recipient", "enclave.verification.test_packaged_runtime"]

# ============================================
# Stage 2: Dependencies
# ============================================
FROM base AS deps
COPY package*.json ./
RUN npm ci --frozen-lockfile --no-audit --no-fund --legacy-peer-deps

# ============================================
# Stage 3a: Backend builder (TypeScript only)
# ============================================
FROM base AS builder-backend
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx tsc -p tsconfig.server.json
# The approval worker ships in this image but runs as a separate process with
# its own authority key and journal; the API never starts it.
RUN npx tsc -p scripts/tsconfig.approval-worker.json

# ============================================
# Stage 3b: Frontend builder (Next.js standalone)
# ============================================
FROM base AS builder-frontend
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_BLOCK_EXPLORER_URL=https://preprod.midnightexplorer.com
ENV NEXT_PUBLIC_BLOCK_EXPLORER_URL=$NEXT_PUBLIC_BLOCK_EXPLORER_URL
# Network the explorer above serves; receipts from any other network render unlinked.
ARG NEXT_PUBLIC_BLOCK_EXPLORER_NETWORK=preprod
ENV NEXT_PUBLIC_BLOCK_EXPLORER_NETWORK=$NEXT_PUBLIC_BLOCK_EXPLORER_NETWORK

# Matomo analytics. These are build args rather than runtime env because every
# public page is statically prerendered, so pages/_document.tsx is evaluated by
# `next build` and the tracker URL is baked into the emitted HTML. Setting these
# on the ECS task at runtime would have no effect on those pages.
#
# Defaults are empty on purpose: an image built without them omits the tracker
# entirely rather than shipping a hardcoded host, which is how the retired
# analytics.atoncap.xyz URL survived in the build for as long as it did.
ARG MATOMO_URL=
ARG MATOMO_SITE_ID=
ENV MATOMO_URL=$MATOMO_URL
ENV MATOMO_SITE_ID=$MATOMO_SITE_ID

# Public release identity is compiled into the browser; no participant secrets.
ARG NEXT_PUBLIC_CONFIDENTIAL_CASES=1
ARG NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST=
ARG NEXT_PUBLIC_CONFIDENTIAL_RELEASE_NOTES=
ENV NEXT_PUBLIC_CONFIDENTIAL_CASES=$NEXT_PUBLIC_CONFIDENTIAL_CASES
ENV NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST=$NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST
ENV NEXT_PUBLIC_CONFIDENTIAL_RELEASE_NOTES=$NEXT_PUBLIC_CONFIDENTIAL_RELEASE_NOTES
# Base64 of the armored release-withdrawal public key (scripts/security/
# confidential-release-withdrawals.cjs keygen). Empty: withdrawal checks off.
ARG NEXT_PUBLIC_CONFIDENTIAL_WITHDRAWAL_KEY=
ENV NEXT_PUBLIC_CONFIDENTIAL_WITHDRAWAL_KEY=$NEXT_PUBLIC_CONFIDENTIAL_WITHDRAWAL_KEY
# Commit of this frontend build, shown in the private screens' security details.
ARG NEXT_PUBLIC_SOURCE_COMMIT=
ENV NEXT_PUBLIC_SOURCE_COMMIT=$NEXT_PUBLIC_SOURCE_COMMIT
ARG NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN=
ARG NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID=
ARG NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE=
ARG NEXT_PUBLIC_LEGAL_AUTH0_ORGANIZATION=
ARG NEXT_PUBLIC_LEGAL_AUTH0_CONNECTION=
ENV NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN=$NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN
ENV NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID=$NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID
ENV NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE=$NEXT_PUBLIC_LEGAL_AUTH0_AUDIENCE
ENV NEXT_PUBLIC_LEGAL_AUTH0_ORGANIZATION=$NEXT_PUBLIC_LEGAL_AUTH0_ORGANIZATION
ENV NEXT_PUBLIC_LEGAL_AUTH0_CONNECTION=$NEXT_PUBLIC_LEGAL_AUTH0_CONNECTION
ARG NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN=
ENV NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN=$NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN
ARG NEXT_PUBLIC_ONBOARDING_AUTH0_CLIENT_ID=
ENV NEXT_PUBLIC_ONBOARDING_AUTH0_CLIENT_ID=$NEXT_PUBLIC_ONBOARDING_AUTH0_CLIENT_ID
ARG NEXT_PUBLIC_ONBOARDING_AUTH0_AUDIENCE=
ENV NEXT_PUBLIC_ONBOARDING_AUTH0_AUDIENCE=$NEXT_PUBLIC_ONBOARDING_AUTH0_AUDIENCE
ARG NEXT_PUBLIC_ONBOARDING_AUTH0_ORGANIZATION=
ENV NEXT_PUBLIC_ONBOARDING_AUTH0_ORGANIZATION=$NEXT_PUBLIC_ONBOARDING_AUTH0_ORGANIZATION

RUN npx next build

# ============================================
# Stage 4: Frontend (Next.js standalone server on port 3000)
# ============================================
FROM base AS frontend

# Match the compiled sign-in tenants and the SSR document CSP.
ARG NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN=
ENV NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN=$NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN
ARG NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN=
ENV NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN=$NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN

# Download AWS DocumentDB TLS CA bundle (needed for MongoDB fallback)
RUN curl -sS -o /app/rds-combined-ca-bundle.pem \
    https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

COPY --from=builder-frontend --chown=appuser:nodejs /app/.next/standalone ./
COPY --from=builder-frontend --chown=appuser:nodejs /app/.next/static ./.next/static
COPY --from=builder-frontend --chown=appuser:nodejs /app/public ./public
# LGPL-3.0 notices for the libvips (sharp) binaries in the standalone bundle.
COPY THIRD_PARTY_NOTICES.md LICENSE licenses/ /app/licenses/

USER appuser
EXPOSE 3000 3444
ENV TLS_PORT=3444 TLS_UPSTREAM_PORT=3000

ENV PORT=3000
ENV HOSTNAME=0.0.0.0

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

ENTRYPOINT ["tini", "--", "node", "/app/start-tls.cjs"]
CMD ["node", "server.js"]

# ============================================
# Stage 5: Backend (Express on port 3001)
# Runs the web API
# ============================================
FROM attestation-runtime AS backend

COPY --chown=appuser:nodejs scripts/ipfs-loopback-relay.cjs scripts/start-ipfs-transport.cjs /app/

# Download AWS DocumentDB TLS CA bundle
RUN curl -sS -o /app/rds-combined-ca-bundle.pem \
    https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

# LGPL-3.0 notices for the openpgp and libvips (sharp) binaries in node_modules.
COPY THIRD_PARTY_NOTICES.md LICENSE licenses/ /app/licenses/

COPY --from=deps --chown=appuser:nodejs /app/node_modules ./node_modules
COPY --from=builder-backend --chown=appuser:nodejs /app/dist ./dist
COPY --from=builder-backend --chown=appuser:nodejs /app/package*.json ./

RUN mkdir -p /app/logs /app/data && chown appuser:nodejs /app/logs /app/data

USER appuser
EXPOSE 3001 3443
ENV TLS_PORT=3443 TLS_UPSTREAM_PORT=3001

ENV RUN_MODE=api

# Raise Node's V8 old-space ceiling so it uses the container's memory instead
# of the ~2 GiB default. Keep this < the ECS task memory (currently 4 GiB) with
# headroom for off-heap memory. Overridable via the task-def NODE_OPTIONS env if
# resized.
ENV NODE_OPTIONS="--max-old-space-size=3072"

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

ENTRYPOINT ["tini", "--", "node", "/app/start-ipfs-transport.cjs"]
CMD ["node", "dist/index.js"]

# Exercise the compiled backend-to-Python boundary without provider access.
FROM backend AS attested-backend-verification
COPY scripts/check-attested-backend.cjs /app/scripts/check-attested-backend.cjs
ENTRYPOINT ["tini", "--"]
HEALTHCHECK NONE
CMD ["node", "--test", "scripts/check-attested-backend.cjs"]

# Full-size crypto/storage acceptance harness; synthetic data only.
FROM backend AS large-evidence-verification
ENTRYPOINT ["tini", "--"]
HEALTHCHECK NONE
COPY --chown=appuser:nodejs scripts/check-large-evidence.cjs ./scripts/check-large-evidence.cjs
ENV NODE_ENV=test ENCLAVE_ENABLED=false IPFS_STORAGE_BACKEND=local-enclave ENCLAVE_IPFS_URL=http://127.0.0.1:5002
CMD ["node", "scripts/check-large-evidence.cjs"]

# ============================================
# Stage 6: Development (both servers)
# ============================================
FROM media-runtime AS development
COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN npm run build

EXPOSE 3000 3001

CMD ["sh", "-c", "node dist/index.js & npx next start -p ${PORT:-3000}"]

# Synthetic verification uses the same FFmpeg/prlimit layer as the API.
# No database, wallet, network service or secret is needed at runtime.
FROM media-runtime AS media-verification
COPY --from=builder-backend --chown=appuser:nodejs /app/dist/services/mediaMetadata.js ./dist/services/mediaMetadata.js
COPY --from=builder-backend --chown=appuser:nodejs /app/dist/utils/mediaFormats.js ./dist/utils/mediaFormats.js
COPY --from=builder-backend --chown=appuser:nodejs /app/dist/utils/evidenceLimits.js ./dist/utils/evidenceLimits.js
COPY --from=builder-backend --chown=appuser:nodejs /app/dist/utils/evidenceValidationError.js ./dist/utils/evidenceValidationError.js
COPY --chown=appuser:nodejs scripts/check-media-runtime.cjs ./scripts/check-media-runtime.cjs
USER appuser
ENV NODE_ENV=production
CMD ["node", "scripts/check-media-runtime.cjs"]
