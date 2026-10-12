# Uses the same base image, UID and TLS supervisor as the API, without starting
# application workers or supplying application credentials.
ARG VERA_TRANSPORT_BASE=vera-ipfs-transport-base
FROM ${VERA_TRANSPORT_BASE}
COPY --chown=appuser:nodejs scripts/ipfs-loopback-relay.cjs scripts/start-ipfs-transport.cjs /app/scripts/
COPY --chown=appuser:nodejs scripts/start-tls.cjs /app/scripts/start-tls.cjs
COPY --chown=appuser:nodejs integrations/ipfs/transport/verify-container.cjs /app/integrations/ipfs/transport/
USER appuser
ENV RUN_MODE=api VERA_IPFS_TRANSPORT_ENABLED=1 TLS_PORT=3443 TLS_UPSTREAM_PORT=3001
ENTRYPOINT ["tini", "--", "node", "/app/integrations/ipfs/transport/verify-container.cjs"]
