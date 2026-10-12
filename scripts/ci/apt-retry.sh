#!/bin/sh
# Retry a complete APT operation: some TLS resets bypass Acquire::Retries.
set -u
attempt=1
while :; do
  if apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 "$@"; then
    exit 0
  else
    status=$?
  fi
  if [ "$attempt" -ge 3 ]; then
    exit "$status"
  fi
  echo "APT operation failed (exit $status); retrying attempt $((attempt + 1))/3" >&2
  sleep 5
  attempt=$((attempt + 1))
done
