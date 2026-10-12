#!/usr/bin/env bash
# Install Playwright's Chromium and its system packages in CI, surviving a
# stalled package mirror or browser CDN.
#
# `playwright install --with-deps` runs apt-get under sudo. When a per-attempt
# timeout kills npx, that apt-get keeps running and holds the dpkg lock, so a
# plain retry fails at once ("Could not get lock /var/lib/dpkg/lock-frontend").
# Before each retry this waits for leftover apt/dpkg processes to exit and lets
# dpkg finish any half-configured packages.
#
# Usage: scripts/ci/install-playwright-chromium.sh [directory with @playwright/test]
set -uo pipefail
cd "${1:-.}"
ATTEMPTS="${PLAYWRIGHT_INSTALL_ATTEMPTS:-3}"
ATTEMPT_SECONDS="${PLAYWRIGHT_INSTALL_ATTEMPT_SECONDS:-240}"

apt_busy() { pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null 2>&1; }

wait_for_apt() {
  for _ in $(seq 1 60); do
    apt_busy || return 0
    sleep 5
  done
  echo "::warning::apt/dpkg is still busy after 5 minutes" >&2
  return 1
}

for attempt in $(seq 1 "$ATTEMPTS"); do
  if [ "$attempt" -gt 1 ]; then
    wait_for_apt || true
    sudo dpkg --configure -a || true
  fi
  if timeout --kill-after=15 "$ATTEMPT_SECONDS" npx --no-install playwright install --with-deps chromium; then
    exit 0
  fi
  echo "::warning::Playwright install attempt $attempt/$ATTEMPTS failed or timed out" >&2
  sleep 5
done
echo "::error::Playwright Chromium could not be installed after $ATTEMPTS attempts" >&2
exit 1
