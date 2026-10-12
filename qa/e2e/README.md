# Confidential-case click-through tests

Install root, enclave and `qa` lockfiles and Playwright Chromium as shown in [local development](../../docs/development.md#install). Current coverage is confidential submission/recovery, firm enrollment and scoped report access. Private conversations are retired; current tests assert that conversation controls are absent.

This harness provides local verification only. Hosted deployment and hardware acceptance require a separately configured environment.

Real pages and services, with synthetic attestation and identity-provider fixtures. `playwright.e2e.config.ts` boots, in its global setup:

- MongoDB (`mongodb-memory-server`, single-node replica set);
- the confidential-only API process (`createConfidentialApp` from `src/confidentialServer.ts`):
  the attested-channel relay, ciphertext staging, storage RPC and the admin routes;
- the enclave composition (`composeConfidentialServer` from `enclave/src/confidential-server.ts`):
  session core, owner and legal dispatchers, sealed store, trusted clock, release checks;
- a fresh Next production build and server with a confidential release configuration;
- a loopback ingress that routes `/api/confidential` to the confidential API and all other paths
  to Next, matching production ingress without development rewrites or Fast Refresh.

Nitro attestation is synthetic (`stack/syntheticNitro.ts`): an OpenSSL-issued root and leaf
replace the AWS PKI and sign real COSE/CBOR NSM documents that bind the browser nonce, the channel
key and PCRs matching the synthetic release manifest. The test browser trusts that root: the page's
own compiled code is served with the pinned AWS root constant swapped (`support/browser.ts`); every
other verification step runs unchanged.

Identity-provider traffic (`identity.example`, the legal and onboarding sign-ins) is answered by the
test with RS256 tokens from a local issuer whose JWKS the measured configuration pins. Firms never
publish anything on their own website: the browser contexts block firm domains outright. VERA admin uses a synthetic session cookie, as in `scripts/test-legal-onboarding-admin.cjs`.
There is no legacy backend: legacy proxies point at a closed port, so a 400 proves a route refused
an identifier before forwarding it.

Run from the repository root, with no other Next build or server in this checkout:

```sh
npm run test:e2e:confidential
```

The harness needs OpenSSL on `PATH` and Playwright Chromium installed. For a Windows
worktree that shares `node_modules` through a junction outside the checkout, set
`VERA_E2E_WEBPACK=1` to use `next build --webpack`; CI uses the default bundler.
This changes only the production asset build, not session limits or test retries.

The positive journey models one shared network address at **eight channel requests
per second across all browser contexts**. The harness paces original open/call
requests before forwarding them; it never replays a failed request. The API's
600-per-minute limit, four concurrent leases per address, global capacity and
enclave deadlines remain unchanged. An unpaced run measured 608 channel requests
in one rolling minute: several participants and multi-frame evidence downloads
run much faster than human clicks, so fixed-window alignment previously decided
whether this functional journey hit the rate limit. This is a bounded functional
workload, not a claim of unlimited throughput for an office sharing one address.
`tests/unit/api/confidentialAdmission.test.ts` exercises quota exhaustion and
admission reclamation without this browser pacing; client failure tests retain
the no-replay assertions for ambiguous writes and explicit throttle handling.

CI runs the same script (`.github/workflows/confidential-e2e.yml`) on pull requests that touch the
feature; `tests/unit/scripts/confidentialE2eGate.test.ts` fails if the script, the workflow or one of
the covered flows below disappears.

Leak checks run twice. Each spec records what participant browsers send (URLs, headers, bodies) and
fails if a sentinel or a device secret (recovery code and file in every encoding, organization key
files and codes, device codes) appears in it. The specs also register those values
(`sweptFromHost` in `support/state.ts`, stored in a register file named in the state file), and global
teardown sweeps what the host kept before the stack stops: the Next production server output (`next.log`),
the output of the confidential API and enclave (they run in the global-setup process, whose stdout and
stderr are captured), and every document, collection option and index of every database in the e2e
MongoDB, the oplog included so records written and later deleted still count
(architecture acceptance test 7). A hit fails the run and names the source; device secrets are
reported by length only.

`VERA_E2E_PORT` picks the Next port (default 3196). `VERA_E2E_DEBUG=1` logs API method, path and
status, monotonic timing and numeric rate-limit remaining/Retry-After values (never
bodies or identity headers), and browser page errors. Synthetic keys only; the stack state file
(`qa/e2e/.stack-state.json`) is removed on teardown.
Each participant also prints counts of channel open/call HTTP statuses when its
browser context closes, retaining availability diagnostics without logging
identities, session nonces, URLs, headers or ciphertext.

Flows: firm onboarding checklist, onboarding invitation, steward adding a lawyer (device code and
invitation), confidential submission with the recovery file check, firm request, restore on a fresh
device, the Allow chooser (report and one of two files), firm download, renewing
access (new end date and back to "until revoked"), sharing and then no longer sharing contact
details, adding a file after submission and sharing it, steward removal of a lawyer with an
organization key replacement followed by the firm's new request and the reporter's Allow, revocation,
a firm renewal request that the reporter declines, the authorized directory API's public projection, legacy route
isolation, summary edit and withdrawal, "Approve update" on a later release (`release-update.spec.ts`:
the browser receives a release manifest with another source commit for the same measured image),
phone-sized restore by recovery file and by typed code, and the absence of host-readable
reporter-email controls on both receipt and status (`owner-notifications.spec.ts`).

`confidential-two-firms.spec.ts` runs on its own organizations (`north-counsel.example`,
`south-counsel.example`; `FIRM_DOMAINS` in `stack/stack.ts`) through `support/firm.ts`: two firms
each onboard through the full setup checklist (backup, optional second key holder, terms, signed key approval,
invitation); both ask for access; the reporter restores on a fresh device and allows one "files
I add later" and the other 30 days of current files; a file added after submission reaches only
the first (the other still sees one file); revoking the first is refused at the enclave when it
opens the report from the signed listing, while the second still downloads the file from before
the revocation; and a fresh desktop browser restored from the recovery file shows the reporter the
"ends soon" and "ended" notices for the 30-day grant. Here only the reporter's browser clock is moved
forward, after the report is open, and the page is re-rendered by a local toggle: the notices are
checked as rendered, not as enforced. Enforcement of an ended grant, with the whole stack's time
moved forward, is `access-expiry.spec.ts` below.

Access that has ended (`access-expiry.spec.ts`): the reporter allows a second organization
(`second-counsel.example`) for 30 days, the stack's time then moves 31 days forward, and the firm
(set up through the same `support/firm.ts` checklist, and invited again since its membership lease
lapsed too) sees access ended and cannot open the report
until the reporter renews. Time moves through `stack/timeShift.ts`: one forward-only offset added to
the synthetic NSM timestamps, the enclave's trusted clock (the test-only `timeShift` composition
dependency; production passes none), the global-setup process's `Date` (OpenPGP checks signature
times against it), identity tokens and browser clocks (`support/time.ts`, via a
loopback control whose token is in the state file). Trusted time never moves back, so this spec is
its own Playwright project (`time-shifted`) that depends on, and runs after, every other spec. To run
it alone: `npm --prefix qa run test:e2e -- access-expiry --no-deps`.

## Interactive local review

Run `npm run dev:review` with no other Next process in this checkout. Open
`http://127.0.0.1:3000`. This runs Next in development mode with the local MongoDB,
confidential API, and enclave composition above. The loopback-only ingress swaps
the attestation root in served JavaScript for the synthetic root, as the E2E
browser fixture does. Production application source and trust pins are unchanged.
The page displays a local simulation banner; use test data only. Data is temporary
and disappears when the stack stops. Legal identity-provider fixtures still need
the E2E browser harness; interactive report submission needs no sign-in.

`node qa/node_modules/@playwright/test/cli.js test --config qa/dev/playwright.config.ts`
checks editable review and real encrypted submission on desktop and mobile against
that running stack, without intercepting the relay or replacing browser checks.
