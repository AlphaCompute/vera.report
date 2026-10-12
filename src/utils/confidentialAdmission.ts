import { performance } from 'node:perf_hooks';

/** Availability controls only. These bounded process-local maps contain quota
 * keys/nonces, never case or legal identity. Restarts reset them; replicas each
 * have their own budget. Confidentiality still depends on enclave verification. */
/** Relay-side session leases. The enclave keeps a session for follow-up
 * requests (one multi-range evidence download needs one session, not hundreds),
 * so a lease lives as long as the enclave may still hold that session:
 * - during open, key generation plus anonymous idle and relay deadlines;
 * - once the enclave confirmed the open, only its anonymous idle window, so
 *   unused opens cannot hold the pool for the whole open lease;
 * - before a call, the request deadline plus possible authenticated idle;
 * - after each successful call the enclave reports as still open, its
 *   authenticated idle window plus the relay deadline, never past the enclave's
 *   absolute lifetime plus the deadline.
 * Per-client fairness is the binding limit: one quota key holds at most
 * CHANNEL_ADMISSION.perClient leases, and the pool is smaller than the enclave's,
 * so the relay never forwards opens the enclave would refuse. */
export const CHANNEL_ADMISSION = Object.freeze({
  capacity: 48, perClient: 4, relayDeadline: 20_000,
  openLease: 60_000 + 15_000 + 20_000 + 5_000,
  /** After the enclave confirmed an open: its anonymous idle window (counted from
   * before the reply was sent) plus margin. An unused session stops holding the
   * pool as soon as the enclave has dropped it. */
  openedLease: 15_000 + 5_000,
  callLease: 60_000 + 60_000 + 20_000 + 5_000,
  renewLease: 60_000 + 20_000 + 5_000,
  maxLease: 10 * 60_000 + 20_000 + 5_000,
});
export function createChannelAdmission(clock = () => performance.now()) {
  /** `idle`: the enclave kept this session after its last call and no call is
   * running on it, so the relay may ask the enclave to close it. */
  const leases = new Map<string, { key: string; until: number; created: number; idle: boolean; evicting: boolean; lastUsed: number }>();
  let previous = -Infinity;
  function time(): number | null {
    const now = clock();
    if (!Number.isFinite(now) || now < previous) return null;
    previous = now;
    for (const [id, lease] of leases) if (lease.until <= now) leases.delete(id);
    return now;
  }
  return {
    reserve(nonce: string, key: string): boolean {
      const now = time();
      if (now === null) return false;
      let held = 0;
      for (const lease of leases.values()) if (lease.key === key) held++;
      if (leases.has(nonce) || leases.size >= CHANNEL_ADMISSION.capacity || held >= CHANNEL_ADMISSION.perClient) return false;
      leases.set(nonce, { key, created: now, until: now + CHANNEL_ADMISSION.openLease, idle: false, evicting: false, lastUsed: now });
      return true;
    },
    /** When a client is at its own cap, its least recently used idle session:
     * closing it in the enclave frees the slot for this client's new open
     * without letting the client exceed its cap. Several workspaces behind one
     * address (a firm office) then rotate sessions instead of being refused.
     * The lease stops being idle, so two opens never pick the same victim. */
    idleVictim(key: string): string | null {
      if (time() === null) return null;
      let held = 0, victim: string | null = null, oldest = Infinity;
      for (const [id, lease] of leases) if (lease.key === key) {
        held++;
        if (lease.idle && lease.lastUsed < oldest) { oldest = lease.lastUsed; victim = id; }
      }
      if (held < CHANNEL_ADMISSION.perClient || victim === null) return null;
      leases.get(victim)!.idle = false;
      leases.get(victim)!.evicting = true;
      return victim;
    },
    /** A confirmed refusal (or shedding before transport) leaves the lease
     * charged, but eligible for a later close attempt. Never undo a concurrent
     * begin: that call owns the non-idle state until it settles. */
    restoreVictim(nonce: string, key: string): void {
      const now = time(), lease = leases.get(nonce);
      if (now === null || !lease || lease.key !== key || !lease.evicting) return;
      lease.evicting = false; lease.idle = true; lease.lastUsed = now;
    },
    /** Reserve before forwarding; a lost reply may leave the enclave session
     * open. Mark it non-idle so eviction cannot target in-flight work. Unknown
     * cross-replica nonces never allocate entries. */
    begin(nonce: string, key: string): void {
      const now = time(), lease = leases.get(nonce);
      if (now === null || !lease || lease.key !== key) return;
      lease.idle = false;
      lease.evicting = false;
      lease.until = Math.min(Math.max(lease.until, now + CHANNEL_ADMISSION.callLease), lease.created + CHANNEL_ADMISSION.maxLease);
    },
    /** The enclave confirmed the open. Charge only its anonymous idle window.
     * A later open may request reclamation, but the enclave decides whether
     * verification or a proof follow-up still protects this session. */
    opened(nonce: string, key: string): void {
      const now = time(), lease = leases.get(nonce);
      if (now === null || !lease || lease.key !== key) return;
      lease.until = Math.min(lease.until, now + CHANNEL_ADMISSION.openedLease);
      lease.idle = true; lease.evicting = false; lease.lastUsed = now;
    },
    /** The enclave kept the session after a successful call. */
    renew(nonce: string, key: string): void {
      const now = time(), lease = leases.get(nonce);
      if (now === null || !lease || lease.key !== key) return;
      lease.until = Math.min(now + CHANNEL_ADMISSION.renewLease, lease.created + CHANNEL_ADMISSION.maxLease);
      lease.idle = true; lease.evicting = false; lease.lastUsed = now;
    },
    complete(nonce: string, key: string): void {
      if (leases.get(nonce)?.key === key) leases.delete(nonce);
    },
  };
}

export const STAGING_CLIENT_HOURLY_BYTES = 192 * 1024 * 1024;
export const STAGING_PROCESS_DAILY_BYTES = 512 * 1024 * 1024;
export type UploadAdmissionLimits = {
  processActive: number; clientActive: number; clientHourlyBytes: number; processDailyBytes: number;
};
/** Whole-object staging (/objects): narrative, contact and other small objects. */
export const STAGING_LIMITS: UploadAdmissionLimits = { processActive: 4, clientActive: 2,
  clientHourlyBytes: STAGING_CLIENT_HOURLY_BYTES, processDailyBytes: STAGING_PROCESS_DAILY_BYTES };
/** Evidence chunks (/chunks). One upload (submission or "add files") carries at
 * most 256 MiB, but a whistleblower may add evidence repeatedly; product policy
 * is that one reporter can move about 10 GiB of evidence without hitting a
 * budget. Bytes are charged on the wire (base64 adds a third) and chunk-count
 * padding (caseChunks.ts) adds under 25%, so 10 GiB of evidence is at most
 * ~16.7 GiB here; 20 GiB per client per hour covers that plus retries of
 * interrupted chunks. At most three chunks per client are in flight
 * (the browser uses three workers) and 24 per process, each one bounded
 * (~683 KiB) before buffering, so memory does not grow with these budgets. The
 * process-wide daily budget bounds how much unreferenced ciphertext one replica
 * can be made to store (staged chunks expire after 24 hours unless an
 * owner-signed index promotes them); it admits four such reporters per day. */
export const CHUNK_LIMITS: UploadAdmissionLimits = { processActive: 24, clientActive: 3,
  clientHourlyBytes: 20 * 1024 * 1024 * 1024, processDailyBytes: 80 * 1024 * 1024 * 1024 };
export function createUploadAdmission(clock = () => performance.now(), limits: UploadAdmissionLimits = STAGING_LIMITS) {
  const clients = new Map<string, { bytes: number; until: number; active: number }>();
  let active = 0, bytes = 0, until = 0, previous = -Infinity;
  return (key: string, size: number): (() => void) | null => {
    const now = clock();
    if (!Number.isFinite(now) || now < previous || !Number.isSafeInteger(size) || size < 1) return null;
    previous = now;
    if (now >= until) { bytes = 0; until = now + 86_400_000; }
    for (const [id, client] of clients) if (client.until <= now && client.active === 0) clients.delete(id);
    let client = clients.get(key);
    if (client && now >= client.until) { client.bytes = 0; client.until = now + 3_600_000; }
    if (active >= limits.processActive || (client?.active ?? 0) >= limits.clientActive || (!client && clients.size >= 4096) ||
        bytes + size > limits.processDailyBytes || (client?.bytes ?? 0) + size > limits.clientHourlyBytes) return null;
    if (!client) { client = { bytes: 0, active: 0, until: now + 3_600_000 }; clients.set(key, client); }
    bytes += size; client.bytes += size; client.active++; active++;
    let released = false;
    return () => { if (!released) { released = true; client!.active--; active--; } };
  };
}
