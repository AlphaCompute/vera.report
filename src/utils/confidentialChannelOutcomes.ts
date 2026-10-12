import { emitTelemetry } from './runtimeTelemetry';

/** How a confidential channel request ended at the relay. */
export type ChannelOutcome =
  | 'open_ok' | 'open_shed' | 'open_throttled' | 'open_rate_limited' | 'open_enclave_error' | 'open_transport_error'
  | 'call_ok' | 'call_shed' | 'call_rate_limited' | 'call_session_missing' | 'call_session_busy' | 'call_enclave_error'
  | 'call_transport_error';

/** Per-minute outcome counts for the confidential channel. The confidential
 * family keeps no per-request records (docs/security/README.md#storage-and-metadata):
 * this emits one aggregate line per minute that saw
 * traffic, with counts only — no nonce, address, path, timing or case data. It
 * reveals no more than the load balancer's per-minute request and status
 * metrics already do, and says why channel requests failed. Idle minutes emit
 * nothing and hold no timer. */
export function createChannelOutcomeCounter(emit: (event: Record<string, string | number>) => void = emitTelemetry,
  intervalMs = 60_000) {
  let counts = new Map<ChannelOutcome, number>();
  let timer: ReturnType<typeof setInterval> | undefined;
  const flush = () => {
    if (!counts.size) {
      clearInterval(timer); timer = undefined;
      return;
    }
    const event: Record<string, string | number> = { source: 'confidential-relay', windowSeconds: Math.round(intervalMs / 1000) };
    for (const [outcome, count] of counts) event[outcome] = count;
    counts = new Map();
    emit(event);
  };
  return {
    record(outcome: ChannelOutcome): void {
      counts.set(outcome, (counts.get(outcome) ?? 0) + 1);
      if (!timer) {
        timer = setInterval(flush, intervalMs);
        timer.unref();
      }
    },
    /** Emit what is pending and stop the timer (shutdown). */
    close(): void {
      flush();
      clearInterval(timer); timer = undefined;
    },
  };
}
