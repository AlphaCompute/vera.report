import { createWithdrawalMonitor, readWithdrawalPublicKey } from '../confidential/releaseWithdrawals.js';
import type { ChannelDispatch } from '../application-channel-sessions.js';

/** Enclave self-check against the signed release withdrawal list.
 *
 * With a withdrawal key pinned in the measured configuration, this enclave pauses
 * every case operation (owner and firm) while it has no current verified list, or
 * while the newest list withdraws its own release. It never switches release or
 * approves anything on an owner's behalf: a withdrawn release simply stops. With
 * no pinned key (null), checks are not configured and nothing is paused. */
export async function createReleaseWithdrawalGuard(input: {
  publicKey: string | null;
  releaseDigest: string;
  fetchList: () => Promise<string | null>;
  clock: () => number;
  refreshMs?: number;
}) {
  if (input.publicKey === null) {
    return { paused: () => false, refresh: async () => undefined, wrap: (dispatch: ChannelDispatch) => dispatch, stop: () => undefined };
  }
  const monitor = createWithdrawalMonitor(await readWithdrawalPublicKey(input.publicKey));
  let paused = true;
  const refresh = async () => {
    let wire: string | null = null;
    try { wire = await input.fetchList(); } catch { wire = null; }
    try { await monitor.check(wire, input.releaseDigest, input.clock()); paused = false; }
    catch { paused = true; }
  };
  await refresh();
  const timer = setInterval(() => { void refresh(); }, input.refreshMs ?? 5 * 60_000);
  timer.unref?.();
  return {
    paused: () => paused,
    refresh,
    /** Also re-evaluates expiry on every call, independent of the refresh timer. */
    wrap: (dispatch: ChannelDispatch): ChannelDispatch => async (body, context) => {
      const current = monitor.current();
      if (paused || !current || input.clock() >= current.expiresAt) {
        paused = true;
        throw new Error('Confidential release paused');
      }
      return dispatch(body, context);
    },
    stop: () => clearInterval(timer),
  };
}
