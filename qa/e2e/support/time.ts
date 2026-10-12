import type { BrowserContext } from '@playwright/test';
import { stackState } from './state';

// The stack's forward-only time shift (stack/timeShift.ts), read and moved
// through its loopback control. Browser clocks follow it with Playwright's
// clock (Date only: timers and performance.now keep running in real time).

async function control(init?: { method: 'POST'; body: string }): Promise<number> {
  const { url, token } = stackState().timeControl;
  const response = await fetch(url, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } });
  if (!response.ok) throw new Error(`Stack time control refused (${response.status})`);
  return ((await response.json()) as { offsetMs: number }).offsetMs;
}

/** What the enclave's trusted clock reads, within its tolerance. */
export async function stackNow(): Promise<number> {
  return Date.now() + await control();
}

/** Put this browser context's clock on the stack's time (no-op until a spec shifts it). */
export async function followStackTime(context: BrowserContext, offsetMs?: number): Promise<void> {
  const offset = offsetMs ?? await control();
  if (offset) await context.clock.setSystemTime(Date.now() + offset);
}

/** Move the whole stack `ms` forward, and each open participant with it. It
 * cannot move back: every later spec and context runs on the shifted time. */
export async function advanceStackTime(ms: number, contexts: BrowserContext[]): Promise<void> {
  const offset = await control({ method: 'POST', body: JSON.stringify({ offsetMs: await control() + ms }) });
  for (const context of contexts) await followStackTime(context, offset);
}
