import { useEffect, useRef, useState } from 'react';
import { PASSPHRASE_GUIDANCE, passphraseProblem } from '@/lib/confidential/passphraseStrength';
import { browserVaultStore, createDeviceBoundVault, createDeviceVault } from '@/lib/confidential/deviceVault';
import type { UnlockedVault } from '@/lib/confidential/deviceVault';
import { clearDeviceLocked, lockParticipantTabs, subscribeDeviceLock } from '@/lib/confidential/deviceWorkspace';
import { userFacingMessage } from '@/lib/confidential/userFacingError';
import { ForgetDevice, ownerWords } from './DeviceWorkspaces';

/** What this browser keeps for a reporter. One choice, off by default:
 * - none: nothing about the report is saved here;
 * - history: only the encrypted report history check (devicePin);
 * - report: the report itself, encrypted with a device passphrase (deviceVault),
 *   which also keeps the history check;
 * - device: explicit private-device shortcut using a non-extractable local key. */
export type DeviceChoice = 'none' | 'history' | 'report' | 'device';

export const DEVICE_CHOICES: Record<DeviceChoice, { title: string; text: string }> = {
  none: {
    title: 'Nothing (default)',
    text: 'Nothing about your report is saved in this browser. You open it with your recovery code or recovery file each time.',
  },
  history: {
    title: 'Only the report history check',
    text: 'Saves a small check value in this browser so a later visit can tell if your report’s history was rolled back. ' +
      'It does not save your recovery code, keys or report, and it is encrypted with your recovery code, so it does not show ' +
      'which report is yours. Anyone using this browser could still tell it was used to open a VERA confidential report.',
  },
  device: {
    title: 'Keep unlocked on this private device',
    text: 'Open automatically when you return, without typing a code. Anyone using this browser can read your report and act as you. Never choose this on a shared computer.',
  },
  report: {
    title: 'My report, protected by a device passphrase',
    text: 'You can open your report here with a passphrase instead of your recovery code. Also keeps the history check. ' +
      'Anyone who learns the passphrase and can use this browser can act as you. Choose this only on a device you trust.',
  },
};

export function deviceChoiceOf(saved: boolean, historyCheck: boolean, protection?: UnlockedVault['protection']): DeviceChoice {
  return saved ? (protection === 'device' ? 'device' : 'report') : historyCheck ? 'history' : 'none';
}

/** What changing from one choice to another does, in order. Leaving "report"
 * removes the saved report; choosing "report" also keeps the history check. */
export function deviceChoiceSteps(from: DeviceChoice, to: DeviceChoice, historyOn: boolean): {
  removeReport: boolean; saveReport: boolean; historyCheck: boolean | null;
} {
  if (from === to) return { removeReport: false, saveReport: false, historyCheck: null };
  const keepHistory = to !== 'none';
  return { removeReport: from === 'report' || from === 'device', saveReport: to === 'report' || to === 'device',
    historyCheck: keepHistory !== historyOn ? keepHistory : null };
}

const button = 'border border-current px-3 py-2 disabled:opacity-50';
const field = 'mt-1 block w-full border border-black/30 px-3 py-2';
const failure = (error: unknown) =>
  ownerWords(userFacingMessage(error, 'Device storage is unavailable. Keep your recovery code and recovery file.'));

/** The reporter's single "This device" panel. The recovery code and file stay
 * the backup; nothing here replaces them. */
export function OwnerDevicePanel({ className, vault, onVaultChange, getPayload, history, freshness, locked = false }: {
  className: string; vault: UnlockedVault | null; onVaultChange: (vault: UnlockedVault | null) => void;
  getPayload: () => Promise<unknown>;
  /** Absent where the history check is not offered (then the choices are "nothing" or "my report"). */
  history?: { on: boolean; set: (on: boolean) => Promise<void> };
  freshness?: 'confirmed' | 'unconfirmed';
  /** The choice can only change once the report is open. */
  locked?: boolean;
}) {
  const current = deviceChoiceOf(vault !== null, history?.on ?? false, vault?.protection);
  const [pending, setPending] = useState<DeviceChoice | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [secret, setSecret] = useState(''), [confirmation, setConfirmation] = useState('');
  const operation = useRef<AbortController | null>(null);
  useEffect(() => {
    const unsubscribe = subscribeDeviceLock(() => operation.current?.abort());
    return () => { operation.current?.abort(); unsubscribe(); };
  }, []);
  const choices: DeviceChoice[] = history ? ['none', 'history', 'report', 'device'] : ['none', 'report', 'device'];
  const selected = pending ?? current;

  const run = async (to: DeviceChoice, passphrase = '') => {
    const steps = deviceChoiceSteps(current, to, history?.on ?? false);
    const controller = new AbortController(); operation.current = controller;
    setBusy(true); setError('');
    let replacement: UnlockedVault | null = null;
    let committed = false, oldRemoved = false;
    try {
      // Preserve the old saved access until its replacement is safely written.
      if (steps.saveReport) {
        const payload = await getPayload(); controller.signal.throwIfAborted();
        replacement = to === 'device'
          ? await createDeviceBoundVault(browserVaultStore(), 'owner', payload, controller.signal)
          : await createDeviceVault(browserVaultStore(), 'owner', passphrase, payload, controller.signal);
      }
      controller.signal.throwIfAborted();
      if (steps.removeReport && vault) {
        await browserVaultStore().remove(vault.id);
        oldRemoved = true;
        vault.lock();
      }
      controller.signal.throwIfAborted();
      if (replacement) clearDeviceLocked();
      if (steps.removeReport || replacement) onVaultChange(replacement);
      committed = true;
      if (steps.historyCheck !== null && history) await history.set(steps.historyCheck);
      controller.signal.throwIfAborted();
      setPending(null); setSecret(''); setConfirmation('');
    } catch (caught) {
      if (replacement && !committed) {
        replacement.lock();
        // Once the old copy is gone, retain the encrypted replacement as the
        // only saved access. The lock marker stays set; never unlock after abort.
        if (!oldRemoved) {
          try { await browserVaultStore().remove(replacement.id); }
          catch { if (!controller.signal.aborted) setError('Device storage could not be cleared. Use Forget this device or clear this site’s data in your browser settings.'); return; }
        }
      }
      if (!controller.signal.aborted) setError(failure(caught));
    }
    finally { if (!controller.signal.aborted) setBusy(false); }
  };
  const choose = (to: DeviceChoice) => {
    setError('');
    if (to === current) { setPending(null); return; }
    // Saving the report needs a passphrase; removing it needs a confirmation.
    if (to === 'report' || to === 'device' || current === 'report' || current === 'device') { setPending(to); return; }
    void run(to);
  };
  const cancel = () => { operation.current?.abort(); setPending(null); setBusy(false); setSecret(''); setConfirmation(''); };
  const ready = passphraseProblem(secret) === null && secret === confirmation;

  return <section className={className} aria-labelledby="owner-device-title" aria-busy={busy}>
    <h3 id="owner-device-title" className="mb-3 font-semibold">This device</h3>
    {freshness && <>
      <p className="mb-1 text-sm font-semibold">
        {freshness === 'unconfirmed' ? 'Newest state: not confirmed on this device' : 'Newest state: checked against this device’s earlier visit'}
      </p>
      <p className="mb-4 max-w-[62ch] text-sm text-black/70">
        {freshness === 'unconfirmed'
          ? 'This device hasn’t opened your report before (or doesn’t remember it), so it can’t tell whether VERA is showing an older state. That only matters before you share something new: if you changed access on another device, check that the change appears here first.'
          : 'This device remembered your report’s history from an earlier visit and confirmed VERA didn’t roll it back.'}
      </p>
    </>}
    <fieldset className="space-y-2" disabled={busy || locked}>
      <legend className="mb-2 text-sm font-semibold">What should this device remember?</legend>
      {choices.map(choice => <label key={choice} className="flex items-start gap-3 border border-black/10 p-3 text-sm">
        <input type="radio" name="owner-device-choice" value={choice} className="mt-1" checked={selected === choice}
          onChange={() => choose(choice)} />
        <span className="max-w-[62ch]"><span className="block font-semibold">{DEVICE_CHOICES[choice].title}</span>
          <span className="block text-black/70">{DEVICE_CHOICES[choice].text}</span></span>
      </label>)}
    </fieldset>
    {locked && <p className="mt-2 text-sm text-black/60">You can change this once your report is open.</p>}
    {vault && pending === null && <p className="mt-3 text-sm" aria-live="polite">
      Your report is saved in this browser{vault.protection === 'device' ? ' and opens without a code.' : ' and opens with your device passphrase.'} Keep your recovery file too.</p>}
    {pending === 'report' && <form className="mt-4 space-y-3" onSubmit={event => {
      event.preventDefault(); if (busy || !ready) return;
      void run('report', secret);
    }}>
      <p className="text-sm">Choose a unique device passphrase. {PASSPHRASE_GUIDANCE} VERA cannot reset it, and browser storage
        can be cleared or lost, so keep your recovery file as well.</p>
      <label className="block text-sm">New device passphrase<input type="password" autoComplete="new-password" className={field}
        value={secret} disabled={busy} onChange={event => setSecret(event.target.value)} /></label>
      <label className="block text-sm">Confirm device passphrase<input type="password" autoComplete="new-password" className={field}
        value={confirmation} disabled={busy} onChange={event => setConfirmation(event.target.value)} /></label>
      {secret.length > 0 && confirmation.length > 0 && secret !== confirmation && <p className="text-sm">The passphrases do not match.</p>}
      <div className="flex flex-wrap items-center gap-3">
        <button className={button} disabled={busy || !ready}>{busy ? 'Saving…' : 'Save my report on this device'}</button>
        <button type="button" className="underline text-sm" onClick={cancel}>Cancel</button>
      </div>
    </form>}
    {pending === 'device' && <div className="mt-4 border border-red-700 bg-red-50 p-3 text-sm">
      <p className="font-bold text-red-800">Not private from other people using this browser. They can open your report and keys without a password, even after you lock the report.</p>
      <p className="mt-2">Use only your own locked computer. Choose Forget this device to remove saved access. Keep your recovery file: clearing browser storage loses this shortcut.</p>
      <button type="button" className={`${button} mt-3`} disabled={busy} onClick={() => void run('device')}>
        {busy ? 'Saving…' : 'I understand — keep unlocked on this device'}</button>
      <button type="button" className="ml-3 underline" disabled={busy} onClick={cancel}>Cancel</button>
    </div>}
    {pending !== null && pending !== 'report' && pending !== 'device' && vault && <div role="group" aria-label="Remove saved report"
      className="mt-4 border border-red-700 p-3 text-sm">
      <p className="font-bold text-red-800">Remove your saved report from this browser?{pending === 'history' ? ' The history check stays.' : ' The history check is removed too.'} You
        will need your recovery code or recovery file to open it again.</p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button type="button" className={button} disabled={busy} onClick={() => void run(pending)}>
          {busy ? 'Removing…' : 'Remove saved report'}</button>
        <button type="button" className="underline" disabled={busy} onClick={cancel}>Cancel</button>
      </div>
    </div>}
    {error && <p role="alert" className="mt-3 text-sm">{error}</p>}
    <p className="mt-4 text-sm">Locking closes your report in every open VERA tab, including unsaved drafts and a recovery code on
      screen. Download your recovery file first.</p>
    <button type="button" className="mt-2 underline text-sm" onClick={lockParticipantTabs}>Lock report</button>
    <ForgetDevice role="owner" />
  </section>;
}
