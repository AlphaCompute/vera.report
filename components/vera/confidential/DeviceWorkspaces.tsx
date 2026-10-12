import { PASSPHRASE_GUIDANCE, passphraseProblem } from '@/lib/confidential/passphraseStrength';
import { useEffect, useRef, useState } from 'react';
import {
  browserVaultStore, createDeviceBoundVault, createDeviceVault, createPasskeyVault, passkeyCredentialId, readVaultBackup,
  unlockDeviceBoundVault, unlockDeviceVault, unlockPasskeyVault, vaultProtection, exportTemporaryWorkspace,
} from '@/lib/confidential/deviceVault';
import type { UnlockedVault, VaultProtection, VaultRecord, VaultRole } from '@/lib/confidential/deviceVault';
import {
  clearDeviceLocked, deviceLockedInThisTab, forgetParticipantDevice, lockParticipantTabs, subscribeDeviceLock,
} from '@/lib/confidential/deviceWorkspace';
import { userFacingMessage } from '@/lib/confidential/userFacingError';

const button = 'border border-black px-3 py-2 disabled:opacity-50';
const field = 'mt-1 block w-full border border-black/30 px-3 py-2';
/** Reporters see one term per concept: their saved report and their recovery
 * file. Shared vault errors are written for legal organizations ("workspace",
 * "key file"), so they are reworded before a reporter sees them. */
export function ownerWords(text: string): string {
  return text
    .replace(/\bworkspaces\b/g, 'reports').replace(/\bWorkspaces\b/g, 'Reports')
    .replace(/\bworkspace\b/g, 'report').replace(/\bWorkspace\b/g, 'Report')
    .replace(/\brecovery backups?\b/g, 'recovery file').replace(/\bkey file\b/g, 'recovery file')
    .replace(/\bcase references\b/g, 'report details');
}
const FALLBACK: Record<VaultRole, string> = {
  owner: 'Device storage is unavailable. Keep your recovery code and recovery file.',
  legal: 'Device storage is unavailable. Keep your recovery backup.',
};
const message = (error: unknown, role: VaultRole = 'legal') => {
  const text = userFacingMessage(error, FALLBACK[role]);
  return role === 'owner' ? ownerWords(text) : text;
};

export { useParticipantLock } from '@/lib/confidential/participantLock';

export function ForgetDevice({ role = 'owner' }: { role?: VaultRole }) {
  const [confirm, setConfirm] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  return <div className="mt-4 text-sm">
    <button type="button" className="underline" aria-expanded={confirm} onClick={() => setConfirm(!confirm)}>Forget this device</button>
    {confirm && <div className="mt-3 border border-red-700 p-3">
      {role === 'owner'
        ? <p className="font-bold text-red-800">This removes every report and history check VERA saved in this browser, and locks open VERA tabs, discarding unsaved drafts and recovery codes shown in them.
          Download your recovery file first if you have no other copy. It does not delete downloaded files, browser history, clipboard history, password-manager entries or copies held by others. Remove those separately on shared devices.</p>
        : <p>This removes all saved VERA participant workspaces and history checks in this browser, and locks open VERA participant tabs, discarding unsaved drafts and recovery codes in them.
          Save a recovery backup first if this is your only copy. It does not delete downloaded files, browser history or copies held by others.</p>}
      {role === 'legal' && <p className="mt-2">If you used a passkey, you can also delete the “VERA legal” passkey in your device or password manager settings.</p>}
      <button type="button" className={`${button} mt-3`} disabled={busy} onClick={() => {
        setBusy(true); setError('');
        void forgetParticipantDevice().catch(error => setError(message(error, role))).finally(() => setBusy(false));
      }}>{busy ? 'Clearing…' : 'Confirm: forget this device'}</button>
      <button type="button" className="ml-3 underline" disabled={busy} onClick={() => setConfirm(false)}>Cancel</button>
    </div>}
    {error && <p role="alert" className="mt-3">{error} <button type="button" className="underline" onClick={lockParticipantTabs}>Lock now</button></p>}
  </div>;
}

const savedName = (role: VaultRole, index: number) => `Saved ${role === 'owner' ? 'report' : 'organization'} ${index + 1}`;
export const SAVED_COPY: Record<VaultRole, { label: string; heading: string; looking: string; damaged: string; select: string;
  unlock: string; forgot: string; none: string }> = {
  owner: {
    label: 'Reports saved on this device', heading: 'Open a report saved on this device', looking: 'Looking for saved reports…',
    damaged: 'This saved report is damaged. Use your recovery code or recovery file.', select: 'Saved report',
    unlock: 'Open saved report', forgot: 'If you forgot this passphrase, use your recovery code or recovery file.',
    none: 'No report is saved on this device. Enter your recovery code or open your recovery file to continue.',
  },
  legal: {
    label: 'Saved workspaces', heading: 'Return to a saved workspace', looking: 'Looking for saved workspaces…',
    damaged: 'This saved workspace is damaged. Use your key file.', select: 'Saved workspace',
    unlock: 'Unlock saved workspace', forgot: 'No file import needed. If you forgot this passphrase, use your recovery backup.',
    none: 'No saved workspace found. Open your recovery backup to continue on this device.',
  },
};

/** Reporters only see the saved-report section when this browser holds a saved
 * report. With nothing saved it would compete with the recovery-code box and the
 * recovery-file control, so the page shows nothing until one is found. Legal
 * organizations always see theirs, since it also restores workspace backups. */
export function showSavedSection(role: VaultRole, records: readonly Pick<VaultRecord, 'role'>[] | null): boolean {
  if (role !== 'owner') return true;
  return (records ?? []).some(record => record.role === 'owner');
}

export function SavedWorkspaces({ role, onUnlocked, onRecovered }: { role: VaultRole;
  onUnlocked: (vault: UnlockedVault, signal: AbortSignal) => Promise<void>;
  onRecovered: (payload: unknown, signal: AbortSignal) => Promise<void> }) {
  const [records, setRecords] = useState<VaultRecord[] | null>(null), [selected, setSelected] = useState('');
  const [secret, setSecret] = useState(''), [busy, setBusy] = useState<string | null>(null), [error, setError] = useState('');
  const operation = useRef<AbortController | null>(null), autoOpened = useRef(false);
  const unlocked = useRef(onUnlocked);
  unlocked.current = onUnlocked;
  const open = (id: string, run: (signal: AbortSignal) => Promise<UnlockedVault>) => {
    if (busy !== null) return;
    const controller = new AbortController(); operation.current = controller; setBusy(id); setError('');
    void (async () => {
      let vault: UnlockedVault | undefined;
      try {
        vault = await run(controller.signal);
        controller.signal.throwIfAborted();
        setSecret(''); clearDeviceLocked();
        await unlocked.current(vault, controller.signal);
      } catch (error) { vault?.lock(); if (!controller.signal.aborted) setError(message(error, role)); }
      finally { if (!controller.signal.aborted) setBusy(null); }
    })();
  };
  useEffect(() => {
    let active = true;
    const unsubscribe = subscribeDeviceLock(() => operation.current?.abort());
    void browserVaultStore().list().then(all => {
      if (!active) return;
      const mine = all.filter(record => record.role === role);
      setRecords(mine);
      setSelected(mine.find(record => vaultProtection(record) === 'passphrase')?.id ?? '');
    }).catch(error => { if (active) { setRecords([]); setError(message(error, role)); } });
    return () => { active = false; operation.current?.abort(); unsubscribe(); };
  }, [role]);
  // "Keep unlocked on this device": open after sign-in, unless this tab was locked.
  useEffect(() => {
    if (!records || autoOpened.current) return;
    const device = records.filter(record => vaultProtection(record) === 'device');
    if (device.length !== 1 || deviceLockedInThisTab()) return;
    autoOpened.current = true;
    open(device[0].id, signal => unlockDeviceBoundVault(browserVaultStore(), device[0].id, role, signal));
  }, [records, role]); // One automatic attempt; `open` reads current callbacks through refs.

  const list = records ?? [];
  const passphraseRecords = list.filter(record => vaultProtection(record) === 'passphrase');
  const quick = list.filter(record => vaultProtection(record) !== 'passphrase');
  const copy = SAVED_COPY[role];
  if (!showSavedSection(role, records)) return null;
  return <section className="my-6 border border-black/20 p-4" aria-label={copy.label} aria-busy={busy !== null || records === null}>
    <h2 className="font-semibold">{copy.heading}</h2>
    {records === null && <p role="status" className="mt-2 text-sm">{copy.looking}</p>}
    {quick.length > 0 && <ul className="mt-3 space-y-3">
      {quick.map(record => {
        const index = list.indexOf(record), protection = vaultProtection(record);
        return <li key={record.id} className="flex flex-wrap items-center gap-3">
          <span className="text-sm">{savedName(role, index)}</span>
          {protection === 'passkey' ? <button type="button" className={button} disabled={busy !== null} onClick={() => open(record.id, async signal => {
            const { evaluatePasskeyPrf } = await import('@/lib/confidential/passkeyUnlock');
            if (!passkeyCredentialId(record)) throw new Error(copy.damaged);
            return unlockPasskeyVault(browserVaultStore(), record.id, role, (id, salt) => evaluatePasskeyPrf(id, salt, signal), signal);
          })}>{busy === record.id ? 'Waiting for passkey…' : 'Unlock with passkey'}</button>
            : <button type="button" className={button} disabled={busy !== null}
              onClick={() => open(record.id, signal => unlockDeviceBoundVault(browserVaultStore(), record.id, role, signal))}>
              {busy === record.id ? 'Opening…' : 'Open on this device'}</button>}
          {protection === 'device' && deviceLockedInThisTab() && busy === null &&
            <span className="text-sm text-black/60">Locked in this tab.</span>}
        </li>;
      })}
    </ul>}
    {passphraseRecords.length > 0 && <form className="mt-3 space-y-3" onSubmit={event => {
      event.preventDefault();
      if (busy !== null || !selected) return;
      const passphrase = secret;
      open(selected, signal => unlockDeviceVault(browserVaultStore(), selected, role, passphrase, signal));
    }}>
      <label className="block text-sm">{copy.select}
        <select className={field} value={selected} disabled={busy !== null} onChange={event => setSelected(event.target.value)}>
          {passphraseRecords.map(record => <option key={record.id} value={record.id}>{savedName(role, list.indexOf(record))}</option>)}
        </select>
      </label>
      <label className="block text-sm">Device passphrase
        <input type="password" autoComplete="current-password" className={field} value={secret} disabled={busy !== null}
          onChange={event => setSecret(event.target.value)} />
      </label>
      <button className={button} disabled={busy !== null || !secret}>{busy === selected ? 'Unlocking…' : copy.unlock}</button>
      <p className="text-sm">{copy.forgot}</p>
    </form>}
    {records !== null && !list.length && <p className="mt-2 text-sm">{copy.none}</p>}
    {error && <p role="alert" className="mt-3 text-sm">{error}</p>}
    {/* Reporters open older backup files from OtherWaysToOpen, next to the recovery file control. */}
    {role === 'legal' && <WorkspaceBackupImport role={role} onRecovered={onRecovered} />}
    <ForgetDevice role={role} />
  </section>;
}

type Method = VaultProtection;
const METHOD_TEXT: Record<Method, string> = {
  passkey: 'Opens with your passkey',
  device: 'Opens on this device after you sign in',
  passphrase: 'Opens with your device passphrase',
};

/** Legal organizations choose how this browser opens their workspace next time.
 * OwnerDevicePanel presents the reporter’s separate device choices. */
function MethodChooser({ role, organizationDomain, busy, onCreate, onCancel }: {
  role: VaultRole; organizationDomain?: string; busy: boolean;
  onCreate: (method: Method, passphrase: string) => void; onCancel: () => void;
}) {
  const [support, setSupport] = useState<'supported' | 'unsupported' | 'unknown' | null>(role === 'legal' ? null : 'unsupported');
  const [method, setMethod] = useState<Method>(role === 'legal' ? 'passkey' : 'passphrase');
  const [secret, setSecret] = useState(''), [confirmation, setConfirmation] = useState('');
  useEffect(() => {
    if (role !== 'legal') return;
    let active = true;
    void import('@/lib/confidential/passkeyUnlock').then(module => module.passkeyPrfSupport()).catch(() => 'unsupported' as const)
      .then(result => { if (!active) return; setSupport(result); if (result === 'unsupported') setMethod('passphrase'); });
    return () => { active = false; };
  }, [role]);
  const options: { value: Method; title: string; text: string }[] = role === 'legal' ? [
    ...(support !== 'unsupported' ? [{ value: 'passkey' as const, title: 'Passkey (recommended)',
      text: 'Unlock with Touch ID, Windows Hello, your phone or a security key. VERA does not receive your passkey. Your device or password manager may sync it.' }] : []),
    { value: 'device', title: 'Keep unlocked on this device',
      text: 'No prompt after you sign in. Anyone who can use this browser profile can open your organization key, so choose this only on a computer that only you use and that locks when you step away.' },
    { value: 'passphrase', title: 'Device passphrase', text: 'Type a separate passphrase each time.' },
  ] : [];
  const ready = method !== 'passphrase' || (passphraseProblem(secret) === null && secret === confirmation);
  return <form className="mt-3 space-y-3" onSubmit={event => {
    event.preventDefault(); if (busy || !ready) return;
    const passphrase = secret;
    setSecret(''); setConfirmation('');
    onCreate(method, passphrase);
  }}>
    {role === 'legal' && <fieldset className="space-y-2">
      <legend className="mb-1 text-sm font-semibold">How should this browser open your organization workspace next time?</legend>
      {support === null && <p role="status" className="text-sm">Checking passkey support…</p>}
      {options.map(option => <label key={option.value} className="flex gap-3 border border-black/10 p-3 text-sm">
        <input type="radio" name="device-method" value={option.value} checked={method === option.value} disabled={busy}
          onChange={() => setMethod(option.value)} className="mt-1" />
        <span><span className="block font-semibold">{option.title}</span><span className="block text-black/70">{option.text}</span></span>
      </label>)}
      {support === 'unsupported' && <p className="text-sm text-black/60">This browser cannot unlock with a passkey. Your key file and recovery code remain the backup either way.</p>}
    </fieldset>}
    {method === 'passphrase' && <>
      <p className="text-sm">Choose a unique passphrase. {PASSPHRASE_GUIDANCE} You will use it to unlock this browser on return.
        Save it separately. VERA cannot reset it. Browser storage can be cleared or lost.</p>
      <label className="block text-sm">New device passphrase<input type="password" autoComplete="new-password" className={field}
        value={secret} disabled={busy} onChange={event => setSecret(event.target.value)} /></label>
      <label className="block text-sm">Confirm device passphrase<input type="password" autoComplete="new-password" className={field}
        value={confirmation} disabled={busy} onChange={event => setConfirmation(event.target.value)} /></label>
      {secret.length > 0 && confirmation.length > 0 && secret !== confirmation && <p className="text-sm">The passphrases do not match.</p>}
    </>}
    {method === 'passkey' && <p className="text-sm">Your browser will ask you to create a passkey named “VERA legal ({organizationDomain ?? 'your organization'})”, and may ask you to use it once more.</p>}
    <div className="flex flex-wrap items-center gap-3">
      <button className={button} disabled={busy || !ready}>{busy ? 'Saving encrypted workspace…'
        : method === 'passkey' ? 'Create passkey and save' : method === 'device' ? 'Keep unlocked on this device' : 'Save encrypted workspace'}</button>
      <button type="button" className="underline" disabled={busy} onClick={onCancel}>Use temporarily</button>
    </div>
  </form>;
}

/** Legal organizations only. Reporters use OwnerDevicePanel (OwnerDevice.tsx), whose
 * single choice and recovery-file backup avoid a second "workspace" concept. */
export function RememberWorkspace({ role, getPayload, vault, onRemembered, organizationDomain, onBackedUp }: { role: VaultRole;
  getPayload: () => Promise<unknown>; vault: UnlockedVault | null; onRemembered: (vault: UnlockedVault) => void;
  organizationDomain?: string;
  /** Called once an encrypted backup file of this workspace has been handed to the browser to save. */
  onBackedUp?: () => void }) {
  const [saving, setSaving] = useState(false), [show, setShow] = useState(false), [error, setError] = useState('');
  const [backupSecret, setBackupSecret] = useState(''), [backupConfirmation, setBackupConfirmation] = useState('');
  const operation = useRef<AbortController | null>(null);
  useEffect(() => () => operation.current?.abort(), []);
  const create = (method: Method, passphrase: string) => {
    const controller = new AbortController(); operation.current = controller; setSaving(true); setError('');
    void (async () => {
      try {
        const payload = await getPayload(); controller.signal.throwIfAborted();
        const store = browserVaultStore();
        let saved: UnlockedVault;
        if (method === 'passkey') {
          const { createPasskeySecret, forgetPasskey } = await import('@/lib/confidential/passkeyUnlock');
          const secret = await createPasskeySecret({ organizationDomain: organizationDomain ?? 'organization', signal: controller.signal });
          try { saved = await createPasskeyVault(store, role, payload, secret, controller.signal); }
          catch (caught) { await forgetPasskey(secret.credentialId); throw caught; }
          finally { secret.prfOutput.fill(0); }
        } else if (method === 'device') {
          saved = await createDeviceBoundVault(store, role, payload, controller.signal);
        } else saved = await createDeviceVault(store, role, passphrase, payload, controller.signal);
        clearDeviceLocked(); setShow(false); onRemembered(saved);
      } catch (error) { if (!controller.signal.aborted) setError(message(error)); }
      finally { if (!controller.signal.aborted) setSaving(false); }
    })();
  };
  const portable = !vault || vault.protection === 'passphrase';
  const backupReady = portable || (passphraseProblem(backupSecret) === null && backupSecret === backupConfirmation);
  return <section className="mt-6 border border-black/20 p-4" aria-label="Device workspace">
    <h3 className="font-semibold">This device</h3>
    <p className="my-2 text-sm" aria-live="polite">{vault ? `An encrypted copy is saved in this browser. ${METHOD_TEXT[vault.protection]}. Keep an independent recovery backup.` :
      'You are using this workspace temporarily. Remember it only on a device you trust.'}</p>
    {!vault && !show && <button type="button" className={button} onClick={() => setShow(true)}>
      {role === 'legal' ? 'Keep this workspace on this device' : 'Remember this workspace'}</button>}
    {show && !vault && <MethodChooser role={role} organizationDomain={organizationDomain} busy={saving} onCreate={create}
      onCancel={() => { operation.current?.abort(); setShow(false); setSaving(false); }} />}
    {error && <p role="alert" className="mt-3 text-sm">{error}</p>}
    {!vault && <TemporaryWorkspaceBackup role={role} getPayload={getPayload} onBackedUp={onBackedUp} />}
    {vault && !portable && <div className="mt-3 space-y-3">
      <p className="text-sm">This saved copy only opens in this browser. To move your workspace to another device, download a backup protected by a separate backup passphrase.</p>
      <label className="block text-sm">Backup passphrase<input type="password" autoComplete="new-password" className={field}
        value={backupSecret} disabled={saving} onChange={event => setBackupSecret(event.target.value)} /></label>
      <label className="block text-sm">Confirm backup passphrase<input type="password" autoComplete="new-password" className={field}
        value={backupConfirmation} disabled={saving} onChange={event => setBackupConfirmation(event.target.value)} /></label>
    </div>}
    {vault && <button type="button" className={`${button} mt-3 block`} disabled={saving || !backupReady} onClick={() => {
      setSaving(true); setError('');
      const passphrase = backupSecret;
      void (async () => {
        try {
          const payload = await getPayload();
          let saved = true;
          try { await vault.save(payload); } catch { saved = false; }
          const text = await vault.exportBackup(payload, portable ? undefined : passphrase);
          setBackupSecret(''); setBackupConfirmation('');
          if (!saved) setError('This download contains the open workspace, but it was not saved in this browser. Another tab may have newer history. Keep the backup and resolve the device-storage conflict before relying on the saved copy.');
          const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
          const link = document.createElement('a'); link.href = url; link.download = `vera-${role}-workspace.json`;
          document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
          onBackedUp?.();
        } catch (error) { setError(message(error)); }
        finally { setSaving(false); }
      })();
    }}>Download encrypted workspace backup</button>}
    {vault && <p className="mt-2 text-sm">Includes recovery keys and saved report references, not evidence files.
      {portable ? ' Unlock it on another device with this workspace’s device passphrase. Keep that passphrase separately.'
        : ' Unlock it on another device with the backup passphrase. Keep that passphrase separately.'}</p>}
    <p className="mt-3 text-sm">Locking clears open confidential tabs, including unsaved drafts and recovery codes. Save your backup first.</p>
    <button type="button" className="mt-3 underline text-sm" onClick={lockParticipantTabs}>Lock workspace</button>
    <ForgetDevice role={role} />
  </section>;
}

function TemporaryWorkspaceBackup({ role, getPayload, onBackedUp }: { role: VaultRole; getPayload: () => Promise<unknown>;
  onBackedUp?: () => void }) {
  const [secret, setSecret] = useState(''), [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const operation = useRef<AbortController | null>(null);
  useEffect(() => () => operation.current?.abort(), []);
  return <details className="mt-3 text-sm">
    <summary className="cursor-pointer underline">Back up this temporary workspace</summary>
    <form className="mt-3 space-y-3" onSubmit={event => {
      event.preventDefault(); if (busy || secret !== confirmation) return;
      const controller = new AbortController(); operation.current = controller; setBusy(true); setError('');
      void (async () => {
        try {
          const payload = await getPayload(); controller.signal.throwIfAborted();
          const text = await exportTemporaryWorkspace(role, secret, payload, controller.signal);
          controller.signal.throwIfAborted();
          const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
          const link = document.createElement('a'); link.href = url; link.download = `vera-${role}-workspace.json`;
          document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
          setSecret(''); setConfirmation(''); onBackedUp?.();
        } catch (error) { if (!controller.signal.aborted) setError(message(error)); }
        finally { if (!controller.signal.aborted) setBusy(false); }
      })();
    }}>
      <p>Includes your keys, report references and history checks, not evidence files. Nothing is saved in browser storage.
        {PASSPHRASE_GUIDANCE} Keep the passphrase separately. Restore using “Restore an encrypted workspace backup”.</p>
      <label className="block">Backup passphrase<input type="password" autoComplete="new-password" className={field}
        value={secret} disabled={busy} onChange={event => setSecret(event.target.value)} /></label>
      <label className="block">Confirm backup passphrase<input type="password" autoComplete="new-password" className={field}
        value={confirmation} disabled={busy} onChange={event => setConfirmation(event.target.value)} /></label>
      <button className={button} disabled={busy || passphraseProblem(secret) !== null || secret !== confirmation}>
        {busy ? 'Encrypting backup…' : 'Download temporary workspace backup'}</button>
      {error && <p role="alert">{error}</p>}
    </form>
  </details>;
}

const IMPORT_COPY: Record<VaultRole, { summary: string; intro: string; tooLarge: string; file: string; secret: string; submit: string }> = {
  // Reporters no longer download these; this only opens backups saved before.
  owner: { summary: 'Open an older encrypted backup file', intro: 'Only for a backup file downloaded from an earlier version of this page. Your recovery file opens above. The file is read locally and nothing is saved on this device.',
    tooLarge: 'This backup file is too large', file: 'Encrypted backup file', secret: 'Backup passphrase', submit: 'Open backup' },
  legal: { summary: 'Restore an encrypted workspace backup', intro: 'The file is read locally. Restoring does not automatically remember this device.',
    tooLarge: 'This workspace file is too large', file: 'Encrypted workspace file', secret: 'Backup’s device passphrase', submit: 'Restore workspace' },
};

/** Reporters: the older backup-file importer, tucked behind one small disclosure
 * so it does not compete with the recovery code and recovery file controls. */
export function OtherWaysToOpen({ onRecovered }: { onRecovered: (payload: unknown, signal: AbortSignal) => Promise<void> }) {
  return <details className="mt-4 text-sm">
    <summary className="cursor-pointer underline">Other ways to open</summary>
    <div className="mt-3">
      <h3 className="font-semibold">{IMPORT_COPY.owner.summary}</h3>
      <BackupImportForm role="owner" onRecovered={onRecovered} />
    </div>
  </details>;
}

function WorkspaceBackupImport({ role, onRecovered }: { role: VaultRole;
  onRecovered: (payload: unknown, signal: AbortSignal) => Promise<void> }) {
  return <details className="mt-4 text-sm">
    <summary className="cursor-pointer underline">{IMPORT_COPY[role].summary}</summary>
    <BackupImportForm role={role} onRecovered={onRecovered} />
  </details>;
}

function BackupImportForm({ role, onRecovered }: { role: VaultRole;
  onRecovered: (payload: unknown, signal: AbortSignal) => Promise<void> }) {
  const copy = IMPORT_COPY[role];
  const [file, setFile] = useState<File | null>(null), [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const operation = useRef<AbortController | null>(null);
  useEffect(() => () => operation.current?.abort(), []);
  return <form className="mt-3 space-y-3" onSubmit={event => {
      event.preventDefault(); if (!file || busy) return;
      const controller = new AbortController(); operation.current = controller; setBusy(true); setError('');
      void (async () => {
        try {
          if (file.size > 1500 * 1024) throw new Error(copy.tooLarge);
          const value = await readVaultBackup(await file.text(), role, secret, controller.signal);
          controller.signal.throwIfAborted(); setSecret('');
          await onRecovered(value, controller.signal);
        } catch (error) { if (!controller.signal.aborted) setError(message(error, role)); }
        finally { if (!controller.signal.aborted) setBusy(false); }
      })();
    }}>
      <p>{copy.intro}</p>
      <label className="block">{copy.file}<input className="mt-1 block" type="file" accept=".json,application/json" disabled={busy}
        onChange={event => setFile(event.target.files?.[0] ?? null)} /></label>
      <label className="block">{copy.secret}<input className={field} type="password" autoComplete="off" value={secret} disabled={busy}
        onChange={event => setSecret(event.target.value)} /></label>
      <button className={button} disabled={busy || !file || !secret}>{busy ? 'Restoring…' : copy.submit}</button>
      {error && <p role="alert">{error}</p>}
    </form>;
}
