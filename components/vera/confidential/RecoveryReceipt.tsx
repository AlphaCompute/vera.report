import { useParticipantLock } from './DeviceWorkspaces';
import { OwnerDevicePanel } from './OwnerDevice';
import type { UnlockedVault } from '@/lib/confidential/deviceVault';
import { useCallback, useState } from "react";
import { RecoveryCodeCard } from './RecoveryCodeCard';
import { recoveryFileText } from '@/lib/confidential/recoveryFile';

type Props = { recoveryCode: string; recoveryPackage: string; onSaved: () => void };

/** Participant-only recovery credential. It is never sent to VERA; only this page shows it. */
export function RecoveryReceipt({ recoveryCode, recoveryPackage, onSaved }: Props) {
  const [verified, setVerified] = useState(false);
  const [vault, setVault] = useState<UnlockedVault | null>(null);
  // Preserve the only recovery copy against automatic locks until verified.
  // An explicit Lock or Forget request still clears this tab.
  useParticipantLock('/status', verified, verified);
  const [checking, setChecking] = useState(false);
  const [backupError, setBackupError] = useState(false);
  const prepareDownload = useCallback(() =>
    recoveryFileText({ recoveryCode, recoveryPackage, statusUrl: `${window.location.origin}/status` }), [recoveryCode, recoveryPackage]);
  const verify = async (file: File) => {
    setChecking(true); setBackupError(false);
    try {
      const { verifyOwnerBackup } = await import('@/lib/confidential/backupVerification');
      await verifyOwnerBackup(file, recoveryCode, recoveryPackage);
      setVerified(true); onSaved();
    } catch { setBackupError(true); }
    finally { setChecking(false); }
  };
  return (
    <div className="mb-6">
      <RecoveryCodeCard recoveryCode={recoveryCode} prepareDownload={prepareDownload} />
      <p className="mb-4 text-sm font-bold text-red-800">NOT CONFIDENTIAL: VERA staff and approved legal organizations can see your summary, submission time and whether
        you included attachments. File names, contents and contact details stay encrypted.</p>
      <div className="border border-red-700 bg-red-50 p-4">
        <p className="mb-2 font-bold text-red-800">Before leaving or closing this page, save your recovery code. Without a saved copy or saved device access, you permanently lose access to this report. VERA cannot reset or recover it.</p>
        <p className="text-red-800">
          It is the only way to read your report, see requests from legal organizations and decide who may access it.
          Treat it like a password. Write it down, print the recovery sheet or download the recovery file. Do not save it on a shared computer.
        </p>
        <p className="mt-4 font-semibold">Check your backup before leaving</p>
        <p className="mt-2 text-sm">
          Download the recovery file and save it somewhere you control, then select it below to check that it opens this report.
          The file is checked on this device and is not uploaded. Copying the code alone is not an offline backup.
          Browser storage is not a substitute for this file.
        </p>
        <label className="mt-3 block text-sm">
          <span className="mb-2 block">Select your saved recovery file</span>
          <input type="file" accept=".txt,text/plain" disabled={checking || verified} onChange={event => {
            const file = event.target.files?.[0]; event.target.value = '';
            if (file) void verify(file);
          }} />
        </label>
        {checking && <p role="status" className="mt-3">Checking your backup…</p>}
        {verified && <p role="status" className="mt-3">Backup verified. Keep it safe: anyone with this file can act as you.</p>}
        {backupError && <p role="alert" className="mt-3">That file did not restore this report. Download the recovery file and try again.</p>}
      </div>
      {verified && <OwnerDevicePanel className="mt-6 border border-black/10 p-6" vault={vault} onVaultChange={setVault} getPayload={async () => {
        const { restoreOwnerRecovery } = await import('@/enclave/src/confidential/recovery');
        const restored = await restoreOwnerRecovery(recoveryCode, recoveryPackage);
        return { format: 'vera-owner-workspace/v1', recoveryCode, recoveryPackage, pin: restored.pin };
      }} />}
    </div>
  );
}
