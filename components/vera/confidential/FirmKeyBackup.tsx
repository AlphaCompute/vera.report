import { useEffect, useState } from 'react';
import { exportFirmIdentity } from '@/lib/confidential/firmKey';
import type { FirmIdentity } from '@/lib/confidential/firmKey';
import { safeDownloadName } from '@/lib/confidential/safeDownload';
import { userFacingMessage } from '@/lib/confidential/userFacingError';

type SavePicker = (options: { suggestedName: string; types: { description: string; accept: Record<string, string[]> }[] }) => Promise<{
  createWritable(): Promise<{ write(data: string): Promise<void>; close(): Promise<void>; abort(): Promise<void> }>;
}>;
type PreparedBackup = { firm: FirmIdentity; secret: string; text: string; url: string };

/** Prepare the encrypted export before the click, and keep its URL alive until
 * the key/code changes or this screen unmounts. Embedded browsers may consume a
 * download asynchronously; a short-lived programmatic link can disappear first.
 * Only encrypted export text is offered by the manual-save fallback.
 * `verifyStep` is false where no saved-copy check follows on the same screen. */
export function FirmKeyBackup({ firm, secret, className, verifyStep = true }: {
  firm: FirmIdentity; secret: string; className: string; verifyStep?: boolean;
}) {
  const [prepared, setPrepared] = useState<PreparedBackup | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [save, setSave] = useState<{ backup: PreparedBackup; pending: boolean; message: string; failed?: boolean } | null>(null);
  const filename = safeDownloadName(`vera-legal-key-PRIVATE-${firm.domain}.txt`);
  const current = prepared?.firm === firm && prepared.secret === secret ? prepared : null;
  const result = save?.backup === current ? save : null;
  useEffect(() => {
    let cancelled = false, url: string | undefined;
    setError(null);
    const timer = setTimeout(() => {
      void exportFirmIdentity(firm, secret).then(text => {
        if (cancelled) return;
        url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
        setPrepared({ firm, secret, text, url });
      }).catch(caught => {
        if (!cancelled) setError(userFacingMessage(caught, 'The encrypted key file could not be prepared.'));
      });
    }, 150);
    return () => { cancelled = true; clearTimeout(timer); if (url) URL.revokeObjectURL(url); };
  }, [firm, secret]);
  const saveAs = async (backup: PreparedBackup, picker: SavePicker) => {
    setSave({ backup, pending: true, message: 'Choose where to save your encrypted key file.' });
    try {
      // Open the picker before awaiting anything: it requires the actual click's
      // user activation. Write only the already-encrypted export, on this device.
      const handle = await picker.call(window, { suggestedName: filename,
        types: [{ description: 'Encrypted Vera key backup', accept: { 'text/plain': ['.txt'] } }] });
      const writer = await handle.createWritable();
      try { await writer.write(backup.text); await writer.close(); }
      catch (caught) { await writer.abort().catch(() => {}); throw caught; }
      setSave({ backup, pending: false, message: verifyStep
        ? 'Encrypted key file saved. Check it with your saved recovery code below.'
        : 'Encrypted key file saved. Keep your recovery code separately from it.' });
    } catch (caught) {
      const cancelled = caught instanceof DOMException && caught.name === 'AbortError';
      setSave({ backup, pending: false, failed: !cancelled, message: cancelled
        ? 'Save cancelled. Choose Download encrypted key file to try again.'
        : 'This browser could not save the file. Open the download alternatives below to save your encrypted backup.' });
    }
  };
  return <>
    {current ? <a role="button" className={className} href={current.url} download={filename} rel="noopener"
      aria-disabled={result?.pending || undefined}
      onClick={event => {
        if (result?.pending) { event.preventDefault(); return; }
        const picker = (window as Window & { showSaveFilePicker?: SavePicker }).showSaveFilePicker;
        if (picker) { event.preventDefault(); void saveAs(current, picker); }
        else setSave({ backup: current, pending: false,
          message: 'Download requested. If no file appears, use the download alternatives below.' });
      }}
      onKeyDown={event => { if (event.key === ' ') { event.preventDefault(); event.currentTarget.click(); } }}>
      Download encrypted key file
    </a> : <button type="button" className={className} disabled>Preparing encrypted key file…</button>}
    {result && <p role={result.failed ? 'alert' : 'status'} className="mt-3 text-sm">{result.message}</p>}
    {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
    {current && <details className="mt-4 text-sm">
      <summary className="cursor-pointer underline">Download not starting? Save a copy manually</summary>
      <p className="my-3"><a href={current.url} download={filename} rel="noopener" className="underline">Use browser download instead</a></p>
      <p className="my-3">Copy all the encrypted text below into a plain-text file named <strong>{filename}</strong>.
        Keep your recovery code separate.{verifyStep && ' Select the saved file below to verify it before continuing.'}</p>
      <label className="block">Encrypted key backup
        <textarea aria-label="Encrypted key backup" readOnly spellCheck={false} autoComplete="off" rows={6} value={current.text}
          onFocus={event => event.currentTarget.select()}
          className="mt-2 block w-full border border-black/30 p-2 font-mono text-xs" />
      </label>
    </details>}
  </>;
}
