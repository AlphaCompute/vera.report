import { useEffect, useRef, useState } from 'react';
import { Download } from 'lucide-react';
import { RECOVERY_FILE_NAME } from '@/lib/confidential/recoveryFile';

type SavePicker = (options: { suggestedName: string; types: { description: string; accept: Record<string, string[]> }[] }) => Promise<{
  createWritable(): Promise<{ write(data: string): Promise<void>; close(): Promise<void>; abort(): Promise<void> }>;
}>;
type Prepared = { source: () => string | Promise<string>; text: string; url: string };

/** Keep the local download alive until this recovery copy changes or is closed.
 * The picker opens directly from the click, before any asynchronous preparation.
 * A successful save does not establish that the user can restore the file. */
export function RecoveryFileDownload({ prepare, className, onDownload }: {
  prepare: () => string | Promise<string>; className: string; onDownload?: () => void;
}) {
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [notice, setNotice] = useState<{ source: Prepared['source']; text: string; failed?: boolean } | null>(null);
  const [pending, setPending] = useState(false);
  const source = useRef(prepare);
  source.current = prepare;
  const current = prepared?.source === prepare ? prepared : null;
  const message = notice?.source === prepare ? notice : null;
  useEffect(() => {
    let cancelled = false, url: string | undefined;
    source.current = prepare;
    void Promise.resolve().then(prepare).then(text => {
      if (cancelled) return;
      url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
      setPrepared({ source: prepare, text, url });
    }).catch(() => {
      if (!cancelled) setNotice({ source: prepare, failed: true,
        text: 'The recovery file could not be prepared. Keep this page open and try again.' });
    });
    return () => {
      cancelled = true;
      if (source.current === prepare) source.current = () => '';
      if (url) URL.revokeObjectURL(url);
    };
  }, [prepare]);

  const saveAs = async (backup: Prepared, picker: SavePicker) => {
    setPending(true);
    setNotice({ source: prepare, text: 'Choose where to save your private recovery file.' });
    let writer: Awaited<ReturnType<Awaited<ReturnType<SavePicker>>['createWritable']>> | undefined;
    try {
      const handle = await picker.call(window, { suggestedName: RECOVERY_FILE_NAME,
        types: [{ description: 'Private Vera report recovery file', accept: { 'text/plain': ['.txt'] } }] });
      // Locking or changing reports invalidates a picker that is still open.
      if (source.current !== backup.source) return;
      writer = await handle.createWritable();
      if (source.current !== backup.source) { await writer.abort(); return; }
      await writer.write(backup.text);
      if (source.current !== backup.source) { await writer.abort(); return; }
      await writer.close();
      if (source.current !== backup.source) return;
      onDownload?.();
      setNotice({ source: backup.source, text: 'Recovery file saved. Keep it private and check that your saved copy opens this report.' });
    } catch (caught) {
      await writer?.abort().catch(() => {});
      const cancelled = caught instanceof DOMException && caught.name === 'AbortError';
      if (source.current === backup.source) setNotice({ source: backup.source, failed: !cancelled, text: cancelled
        ? 'Save cancelled. Choose Download recovery file to try again.'
        : 'This browser could not save the file. Use the download alternatives below.' });
    } finally { setPending(false); }
  };

  return <div>
    {current ? <a role="button" className={className} href={current.url} download={RECOVERY_FILE_NAME} rel="noopener"
      aria-disabled={pending || undefined} onClick={event => {
        if (pending) { event.preventDefault(); return; }
        const picker = (window as Window & { showSaveFilePicker?: SavePicker }).showSaveFilePicker;
        if (picker) { event.preventDefault(); void saveAs(current, picker); }
        else { onDownload?.(); setNotice({ source: prepare, text: 'Download requested. If no file appears, use the download alternatives below.' }); }
      }} onKeyDown={event => { if (event.key === ' ') { event.preventDefault(); event.currentTarget.click(); } }}>
      <Download className="size-[14px]" aria-hidden />Download recovery file
    </a> : <button type="button" className={className} disabled>Preparing recovery file…</button>}
    {message && <p role={message.failed ? 'alert' : 'status'} className="mt-3 text-sm">{message.text}</p>}
    {current && <details className="mt-3 text-sm">
      <summary className="cursor-pointer underline">Download not starting? Save a copy manually</summary>
      <p className="my-3"><a className="underline" href={current.url} download={RECOVERY_FILE_NAME} rel="noopener" onClick={onDownload}>Use browser download instead</a></p>
      <p className="my-3">Save all the text below in a plain-text file named <strong>{RECOVERY_FILE_NAME}</strong>.
        This file includes your recovery code. Anyone with it can open your report. Keep it private, then open the saved file to check it.</p>
      <label className="block">Private recovery file contents
        <textarea aria-label="Private recovery file contents" readOnly spellCheck={false} autoComplete="off" rows={6} value={current.text}
          onFocus={event => event.currentTarget.select()} className="mt-2 block w-full border border-black/30 p-2 font-mono text-xs" />
      </label>
    </details>}
  </div>;
}
