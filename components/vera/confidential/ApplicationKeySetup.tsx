import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { ArrowRight, Check, CheckCircle2, Clock3, FileKey2, KeyRound, ShieldCheck } from 'lucide-react';
import { FirmKeyBackup } from './FirmKeyBackup';
import { LegalPortalLayout } from './LegalPortal';
import { canonicalFirmProfile, FIRM_PRACTICE_AREAS } from '@/enclave/src/confidential/firmProfile';
import type { FirmIdentity } from '@/lib/confidential/firmKey';
import type { LegalApplicationInput } from '@/src/utils/legalApplications';
import { LEGAL_APPLICATION_INTAKE_CLOSED, legalApplicationIntakeClosedCode } from '@/src/utils/legalApplications';
import { legalAuthConfig, legalSignedIn, legalSetupContext, renewLegalSignIn } from '@/lib/confidential/legalAuth';
import { useReceiptNavigationGuard } from '@/lib/useReceiptNavigationGuard';
import { APPLICATION_DRAFT_KEY } from '@/lib/legalApplicationDraft';
import { AlertDialog, AlertDialogContent, AlertDialogTitle, AlertDialogDescription } from '@/components/ui/alert-dialog';
import styles from './LegalOnboarding.module.css';

/** Key generation precedes the single firm/key approval. Only the self-signed
 * PUBLIC document leaves this component; key and recovery code stay in memory. */
export function ApplicationKeySetup({ application, onBack }: { application: LegalApplicationInput; onBack: () => void }) {
  const router = useRouter();
  const [firm, setFirm] = useState<FirmIdentity | null>(null), [secret, setSecret] = useState('');
  const [saved, setSaved] = useState(false), [file, setFile] = useState<File | null>(null), [checkSecret, setCheckSecret] = useState('');
  const [backupError, setBackupError] = useState(''), [checkingFile, setCheckingFile] = useState(false);
  const fileSelection = useRef(0);
  const backupErrorRef = useRef<HTMLParagraphElement>(null);
  useEffect(() => { if (backupError) backupErrorRef.current?.scrollIntoView({ block: 'nearest' }); }, [backupError]);
  const [areas, setAreas] = useState<string[]>([]), [website, setWebsite] = useState(`https://${application.domain}/`);
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [submitted, setSubmitted] = useState(false);
  const [showSecret, setShowSecret] = useState(false), [locked, setLocked] = useState(false);
  const submission = useRef<string | null>(null);
  const [status, setStatus] = useState<{ state: string; providerOrganizationId?: string }>({ state: 'pending' });
  const approved = status.state === 'ready' || status.state === 'sign-in-ready';
  const attempt = useRef(false);
  const guard = useReceiptNavigationGuard(router, !!firm && !saved);
  useEffect(() => {
    if (!submitted || !firm) return;
    let alive = true, pending = false;
    const check = async () => {
      if (pending || document.visibilityState !== 'visible') return;
      pending = true;
      try {
        const response = await fetch('/api/legal-applications/status', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: firm.organizationId }), signal: AbortSignal.timeout(10000) });
        if (response.ok && alive) setStatus(await response.json());
      } catch { /* Keep the saved key; a temporary outage is not a denial. */ }
      finally { pending = false; }
    };
    void check(); const timer = setInterval(() => void check(), 15000);
    return () => { alive = false; clearInterval(timer); };
  }, [submitted, firm]);
  const activate = async (interactive: boolean) => {
    if (!firm || !saved || !approved || !status.providerOrganizationId || attempt.current) return;
    const base = legalAuthConfig();
    if (!base) { setError('Legal sign-in is not configured. Your saved key is still valid.'); return; }
    const config = { ...base, organization: status.providerOrganizationId };
    const sameAccount = legalSignedIn() && legalSetupContext(config)?.organizationId === firm.organizationId;
    if (!sameAccount && !interactive) return;
    attempt.current = true; setBusy(true); setError('');
    try {
      if (!sameAccount) await renewLegalSignIn(config, { firstSignIn: status.state === 'sign-in-ready' });
      const { waitForCombinedActivation } = await import('@/lib/confidential/combinedEnrollment');
      await waitForCombinedActivation(config, firm);
      await router.push('/legal');
    } catch { setError('Activation could not be confirmed. Keep this page open and retry. Approval never requires sharing your private file or recovery code.'); }
    finally { attempt.current = false; setBusy(false); }
  };
  useEffect(() => { if (status.state === 'ready') void activate(false); }, [status.state]); // One automatic attempt; retries use the button.
  return <LegalPortalLayout title={submitted ? 'Waiting for approval.' : 'Protect your organization key.'} onboarding backHref="/legal"
    intro="One review approves your organization and this specific key. Your private key stays on your device.">
    <div className={styles.applicationSetup}>
    <div className={styles.organization}>
      <strong>{application.displayName}</strong><span>{application.domain}</span>
      <span className={styles.pill}><ShieldCheck size={14} aria-hidden />Private key stays on this device</span>
    </div>
    <ol className={styles.applicationSteps} aria-label="Application progress">
      {['Application details', 'Protect your key', 'Staff review'].map((label, index) => <li key={label}
        aria-current={index === (submitted ? 2 : 1) ? 'step' : undefined}>
        <span className={styles.stepNumber}>{index < (submitted ? 2 : 1) ? <Check size={14} aria-hidden /> : `0${index + 1}`}</span>
        <span>{label}</span>
      </li>)}
    </ol>
    <section className={styles.card}>
      {!firm ? <>
        <div className={styles.keyIntro}><span className={styles.statusIcon}><KeyRound size={26} aria-hidden /></span>
          <div><p className={styles.eyebrow}>YOUR PRIVATE BACKUP</p><h2>Create your organization’s key.</h2>
            <p className={styles.muted}>Vera generates it on this device. Save the encrypted file and recovery code separately, then check both before submitting.</p></div></div>
        <div className={styles.actions}>
        <button className={styles.primary} disabled={busy} onClick={async () => {
          setBusy(true); setError('');
          try {
            const keys = await import('@/lib/confidential/firmKey');
            setFirm(await keys.generateApplicationIdentity(application.domain)); setSecret(keys.generateFirmRecoveryCode());
          } catch { setError('Your key could not be generated. Try again.'); } finally { setBusy(false); }
        }}>{busy ? 'Creating…' : 'Create key'} <ArrowRight size={16} aria-hidden /></button>
        <button className={styles.secondary} onClick={onBack} disabled={busy}>Back to application</button>
        </div>
      </> : <>
        {!submitted && <>
          <div className={styles.sectionHeading}><p className={styles.eyebrow}>STEP 02 · PROTECT YOUR KEY</p>
            <h2>Save a backup you can rely on.</h2><p className={styles.muted}>You need both saved copies to recover access. Vera cannot replace a lost key.</p></div>
          <div className={styles.backupGrid}>
          <div className={styles.backupTile}>
          <FileKey2 size={22} className={styles.tileIcon} aria-hidden /><h3>1. Save the encrypted file</h3>
          <p>Choose a private location on your device or secure storage.</p>
          <FirmKeyBackup firm={firm} secret={secret} className={styles.secondary} />
          </div>
          <div className={styles.backupTile}>
          <KeyRound size={22} className={styles.tileIcon} aria-hidden /><h3>2. Save the recovery code</h3>
          <p>Keep it separately from the file. Never send either copy to staff.</p>
          <label className={styles.field}>Recovery code — save separately<input type={showSecret ? 'text' : 'password'} readOnly value={secret} autoComplete="off" spellCheck={false} /></label>
          <button className={styles.textButton} aria-pressed={showSecret} onClick={() => setShowSecret(value => !value)}>{showSecret ? 'Hide recovery code' : 'Show recovery code'}</button>
          </div></div>
          {!saved ? <div className={styles.backupCheck}>
            <h3>3. Check your saved copies</h3><p className={styles.muted}>Reopen the saved file and enter the code from your separate copy. Both are checked on this device.</p>
            <div className={styles.formGrid}>
            <label className={styles.field}>Saved encrypted key file<input type="file" accept=".txt,text/plain" disabled={busy}
              aria-invalid={!!backupError} aria-describedby={backupError ? 'backup-check-error' : undefined}
              onChange={async e => {
                const selected = e.target.files?.[0] ?? null, selection = ++fileSelection.current;
                setFile(null); setBackupError(''); setCheckingFile(!!selected);
                if (!selected) return;
                try {
                  const { checkFirmBackupFile } = await import('@/lib/confidential/backupVerification');
                  await checkFirmBackupFile(selected, firm);
                  if (selection === fileSelection.current) setFile(selected);
                } catch (cause) {
                  if (selection === fileSelection.current) setBackupError(cause instanceof Error ? cause.message : 'The file could not be checked. Choose it again.');
                } finally { if (selection === fileSelection.current) setCheckingFile(false); }
              }} /></label>
            <label className={styles.field}>Saved recovery code<input type="password" value={checkSecret} autoComplete="off" disabled={busy}
              aria-invalid={!!backupError} aria-describedby={backupError ? 'backup-check-error' : undefined}
              onChange={e => { setCheckSecret(e.target.value); if (file) setBackupError(''); }} /></label>
            </div>
            <button className={styles.secondary} disabled={busy || checkingFile || !file || !checkSecret} onClick={async () => {
              if (!file) return; setBusy(true); setBackupError('');
              try { const { verifyFirmBackup } = await import('@/lib/confidential/backupVerification'); await verifyFirmBackup(file, checkSecret, firm);
                setSaved(true); setCheckSecret(''); setFile(null); setShowSecret(false);
              } catch { setBackupError('That file and recovery code do not restore this key. Check both saved copies and try again.'); } finally { setBusy(false); }
            }}>{busy ? 'Verifying…' : 'Verify saved backup'}</button>
            {checkingFile && <p role="status">Checking selected file…</p>}
            {backupError && <p ref={backupErrorRef} id="backup-check-error" role="alert" className={styles.error}>{backupError}</p>}
          </div> : <div className={styles.notice + ' ' + styles.success} role="status"><CheckCircle2 size={20} aria-hidden />
            <div><strong>Backup verified.</strong><p>Your saved file and code restore this key. Keep them separately.</p></div></div>}
          <form className={styles.applicationProfile} onSubmit={async e => {
            e.preventDefault(); if (!saved || busy) return; setError('');
            const profile = canonicalFirmProfile({ practiceAreas: areas, jurisdiction: application.jurisdiction, website }, application.domain);
            if (!profile.profile) { setError(profile.error); return; }
            setBusy(true);
            try {
              const { firmBindingDocument } = await import('@/lib/confidential/firmKey');
              if (!submission.current) {
                const bindingDocument = await firmBindingDocument(firm, Date.now(), profile.profile);
                submission.current = JSON.stringify({ ...application, enrollment: { organizationId: firm.organizationId, recipientKeyId: firm.recipientKeyId, bindingDocument } });
                setLocked(true);
              }
              const response = await fetch('/api/legal-applications', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: submission.current });
              if (!response.ok) {
                const result = await response.json().catch(() => null);
                if (response.status === 400 && result?.code === 'invalid-application-key') {
                  setError('Your public key could not be verified. Check this device’s date and time. Keep your key and contact VERA if this continues.');
                  return;
                }
                const closed = response.status === 429 ? legalApplicationIntakeClosedCode(result?.code) : null;
                if (closed) { setError(`${LEGAL_APPLICATION_INTAKE_CLOSED[closed]} Keep your saved key; you can submit it later.`); return; }
                throw new Error();
              }
              try { window.sessionStorage.removeItem(APPLICATION_DRAFT_KEY); } catch { /* in-memory application */ }
              setSubmitted(true);
            } catch { setError('The application could not be confirmed. Keep your key and retry.'); } finally { setBusy(false); }
          }}>
            <div className={styles.sectionHeading}><p className={styles.eyebrow}>YOUR PUBLIC PROFILE</p><h2>Help reporters find the right support.</h2>
              <p className={styles.muted}>Administrators and reporters can read these details.</p></div>
            <fieldset className={styles.practiceFieldset}><legend>Practice areas (choose up to 6)</legend><div className={styles.practiceGrid}>{Object.entries(FIRM_PRACTICE_AREAS).map(([id, label]) => <label key={id} className={styles.practiceOption}>
              <input type="checkbox" checked={areas.includes(id)} disabled={busy || locked || !areas.includes(id) && areas.length >= 6}
                onChange={() => setAreas(current => current.includes(id) ? current.filter(area => area !== id) : [...current, id])} /> <span>{label}</span></label>)}</div></fieldset>
            <label className={styles.field}>Website<input spellCheck={false} value={website} disabled={busy || locked} onChange={e => setWebsite(e.target.value)} /></label>
            <div className={styles.keyFingerprint}><span>Public key fingerprint</span><code>{firm.recipientKeyId.match(/.{1,4}/g)?.join(' ')}</code>
              <p>This identifies the public key staff will approve.</p></div>
            <div className={styles.actions}><p className={styles.hint}>Only your profile and public key are submitted.</p>
              <button className={styles.primary} disabled={!saved || busy}>{busy ? 'Submitting…' : 'Submit firm and key for approval'} <ArrowRight size={16} aria-hidden /></button></div>
          </form>
        </>}
        {submitted && <div role="status" className={styles.approvalStatus}>
          <span className={styles.statusIcon}>{approved ? <CheckCircle2 size={28} aria-hidden /> : <Clock3 size={28} aria-hidden />}</span>
          <p className={styles.eyebrow}>{status.state === 'denied' ? 'REVIEW COMPLETE' : approved ? 'APPROVED' : 'SUBMITTED FOR REVIEW'}</p>
          <h2>{status.state === 'denied' ? 'Your application needs attention.' : approved ? 'Your workspace is ready to activate.' : 'Your next step is with our team.'}</h2>
          <p className={styles.muted}>{status.state === 'denied' ? 'Your application was not approved. Contact VERA for help.' : status.state === 'ready'
            ? 'Your firm and key are approved. Sign in to open your workspace.' : 'Application and public key submitted. Staff will approve them together in Slack.'}</p>
          <div className={styles.approvalNext}><CheckCircle2 size={18} aria-hidden /><div><strong>Your backup is verified.</strong>
            <p>Keep this tab open. It updates automatically after review. Then sign in with your approved email to open your workspace.</p></div></div>
          <details className={styles.details}><summary>View public key fingerprint</summary>
            <div className={styles.keyFingerprint}><code>{firm.recipientKeyId.match(/.{1,4}/g)?.join(' ')}</code><p>Staff approval applies to this exact key. Your private file and recovery code stay with you.</p></div></details>
          {approved && <button className={styles.primary} disabled={busy} onClick={() => void activate(true)}>{busy ? 'Opening workspace…' : 'Sign in and open workspace'}</button>}
        </div>}
      </>}
      {error && <p role="alert" className={styles.error}>{error}</p>}
    </section>
    </div>
    <AlertDialog open={guard.open} onOpenChange={open => { if (!open) guard.stay(); }}><AlertDialogContent>
      <AlertDialogTitle>Your key backup has not been checked.</AlertDialogTitle><AlertDialogDescription>Leaving now loses the key in memory. Stay to save and verify your private file and recovery code.</AlertDialogDescription>
      <button className={styles.primary} onClick={guard.stay}>Stay and check backup</button><button className={styles.secondary} onClick={guard.leave}>Leave and discard key</button>
    </AlertDialogContent></AlertDialog>
  </LegalPortalLayout>;
}
