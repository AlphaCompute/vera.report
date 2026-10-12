import { readLegalSetup } from '@/src/utils/legalOnboarding';
import { RememberWorkspace, useParticipantLock } from '@/components/vera/confidential/DeviceWorkspaces';
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from 'react';
import { useRouter } from 'next/router';
import { ArrowLeft, ArrowRight, CheckCircle2, ShieldAlert } from 'lucide-react';
import { useReceiptNavigationGuard } from '@/lib/useReceiptNavigationGuard';
import { AlertDialog, AlertDialogContent, AlertDialogTitle, AlertDialogDescription } from '@/components/ui/alert-dialog';
import { LegalSetupSteps } from '@/components/vera/confidential/LegalSetupSteps';
import { FirmKeyBackup } from '@/components/vera/confidential/FirmKeyBackup';
import { AutomaticApplicationActivation } from '@/components/vera/confidential/AutomaticApplicationActivation';
import type { LegalSetupStep } from '@/components/vera/confidential/LegalSetupSteps';
import styles from '@/components/vera/confidential/LegalOnboarding.module.css';
import Link from "next/link";
import {
  FirmKeyUnlock, FirmWorkspaceUnlock, LegalPortalDisabled, LegalPortalLayout, failureMessage, panel, primaryButton, secondaryButton,
} from "@/components/vera/confidential/LegalPortal";
import { CONFIDENTIAL_RELEASE_MANIFEST, confidentialCasesEnabled } from "@/lib/confidential/config";
import { beginLegalSignIn, cancelLegalSignInRenewal, legalAccessToken, legalAuthConfig, legalSignedIn, legalSetupContext, renewLegalSignIn } from "@/lib/confidential/legalAuth";
import { membershipInvitation } from "@/lib/confidential/legalSetup";
import { startFirmSetupSession, validateFirmSession } from '@/lib/confidential/legalWorkspaceSession';
import type { LegalAuthConfig } from "@/lib/confidential/legalAuth";
import { currentFirmSession, currentFirmVault, currentFirmPayload, setFirmVault } from "@/lib/confidential/firmPortal";
import type { FirmSession } from "@/lib/confidential/firmCase";
import type { UnlockedVault } from '@/lib/confidential/deviceVault';
import type { FirmIdentity } from "@/lib/confidential/firmKey";
import { userFacingMessage } from "@/lib/confidential/userFacingError";
import { AddLawyersHint, FirmOnboardingChecklist, OrganizationProfile, useDomainCheck, useMembershipStatus, useOnboardingRecord } from "@/components/vera/confidential/FirmOnboarding";

/** Survives only the sign-in redirect in this tab; removed as soon as it is read. */
const INVITATION_KEY = "vera-legal-invitation";

// Temporarily omit the advanced checklist from initial enrollment. It remains
// available in the legal workspace after activation.
const SHOW_ENROLLMENT_RECOVERY_PLAN = false;

/** Reads the invitation token from the URL fragment (never a query string), then
 * strips it so it stays out of history, referrers and analytics. */
function takeInvitation(): string | null {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  let token = fragment.get("invitation");
  if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
  if (!token) {
    try { token = window.sessionStorage.getItem(INVITATION_KEY); window.sessionStorage.removeItem(INVITATION_KEY); } catch { token = null; }
  }
  return token && /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

type SetupDetails = { organizationId: string; domain: string; displayName?: string };
function NewFirmKey({ config, setup, onReady, initialSession, onBack, hasInvitation, children }: {
  config: LegalAuthConfig; setup: SetupDetails | null; onReady: (session: FirmSession, config: LegalAuthConfig) => void;
  initialSession: FirmSession | null; onBack: () => void; hasInvitation: boolean; children: ReactNode;
}) {
  const router = useRouter();
  const organizationId = setup?.organizationId ?? "";
  const domain = setup?.domain ?? "";
  const [firm, setFirm] = useState<FirmIdentity | null>(initialSession?.firm ?? null);
  const [secret, setSecret] = useState("");
  const [saved, setSaved] = useState(initialSession !== null);
  const [showSecret, setShowSecret] = useState(false);
  const [step, setStep] = useState<LegalSetupStep>(initialSession ? 2 : 1);
  const stepFocus = useRef<HTMLDivElement>(null);
  const move = (next: LegalSetupStep) => { setStep(next); requestAnimationFrame(() => stepFocus.current?.focus()); };
  const [vault, setVault] = useState<UnlockedVault | null>(null);
  const [backupFile, setBackupFile] = useState<File | null>(null);
  const [backupSecret, setBackupSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opening, setOpening] = useState(false);
  const [continueError, setContinueError] = useState<string | null>(null);
  const domainCheck = useDomainCheck(firm);
  const membership = useMembershipStatus(config, firm);
  const onboarding = useOnboardingRecord(firm);
  const guard = useReceiptNavigationGuard(router, !!firm && !saved);

  const generate = async () => {
    setBusy(true); setError(null);
    try {
      const keys = await import("@/lib/confidential/firmKey");
      const created = await keys.generateFirmIdentity({ organizationId, domain });
      setSecret(keys.generateFirmRecoveryCode());
      setFirm(created);
    } catch (caught) { setError(userFacingMessage(caught, "The key could not be created.")); }
    finally { setBusy(false); }
  };
  const verifyBackup = async () => {
    if (!firm || !backupFile || busy) return;
    setBusy(true); setError(null);
    try {
      const { verifyFirmBackup } = await import("@/lib/confidential/backupVerification");
      await verifyFirmBackup(backupFile, backupSecret, firm);
      setSaved(true); setBackupSecret(""); setBackupFile(null);
    } catch { setError("That file and recovery code did not restore this organization key. Check both saved copies and try again."); }
    finally { setBusy(false); }
  };

  const openWorkspace = async () => {
    if (!firm || !saved || opening) return;
    if (initialSession) { move(2); return; }
    setOpening(true); setContinueError(null);
    try {
      if (!legalSignedIn()) await renewLegalSignIn(config);
      // First email sign-in selects the approved organization. Use that new
      // identity binding for verification and the remaining setup steps.
      const signedInConfig = legalAuthConfig() ?? config;
      const session = await startFirmSetupSession(signedInConfig, firm);
      if (vault) { const { setFirmVault } = await import('@/lib/confidential/firmPortal'); setFirmVault(vault); }
      onReady(session, signedInConfig); move(2);
    } catch { setContinueError('Sign-in or setup could not finish. Keep this page open, allow the sign-in window, and try again.'); }
    finally { setOpening(false); }
  };

  if (!firm) {
    return (
      <div className={styles.setupBody}>
      <button type="button" className={styles.back} onClick={onBack}><ArrowLeft size={15} aria-hidden />Back to setup options</button>
      <LegalSetupSteps current={1} />
      <section className={styles.card} aria-labelledby="new-key-title">
        <p className={styles.eyebrow}>STEP 01 / 02 · PROTECT YOUR KEY</p>
        <h2 id="new-key-title">Create your organization key.</h2>
        <p className="mb-4 max-w-[62ch] text-sm text-black/70">
          After your application is approved, this one-time step creates your encryption key on this device; it is not another registration. VERA receives only the public part.
        </p>
        <div className={styles.notice + ' ' + styles.danger}><ShieldAlert size={20} aria-hidden /><div>
          <strong>You’ll need to save a private file and a recovery code.</strong>
          <p>Keep this page open until you have saved and checked both. VERA cannot recover a lost key.</p>
        </div></div>
        <form onSubmit={event => { event.preventDefault(); if (!busy && organizationId && domain) void generate(); }}>
          {setup && <p className={styles.organization}><CheckCircle2 size={16} aria-hidden />{setup.displayName ? setup.displayName + ' · ' : ''}{setup.domain}</p>}
          <button className={styles.primary + ' mt-6'} disabled={busy || !organizationId || !domain}>
            {busy ? "Creating…" : "Create key"}
          </button>
        </form>
        {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
      </section>
      </div>
    );
  }
  return (
    <div className={styles.setupBody}>
      <div className={styles.organization}><strong>{setup?.displayName ?? firm.domain}</strong><span>{firm.domain}</span><span className={styles.pill}>Key stays on this device</span></div>
      <LegalSetupSteps current={step} saved={saved} onStep={next => {
        if (next === 1) move(next); else void openWorkspace();
      }} />
      <div ref={stepFocus} tabIndex={-1} aria-label={'Step ' + step + ' of 2'} />
      {/* Hidden steps remain mounted so Back preserves the key, selected backup files. */}
      <div hidden={step !== 1}>
      <section className={styles.card} aria-labelledby="export-title">
        <p className={styles.eyebrow}>STEP 01 / 02</p>
        <h2 id="export-title">Protect your organization’s key.</h2>
        {!saved && <div className={styles.notice + ' ' + styles.danger}>
          <ShieldAlert size={20} aria-hidden /><div>
          <p className="mb-2 font-bold">Save and check your key before leaving. VERA cannot recover it.</p>
          <p className="font-bold">
            You need the encrypted key file and its recovery code to restore access. If every usable copy of this key is lost,
            reports shared with it cannot be opened. Store the file and code separately and offline. Closing or reloading this
            page before saving them loses this key. Do not email or upload them.
          </p>
          </div>
        </div>}
        {secret && <div className={styles.backupGrid}>
        <div className={styles.backupTile}><h3>1. Save the private file</h3><p>Keep this encrypted backup in private storage. Never publish it on your website.</p>
          <FirmKeyBackup firm={firm} secret={secret} className={styles.secondary} />
        </div>
        <div className={styles.backupTile}><h3>2. Save the recovery code</h3><p>Store it separately from the private file. You need both to recover.</p>
        <label className="mb-3 block text-sm">
          <span className="mb-1 block">Recovery code (or replace with a passphrase of at least 16 characters)</span>
          <input type={showSecret ? 'text' : 'password'} value={secret} disabled={busy} onChange={event => { setSecret(event.target.value); setSaved(false); setBackupSecret(""); setBackupFile(null); }} autoComplete="off" spellCheck={false}
            className="w-full select-all border border-black/30 px-3 py-2 font-mono" />
        </label>
        <button type="button" className="min-h-11 text-sm underline" aria-pressed={showSecret} onClick={() => setShowSecret(value => !value)}>{showSecret ? 'Hide recovery code' : 'Show recovery code'}</button>
        </div></div>}
        {!saved && <p className="mt-4 text-sm"><strong>3. Check your saved copies.</strong> Reopen your file and enter the code from your separate saved copy.
          Both are checked only on this device.</p>}
        {!saved && <div className="mt-3 space-y-3">
          <label className="block text-sm">Saved encrypted key file
            <input type="file" accept=".txt,text/plain" disabled={busy} className="mt-1 block"
              onChange={event => setBackupFile(event.target.files?.[0] ?? null)} />
          </label>
          <label className="block text-sm">Saved recovery code or passphrase
            <input type="password" autoComplete="off" value={backupSecret} disabled={busy}
              onChange={event => setBackupSecret(event.target.value)} className="mt-1 block w-full border border-black/30 px-3 py-2" />
          </label>
          <button type="button" className={secondaryButton} disabled={busy || !backupFile || !backupSecret}
            onClick={() => void verifyBackup()}>{busy ? "Checking…" : "Verify saved backup"}</button>
        </div>}
        {saved && <div className={styles.notice + ' ' + styles.success} role="status"><CheckCircle2 size={20} aria-hidden /><div><strong>Backup verified.</strong><p>Your saved file and code restore this key. Keep them separately.</p></div></div>}
        {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
        <div className={styles.actions}><span className={styles.hint}>Next: activate your approved workspace.</span><button type="button" className={styles.primary} disabled={!saved || opening} onClick={() => void openWorkspace()}>{opening ? 'Continuing…' : 'Continue to workspace'} <ArrowRight size={16} aria-hidden /></button></div>
        {opening && <div className="mt-3 text-sm" role="status"><p>Complete sign-in in the separate tab, then return here. Keep this key page open.</p>
          <button type="button" className="mt-2 underline" onClick={() => { cancelLegalSignInRenewal(); setOpening(false); }}>Cancel sign-in and try again</button>
        </div>}
        {continueError && <p role="alert" className="mt-3 text-red-800">{continueError}</p>}
        <details className={styles.details}><summary>Recovery options and a second key holder</summary>
          <p>Keep your private file and recovery code separately. A second authorized recovery custodian may hold an emergency copy. Everyday members get their own sign-in and device key.</p>
          <p>Your sign-in cannot recover a lost private key. Recovery needs a usable copy of both the file and code.</p>
        </details>
      </section>
      {saved && <details className={styles.details}><summary>Remember this workspace on this device (optional)</summary><RememberWorkspace role="legal" vault={vault} onRemembered={setVault} organizationDomain={firm.domain} getPayload={async () => ({
        format: 'vera-legal-workspace/v1', organizationId: firm.organizationId, domain: firm.domain,
        recipientKeyId: firm.recipientKeyId, privateKey: firm.privateKey.armor(), requests: [], owners: [], pins: [], sequences: [],
      })} /></details>}
      </div>
      <div hidden={step !== 2}><section className={styles.card} aria-labelledby="public-title">
        <p className={styles.eyebrow}>STEP 02 / 02</p><h2 id="public-title">Activate your workspace.</h2>
        <p className={styles.muted}>VERA onboarding independently reviews your organization key before activating access to your workspace.</p>
        <div className={styles.notice + ' ' + styles.success}><CheckCircle2 size={20} aria-hidden /><p>Your key backup has been checked.</p></div>
        <OrganizationProfile firm={firm} domain={domainCheck} title="Organization profile and key approval" />
        {hasInvitation ? children : <AutomaticApplicationActivation firm={firm} config={config} onDone={() => { void router.push('/legal'); }}>{children}</AutomaticApplicationActivation>}
        {SHOW_ENROLLMENT_RECOVERY_PLAN && <details className={styles.details}><summary>Recovery plan and organization commitments</summary>
          <FirmOnboardingChecklist firm={firm} keySaved={saved} domain={domainCheck} membership={membership} onboarding={onboarding}>
            {{ lawyers: <AddLawyersHint /> }}
          </FirmOnboardingChecklist>
        </details>}
        <div className={styles.actions}><button type="button" className={styles.secondary} onClick={() => move(1)}><ArrowLeft size={16} aria-hidden />Back to key backup</button></div>
      </section></div>
      <AlertDialog open={guard.open} onOpenChange={open => { if (!open) guard.stay(); }}><AlertDialogContent>
        <AlertDialogTitle className="font-bold text-red-800">Your key backup hasn’t been checked.</AlertDialogTitle>
        <AlertDialogDescription>Leaving this setup page clears this key from memory. If you have not saved both the private file and recovery code, you will lose this key. Stay here to finish your backup.</AlertDialogDescription>
        <button type="button" className={styles.primary} onClick={guard.stay}>Stay and check my backup</button>
        <button type="button" className={styles.secondary} onClick={guard.leave}>Leave and discard this key</button>
      </AlertDialogContent></AlertDialog>
    </div>
  );
}

function Activation({ config, token, session, onDone }: { config: LegalAuthConfig; token: string; session: FirmSession | null; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const attempted = useRef<string | null>(null);
  // Membership before this link's first redemption attempt, kept across retries:
  // a retry after a lost reply must still compare against the original lease.
  const baseline = useRef<{ link: string; lease: number | null } | null>(null);
  const alive = useRef(true), completed = useRef(onDone);
  completed.current = onDone;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    if (!session || !legalSignedIn()) return;
    const link = token + ':' + session.firm.recipientKeyId;
    const attempt = link + ':' + retry;
    if (attempted.current === attempt) return;
    attempted.current = attempt;
    setBusy(true); setError(null);
    void (async () => {
      try {
        const [{ fetchRelay }, { completeLegalSetup, matchingMembershipLease }] = await Promise.all([import('@/lib/confidential/client'), import('@/lib/confidential/completeLegalSetup')]);
        const input = { relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST, now: Date.now(), invitation: token,
          accessToken: await legalAccessToken(config), firm: session.firm };
        if (baseline.current?.link !== link || baseline.current.lease === null) {
          baseline.current = { link, lease: await matchingMembershipLease(input) };
        }
        await completeLegalSetup(input, baseline.current.lease);
        await validateFirmSession(config, session);
        const { prepareStewardDevice } = await import("@/lib/confidential/firmDeviceSession");
        await prepareStewardDevice(session, Date.now());
        if (alive.current) completed.current();
      } catch (caught) {
        if (alive.current) setError(failureMessage(caught, 'Workspace activation could not be confirmed. Try again, or ask VERA onboarding for a fresh setup link.'));
      } finally { if (alive.current) setBusy(false); }
    })();
  }, [config, session, token, retry]);
  if (!legalSignedIn()) return <section className={panel}>
    <p className="mb-4">Sign in with your approved organization account to finish setup.</p>
    <button type="button" className={primaryButton} disabled={busy} onClick={() => {
      if (session) {
        setBusy(true); setError(null);
        void renewLegalSignIn(config).then(() => setRetry(value => value + 1))
          .catch(() => setError('Sign-in did not finish. Allow the sign-in window and try again.')).finally(() => setBusy(false));
      } else {
        try { window.sessionStorage.setItem(INVITATION_KEY, token); } catch { /* reopen the setup link */ }
        void beginLegalSignIn(config, '/legal/enroll');
      }
    }}>{busy ? 'Signing in…' : 'Sign in'}</button>
    {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
  </section>;
  if (!session) return <p className="text-sm text-black/60">Open or create your organization key to finish setup.</p>;
  return <section className={panel}>
    <h2 className="mb-3 font-semibold">Activating your workspace</h2>
    <p role="status">{busy ? 'Checking your account and signed key approval…' : error ? 'Activation needs another check.' : 'Finishing setup…'}</p>
    <p className="mt-3 text-sm text-black/70">Your application already requested access. There is no additional invitation to accept. Private report information still needs each reporter’s permission.</p>
    {error && <><p role="alert" className="mt-3 text-red-800">{error}</p><button type="button" className={secondaryButton} disabled={busy} onClick={() => setRetry(value => value + 1)}>Try activation again</button></>}
  </section>;
}

/** Nothing runs (no invitation is read from the URL, no workspace or lock is
 * touched) unless this build enables confidential cases. */
function EnrolledWorkspace() {
  const [vault, setVault] = useState(currentFirmVault());
  const [error, setError] = useState<string | null>(null);
  return <section className={panel}>
    <p className="mb-4">Your account is enrolled for your organization.</p>
    <p className="mb-4 font-bold text-red-800">Your original organization-key file does not include this device&apos;s renewal credential.
      Keep this workspace on your private device to renew membership automatically, then download a full workspace backup below.
      Without a saved device credential, restoring the original key file may require a new VERA enrollment invitation after membership expires.</p>
    <RememberWorkspace role="legal" vault={vault} getPayload={async () => currentFirmPayload()} onRemembered={async saved => {
      setFirmVault(saved); setVault(saved); setError(null);
      try {
        const session = currentFirmSession();
        if (!session) throw new Error('Workspace locked');
        const { prepareStewardDevice } = await import('@/lib/confidential/firmDeviceSession');
        await prepareStewardDevice(session, Date.now());
      } catch { setError('Automatic renewal setup could not finish. Your encrypted workspace is saved; reopen it and retry while your current membership is active.'); }
    }} />
    {error && <p className="mt-3 font-bold text-red-800" role="alert">{error}</p>}
    <Link className={`mt-4 inline-block ${primaryButton}`} href="/legal">Open workspace</Link>
  </section>;
}

export default function LegalEnroll() {
  return confidentialCasesEnabled() ? <LegalEnrollment /> : <LegalPortalDisabled title="Organization setup" />;
}

function LegalEnrollment() {
  const router = useRouter();
  const [lookupError, setLookupError] = useState(false);
  const retryLookup = useRef<(() => Promise<void>) | null>(null);
  const [ready, setReady] = useState<{ config: LegalAuthConfig | null } | null>(null);
  const [setup, setSetup] = useState<SetupDetails | null>(null);
  const [membershipLink, setMembershipLink] = useState(''), [linkError, setLinkError] = useState('');
  const [token, setToken] = useState<string | null>(null);
  const [session, setSession] = useState<FirmSession | null>(null);
  useParticipantLock("/legal", session !== null);
  const [mode, setMode] = useState<"choose" | "new" | "existing">("choose");
  const [enrolled, setEnrolled] = useState(false);
  const initialized = useRef(false);
  useEffect(() => {
    // Strict Mode replays mount effects. Consuming the URL/session token twice
    // would overwrite the first valid invitation with null after its removal.
    if (initialized.current) return;
    initialized.current = true;
    const details = readLegalSetup(window.location.hash);
    if (details) setMode("new");
    const invitation = takeInvitation();
    const current = currentFirmSession();
    setToken(invitation);
    setSession(current);
    // The Auth0 email is sufficient for an invited colleague. Only an attested
    // registered key selects join; first-time applicants still create their key.
    // Explicit VERA membership invitations retain their redemption flow.
    const resolveSetup = async () => {
      setLookupError(false);
      // First email sign-in selects the approved organization. Re-read both its
      // configuration and identity so setup uses the new organization binding.
      const config = legalAuthConfig();
      const context = (config ? legalSetupContext(config) : null) ?? details;
      setSetup(context);
      if (!invitation && !current && config && context && legalSignedIn()) {
        try {
          const [{ publishedOrganizationKey }, { fetchRelay }] = await Promise.all([
            import('@/lib/confidential/firmMemberDevices'), import('@/lib/confidential/client')]);
          await publishedOrganizationKey(context, { relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST,
            accessToken: await legalAccessToken(config), now: Date.now() });
          await router.replace(`/legal/join#organization=${context.organizationId}&domain=${encodeURIComponent(context.domain)}`);
          return;
        } catch (error) {
          if (!(error instanceof Error) || error.name !== 'OrganizationKeyPendingError') setLookupError(true);
        }
      }
      setReady({ config });
    };
    retryLookup.current = resolveSetup;
    void resolveSetup();
  }, []);
  // An invitation link opened in this same tab (for example after "I have an
  // invitation link") only changes the fragment, so the page does not reload
  // and the unlocked key stays in memory. Pick the new token up from there.
  useEffect(() => {
    const picked = () => { const next = takeInvitation(); if (next) { setToken(next); setEnrolled(false); } };
    window.addEventListener("hashchange", picked);
    return () => window.removeEventListener("hashchange", picked);
  }, []);

  let content;
  if (!ready) content = <p role="status">Loading…</p>;
  else if (!ready.config) content = <p className={panel}>Legal portal not configured.</p>;
  else if (lookupError && !token && !session) {
    content = <section className={panel}>
      <p className="mb-4" role="alert">We could not confirm your organization setup. Check your connection or sign in again before continuing.</p>
      <button type="button" className={primaryButton} onClick={() => { setReady(null); void retryLookup.current?.(); }}>Try again</button>
      <button type="button" className={`${secondaryButton} ml-3`} onClick={() => void renewLegalSignIn(ready.config!).then(() => retryLookup.current?.()).catch(() => setLookupError(true))}>Sign in again</button>
      <FirmWorkspaceUnlock config={ready.config} onUnlocked={setSession} setup />
    </section>;
  } else if (enrolled) {
    content = <EnrolledWorkspace />;
  } else if (!setup && !token && !session) {
    content = <section className={panel}>
      <h2 className="mb-3 text-xl">Load your approved organization.</h2>
      <p className="mb-4">Sign in to load your organization details before creating its key. Your existing sign-in session can be reused.</p>
      <button type="button" className={primaryButton} onClick={() => void renewLegalSignIn(ready.config!)
        .then(() => retryLookup.current?.()).catch(() => setLookupError(true))}>Sign in and load organization</button>
      <p className="mt-4">Not yet approved? <Link href="/legal/apply" className="underline">Start a new application</Link>.</p>
      <FirmWorkspaceUnlock config={ready.config} onUnlocked={setSession} setup />
    </section>;
  } else {
    const config = ready.config;
    const membershipContent = <>
      {token ? <Activation config={config} token={token} session={session} onDone={() => { setEnrolled(true); setToken(null); }} />
        : <div className="mt-5">
          <h3 className="mb-2 font-semibold">Waiting for your signed key approval?</h3>
          <p className={styles.muted}>After staff confirm your Key ID, use their private Finish setup link here. Your saved key stays in this tab, and activation happens automatically.</p>
          <form className="mt-4 space-y-3" onSubmit={event => {
            event.preventDefault();
            const invitation = membershipInvitation(membershipLink, window.location.origin);
            if (!invitation) { setLinkError('Use the complete Finish setup link from VERA onboarding for this site.'); return; }
            setToken(invitation); setMembershipLink(''); setLinkError('');
          }}>
            <label className={styles.field}>Private Finish setup link<input type="password" autoComplete="off" spellCheck={false} value={membershipLink} onChange={event => setMembershipLink(event.target.value)} /></label>
            <button type="submit" className={styles.primary} disabled={!membershipLink}>Continue</button>
          </form>
          {linkError && <p role="alert" className={styles.error}>{linkError}</p>}
          <p className="mt-4 text-sm">Your application is already approved. Onboarding staff still need to confirm this key before access can activate.</p>
          <p className="mt-3 text-sm">Already set up? <Link className="underline" href="/legal">Open workspace</Link>.</p>
        </div>}
    </>;
    content = (
      <div className="space-y-6">
        {token && !session && <Activation config={config} token={token} session={null} onDone={() => { setEnrolled(true); setToken(null); }} />}
        {mode === "new" || session ? <NewFirmKey config={config} setup={setup} onReady={(session, config) => { setSession(session); setReady({ config }); }}
          initialSession={session} hasInvitation={!!token} onBack={() => setMode("choose")}>{membershipContent}</NewFirmKey>
          : mode === "existing" ? <div className={styles.setupBody}>
            <button type="button" className={styles.back} onClick={() => setMode("choose")}><ArrowLeft size={15} aria-hidden />Back to setup options</button>
            <FirmKeyUnlock config={config} title="Open your organization key backup" onUnlocked={setSession} setup />
            {legalSignedIn() && <FirmWorkspaceUnlock config={config} onUnlocked={setSession} setup />}
            <details className={styles.details}><summary>Missing your private file or recovery code?</summary>
              <p>You need both. Check your separate recovery storage or ask your designated recovery custodian. Your sign-in password cannot recover this key.</p>
              <p>If all usable copies are lost, VERA cannot restore information encrypted to it. Contact onboarding about setting up a new key.</p>
            </details>
          </div> : <>
            {setup && <div className={styles.organization}><CheckCircle2 size={17} aria-hidden /><strong>{setup.displayName ?? setup.domain}</strong><span>{setup.domain}</span><span className={styles.pill}>Application approved</span></div>}
            <LegalSetupSteps current={1} />
            <div className={styles.grid}>
              <section className={styles.card}><p className={styles.eyebrow}>FIRST TIME SETTING UP</p><h2>Create your organization’s key.</h2>
                <p className={styles.muted}>For the organization’s designated key holder. Create a key on this device, save your recovery backup, and activate your workspace.</p>
                {!setup && <p className="mt-3 text-sm">Your approval email contains the setup link with your organization details.</p>}
                <div className={styles.actions}><button type="button" className={styles.primary} onClick={() => setMode("new")}>Create a new organization key <ArrowRight size={16} aria-hidden /></button></div>
              </section>
              <section className={styles.card}><p className={styles.eyebrow}>CONTINUING YOUR SETUP</p><h2>Bring your key with you.</h2>
                <p className={styles.muted}>Already saved a key? Open your encrypted file with its recovery code, or unlock a workspace saved on this device.</p>
                <div className={styles.actions}><button type="button" className={styles.secondary} onClick={() => setMode("existing")}>Use our existing key file <ArrowRight size={16} aria-hidden /></button></div>
              </section>
            </div>
            <div className={styles.notice}><p><strong>Joining an organization that already uses VERA?</strong> Ask your organization’s steward for a join link. Each lawyer gets a separate device key.
              {' '}<Link className="underline" href="/legal/join">Join with a device key</Link>.</p></div>
          </>}
      </div>
    );
  }
  return <LegalPortalLayout title={enrolled ? 'Welcome to your workspace.' : setup ? 'Finish setup' : 'Set up your organization.'} onboarding backHref="/legal"
    intro="Two steps to get ready: protect your key and activate your workspace. Your private key stays on your device.">{content}</LegalPortalLayout>;
}

/** Server-rendered so `_document` applies the strict key-page headers. */
export const getServerSideProps = async () => ({ props: {} });
