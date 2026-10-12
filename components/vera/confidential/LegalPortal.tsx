import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { ArrowLeft, ArrowRight, ShieldCheck, LockKeyhole, Building2, Files, Users, LogOut, Clock3 } from 'lucide-react';
import onboardingStyles from './LegalOnboarding.module.css';
import workspaceStyles from './LegalWorkspace.module.css';
import { VeraReportLogo } from "@/components/vera/VeraReportLogo";
import { CONFIDENTIAL_RELEASE_MANIFEST, confidentialCasesEnabled } from "@/lib/confidential/config";
import {
  LEGAL_INVITATION_REDIRECTED, LEGAL_SIGN_IN_REDIRECTED, LEGAL_RENEWAL_RELAYED, LegalPopupBlocked, LegalSignInRequired, beginLegalSignIn, completeLegalSignIn, legalAccessToken, legalAuthConfig,
  legalSignedIn, renewLegalSignIn, signOutLegal, subscribeLegalIdentityChange,
} from "@/lib/confidential/legalAuth";
import type { LegalAuthConfig } from "@/lib/confidential/legalAuth";
import { SavedWorkspaces, RememberWorkspace, useParticipantLock } from './DeviceWorkspaces';
import { lockParticipantTabs, lockParticipantTabsForSignOut } from '@/lib/confidential/deviceWorkspace';
import type { UnlockedVault } from '@/lib/confidential/deviceVault';
import { currentFirmVault, currentFirmPayload, persistFirmWorkspace, setFirmVault, currentFirmSession, setFirmSession } from "@/lib/confidential/firmPortal";
import type { FirmSession } from "@/lib/confidential/firmCase";
import type { FirmIdentity } from "@/lib/confidential/firmKey";
import { OPAQUE_DOWNLOAD_TYPE, safeDownloadName } from "@/lib/confidential/safeDownload";
import { userFacingMessage } from "@/lib/confidential/userFacingError";
import type { BadgeTone } from "@/lib/confidential/firmCaseView";
import { isReleasePaused } from "@/lib/confidential/releaseWithdrawals";
import { SecurityDetails } from "./SecurityDetails";
import { CONNECTION_FALLBACK, unlockFirmKey } from "./firmKeyUnlock";
import { FirmKeyBackup } from './FirmKeyBackup';
import { startFirmSession, startFirmSetupSession, validateFirmSession, WorkspaceKeyMismatchError, WorkspaceMembershipRequiredError } from '@/lib/confidential/legalWorkspaceSession';
export { startFirmSession } from '@/lib/confidential/legalWorkspaceSession';

/** Shared frame for the private /legal portal. No analytics or third-party
 * scripts; referrers are suppressed so invitation or case URLs never leak. */
export const panel = "border border-black/10 p-6";
export const primaryButton = "border border-black bg-black px-4 py-2 text-white disabled:opacity-50";
export const secondaryButton = "border border-black px-4 py-2 disabled:opacity-50";

export function LegalPortalLayout({ title, children, onboarding = false, wide = false, intro, backHref, backLabel = 'Legal portal' }: {
  title: string; children: ReactNode; onboarding?: boolean; wide?: boolean; intro?: string; backHref?: string; backLabel?: string;
}) {
  useEffect(() => subscribeLegalIdentityChange(() => {
    setFirmSession(null);
    lockParticipantTabs();
  }), []);
  return (
    <>
      <Head>
        <title>{`${title} - Vera`}</title>
        <meta name="robots" content="noindex, nofollow" />
        <meta name="referrer" content="no-referrer" />
      </Head>
      <div className="min-h-screen" style={{ backgroundColor: "var(--vera-paper)" }}>
        <header className="border-b border-black/10">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-7 py-3">
            <Link href="/" style={{ width: 90, height: 34, display: "block", overflow: "hidden" }} aria-label="Vera Report home">
              <VeraReportLogo style={{ width: "100%", height: "100%", maxWidth: 90, maxHeight: 34, display: "block" }} />
            </Link>
            <span className="text-xs uppercase tracking-[0.3em] text-black/50">Legal portal</span>
          </div>
        </header>
        <main id="main-content" className={onboarding ? onboardingStyles.page : 'mx-auto px-6 py-10 md:py-14'}
          style={onboarding ? (wide ? { maxWidth: 1480 } : undefined) : { maxWidth: wide ? 1280 : "var(--vera-doc-max-w)" }}>
          {backHref && <Link href={backHref} className={onboardingStyles.back}><ArrowLeft size={15} aria-hidden />Back to {backLabel}</Link>}
          {onboarding && <p className={onboardingStyles.eyebrow}>VERA · Legal organizations</p>}
          <h1 className={onboarding ? undefined : wide ? 'mb-4 font-serif text-3xl sm:text-4xl' : 'mb-8 text-2xl font-semibold'}>{title}</h1>
          {intro && <p className={onboardingStyles.intro}>{intro}</p>}
          {children}
        </main>
        <footer className="mx-auto px-6 pb-10" style={{ maxWidth: "var(--vera-doc-max-w)" }}>
          <SecurityDetails />
        </footer>
      </div>
    </>
  );
}

/** Shown on every legal page of a build that does not enable confidential cases. */
export function LegalPortalDisabled({ title }: { title: string }) {
  return <LegalPortalLayout title={title}><p className={panel}>The legal portal is not available on this site.</p></LegalPortalLayout>;
}

/** Browser-side equivalent of `Content-Disposition: attachment` with a safe
 * filename and `X-Content-Type-Options: nosniff`: decrypted evidence is a Blob
 * typed `application/octet-stream` behind a `download` link, so the browser saves
 * it and never renders, sniffs or executes it in this origin. */
export function downloadBytes(bytes: Uint8Array | string, filename: string, type = OPAQUE_DOWNLOAD_TYPE) {
  const part: BlobPart = typeof bytes === "string" ? bytes : new Uint8Array(bytes);
  const url = URL.createObjectURL(new Blob([part], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = safeDownloadName(filename);
  link.rel = "noopener";
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const BADGE: Record<BadgeTone, string> = {
  positive: "border-green-800 text-green-900",
  attention: "border-amber-700 bg-amber-50 text-amber-900",
  negative: "border-red-800 text-red-900",
  neutral: "border-black/30 text-black/70",
};
/** Request/access status label. The tone is decoration only; the text carries the meaning. */
export function StatusBadge({ label, tone }: { label: string; tone: BadgeTone }) {
  return <span className={`inline-block border px-2 py-0.5 text-xs font-semibold ${BADGE[tone]}`}>{label}</span>;
}

/** Prominent inline notice, for example access ending soon or an update waiting for the reporter. */
export function Banner({ tone, title, children, role = "status" }: {
  tone: "attention" | "neutral" | "negative"; title: string; children: ReactNode; role?: "status" | "alert";
}) {
  const colors = tone === "attention" ? "border-amber-700 bg-amber-50" : tone === "negative" ? "border-red-800" : "border-black/30";
  return (
    <section role={role} className={`border border-l-4 p-4 ${colors}`}>
      <h2 className="mb-1 font-semibold">{title}</h2>
      <div className="max-w-[62ch] text-sm text-black/80">{children}</div>
    </section>
  );
}

/** Encrypted key file + its separate recovery secret -> verified in-memory firm session. */
export function FirmKeyUnlock({ config, onUnlocked, title = "Open your organization", signedIn = false, setup = false }: {
  config: LegalAuthConfig; onUnlocked: (session: FirmSession) => void; title?: string; signedIn?: boolean; setup?: boolean;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unlock = async () => {
    if (!file || busy) return;
    setBusy(true); setError(null);
    try {
      // Load the key module first: a failed load is a connection problem, not a credential mismatch.
      const { importFirmIdentity } = await import("@/lib/confidential/firmKey");
      const result = await unlockFirmKey(await file.text(), secret, {
        importIdentity: importFirmIdentity,
        start: firm => (setup ? startFirmSetupSession : startFirmSession)(config, firm),
        describeStartFailure: failureMessage,
      });
      if (result.ok) { setSecret(""); onUnlocked(result.session); }
      else setError(result.message);
    } catch (caught) {
      setError(failureMessage(caught, CONNECTION_FALLBACK));
    } finally { setBusy(false); }
  };
  return (
    <section className={onboardingStyles.card} aria-labelledby="unlock-title">
      <p className={`${onboardingStyles.eyebrow} flex items-center gap-2 text-[#395944]`}><ShieldCheck size={18} aria-hidden />{signedIn ? 'Sign-in complete' : 'Organization key'}</p>
      <h2 id="unlock-title">{title}</h2>
      <p className={`${onboardingStyles.muted} max-w-[72ch]`}>
        Choose your organization&apos;s encrypted private key file, then enter its separate recovery passphrase or code to open the workspace.
      </p>
      <div className="mt-7 space-y-4">
        <div className="min-w-0 border border-[#dce1d7] bg-[#fafbf8] p-5">
          <label className="block text-sm font-semibold text-[#243d2e]">
            <span className="mb-3 block">Encrypted private key file</span>
            <input type="file" accept=".txt,text/plain" aria-describedby="organization-key-file-hint"
              onChange={event => setFile(event.target.files?.[0] ?? null)}
              className="block w-full min-w-0 border border-[#b9beb6] bg-white p-3 text-sm font-normal file:mr-3 file:border-0 file:bg-[#eaf0e7] file:px-3 file:py-2 file:text-[#243d2e]" />
          </label>
          <p id="organization-key-file-hint" className="mt-3 break-words text-sm leading-relaxed text-black/65">Select your organization&apos;s <strong>vera-legal-key-PRIVATE-….txt</strong> file.</p>
        </div>
        <div className="min-w-0 border border-[#dce1d7] bg-[#fafbf8] p-5">
          <label className="block text-sm font-semibold text-[#243d2e]">
            <span className="mb-3 block">Recovery passphrase or code</span>
            <input type="password" autoComplete="off" value={secret} onChange={event => setSecret(event.target.value)}
              aria-describedby="organization-key-passphrase-hint" className="min-h-12 w-full border border-[#b9beb6] bg-white px-3 py-3 text-base font-normal" />
          </label>
          <p id="organization-key-passphrase-hint" className="mt-3 text-sm leading-relaxed text-black/65">Enter the passphrase or recovery code you saved separately for this key file.</p>
        </div>
      </div>
      <div className="mt-6 flex flex-wrap items-center justify-between gap-5">
        <p className="flex max-w-[62ch] items-start gap-2 text-sm leading-relaxed text-black/65"><LockKeyhole size={17} className="mt-1 shrink-0" aria-hidden />Your private key is unlocked on this device. It is never sent to VERA.</p>
        <button type="button" className={onboardingStyles.primary} disabled={!file || !secret || busy} onClick={() => void unlock()}>
          {busy ? "Opening organization…" : "Open organization"}<ArrowRight size={16} aria-hidden />
        </button>
      </div>
      {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
    </section>
  );
}

/** Shared restoration path for sign-in and invitation renewal. Handles member
 * devices too: a device waiting for approval, an approval that has arrived, and
 * an organization key that was replaced since the last visit. */
export function FirmWorkspaceUnlock({ config, onUnlocked, setup = false }: {
  config: LegalAuthConfig; onUnlocked: (session: FirmSession, notice?: string | null) => void; setup?: boolean;
}) {
  const [pending, setPending] = useState<{ code: string; removed: boolean } | null>(null);
  const open = async (payload: unknown, vault: UnlockedVault | null, signal: AbortSignal) => {
    const [{ openLegalWorkspace, PendingDeviceError }, { fetchRelay }, { formatDeviceCode }, { readDeviceKey }] = await Promise.all([
      import('@/lib/confidential/firmDeviceSession'), import('@/lib/confidential/client'),
      import('@/enclave/src/confidential/firmMembers'), import('@/lib/confidential/firmMemberDevices')]);
    setPending(null);
    try {
      const opened = await openLegalWorkspace(payload, { relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST,
        accessToken: () => legalAccessToken(config), start: (firm, abort) => (setup ? startFirmSetupSession : startFirmSession)(config, firm, abort) }, vault, signal);
      onUnlocked(opened.session, opened.notice);
    } catch (error) {
      if (error instanceof PendingDeviceError) {
        const key = await readDeviceKey(error.pending.privateKey).catch(() => null);
        setPending({ code: key ? formatDeviceCode(key.getFingerprint()) : '', removed: error.status?.state === 'removed' });
      }
      throw error;
    }
  };
  return <>
    <SavedWorkspaces role="legal" onRecovered={(payload, signal) => open(payload, null, signal)}
      onUnlocked={(vault, signal) => open(vault.read(), vault, signal)} />
    {pending && <section className={panel} role="status" aria-labelledby="pending-device-title">
      <h2 id="pending-device-title" className="mb-2 font-semibold">{pending.removed ? 'This device was removed' : 'Waiting for approval'}</h2>
      {pending.removed ? <p className="max-w-[62ch] text-sm">Your organization removed this device. Ask your steward if you need access again.</p> : <>
        <p className="mb-3 max-w-[62ch] text-sm">Your organization&apos;s steward has not approved this device yet. Read them this device code
          by phone or in person so they can check it before approving:</p>
        {pending.code && <p className="mb-3 break-words font-mono text-lg tracking-wide">{pending.code}</p>}
        <Link className="underline" href="/legal/join">Wait for approval on the join page</Link>
      </>}
    </section>}
  </>;
}

type GateState =
  | { state: "loading" } | { state: "disabled" } | { state: "unconfigured" } | { state: "renewal-relayed" }
  | { state: "signed-out"; config: LegalAuthConfig; error?: string }
  | { state: "needs-key"; config: LegalAuthConfig; error?: string }
  | { state: "ready"; config: LegalAuthConfig; session: FirmSession; notice?: string | null };

/** Sign-in (separate legal Auth0 application) and firm-key gate. Renders
 * children only with a signed-in user and an unlocked firm key. */
export function LegalGate({ returnPath, children, welcome = false }: {
  returnPath: string; children: (context: { session: FirmSession; config: LegalAuthConfig; lock: () => void }) => ReactNode; welcome?: boolean;
}) {
  const router = useRouter();
  const [gate, setGate] = useState<GateState>({ state: "loading" });
  const [expired, setExpired] = useState(false), [renewalError, setRenewalError] = useState(''), [renewing, setRenewing] = useState(false);
  useEffect(() => {
    if (gate.state !== 'ready') { setExpired(false); return; }
    const check = () => setExpired(!legalSignedIn());
    check();
    const timer = setInterval(check, 1000);
    return () => clearInterval(timer);
  }, [gate.state]);
  useParticipantLock("/legal", gate.state === "ready");
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!confidentialCasesEnabled()) { setGate({ state: "disabled" }); return; }
      const config = legalAuthConfig();
      if (!config) { setGate({ state: "unconfigured" }); return; }
      try {
        const next = await completeLegalSignIn(config);
        if (next === LEGAL_INVITATION_REDIRECTED || next === LEGAL_SIGN_IN_REDIRECTED) return;
        if (next === LEGAL_RENEWAL_RELAYED) { if (!cancelled) setGate({ state: "renewal-relayed" }); return; }
        if (next && next !== router.asPath) { void router.replace(next); return; }
      } catch {
        if (!cancelled) setGate({ state: "signed-out", config, error: "Sign-in did not complete. Please try again." });
        return;
      }
      if (cancelled) return;
      if (!legalSignedIn()) { setGate({ state: "signed-out", config }); return; }
      const session = currentFirmSession();
      if (session) {
        try { await validateFirmSession(config, session); }
        catch (error) {
          if (cancelled) return;
          setFirmSession(null);
          setGate({ state: 'needs-key', config, error: failureMessage(error, 'Your workspace could not be verified. Please try again.') });
          return;
        }
      }
      if (cancelled) return;
      setGate(session ? { state: "ready", config, session } : { state: "needs-key", config });
    })();
    return () => { cancelled = true; };
  }, [router]);

  if (gate.state === "loading") return <p role="status">Loading…</p>;
  if (gate.state === "disabled") return <p className={panel}>The legal portal is not available on this site.</p>;
  if (gate.state === "unconfigured") return <p className={panel}>Legal portal not configured.</p>;
  // This is the separate sign-in window; the page that opened it continues.
  if (gate.state === "renewal-relayed") return <p role="status" className={panel}>You are signed in again. You can close this window.</p>;
  if (gate.state === "signed-out") {
    if (welcome) return <>
      <div className={onboardingStyles.grid}>
        <section className={onboardingStyles.card}>
          <ShieldCheck size={28} strokeWidth={1.4} aria-hidden />
          <p className={`${onboardingStyles.eyebrow} mt-5`}>NEW TO VERA</p>
          <h2>Bring your organization on board.</h2>
          <p className={onboardingStyles.muted}>Apply once for your organization and lawyer registration. After approval, sign in with your email code to join your organization automatically.</p>
          <div className={onboardingStyles.actions}><Link href="/legal/apply" className={onboardingStyles.primary}>Apply for approval <ArrowRight size={16} aria-hidden /></Link></div>
        </section>
        <section className={onboardingStyles.card}>
          <LockKeyhole size={28} strokeWidth={1.4} aria-hidden />
          <p className={`${onboardingStyles.eyebrow} mt-5`}>ALREADY APPROVED</p>
          <h2>Pick up where you left off.</h2>
          <p className={onboardingStyles.muted}>{gate.config.connection === 'email'
            ? 'Continue with your existing sign-in on this browser. If it has expired, verify your approved organization email with a code. No password required.'
            : 'Sign in with your approved organization email. Your membership is added automatically after approval.'}</p>
          <p className={`${onboardingStyles.muted} mt-3`}>After sign-in, open your workspace with your organization&apos;s encrypted private key file and its separate recovery code or passphrase.</p>
          <div className={onboardingStyles.actions}><button type="button" className={onboardingStyles.secondary} onClick={() => void beginLegalSignIn(gate.config, returnPath)
            .catch(() => setGate({ ...gate, error: 'Sign-in could not start. Please try again.' }))}>{gate.config.connection === 'email' ? 'Sign in with email' : 'Sign in'} <ArrowRight size={16} aria-hidden /></button></div>
          {gate.error && <p role="alert" className={onboardingStyles.error}>{gate.error}</p>}
        </section>
      </div>
      <div className={onboardingStyles.overview}>
        {[
          ['01', 'Apply once', 'We review your application.'],
          ['02', 'Finish your setup', 'Save and check your key, then open your approved workspace.'],
          ['03', 'Work with permission', 'Each reporter decides whether to share private information with you.'],
        ].map(([number, heading, text]) => <div key={number}><span className={onboardingStyles.number}>{number}</span><strong>{heading}</strong><p>{text}</p></div>)}
      </div>
    </>;
    return (
      <section className={panel}>
        <p className="mb-4 max-w-[62ch]">
          Approved legal organizations can sign in with their organization account.
        </p>
        <button type="button" className={primaryButton} onClick={() => void beginLegalSignIn(gate.config, returnPath)
          .catch(() => setGate({ ...gate, error: "Sign-in could not start. Please try again." }))}>Sign in</button>
        <p className="mt-4 text-sm">New organization? <Link href="/legal/apply" className="underline">Apply for approval</Link>.</p>
        {gate.error && <p role="alert" className="mt-3 text-red-800">{gate.error}</p>}
      </section>
    );
  }
  if (gate.state === "needs-key") {
    return (
      <div className="space-y-6">
        {gate.error && <p role="alert" className="text-sm text-red-800">{gate.error}</p>}
        <FirmKeyUnlock config={gate.config} signedIn
          onUnlocked={session => setGate({ state: "ready", config: gate.config, session })} />
        <FirmWorkspaceUnlock config={gate.config} onUnlocked={(session, notice) => setGate({ state: "ready", config: gate.config, session, notice })} />
        <section className="border-t border-black/10 pt-6 text-sm">
          <h2 className="mb-2 font-semibold">Setting up your organization for the first time?</h2>
          <p className="max-w-[72ch] leading-relaxed text-black/65">If you have not created and saved your organization key yet, finish your approved setup first.</p>
          <Link className={onboardingStyles.textButton} href="/legal/enroll">Finish your approved setup <ArrowRight size={14} className="ml-1 inline" aria-hidden /></Link>
        </section>
      </div>
    );
  }
  const lock = () => { setFirmSession(null); lockParticipantTabs(); };
  return (
    <div className={workspaceStyles.workspace}>
      <div className={workspaceStyles.identity}>
        <div className={workspaceStyles.firm}>
          <span className={workspaceStyles.firmIcon}><Building2 size={23} strokeWidth={1.5} aria-hidden /></span>
          <div><strong>{gate.session.firm.domain}</strong><small>Organization key unlocked on this device</small></div>
        </div>
        <span className={workspaceStyles.sessionActions}>
          <button type="button" onClick={lock}><LockKeyhole size={15} aria-hidden />Lock key</button>
          <button type="button" onClick={() => { setFirmSession(null); lockParticipantTabsForSignOut(); signOutLegal(gate.config); }}><LogOut size={15} aria-hidden />Sign out</button>
        </span>
      </div>
      <p className={workspaceStyles.lockNote}>Locking or signing out clears open confidential tabs, including unsaved drafts and recovery codes.</p>
      <nav aria-label="Legal portal" className={workspaceStyles.navigation}>
        <Link href="/legal" aria-current={router.pathname === '/legal' ? 'page' : undefined}><Files size={16} aria-hidden />Requests and reports</Link>
        <Link href="/legal/members" aria-current={router.pathname === '/legal/members' ? 'page' : undefined}><Users size={16} aria-hidden />Lawyers and devices</Link>
      </nav>
      {expired && <section className={workspaceStyles.renewal} role="status">
        <Clock3 size={23} strokeWidth={1.5} aria-hidden />
        <div className={workspaceStyles.renewalText}><h2>Sign in to keep working</h2>
          <p>Your sign-in has expired. Sign in again in a separate window; your open key, this page and any download in progress stay in place.</p></div>
        <button type="button" className={onboardingStyles.primary} disabled={renewing} onClick={() => {
          setRenewing(true); setRenewalError('');
          // Opened straight from this click so the browser allows the window.
          renewLegalSignIn(gate.config).then(() => { setRenewing(false); setExpired(!legalSignedIn()); }, error => {
            setRenewing(false);
            setRenewalError(error instanceof LegalPopupBlocked ? error.message : 'Sign-in did not finish. Try again.');
          });
        }}>{renewing ? 'Waiting for sign-in…' : 'Sign in again'}</button>
        {renewalError && <div role="alert" className={`${workspaceStyles.renewalError} mt-2 text-sm`}>
          <p>{renewalError}</p>
          <p className="mt-1">
            {!currentFirmVault() && 'Signing in on this page reloads it. Save an encrypted workspace backup below first to keep your list of requests and report history checks. '}
            <button type="button" className="underline" onClick={() => {
              setRenewalError('');
              void persistFirmWorkspace().then(() => beginLegalSignIn(gate.config, returnPath))
                .catch(() => setRenewalError('The workspace could not be saved. Save a backup before leaving this page.'));
            }}>Sign in on this page instead</button>
          </p>
        </div>}
      </section>}
      {gate.notice && <p role="status" className="mb-6 border border-black/20 p-4 text-sm">{gate.notice}</p>}
      {children({ session: gate.session, config: gate.config, lock })}
      <FirmDeviceTools session={gate.session} />
    </div>
  );
}

export function failureMessage(error: unknown, fallback: string): string {
  if (error instanceof LegalSignInRequired) return error.message;
  if (error instanceof WorkspaceKeyMismatchError || error instanceof WorkspaceMembershipRequiredError) return error.message;
  if (isReleasePaused(error)) {
    return `${error.message} The report stays encrypted. Access resumes only after VERA deploys a replacement and the reporter approves it.`;
  }
  if (error instanceof Error && error.name === "Error" && "code" in error) return userFacingMessage(error, fallback);
  if (error instanceof Error && (error.name === "ConfidentialUnavailableError" || error.message.startsWith("The secure connection"))) return error.message;
  return fallback;
}

function FirmDeviceTools({ session }: { session: FirmSession }) {
  const [vault, setVault] = useState<UnlockedVault | null>(currentFirmVault);
  const [backup, setBackup] = useState<{ firm: FirmIdentity; secret: string } | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const secret = backup?.firm === session.firm ? backup.secret : '';
  return <details className={workspaceStyles.tools}>
    <summary>Key backup and device settings</summary>
    <section className="mt-6 border border-black/20 p-4" aria-label="Organization backup">
      <h3 className="font-semibold">Organization private key backup</h3>
      <p className="my-2 text-sm">Save an encrypted private key file and keep its recovery code separately. This keeps the same
        organization key and reporter access. VERA cannot recover either saved copy.</p>
      {!secret ? <button type="button" className={secondaryButton} onClick={async () => {
        const { generateFirmRecoveryCode } = await import('@/lib/confidential/firmKey');
        setBackup({ firm: session.firm, secret: generateFirmRecoveryCode() }); setShowSecret(false);
      }}>Create encrypted backup</button> : <>
        <label className="my-3 block text-sm">Backup recovery code — save separately
          <input type={showSecret ? 'text' : 'password'} value={secret} readOnly autoComplete="off" spellCheck={false}
            className="mt-1 block w-full border border-black/30 px-3 py-2 font-mono" />
        </label>
        <button type="button" className="mb-4 text-sm underline" aria-pressed={showSecret}
          onClick={() => setShowSecret(value => !value)}>{showSecret ? 'Hide recovery code' : 'Show recovery code'}</button>
        <FirmKeyBackup firm={session.firm} secret={secret} className={secondaryButton} verifyStep={false} />
      </>}
    </section>
    <RememberWorkspace role="legal" vault={vault} organizationDomain={session.firm.domain} getPayload={async () => currentFirmPayload()}
      onRemembered={saved => { setFirmVault(saved); setVault(saved); }} />
  </details>;
}
