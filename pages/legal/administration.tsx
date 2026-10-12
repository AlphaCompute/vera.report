import { useParticipantLock } from '@/components/vera/confidential/DeviceWorkspaces';
import { useCallback, useEffect, useRef, useState } from 'react';
import { LegalPortalDisabled, LegalPortalLayout, panel, primaryButton, secondaryButton } from '@/components/vera/confidential/LegalPortal';
import { CONFIDENTIAL_RELEASE_MANIFEST, confidentialCasesEnabled } from '@/lib/confidential/config';
import {
  LegalSignInRequired, beginOnboardingSignIn, completeOnboardingSignIn, onboardingAccessToken, onboardingAuthConfig,
  onboardingSessionEndsAt, onboardingSignedIn, signOutOnboarding,
} from '@/lib/confidential/onboardingAuth';
import {
  DOMAIN_CHECK_MESSAGES, INVITATION_UNCONFIRMED, copyInvitationLink, LegalAdminError, checkLegalDomain, clearInvitationSelection, formatAdminTime, invitationPlan,
  legalAdminMessage, listLegalOrganizations, readInvitationSelection, rememberInvitationSelection,
} from '@/lib/legalOnboardingClient';
import type { DomainCheck, LegalAdminFailure } from '@/lib/legalOnboardingClient';
import { LEGAL_INVITATION_MAX_DAYS, LEGAL_SUBJECT, groupKeyId } from '@/src/utils/legalOnboarding';
import type { LegalOrganizationView } from '@/src/utils/legalOnboarding';

const field = 'mt-1 block w-full border border-black/30 px-3 py-2';
const hint = 'mt-1 text-sm text-black/60';
const DAY = 24 * 60 * 60 * 1000;

function remaining(endsAt: number | null, now: number): string {
  if (!endsAt || endsAt <= now) return '0:00';
  const seconds = Math.floor((endsAt - now) / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

/** Issue a private, recipient-bound invitation for a legal organization.
 * Needs a VERA admin session (to read the roster), the separate onboarding sign-in
 * and the onboarding authority key; the enclave checks the last two. The authority
 * key and its code stay in this page's memory and are cleared by the idle lock.
 * This page grants no access to any report. Nothing (no sign-in completion, no
 * cross-tab lock, no roster request) runs unless this build enables confidential cases. */
export default function LegalAdministration() {
  return confidentialCasesEnabled() ? <LegalOnboarding /> : <LegalPortalDisabled title="Legal onboarding" />;
}

function LegalOnboarding() {
  useParticipantLock('/legal', true);
  const config = onboardingAuthConfig();
  const [now, setNow] = useState(() => Date.now());
  const [signedIn, setSignedIn] = useState(false);
  const [signInError, setSignInError] = useState('');
  const [organizations, setOrganizations] = useState<LegalOrganizationView[] | null>(null);
  const [failure, setFailure] = useState<LegalAdminFailure | null>(null);
  const [organizationId, setOrganizationId] = useState('');
  const [check, setCheck] = useState<DomainCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const [keyConfirmed, setKeyConfirmed] = useState(false);
  const [readbackKeyId, setReadbackKeyId] = useState('');
  const [recipientConfirmed, setRecipientConfirmed] = useState(false);
  const [replaceKey, setReplaceKey] = useState(false);
  // Typed by the approver from the organization's own read-out (phone or another
  // channel they already trust), never filled from VERA's records.
  const [subject, setSubject] = useState('');
  const [subjectTouched, setSubjectTouched] = useState(false);
  const [days, setDays] = useState(LEGAL_INVITATION_MAX_DAYS);
  const [file, setFile] = useState<File | null>(null);
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<{ link: string; expiresAt: number; subject: string; organization: string } | null>(null);
  const [copied, setCopied] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);
  const checkGeneration = useRef(0);

  useEffect(() => {
    const settings = onboardingAuthConfig();
    if (!settings) return;
    completeOnboardingSignIn(settings).then(() => setSignedIn(onboardingSignedIn()))
      .catch(() => setSignInError('The onboarding sign-in could not be completed. Please sign in again.'));
  }, []);
  useEffect(() => {
    const timer = setInterval(() => { setNow(Date.now()); setSignedIn(onboardingSignedIn()); }, 1000);
    return () => clearInterval(timer);
  }, []);
  const loadOrganizations = useCallback(async () => {
    setFailure(null);
    try {
      const list = await listLegalOrganizations();
      setOrganizations(list);
      const selection = readInvitationSelection();
      const selected = selection && list.find(item => item.organizationId === selection.organizationId && item.status !== 'revoked');
      if (selected) {
        setOrganizationId(selected.organizationId);
      }
    } catch (caught) { setFailure(caught instanceof LegalAdminError ? caught.failure : { kind: 'unavailable' }); }
  }, []);
  useEffect(() => { if (confidentialCasesEnabled() && config) void loadOrganizations(); }, [loadOrganizations]);

  const organization = organizations?.find(item => item.organizationId === organizationId) ?? null;
  const runCheck = useCallback(async (target: LegalOrganizationView) => {
    const generation = ++checkGeneration.current;
    setChecking(true); setCheck(null); setKeyConfirmed(false); setReadbackKeyId(''); setRecipientConfirmed(false); setReplaceKey(false);
    try {
      const checked = await checkLegalDomain(target);
      if (generation === checkGeneration.current) setCheck(checked);
    } finally { if (generation === checkGeneration.current) setChecking(false); }
  }, []);
  useEffect(() => {
    setCheck(null); setKeyConfirmed(false); setReadbackKeyId(''); setRecipientConfirmed(false); setReplaceKey(false);
    if (organization) void runCheck(organization);
    else { checkGeneration.current++; setChecking(false); }
    return () => { checkGeneration.current++; };
  }, [organization?.organizationId, organization?.domain]);
  useEffect(() => { if (result) resultHeading.current?.focus(); }, [result]);
  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);

  const plan = invitationPlan({ organization, check, keyConfirmed, readbackKeyId, replaceKey });
  // Recomputed against the current roster row, which changes after a first registration.
  const keyMatch = check?.kind === 'verified' && organization?.recipientKeyId ? organization.recipientKeyId === check.recipientKeyId
    : check?.kind === 'verified' ? null : undefined;
  const subjectValid = LEGAL_SUBJECT.test(subject.trim());
  const endsAt = onboardingSessionEndsAt();
  const canIssue = !!config && signedIn && plan.ready && subjectValid && recipientConfirmed && !!file && secret.length > 0 && !busy;

  const signIn = () => {
    if (!config) return;
    rememberInvitationSelection({ organizationId });
    void beginOnboardingSignIn(config, '/legal/administration');
  };
  const issue = async () => {
    if (!canIssue || !config || !organization || !plan.ready || !file) return;
    setBusy(true); setError(''); setResult(null);
    const code = secret;
    setSecret('');
    try {
      if (file.size > 131072) throw new Error('key-file');
      const [{ importFirmIdentity }, { issueLegalInvitation }, { fetchRelay }] = await Promise.all([
        import('@/lib/confidential/firmKey'), import('@/lib/confidential/onboarding'), import('@/lib/confidential/client')]);
      let authority;
      try { authority = await importFirmIdentity(await file.text(), code); } catch { throw new Error('key-file'); }
      const issued = await issueLegalInvitation({ relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST,
        accessToken: await onboardingAccessToken(config), authority: authority.privateKey,
        organizationId: organization.organizationId, providerOrganizationId: organization.providerOrganizationId!,
        recipientKeyId: plan.recipientKeyId, subject: subject.trim(), now: Date.now(), lifetimeMs: days * DAY,
        ...(plan.register ? { registration: { domain: organization.domain, displayName: organization.displayName,
          bindingDocument: check?.kind === 'verified' ? check.bindingDocument! : '',
          ...(check?.kind === 'verified' && check.continuity ? { continuity: check.continuity } : {}) } } : {}) });
      clearInvitationSelection();
      setResult({ link: `${window.location.origin}/legal/enroll#invitation=${issued.token}`, expiresAt: issued.expiresAt,
        subject: subject.trim(), organization: organization.displayName });
      setSubject(''); setSubjectTouched(false); setRecipientConfirmed(false); setKeyConfirmed(false); setReadbackKeyId(''); setFile(null);
      if (fileInput.current) fileInput.current.value = '';
      void loadOrganizations();
    } catch (caught) {
      if (caught instanceof LegalSignInRequired) {
        setSignedIn(false);
        setError('Your onboarding sign-in has ended (it lasts five minutes). Sign in again, then choose the key file and enter its code again.');
      } else if (caught instanceof Error && caught.message === 'key-file') {
        setError('The onboarding authority key file or its recovery code is not right. Nothing was issued.');
      } else {
        setError(INVITATION_UNCONFIRMED);
      }
    } finally { setBusy(false); }
  };
  const copyLink = async () => {
    if (!result) return;
    if (!navigator.clipboard) { setCopied('Copy failed. Select the link and copy it instead.'); return; }
    setCopied(await copyInvitationLink(result.link, navigator.clipboard));
  };

  if (!confidentialCasesEnabled() || !config) {
    return <LegalPortalLayout title="Legal onboarding">
      <p>Invitation issuing is not configured on this deployment. It needs encrypted reports and the separate onboarding sign-in.</p>
    </LegalPortalLayout>;
  }

  return <LegalPortalLayout title="Legal onboarding">
    <p className="mb-6 max-w-[62ch] text-sm text-black/70">
      Issue a private, single-use invitation for one named person at a legal organization. Their access lasts until the invitation’s
      end date and is renewed with a new invitation. An invitation never gives access to a report: only the reporter can allow that.
    </p>
    <p className="mb-6 text-sm"><a className="underline" href="/legal/organizations">Back to legal organizations</a></p>

    {result && <section className={`${panel} mb-6 border-black`} aria-labelledby="issued-title">
      <h2 id="issued-title" ref={resultHeading} tabIndex={-1} className="mb-3 font-semibold outline-none">Invitation ready for {result.subject}</h2>
      <p className="mb-3 text-sm">Send this link privately to that person only, for example through the organization’s own secure channel.
        It works once, only for their sign-in at {result.organization}, until {formatAdminTime(result.expiresAt)}.
        It is shown only here and is not stored by VERA.</p>
      <label className="block text-sm" htmlFor="invitation-link">Invitation link</label>
      <textarea id="invitation-link" readOnly rows={3} className={`${field} break-all font-mono text-xs`} value={result.link} spellCheck={false} autoComplete="off" onFocus={event => event.currentTarget.select()} />
      <div className="mt-3 flex flex-wrap gap-3">
        <button type="button" className={primaryButton} onClick={() => void copyLink()}>Copy link</button>
        <button type="button" className={secondaryButton} onClick={() => { setResult(null); setCopied(''); }}>Done, hide the link</button>
      </div>
      <p aria-live="polite" className="mt-2 text-sm text-black/60">{copied}</p>
    </section>}

    {failure ? <div role="alert" className={panel}>
      <p>{legalAdminMessage(failure)}</p>
      {failure.kind === 'signed-out' && <a className={`${primaryButton} mt-4 inline-block`} href="/auth/login?returnTo=/legal/administration">Sign in to VERA admin</a>}
      {failure.kind === 'unavailable' && <button type="button" className={`${secondaryButton} mt-4`} onClick={() => void loadOrganizations()}>Try again</button>}
    </div> : !organizations ? <p role="status">Loading legal organizations…</p> : <div className="space-y-6">
      <section className={panel} aria-labelledby="step-organization">
        <h2 id="step-organization" className="mb-3 font-semibold">1. Legal organization</h2>
        {organizations.filter(item => item.status !== 'revoked').length === 0
          ? <p className="text-sm">No legal organizations yet. <a className="underline" href="/legal/organizations">Add one first</a>.</p>
          : <>
            <label className="block text-sm" htmlFor="invite-organization">Organization</label>
            <select id="invite-organization" className={field} value={organizationId} disabled={busy} onChange={event => { checkGeneration.current++; setCheck(null); setKeyConfirmed(false); setReadbackKeyId(''); setRecipientConfirmed(false); setSubject(''); setReplaceKey(false); setOrganizationId(event.target.value); }}>
              <option value="">Choose…</option>
              {organizations.filter(item => item.status !== 'revoked').map(item =>
                <option key={item.organizationId} value={item.organizationId}>
                  {item.displayName} ({item.domain}){item.status === 'awaiting-registration' ? ' – key not registered yet' : ''}
                </option>)}
            </select>
          </>}
      </section>

      {organization && <section className={panel} aria-labelledby="step-key">
        <h2 id="step-key" className="mb-3 font-semibold">2. Check its key</h2>
        <p className="mb-3 break-all text-sm text-black/70">Candidate public key for {organization.domain}. Its signature proves possession of the key; independently confirm who controls it before signing approval.</p>
        <button type="button" className={secondaryButton} disabled={checking || busy} onClick={() => void runCheck(organization)}>
          {checking ? 'Checking…' : 'Check again'}
        </button>
        <div aria-live="polite" className="mt-3 space-y-3 text-sm">
          {check?.kind === 'verified' && <>
            <p>Key ID submitted by {organization.domain}:</p>
            <p className="break-all font-mono text-base">{groupKeyId(check.recipientKeyId)}</p>
            {keyMatch === true && <p>This is the registered key.</p>}
            {keyMatch === null && <p>The first invitation registers this key for {organization.displayName}.</p>}
            {keyMatch === false && <div className="space-y-2 border border-red-700 p-3">
              <p className="font-semibold text-red-800">This is not the registered key.</p>
              <p>Registered Key ID: <span className="break-all font-mono">{organization.recipientKeyId ? groupKeyId(organization.recipientKeyId) : '—'}</span></p>
              <p>Replace it only if the organization confirms it changed its key. The replacement is signed by the registered key.
                Everyone enrolled with the old key must be invited again, and each reporter must allow the new key before it can read
                their report: the new key receives nothing already shared.</p>
              <label className="flex items-start gap-2">
                <input type="checkbox" className="mt-1" checked={replaceKey} disabled={busy} onChange={event => setReplaceKey(event.target.checked)} />
                <span>Replace the registered key with the submitted one</span>
              </label>
            </div>}
            <p>Contact an authorized representative by phone or in person using contact details established during application review.
              Ask them to read the Key ID from their saved key. Do not copy the displayed value or rely on contact details supplied with this candidate.</p>
            <label className="block" htmlFor="key-readback">Key ID read back by the organization</label>
            <input id="key-readback" className={`${field} font-mono`} value={readbackKeyId} spellCheck={false} autoComplete="off" disabled={busy}
              onChange={event => { setReadbackKeyId(event.target.value); setKeyConfirmed(false); }} />
            <label className="flex items-start gap-2">
              <input type="checkbox" className="mt-1" checked={keyConfirmed} disabled={busy} onChange={event => setKeyConfirmed(event.target.checked)} />
              <span>I confirmed this Key ID with an authorized representative by phone or in person.</span>
            </label>
          </>}
          {check && check.kind !== 'verified' && <p role="alert" className="text-red-800">{DOMAIN_CHECK_MESSAGES[check.kind]}</p>}
        </div>
      </section>}

      {organization && <section className={panel} aria-labelledby="step-signin">
        <h2 id="step-signin" className="mb-3 font-semibold">3. Onboarding sign-in</h2>
        {signedIn ? <p className="text-sm">
          Signed in with the onboarding account. Time left: <span className="font-mono">{remaining(endsAt, now)}</span>.{' '}
          <button type="button" className="underline" onClick={() => signOutOnboarding(config)}>Sign out</button>
        </p> : <>
          <p className="mb-3 text-sm text-black/70">A separate account from your VERA admin sign-in. It lasts five minutes, so sign in just before issuing.</p>
          <button type="button" className={primaryButton} disabled={busy} onClick={signIn}>Sign in with the onboarding account</button>
        </>}
        {signInError && <p role="alert" className="mt-2 text-sm text-red-800">{signInError}</p>}
      </section>}

      {organization && <section className={panel} aria-labelledby="step-person">
        <h2 id="step-person" className="mb-3 font-semibold">4. Person to invite</h2>
        <label className="block text-sm" htmlFor="invite-subject">Their user ID in the legal sign-in tenant</label>
        <input id="invite-subject" className={`${field} font-mono`} value={subject} autoComplete="off" spellCheck={false} disabled={busy}
          placeholder="auth0|…" aria-invalid={subjectTouched && !subjectValid ? true : undefined} aria-describedby="invite-subject-hint"
          onBlur={() => setSubjectTouched(true)} onChange={event => { setSubject(event.target.value); setRecipientConfirmed(false); }} />
        <p id="invite-subject-hint" className={hint}>Only this person, signed in to {organization.providerOrganizationId ?? 'the organization'}, can accept the invitation.</p>
        <p className={hint}>Confirm the person with the organization using the trusted contact above, then independently check their user ID and organization membership in Auth0. Submitted profile data is not identity verification.</p>
        <label className="mt-3 flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1" checked={recipientConfirmed} disabled={busy} onChange={event => setRecipientConfirmed(event.target.checked)} />
          <span>I independently verified this person’s identity and Auth0 organization membership.</span>
        </label>
        {subjectTouched && !subjectValid && <p className="mt-1 text-sm text-red-800">Enter a user ID such as auth0|65f0c1… (letters, a “|”, then the ID).</p>}
        <label className="mt-4 block text-sm" htmlFor="invite-days">Access lasts</label>
        <select id="invite-days" className={field} value={days} disabled={busy} onChange={event => setDays(Number(event.target.value))}>
          {Array.from({ length: LEGAL_INVITATION_MAX_DAYS }, (_, index) => index + 1).map(value =>
            <option key={value} value={value}>{value} day{value === 1 ? '' : 's'}</option>)}
        </select>
        <p className={hint}>The invitation must be accepted within this time, and access ends then. Renew with a new invitation.</p>
      </section>}

      {organization && <section className={panel} aria-labelledby="step-authority">
        <h2 id="step-authority" className="mb-3 font-semibold">5. Onboarding authority key</h2>
        <p className="mb-3 text-sm text-black/70">Used on this device only, to sign the invitation. It never leaves this page and is cleared after 15 idle minutes.</p>
        <label className="block text-sm">Encrypted onboarding authority key file
          <input ref={fileInput} className="mt-1 block" type="file" accept=".txt,text/plain" disabled={busy} onChange={event => setFile(event.target.files?.[0] ?? null)} />
        </label>
        <label className="mt-3 block text-sm">Key recovery code
          <input type="password" className={field} autoComplete="off" value={secret} disabled={busy} onChange={event => setSecret(event.target.value)} />
        </label>
      </section>}

      {organization && <div className="space-y-2">
        <button type="button" className={primaryButton} disabled={!canIssue} onClick={() => void issue()}>
          {busy ? 'Issuing…' : 'Issue invitation'}
        </button>
        {!busy && !canIssue && <p className="text-sm text-black/60" aria-live="polite">
          {!plan.ready ? plan.reason : !signedIn ? 'Sign in with the onboarding account.' : !subjectValid ? 'Enter the person’s user ID.'
            : !recipientConfirmed ? 'Independently verify the recipient’s identity and Auth0 membership.'
            : !file || !secret ? 'Choose the authority key file and enter its code.' : ''}
        </p>}
        {error && <p ref={errorRef} tabIndex={-1} role="alert" className="text-sm text-red-800 outline-none">{error}</p>}
      </div>}
    </div>}
  </LegalPortalLayout>;
}

/** Server-rendered so `_document` applies the strict key-page headers. */
export const getServerSideProps = async () => ({ props: {} });
