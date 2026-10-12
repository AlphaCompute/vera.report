import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { FirmIdentity } from '@/lib/confidential/firmKey';
import type { LegalAuthConfig } from '@/lib/confidential/legalAuth';
import { legalSignedIn, renewLegalSignIn } from '@/lib/confidential/legalAuth';
import styles from './LegalOnboarding.module.css';

export function AutomaticApplicationActivation({ firm, config, onDone, children }: {
  firm: FirmIdentity; config: LegalAuthConfig; onDone: () => void; children?: ReactNode;
}) {
  const [status, setStatus] = useState('checking'), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const [organization, setOrganization] = useState<string | null>(config.organization);
  const attempted = useRef(false), running = useRef(false), done = useRef(onDone);
  done.current = onDone;
  useEffect(() => {
    let active = true, pending = false;
    const poll = async () => {
      if (pending || document.visibilityState !== 'visible') return;
      pending = true;
      try {
        const response = await fetch('/api/legal-applications/status', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: firm.organizationId }), signal: AbortSignal.timeout(10000) });
        if (response.ok && active) {
          const result = await response.json();
          if (['unavailable', 'pending', 'sign-in-ready', 'ready', 'denied'].includes(result.state)) setStatus(result.state);
          if (/^org_[A-Za-z0-9]{1,64}$/.test(result.providerOrganizationId || '')) setOrganization(result.providerOrganizationId);
        }
      } catch { /* Never infer approval from a failed request. */ } finally { pending = false; }
    };
    void poll(); const timer = setInterval(() => void poll(), 15000);
    return () => { active = false; clearInterval(timer); };
  }, [firm.organizationId]);
  const activate = async (interactive: boolean) => {
    if (running.current || !interactive && !legalSignedIn()) return;
    running.current = true; setBusy(true); setError('');
    try {
      const settings = { ...config, organization };
      if (!legalSignedIn() || status === 'sign-in-ready') await renewLegalSignIn(settings, { firstSignIn: status === 'sign-in-ready' });
      const { waitForCombinedActivation } = await import('@/lib/confidential/combinedEnrollment');
      await waitForCombinedActivation(settings, firm);
      done.current();
    } catch { setError('Activation could not be confirmed. Keep this key open and retry. Use the same key that staff approved.'); }
    finally { running.current = false; setBusy(false); }
  };
  useEffect(() => {
    if (status === 'ready' && !attempted.current && legalSignedIn()) { attempted.current = true; void activate(false); }
  }, [status]);
  if (status === 'unavailable') return <>{children}</>;
  return <section className="mt-6 space-y-4" aria-label="Application and key approval">
    <h3 className="font-semibold">{status === 'ready' ? 'Your firm and key are approved.' : 'Firm and key approval'}</h3>
    <p role="status">{status === 'checking' ? 'Checking your application…' : status === 'denied' ? 'This key was not approved. Contact VERA onboarding.' : status === 'pending'
      ? 'Waiting for staff to approve this application and key in Slack. Your workspace will activate here after approval and sign-in.'
      : busy ? 'Activating your workspace…' : 'Your saved key and approved sign-in activate your workspace. No setup link is required.'}</p>
    {['ready', 'sign-in-ready'].includes(status) && <button className={styles.primary} disabled={busy} onClick={() => void activate(true)}>{busy ? 'Activating…' : status === 'ready' && legalSignedIn() ? 'Retry activation' : 'Sign in to open workspace'}</button>}
    {error && <p role="alert" className={styles.error}>{error}</p>}
  </section>;
}
