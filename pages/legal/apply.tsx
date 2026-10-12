import { useEffect, useState } from 'react';
import { ArrowRight, ShieldAlert } from 'lucide-react';
import { LegalPortalDisabled, LegalPortalLayout } from '@/components/vera/confidential/LegalPortal';
import styles from '@/components/vera/confidential/LegalOnboarding.module.css';
import { confidentialCasesEnabled } from '@/lib/confidential/config';
import { APPLICATION_LIMITS, EMPTY_APPLICATION, expireApplicationDraft, loadApplicationDraft, saveApplicationDraft } from '@/lib/legalApplicationDraft';
import { parseLegalApplication } from '@/src/utils/legalApplications';
import type { LegalApplicationInput } from '@/src/utils/legalApplications';
import { ApplicationKeySetup } from '@/components/vera/confidential/ApplicationKeySetup';

const labels: Record<keyof LegalApplicationInput, string> = {
  displayName: 'Legal organization', domain: 'Organization website domain', email: 'Organization email', lawyerName: 'Registered lawyer name',
  jurisdiction: 'Licensing jurisdiction', registrationNumber: 'Bar or registration number',
};
export default function Apply() {
  const [preparedApplication, setPreparedApplication] = useState<LegalApplicationInput | null>(null);
  const [values, setValues] = useState<LegalApplicationInput>({ ...EMPTY_APPLICATION });
  const [error, setError] = useState('');
  const [errors, setErrors] = useState<Partial<Record<keyof LegalApplicationInput, string>>>({});
  const [draftAvailable, setDraftAvailable] = useState(false);
  useEffect(() => {
    if (!confidentialCasesEnabled()) return;
    try { const loaded = loadApplicationDraft(window.sessionStorage); setValues(loaded); setDraftAvailable(Object.values(loaded).some(Boolean)); } catch { /* in-memory form */ }
    // The stored copy expires on schedule even if this tab stays open; the
    // entries on screen remain until the tab is closed or submitted.
    const timer = window.setInterval(() => {
      try { setDraftAvailable(expireApplicationDraft(window.sessionStorage)); } catch { setDraftAvailable(false); }
    }, 15_000);
    return () => window.clearInterval(timer);
  }, []);
  const change = (key: keyof LegalApplicationInput, value: string) => {
    const next = { ...values, [key]: value }; setValues(next); setErrors(current => ({ ...current, [key]: undefined }));
    try { setDraftAvailable(saveApplicationDraft(window.sessionStorage, next)); } catch { setDraftAvailable(false); }
  };
  if (!confidentialCasesEnabled()) return <LegalPortalDisabled title="Legal organization application" />;
  if (preparedApplication) return <ApplicationKeySetup application={preparedApplication} onBack={() => setPreparedApplication(null)} />;
  const field = (key: keyof LegalApplicationInput) => <div key={key} className={styles.field}><label htmlFor={key}>{labels[key]}</label>
    <input id={key} spellCheck={false} autoCorrect="off" name={key} required type={key === 'email' ? 'email' : 'text'}
      maxLength={APPLICATION_LIMITS[key]} value={values[key]} onChange={event => change(key, event.target.value)}
      autoComplete={key === 'email' ? 'email' : 'off'} placeholder={key === 'domain' ? 'organization.example' : undefined}
      aria-invalid={!!errors[key]} aria-describedby={errors[key] ? key + '-error' : key === 'domain' || key === 'email' ? key + '-hint' : undefined} />
    {errors[key] ? <span id={key + '-error'} className={styles.error}>{errors[key]}</span>
      : key === 'domain' ? <span id="domain-hint" className={styles.hint}>Just the domain, without https:// or a page address.</span>
      : key === 'email' ? <span id="email-hint" className={styles.hint}>Use an email at the same domain. This will be your sign-in email.</span> : null}
  </div>;
  return <LegalPortalLayout title="One application. Your next step." onboarding
    backHref="/legal" intro="Tell us about your organization and one registered lawyer. Next, protect your key. One staff approval covers your application and public key.">
    <section className={`${styles.card} ${styles.form}`}>
      <div className={`${styles.notice} ${styles.danger}`}><ShieldAlert size={20} aria-hidden /><div>
        <strong>Not confidential. Do not include whistleblower or report details.</strong>
        <p>These application details are visible to Vera administrators and their staff notification service.</p>
      </div></div>
      <form noValidate onSubmit={async event => {
        event.preventDefault(); setError('');
        const issues: typeof errors = {};
        for (const key of Object.keys(labels) as (keyof LegalApplicationInput)[]) if (!values[key].trim()) issues[key] = 'Please complete this field.';
        if (values.displayName.trim() && values.displayName.trim().length < 2) issues.displayName = 'Enter your full organization name.';
        const domain = values.domain.trim().toLowerCase(), email = values.email.trim().toLowerCase();
        if (domain && !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) issues.domain = 'Enter a domain such as organization.example, without https:// or a path.';
        if (email && (!email.includes('@') || email.split('@')[1] !== domain)) issues.email = 'Use an organization email at the website domain above.';
        setErrors(issues);
        if (Object.keys(issues).length) { document.getElementById(Object.keys(issues)[0])?.focus(); return; }
        const input = parseLegalApplication(values);
        if (!input) { setError('Check your entries for invalid email characters or unsupported text, then try again.'); return; }
        setPreparedApplication(input);
      }}>
        <fieldset className={styles.group}><legend>Your organization</legend><div className={styles.formGrid}>
          {field('displayName')}{field('domain')}{field('email')}
        </div></fieldset>
        <fieldset className={styles.group}><legend>Your registered lawyer</legend><div className={styles.formGrid}>
          {field('lawyerName')}{field('jurisdiction')}{field('registrationNumber')}
        </div></fieldset>
        {error && <p role="alert" className={styles.error}>{error}</p>}
        <div className={styles.actions}><p className={styles.hint}>All fields are required.<br />{draftAvailable ? 'Your draft stays in this tab for 30 minutes.' : 'Keep this tab open to preserve your entries.'}</p>
          <button className={styles.primary}>Continue to key backup <ArrowRight size={16} aria-hidden /></button></div>
      </form>
    </section>
  </LegalPortalLayout>;
}

/** Run the shared nonce CSP and private/no-store headers for every request. */
export const getServerSideProps = async () => ({ props: {} });
