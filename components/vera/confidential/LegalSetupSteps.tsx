import { Check } from 'lucide-react';
import styles from './LegalOnboarding.module.css';

export type LegalSetupStep = 1 | 2;
export function LegalSetupSteps({ current, saved = false, onStep }: {
  current: LegalSetupStep; saved?: boolean; onStep?: (step: LegalSetupStep) => void;
}) {
  const steps = [
    { id: 1 as const, title: 'Protect your key', detail: 'Save and check a backup', enabled: true, done: saved },
    { id: 2 as const, title: 'Open your workspace', detail: 'Activate approved access', enabled: saved, done: false },
  ];
  return <nav aria-label="Organization setup progress" className={styles.stepper}>
    {steps.map(step => <button key={step.id} type="button" className={styles.step}
      aria-current={current === step.id ? 'step' : undefined} disabled={!onStep || !step.enabled}
      onClick={() => onStep?.(step.id)}>
      <span className={styles.stepNumber}>{step.done && current !== step.id ? <Check size={15} aria-hidden /> : `0${step.id}`}</span>
      <span><strong>{step.title}</strong><small>{step.detail}</small></span>
    </button>)}
  </nav>;
}
