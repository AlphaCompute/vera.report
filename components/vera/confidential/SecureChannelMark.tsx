import { useEffect, useState, useSyncExternalStore } from "react";
import { motion } from "motion/react";
import { Check, LockKeyhole } from "lucide-react";
import { usePrefersReducedMotion } from "../../../hooks/usePrefersReducedMotion";
import { lastVerification, subscribeVerification } from "@/lib/confidential/verificationRecord";
import type { VerificationRecord } from "@/lib/confidential/verificationRecord";

export type SecureChannelState = "pending" | "verified" | "failed";

/**
 * What the header mark may claim about the secure service. It only says
 * "verified" after this tab actually verified the release this page expects;
 * a failed check (release identity unavailable, or an attestation that did not
 * verify) always wins over an earlier success.
 */
export function secureChannelState(input: {
  releaseIdentity: "loading" | "failed" | { digest: string };
  connectionState: SecureChannelState;
  verification: VerificationRecord | null;
}): SecureChannelState {
  if (input.connectionState === "failed" || input.releaseIdentity === "failed") return "failed";
  if (input.connectionState === "pending" || input.releaseIdentity === "loading" || !input.verification) return "pending";
  return input.verification.releaseDigest === input.releaseIdentity.digest ? "verified" : "pending";
}

const LOOK: Record<SecureChannelState, { label: string; color: string; description: string }> = {
  pending: { label: "Checking enclave", color: "#dc2626",
    description: "Your browser is checking VERA’s secure service and its encrypted reply." },
  verified: { label: "Enclave verified", color: "var(--color-green-600)",
    description: "Your browser verified VERA’s secure service and its encrypted reply. It checks again before sending your report." },
  failed: { label: "Not verified", color: "#dc2626",
    description: "The latest secure operation did not complete. VERA must verify the service before sending your report." },
};

/** Header status square + label for the confidential intake, driven by real verification state. */
export function SecureChannelMarkView({ state }: { state: SecureChannelState }) {
  const look = LOOK[state];
  return (
    <div className="flex w-full flex-wrap items-center justify-between gap-x-4 gap-y-3" data-secure-channel={state} title={look.description}>
      <span className="inline-flex items-center gap-3 text-sm font-semibold uppercase tracking-[2px]">
        <span className="relative block size-3 shrink-0" aria-hidden="true">
          {state === 'verified' && <span className="absolute inset-0 opacity-40 motion-safe:animate-ping" style={{ backgroundColor: look.color }} />}
          <span className="absolute inset-0 motion-safe:animate-pulse" style={{ backgroundColor: look.color }} />
        </span>
        Confidential
      </span>
      <span
        className="uppercase whitespace-nowrap"
        role="status"
        aria-atomic="true"
        style={{
          fontFamily: "var(--font-display)",
          fontWeight: 600,
          fontSize: "clamp(0.625rem, 0.69vw, 0.75rem)",
          letterSpacing: "2px",
          lineHeight: 1,
          color: "#000",
        }}
      >
        {look.label}
        <span className="sr-only">. {look.description}</span>
      </span>
    </div>
  );
}

/** Entry becomes ready only after the attested service answers an encrypted challenge. */
export function ConfidentialLoading({ ready, failed, onComplete }: { ready: boolean; failed: boolean; onComplete: () => void }) {
  const [presentationStage, setPresentationStage] = useState(0);
  const [leaving, setLeaving] = useState(false);
  const reducedMotion = usePrefersReducedMotion();
  useEffect(() => {
    // Keep each presentation stage readable even when verification is fast.
    const timers = [900, 1900, 3000].map((delay, index) => setTimeout(() => setPresentationStage(index + 1), delay));
    return () => timers.forEach(clearTimeout);
  }, []);
  const settled = presentationStage === 3 && (ready || failed);
  const loaded = settled && ready && !failed;
  const stage = loaded ? 3 : presentationStage === 0 ? 0 : !ready || failed ? 1 : Math.min(presentationStage, 2);
  const steps = ['Opening your private space', 'Verifying your secure connection', 'Getting ready for your story', 'You’re in. Take your time.'];
  useEffect(() => {
    if (!settled) return;
    const timer = setTimeout(() => setLeaving(true), 1500);
    return () => clearTimeout(timer);
  }, [settled]);
  return (
    <motion.main id="main-content" className="flex min-h-screen items-center justify-center bg-white px-6 text-black" tabIndex={-1}
      initial={false} animate={{ opacity: leaving ? 0 : 1 }} transition={{ duration: reducedMotion ? 0 : 0.35 }}
      onAnimationComplete={() => { if (leaving) onComplete(); }}>
      <div className="w-full max-w-md" style={{ fontFamily: 'var(--font-mono)' }}>
        <div className="mb-6 flex items-center justify-between gap-4">
          <h1 className="text-xs uppercase tracking-[2px]" style={{ fontFamily: 'inherit' }}>Confidential workspace</h1>
          <span data-workspace-light aria-hidden="true" className={`block size-2.5 shrink-0 ${loaded ? 'bg-green-600 motion-safe:animate-pulse' : 'bg-red-600'}`} />
        </div>
        <div className={`border p-1 transition-colors ${loaded ? 'border-green-600/40' : 'border-black/20'}`} aria-hidden="true">
          <div className="h-2 overflow-hidden bg-black/5">
            <motion.div className={`h-full origin-left ${loaded ? 'bg-green-600' : 'bg-black'}`}
              initial={{ scaleX: 0 }} animate={{ scaleX: loaded ? 1 : [0.2, 0.5, 0.85][stage] }}
              transition={{ duration: reducedMotion ? 0 : loaded ? 0.35 : 0.8, ease: 'easeInOut' }} />
          </div>
        </div>
        <div className="mt-6 min-h-40" data-workspace-state={loaded ? 'loaded' : settled ? 'failed' : 'loading'}>
          <ol aria-label="Workspace preparation" className="space-y-4 text-xs uppercase tracking-wide">
            {steps.slice(0, stage + 1).map((label, index) => (
              <motion.li key={label} className={`flex items-center gap-3 ${loaded ? 'text-green-700' : index < stage ? 'text-black/40' : 'text-black'}`}
                aria-current={index === stage && !loaded ? 'step' : undefined}
                initial={reducedMotion ? false : { opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
                transition={{ duration: reducedMotion ? 0 : 0.25 }}>
                {loaded && index === 3 ? <LockKeyhole className="size-4 shrink-0" aria-hidden="true" />
                  : index < stage ? <Check className="size-4 shrink-0" aria-hidden="true" />
                    : <span className="inline-block w-4 shrink-0 motion-safe:animate-pulse" aria-hidden="true">&gt;</span>}
                <span>{settled && failed && index === stage ? 'Workspace unavailable' : label}</span>
              </motion.li>
            ))}
          </ol>
          <p role="status" aria-live="polite" aria-atomic="true" className="sr-only">{settled && failed ? 'Workspace unavailable' : steps[stage]}</p>
        </div>
      </div>
    </motion.main>
  );
}

export function SecureChannelMark(props: {
  releaseIdentity: "loading" | "failed" | { digest: string };
  connectionState: SecureChannelState;
}) {
  const verification = useSyncExternalStore<VerificationRecord | null>(subscribeVerification, lastVerification, () => null);
  return <SecureChannelMarkView state={secureChannelState({ ...props, verification })} />;
}
