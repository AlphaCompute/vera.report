/** Staged progress while confidential material opens on this device. Each stage
 * names what the device is waiting for; none of them reveals anything about the
 * report itself. Kept free of path aliases so it renders in unit tests. */
export type LoadStage = "verifying" | "opening" | "unlocking" | "checking";

export const LOAD_STAGE_TEXT: Record<LoadStage, string> = {
  verifying: "Verifying VERA’s secure service…",
  opening: "Opening your encrypted report on this device…",
  unlocking: "Unlocking your report…",
  checking: "Checking requests and access…",
};
const LOAD_STEPS: readonly LoadStage[] = ["verifying", "unlocking", "opening", "checking"];

/** Stages while a legal organization opens a report it has access to. */
export type FirmLoadStage = "verifying" | "unlocking" | "loading";
export const FIRM_STAGE_TEXT: Record<FirmLoadStage, string> = {
  verifying: "Verifying the secure service…",
  unlocking: "Unlocking the report…",
  loading: "Loading and decrypting the report…",
};
const FIRM_STEPS: readonly FirmLoadStage[] = ["verifying", "unlocking", "loading"];

export type ActionStage = "saving" | "refreshing";
export const ACTION_STAGE_TEXT: Record<ActionStage, string> = {
  saving: "Confirming your change with the secure service…",
  refreshing: "Refreshing your report…",
};

type StepState = "done" | "current" | "pending";

/** The steps shown for a stage. "Unlocking" appears only while it actually
 * happens (after the secure service restarted), never as a pending step. */
export function stagedSteps<S extends string>(steps: readonly S[], stage: S): { step: S; state: StepState }[] {
  const current = steps.indexOf(stage);
  return steps.filter(step => step !== "unlocking" || stage === "unlocking").map(step => {
    const index = steps.indexOf(step);
    return { step, state: index < current ? "done" : index === current ? "current" : "pending" };
  });
}
export function progressSteps(stage: LoadStage) { return stagedSteps(LOAD_STEPS, stage); }
export function firmProgressSteps(stage: FirmLoadStage) { return stagedSteps(FIRM_STEPS, stage); }

/** Current step as a sentence, plus a short checklist of done / current /
 * pending steps. Announced politely to screen readers. */
function StagedProgress<S extends string>({ stage, steps, text, className }: {
  stage: S; steps: { step: S; state: StepState }[]; text: Record<S, string>; className?: string;
}) {
  return (
    <div className={className} role="status" aria-live="polite" aria-busy="true">
      <p className="mb-3">{text[stage]}</p>
      <ol className="space-y-1 text-sm" aria-label="Progress">
        {steps.map(({ step, state }) => (
          <li key={step} className={state === "pending" ? "text-black/40" : undefined}
            aria-current={state === "current" ? "step" : undefined}>
            <span aria-hidden="true">{state === "done" ? "✓ " : state === "current" ? "→ " : "· "}</span>
            {text[step].replace("…", "")}
            <span className="sr-only">{state === "done" ? " (done)" : state === "current" ? " (in progress)" : " (waiting)"}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function LoadProgress({ stage, className }: { stage: LoadStage; className?: string }) {
  return <StagedProgress stage={stage} steps={progressSteps(stage)} text={LOAD_STAGE_TEXT} className={className} />;
}

export function FirmLoadProgress({ stage, className }: { stage: FirmLoadStage; className?: string }) {
  return <StagedProgress stage={stage} steps={firmProgressSteps(stage)} text={FIRM_STAGE_TEXT} className={className} />;
}
