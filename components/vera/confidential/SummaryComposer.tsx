import { useDeferredValue, useId, useMemo } from "react";
import { CONFIDENTIAL_SUMMARY_LIMIT } from "@/lib/confidential/config";
import { findIdentifyingDetails, SUMMARY_WARNING_ADVICE } from "@/lib/confidential/summaryWarnings";
import { SUMMARY_EXAMPLES } from "@/lib/confidential/summaryGuidance";
import { type ListingDraft } from "@/lib/confidential/listingDraft";

const label = "mb-2 block text-sm font-semibold uppercase tracking-widest text-black/60";
const box = "border border-black/15 p-4 sm:p-5";

/** Public listings contain the approved summary, opaque reference and optional signed submission facts. */
export function SummaryComposer({ value, onChange, commitVerb = "submit", disabled = false }: {
  value: ListingDraft; onChange: (value: ListingDraft) => void; disabled?: boolean;
  /** The action that publishes the summary ("submit" at intake, "save" when editing). */
  commitVerb?: "submit" | "save";
}) {
  const id = useId();
  const deferred = useDeferredValue(value.summary);
  const warnings = useMemo(() => findIdentifyingDetails(deferred), [deferred]);
  const set = (update: Partial<ListingDraft>) => onChange({ ...value, ...update });
  const remaining = CONFIDENTIAL_SUMMARY_LIMIT - value.summary.length;

  return (
    <div className="space-y-6 text-black">
      <div>
        <label htmlFor={`${id}-summary`} className={label}>Summary for legal review</label>
        <p id={`${id}-help`} className="mb-3 max-w-[62ch] text-sm leading-relaxed font-bold text-red-800">
          NOT CONFIDENTIAL. Legal organizations read this to decide whether to ask for your report. VERA administrators and legal
          organizations, including ones that join later, can read it. Say what kind of wrongdoing it is and what you
          can show, not who you are, who was involved, or exactly where and when.
        </p>
        <details className="mb-3 max-w-[62ch] text-sm">
          <summary className="cursor-pointer underline underline-offset-2">See three examples</summary>
          <ol className="mt-3 space-y-4">
            {SUMMARY_EXAMPLES.map(example => (
              <li key={example.topic} className="border-l-2 border-black/15 pl-3">
                <p className="mb-2 font-semibold">{example.topic}</p>
                <p className="mb-1"><span className="font-semibold text-red-800">Instead of: </span>{example.bad}</p>
                <p className="mb-1 text-black/60">{example.why}</p>
                <p><span className="font-semibold text-green-800">Write: </span>{example.good}</p>
              </li>
            ))}
          </ol>
        </details>
        <textarea
          id={`${id}-summary`}
          aria-describedby={`${id}-help ${id}-count ${id}-check`}
          className="min-h-[140px] w-full border border-black/30 bg-transparent p-3 text-base outline-none focus:border-black focus-visible:ring-2 focus-visible:ring-black"
          maxLength={CONFIDENTIAL_SUMMARY_LIMIT}
          value={value.summary}
          onChange={event => set({ summary: event.target.value })}
          autoComplete="off"
          // Browser "enhanced" spell check can send field contents to a cloud
          // service, which would contradict "nothing is sent until you submit",
          // and the drafts it would see are the ones with identifying details.
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
        />
        <p id={`${id}-count`} className="mt-1 text-right text-sm text-black/60">
          <span className="sr-only">Summary length: </span>{remaining < 60 ? `${remaining} left` : `${value.summary.length}/${CONFIDENTIAL_SUMMARY_LIMIT}`}
        </p>
      </div>

      <section aria-labelledby={`${id}-check-title`} className={box}>
        <h3 id={`${id}-check-title`} className="mb-1 font-semibold">Check for details that could identify you</h3>
        <p className="mb-3 text-sm text-black/60">
          Checked on this device only. Nothing you type is sent until you {commitVerb}.
        </p>
        <p id={`${id}-check`} role="status" aria-live="polite" className="text-sm">
          {!deferred.trim() ? "Start writing to check your summary."
            : warnings.length === 0
              ? "No obvious identifying details detected. This basic check can miss details; review the summary yourself."
              : `${warnings.length} possible identifying detail${warnings.length === 1 ? "" : "s"} found. Consider changing ${warnings.length === 1 ? "it" : "them"} before you continue.`}
        </p>
        {warnings.length > 0 && (
          <ul className="mt-3 space-y-3">
            {warnings.map(warning => (
              <li key={`${warning.kind}-${warning.start}`} className="border-l-2 border-amber-600 pl-3 text-sm">
                <p><span className="font-semibold">{SUMMARY_WARNING_ADVICE[warning.kind].label}:</span>{" "}
                  <q className="break-words">{warning.text}</q></p>
                <p className="text-black/70">{SUMMARY_WARNING_ADVICE[warning.kind].advice}</p>
              </li>
            ))}
          </ul>
        )}
      </section>



    </div>
  );
}
