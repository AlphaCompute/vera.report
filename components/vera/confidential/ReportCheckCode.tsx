import { useEffect, useState } from "react";

/** Owner-side display of the report check code (lib/confidential/reportCheckCode.ts).
 * Shared only if the reporter chooses to contact a legal organization directly. */
export function ReportCheckCode({ caseId, ownerFingerprint, panel }: { caseId: string; ownerFingerprint: string; panel: string }) {
  const [code, setCode] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    void import("@/lib/confidential/reportCheckCode").then(module => module.reportCheckCode(caseId, ownerFingerprint))
      .then(value => { if (!cancelled) setCode(value); }, () => { if (!cancelled) setCode(null); });
    return () => { cancelled = true; };
  }, [caseId, ownerFingerprint]);
  if (!code) return null;
  return (
    <details className={panel}>
      <summary className="cursor-pointer font-semibold">Report check code</summary>
      <p className="mt-3 font-mono text-lg tracking-wider" aria-label={`Report check code ${code.split("").join(" ")}`}>{code}</p>
      <p className="mt-2 max-w-[62ch] text-sm text-black/70">
        Legal organizations see this code next to your summary. If you decide to contact one directly, you can read it to
        them so both of you know they are looking at your report. It is not a password and does not give anyone access.
      </p>
    </details>
  );
}
