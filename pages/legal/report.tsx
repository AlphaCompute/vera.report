import Link from "next/link";
import { LegalGate, LegalPortalLayout, panel } from "@/components/vera/confidential/LegalPortal";
import { CaseView } from "@/components/vera/confidential/LegalReportView";
import { LEGAL_CASE_PATH, useLegalCaseId } from "@/lib/confidential/legalCaseLink";

/** One report in the legal portal. The report is chosen in this tab (see
 * lib/confidential/legalCaseLink.ts), so its ID is in no URL: not in page
 * requests, access logs or browser history. Live RPC and network timing
 * correlation remains possible (see the confidential architecture audit). */
export default function LegalReportPage() {
  const { ready, caseId } = useLegalCaseId();
  return (
    <LegalPortalLayout title="Report workspace" wide
      intro="Read the report and files shared with your organization.">
      {!ready ? <p role="status">Loading…</p> : !caseId ? <p className={panel}>Choose a report from your requests to open it. <Link className="underline" href="/legal">Back to the portal</Link></p> : (
        <LegalGate key={caseId} returnPath={LEGAL_CASE_PATH}>
          {({ session }) => <CaseView key={caseId} session={session} caseId={caseId} />}
        </LegalGate>
      )}
    </LegalPortalLayout>
  );
}

/** Server-rendered so pages/_document.tsx applies the strict private-page headers. */
export const getServerSideProps = async () => ({ props: {} });
