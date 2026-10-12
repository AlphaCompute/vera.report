import { Fragment } from "react";
import { FIRM_PRACTICE_AREAS, FIRM_CONTACT_LABELS } from "@/enclave/src/confidential/firmProfile";
import type { FirmProfile } from "@/enclave/src/confidential/firmProfile";

/** The legal organization's own signed profile, delivered with its approved key. It is
 * shown as the organization's statement: VERA does not vouch for these claims. */
export function FirmProfileSummary({ profile }: { profile: FirmProfile | null }) {
  if (!profile) {
    return <p className="mb-3 text-sm text-black/60">This legal organization has not submitted an approved profile.</p>;
  }
  const host = new URL(profile.website).host;
  return (
    <dl className="mb-3 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[max-content_1fr]" aria-label="Legal organization profile">
      <dt className="text-black/60">Practice areas</dt>
      <dd>{profile.practiceAreas.map(area => FIRM_PRACTICE_AREAS[area]).join(", ")}</dd>
      <dt className="text-black/60">Jurisdiction</dt>
      <dd className="break-words">{profile.jurisdiction}</dd>
      <dt className="text-black/60">Website</dt>
      <dd className="break-all">
        <a className="underline" href={profile.website} target="_blank" rel="noopener noreferrer">{host}</a>
      </dd>
      {Object.entries(profile.contacts ?? {}).map(([key, value]) => <Fragment key={key}>
        <dt className="text-black/60">{FIRM_CONTACT_LABELS[key as keyof typeof FIRM_CONTACT_LABELS]}</dt>
        <dd className="break-all">{value}</dd>
      </Fragment>)}
      {profile.contacts && <dd className="text-black/50 sm:col-span-2">Contacting this organization outside VERA can reveal your identity.</dd>}
      <dt className="sr-only">Source</dt>
      <dd className="text-black/50 sm:col-span-2">Signed by the organization with its approved key. VERA does not check these details.</dd>
    </dl>
  );
}
