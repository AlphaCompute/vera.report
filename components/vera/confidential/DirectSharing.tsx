import { useEffect, useId, useRef, useState } from 'react';
import { trustedNow } from '@/lib/confidential/attestedTime';
import type { VerifiedOrganization } from '@/lib/confidential/ownerCase';
import { FirmProfileSummary } from './FirmProfileSummary';
import type { OwnerGrantDecision } from '@/enclave/src/confidential/ownerGrant';
import boardStyles from './WorkspaceBoard.module.css';

type SharingProps = {
  busy: boolean; published: boolean; revision: number;
  onVerify: (organizationId: string) => Promise<VerifiedOrganization>;
  onShare: (organizationId: string, decision: OwnerGrantDecision) => Promise<unknown>;
};

/** Explicit first-time grant; no request or delivery receipt is fabricated. */
export function DirectSharing({ organizations, existingOrganizationIds, requested = [], ...props }: SharingProps & {
  organizations: VerifiedOrganization[]; existingOrganizationIds: readonly string[]; requested?: readonly string[];
}) {
  const id = useId();
  return <section className={boardStyles.firmDirectory} aria-labelledby={id}>
    <header className={boardStyles.toolbar}>
      <div>
        <h2 id={id}>Available law firms</h2>
        <p>Browse approved organizations and their published contact details. You can share without waiting for a request.</p>
      </div>
      <span className={boardStyles.count}>{organizations.length} {organizations.length === 1 ? 'firm' : 'firms'}</span>
    </header>
    {!organizations.length && <p className={boardStyles.empty}>No approved law firms are available right now. Check for updates to refresh this list.</p>}
    <ul className={boardStyles.firmDirectoryGrid}>
      {[...organizations].sort((a, b) => Number(requested.includes(b.organizationId)) - Number(requested.includes(a.organizationId)) || a.displayName.localeCompare(b.displayName)).map(organization => <FirmSharingCard key={organization.organizationId} organization={organization}
        requested={requested.includes(organization.organizationId)} existing={existingOrganizationIds.includes(organization.organizationId)} {...props} />)}
    </ul>
  </section>;
}

function FirmSharingCard({ organization, existing, requested, busy, published, revision, onShare, onVerify }: SharingProps & {
  organization: VerifiedOrganization; existing: boolean; requested: boolean;
}) {
  const id = useId();
  const [choosing, setChoosing] = useState(false);
  const [verified, setVerified] = useState<VerifiedOrganization | null>(null);
  const [checking, setChecking] = useState(false), [error, setError] = useState('');
  const generation = useRef(0);
  useEffect(() => () => { generation.current++; }, []);
  const [files, setFiles] = useState(false);
  const review = () => {
    const current = ++generation.current;
    setChoosing(true); setChecking(true); setError(''); setVerified(null);
    void onVerify(organization.organizationId).then(result => { if (generation.current === current) setVerified(result); })
      .catch(() => { if (generation.current === current) setError('The approved organization key could not be verified. No access was granted.'); })
      .finally(() => { if (generation.current === current) setChecking(false); });
  };
  const profile = verified ? verified.profile : organization.profile;
  return <li className={`${boardStyles.card} ${boardStyles.firmDirectoryCard}`} aria-labelledby={id}>
    <span className={boardStyles.firmBadge} data-active={existing}>{requested ? 'Requested access' : existing ? 'Previously submitted' : 'Not shared'}</span>
    <h3 id={id}>{organization.displayName}</h3>
    <p className={boardStyles.firmDomain}>{organization.domain}</p>
    {profile ? <FirmProfileSummary profile={profile} /> : <p className="mb-3 text-sm">
      Website: <a className="underline" href={`https://${organization.domain}/`} target="_blank" rel="noopener noreferrer">{organization.domain}</a>
    </p>}
    {!Object.keys(profile?.contacts ?? {}).length && <p className="mb-4 text-sm text-black/60">This firm has not published email or phone details. Visit its website for contact information.</p>}
    {requested && <p className="mb-3 text-sm"><a className="underline" href="#access-requests">Review request</a></p>}
    {existing ? <div className={boardStyles.firmDirectoryAction}>
      <p className="mb-3 text-sm text-black/60">You have shared with this firm before. Review its current permissions and access dates below.</p>
      <a href={`#firm-access-${organization.organizationId}`} className="inline-flex min-h-11 items-center border border-black/20 px-4 py-2 text-sm font-semibold">Manage access</a>
    </div> : !choosing ? <div className={boardStyles.firmDirectoryAction}>
      {!published && <p className="mb-3 text-sm">Publish your summary before sharing so the firm can find your report.</p>}
      <button type="button" className="min-h-11 bg-[#19352a] px-5 py-2.5 text-sm font-semibold text-white disabled:opacity-50"
        disabled={busy || !published} onClick={review}>Select organization</button>
    </div> : <div className={boardStyles.firmChoices}>
      <p className="my-3 text-sm">You can share without waiting for a request. Contact the organization for a conflict check first and disclose only what is needed. Sharing does not itself create representation or guarantee legal privilege.</p>
      {checking && <p role="status" className="my-3 text-sm">Checking organization…</p>}
      {error && <p role="alert" className="my-2 text-sm">{error}</p>}
      {error && <button type="button" className="my-3 underline" disabled={busy || checking} onClick={review}>Try again</button>}
      {verified && <p role="status" className="mb-3 text-sm">Organization key verified. Choose what to share, then select “Submit”.</p>}
      {!published && <p className="my-2 text-sm">Publish your summary before sharing with a new organization so it can find your report.</p>}
      <p className="text-sm">Shares the current report for 30 days. Contact details and files added later stay private.</p>
      <label className="mt-2 block text-sm"><input type="checkbox" checked={files} disabled={busy} onChange={event => setFiles(event.target.checked)} /> Also share all current files</label>
      <button className="mt-3 border border-current px-3 py-2 disabled:opacity-50" type="button" disabled={busy || checking || !published || !verified}
        onClick={() => void onShare(organization.organizationId, { grantId: Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, '0')).join(''),
          scopes: ['narrative', ...(files ? ['evidence' as const] : [])],
          objectRevisionLimit: revision, expiresAt: trustedNow() + 30 * 86_400_000 }).then(result => { if (result !== false) { generation.current++; setChoosing(false); setVerified(null); setFiles(false); } })}>Submit</button>
      <button type="button" className="ml-4 min-h-11 text-sm underline" disabled={busy} onClick={() => {
        generation.current++; setChoosing(false); setChecking(false); setVerified(null); setError(''); setFiles(false);
      }}>Cancel</button>
    </div>}
  </li>;
}
