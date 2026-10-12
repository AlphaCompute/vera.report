import type { GetServerSideProps } from 'next';
import Link from 'next/link';
import { auth0 } from '@/lib/auth0';
import { currentAdminAuthorization } from '@/lib/currentAdminAuthorization';
import { isAdmin } from '@/lib/roles';
import { confidentialCasesEnabled } from '@/lib/confidential/config';
import { LegalPortalLayout } from '@/components/vera/confidential/LegalPortal';
import { LegalOrganizationsView } from '@/components/vera/admin/LegalOrganizationsView';

export default function LegalOrganizations() {
  return <LegalPortalLayout title="Legal organization administration" wide>
    <div className="mb-6 flex flex-wrap gap-4 text-sm">
      <Link className="underline" href="/legal/administration">Issue a legal invitation</Link>
      <a className="underline" href="/auth/logout">Sign out</a>
    </div>
    <LegalOrganizationsView />
  </LegalPortalLayout>;
}

export const getServerSideProps: GetServerSideProps = async (ctx) => {
  ctx.res.setHeader('Cache-Control', 'private, no-store');
  if (!confidentialCasesEnabled()) return { notFound: true };
  const session = await auth0.getSession(ctx.req);
  if (!session) return { redirect: { destination: '/auth/login?returnTo=/legal/organizations', permanent: false } };
  // Use the same current provider authorization as the protected roster API;
  // an old role claim in a session cookie cannot reopen access.
  const current = await currentAdminAuthorization(session.user).catch(() => null);
  if (!current || !isAdmin(current.roles)) return { notFound: true };
  return { props: {} };
};
