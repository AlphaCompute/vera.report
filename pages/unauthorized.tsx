import Head from 'next/head';
import Link from 'next/link';

export default function Unauthorized() {
  return (
    <>
      <Head>
        <title>Access Denied</title>
      </Head>
      <div className="min-h-screen flex items-center justify-center bg-background text-foreground">
        <div className="text-center max-w-md px-6">
          <h1 className="text-3xl font-bold mb-4">Access Denied</h1>
          <p className="text-muted-foreground mb-6">
            This area is restricted to authorized administrators.
            If you believe this is an error, contact your team lead.
          </p>
          <Link
            href="/auth/logout"
            className="inline-block px-5 py-2 rounded-md bg-primary text-primary-foreground hover:opacity-90 transition"
          >
            Sign Out
          </Link>
        </div>
      </div>
    </>
  );
}
