import { useEffect, useState } from "react";
import { failureMessage, panel, secondaryButton } from "./LegalPortal";
import type { FirmSession } from "@/lib/confidential/firmCase";

export function AddLawyer({ session }: { session: FirmSession }) {
  const [link, setLink] = useState("");
  const [copied, setCopied] = useState(false);
  const [email, setEmail] = useState("");
  const [inviting, setInviting] = useState(false);
  const [invitation, setInvitation] = useState<string | null>(null);
  const [inviteCooldown, setInviteCooldown] = useState<{ email: string; until: number } | null>(null);
  const [remainingSeconds, setRemainingSeconds] = useState(0);
  const sameInvitation = inviteCooldown?.email === email.trim().toLowerCase();
  useEffect(() => {
    if (!inviteCooldown) return;
    const update = () => {
      const remaining = Math.max(0, Math.ceil((inviteCooldown.until - Date.now()) / 1000));
      setRemainingSeconds(remaining);
      if (!remaining) setInviteCooldown(null);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [inviteCooldown]);
  const invite = async () => {
    if (inviting || sameInvitation) return;
    const target = email.trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+$/.test(target) || target.split('@')[1] !== session.firm.domain.toLowerCase()) {
      setInvitation(`Use a colleague's work email at ${session.firm.domain}. Nothing was sent.`);
      return;
    }
    setInviting(true); setInvitation(null);
    let attempted = false;
    try {
      const { inviteOrganizationMember } = await import("@/lib/confidential/firmMemberDevices");
      // Local preflight only. The operation still verifies its token and signed
      // authority; once invoked, a failure may have followed a side effect.
      await session.accessToken();
      attempted = true;
      setInviteCooldown({ email: target, until: Date.now() + 10 * 60_000 });
      await inviteOrganizationMember(session, target, Date.now());
      setInvitation("Colleague added. Share the join link below so they can sign in and request device approval.");
      setEmail("");
    } catch (caught) {
      const reason = failureMessage(caught, "We could not add your colleague.");
      setInvitation(attempted
        ? `${reason} We could not confirm whether your colleague was added. Wait before retrying this email to avoid a duplicate. Their device will still need your approval.`
        : `${reason} Nothing was sent. You can retry after resolving this problem.`);
    } finally { setInviting(false); }
  };
  useEffect(() => {
    void import("@/lib/confidential/firmMemberDevices").then(({ joinLink }) =>
      setLink(joinLink(window.location.origin, { organizationId: session.firm.organizationId, domain: session.firm.domain })));
  }, [session]);
  return (
    <section className={panel} aria-labelledby="add-title">
      <h2 id="add-title" className="mb-3 font-semibold">Add a lawyer</h2>
      <ol className="mb-4 max-w-[62ch] list-decimal space-y-2 pl-5 text-sm">
        <li>Add a colleague using their work email at {session.firm.domain}.</li>
        <li>Share the join link below. They sign in and create a key on their own device.</li>
        <li>They appear under &ldquo;Waiting for approval&rdquo; here.</li>
        <li>Compare the device code with the lawyer by phone or in person before you approve it.</li>
      </ol>
      <form className="mb-4" onSubmit={event => { event.preventDefault(); void invite(); }}>
        <label className="block text-sm" htmlFor="invite-email">Colleague&apos;s work email</label>
        <div className="mt-1 flex flex-col gap-2 sm:flex-row">
          <input id="invite-email" type="email" spellCheck={false} autoCapitalize="none" required value={email} onChange={event => setEmail(event.target.value)}
            placeholder={`name@${session.firm.domain}`} className="min-w-0 flex-1 border border-black/30 px-3 py-2" />
          <button type="submit" className={secondaryButton} disabled={inviting || sameInvitation || !email.trim()}>{inviting ? "Adding…" : sameInvitation ? "Wait before retrying" : "Add colleague"}</button>
        </div>
        <p className="mt-2 font-bold text-red-800">Not confidential: VERA administrators and the sign-in provider can see colleagues&apos; email addresses.</p>
        {sameInvitation && !inviting && <p className="mt-2 text-sm">
          Retry this email in {Math.floor(remainingSeconds / 60)}:{String(remainingSeconds % 60).padStart(2, "0")}.
        </p>}
        {invitation && <p className="mt-2 text-sm" role="status">{invitation}</p>}
      </form>
      <label className="block text-sm" htmlFor="join-link">Join link</label>
      <div className="mt-1 flex flex-col gap-2 sm:flex-row">
        <input id="join-link" readOnly value={link} spellCheck={false} autoComplete="off" className="w-full min-w-0 border border-black/30 px-3 py-2 font-mono text-xs"
          onFocus={event => event.currentTarget.select()} />
        <button type="button" className={secondaryButton} disabled={!link} onClick={() => {
          void navigator.clipboard?.writeText(link).then(() => { setCopied(true); setTimeout(() => setCopied(false), 4000); }).catch(() => setCopied(false));
        }}>Copy link</button>
      </div>
      <p className="mt-2 text-sm" aria-live="polite">{copied ? "Link copied." : ""}</p>
    </section>
  );
}

