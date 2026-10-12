import { RememberWorkspace, SavedWorkspaces, useParticipantLock } from "@/components/vera/confidential/DeviceWorkspaces";
import { useCallback, useEffect, useRef, useState } from "react";
import { ApprovedDevice } from "@/components/vera/confidential/ApprovedDevice";
import { LegalPortalLayout, failureMessage, panel, primaryButton, secondaryButton, startFirmSession } from "@/components/vera/confidential/LegalPortal";
import { CONFIDENTIAL_RELEASE_MANIFEST, confidentialCasesEnabled } from "@/lib/confidential/config";
import { beginLegalSignIn, legalAccessToken, legalAuthConfig, legalSignedIn } from "@/lib/confidential/legalAuth";
import type { LegalAuthConfig } from "@/lib/confidential/legalAuth";
import type { UnlockedVault } from "@/lib/confidential/deviceVault";
import type { PrivateKey, PublicKey } from "@/enclave/src/confidential/pgp";
import type { JoinTarget } from "@/lib/confidential/firmMemberDevices";
import type { PendingDeviceWorkspace } from "@/lib/confidential/firmWorkspace";

/** New lawyer joining an organization that already has a key. The device key is
 * created here and never leaves this device; the organization key arrives
 * encrypted to it once a steward approves the device code. */
const TARGET_KEY = "vera-legal-join";
const POLL_MS = 20_000;

function takeTarget(read: (fragment: string) => JoinTarget | null): JoinTarget | null {
  let target = read(window.location.hash);
  if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
  try {
    if (target) window.sessionStorage.setItem(TARGET_KEY, JSON.stringify(target));
    else {
      const saved = window.sessionStorage.getItem(TARGET_KEY);
      const value = saved ? JSON.parse(saved) : null;
      target = value ? read(`organization=${value.organizationId}&domain=${value.domain}`) : null;
    }
  } catch { /* the join link can be opened again */ }
  return target;
}

type Pending = { target: JoinTarget; memberId: string; device: PrivateKey; code: string; registeredAt: number };

function Register({ config, target, organizationKey, onRegistered }: {
  config: LegalAuthConfig; target: JoinTarget; organizationKey: PublicKey; onRegistered: (pending: Pending) => void;
}) {
  const [name, setName] = useState(""), [contact, setContact] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const submit = async () => {
    if (busy || !name.trim()) return;
    setBusy(true); setError(null);
    try {
      const [members, { fetchRelay }] = await Promise.all([import("@/lib/confidential/firmMemberDevices"), import("@/lib/confidential/client")]);
      const device = await members.createMemberDeviceKey();
      const status = await members.registerMemberDevice({ relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST,
        accessToken: await legalAccessToken(config), now: Date.now(), organizationId: target.organizationId,
        organizationPublicKey: organizationKey, device, profile: { name, contact } });
      onRegistered({ target, memberId: status.memberId, device, code: members.deviceCode(device), registeredAt: Date.now() });
    } catch (caught) {
      setError(caught instanceof Error && caught.name === "FirmMemberError" ? caught.message
        : failureMessage(caught, "This device could not be registered. Check that you signed in with the account your organization uses for VERA, then try again."));
    } finally { setBusy(false); }
  };
  return (
    <section className={panel} aria-labelledby="register-title">
      <h2 id="register-title" className="mb-3 font-semibold">Create your device key</h2>
      <p className="mb-4 max-w-[62ch] text-sm text-black/70">
        VERA approved your organization&apos;s domain, {target.domain}, and its key. Tell your steward who you are. Your name and contact are
        encrypted so only your organization can read them; VERA cannot.
      </p>
      <label className="mb-3 block text-sm" htmlFor="member-name">
        <span className="mb-1 block">Your name</span>
        <input id="member-name" value={name} maxLength={80} autoComplete="name" spellCheck={false} autoCorrect="off" onChange={event => setName(event.target.value)}
          className="w-full border border-black/30 px-3 py-2" required aria-required="true" />
      </label>
      <label className="mb-4 block text-sm" htmlFor="member-contact">
        <span className="mb-1 block">Work email or phone (optional)</span>
        <input id="member-contact" value={contact} maxLength={120} autoComplete="email" spellCheck={false} autoCorrect="off" autoCapitalize="off" onChange={event => setContact(event.target.value)}
          className="w-full border border-black/30 px-3 py-2" />
      </label>
      <button type="button" className={primaryButton} disabled={busy || !name.trim()} onClick={() => void submit()}>
        {busy ? "Creating key…" : "Create key and ask for approval"}
      </button>
      {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
    </section>
  );
}

function Waiting({ config, pending, vault, onVault, onApproved }: {
  config: LegalAuthConfig; pending: Pending; vault: UnlockedVault | null; onVault: (vault: UnlockedVault) => void;
  onApproved: (notice: string) => void;
}) {
  const [state, setState] = useState<"waiting" | "checking" | "removed">("waiting");
  const [error, setError] = useState<string | null>(null);
  const [checkedAt, setCheckedAt] = useState<number | null>(null);
  const running = useRef(false);
  const check = useCallback(async () => {
    if (running.current) return;
    running.current = true; setState("checking"); setError(null);
    try {
      const [{ completeApprovedDevice, PendingDeviceError, pendingDevicePayload }, { fetchRelay }] = await Promise.all([
        import("@/lib/confidential/firmDeviceSession"), import("@/lib/confidential/client")]);
      try {
        const opened = await completeApprovedDevice(pendingDevicePayload({ ...pending.target, memberId: pending.memberId,
          device: pending.device, registeredAt: pending.registeredAt }), { relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST,
          accessToken: () => legalAccessToken(config), start: (firm, signal) => startFirmSession(config, firm, signal) }, vault);
        onApproved(opened.notice ?? "Your device was approved. It now holds your organization key.");
      } catch (caught) {
        if (caught instanceof PendingDeviceError) { setState(caught.status?.state === "removed" ? "removed" : "waiting"); setCheckedAt(Date.now()); return; }
        throw caught;
      }
    } catch (caught) {
      setState("waiting");
      setError(caught instanceof Error && caught.name === "FirmMemberError" ? caught.message
        : failureMessage(caught, "Approval could not be checked. We will try again shortly."));
    } finally { running.current = false; }
  }, [config, pending, vault, onApproved]);
  useEffect(() => {
    const timer = setInterval(() => { if (document.visibilityState === "visible") void check(); }, POLL_MS);
    return () => clearInterval(timer);
  }, [check]);
  if (state === "removed") {
    return <section className={panel} role="alert"><h2 className="mb-2 font-semibold">This device was declined</h2>
      <p className="text-sm">Your steward declined or removed this device. Talk to them, then open the join link again to register.</p></section>;
  }
  return (
    <div className="space-y-6">
      <section className={panel} aria-labelledby="code-title">
        <h2 id="code-title" className="mb-3 font-semibold">Read this code to your steward</h2>
        <p className="mb-3 max-w-[62ch] text-sm">Call your organization&apos;s steward or show them this screen in person. Do not send the code
          by email or chat. They approve your device only if the code on their screen matches exactly.</p>
        <p className="mb-4 break-words font-mono text-2xl tracking-wide" aria-label={`Device code ${pending.code.split(" ").join(", ")}`}>{pending.code}</p>
        <p className="text-sm" role="status" aria-live="polite">
          {state === "checking" ? "Checking for approval…" : `Waiting for approval. This page checks every 20 seconds while it is open${checkedAt ? `; last checked ${new Date(checkedAt).toLocaleTimeString()}` : ""}.`}
        </p>
        <button type="button" className={`mt-3 ${secondaryButton}`} disabled={state === "checking"} onClick={() => void check()}>Check now</button>
        {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
      </section>
      <RememberWorkspace role="legal" vault={vault} onRemembered={onVault} getPayload={async () => {
        const { pendingDevicePayload } = await import("@/lib/confidential/firmDeviceSession");
        return pendingDevicePayload({ ...pending.target, memberId: pending.memberId, device: pending.device, registeredAt: pending.registeredAt });
      }} />
      {!vault && <p className="max-w-[62ch] text-sm text-black/70">Approval can take a while. Remember this workspace so you can close this page
        and come back; otherwise keep this page open until your steward approves the device.</p>}
    </div>
  );
}

export default function LegalJoin() {
  const [ready, setReady] = useState<{ config: LegalAuthConfig | null; enabled: boolean; target: JoinTarget | null } | null>(null);
  const [organizationKey, setOrganizationKey] = useState<PublicKey | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [vault, setVault] = useState<UnlockedVault | null>(null);
  const [approved, setApproved] = useState<string | null>(null);
  const initialized = useRef(false);
  useParticipantLock("/legal", pending !== null || approved !== null);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    void import("@/lib/confidential/firmMemberDevices").then(({ readJoinTarget }) =>
      setReady({ config: legalAuthConfig(), enabled: confidentialCasesEnabled(), target: takeTarget(readJoinTarget) }));
  }, []);
  const confirmKey = useCallback(async (target: JoinTarget) => {
    setKeyError(null);
    try {
      const { publishedOrganizationKey } = await import("@/lib/confidential/firmMemberDevices");
      const config = legalAuthConfig();
      if (!config) throw new Error("Sign in to your approved organization first.");
      const { fetchRelay } = await import("@/lib/confidential/client");
      setOrganizationKey(await publishedOrganizationKey(target, { relay: fetchRelay(),
        releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST, accessToken: await legalAccessToken(config), now: Date.now() }));
    } catch (caught) { setKeyError(caught instanceof Error ? caught.message : "Your organization key could not be confirmed."); }
  }, []);
  useEffect(() => {
    if (ready?.target && ready.config && legalSignedIn() && !organizationKey && !pending) void confirmKey(ready.target);
  }, [ready, organizationKey, pending, confirmKey]);

  let content;
  if (!ready) content = <p role="status">Loading…</p>;
  else if (!ready.enabled) content = <p className={panel}>The legal portal is not available on this site.</p>;
  else if (!ready.config) content = <p className={panel}>Legal portal not configured.</p>;
  else if (approved) {
    content = (
      <ApprovedDevice notice={approved} vault={vault} onRemembered={async saved => {
        const { setFirmVault, persistFirmWorkspace } = await import("@/lib/confidential/firmPortal");
        setFirmVault(saved); setVault(saved); await persistFirmWorkspace().catch(() => {});
      }} getPayload={async () => (await import("@/lib/confidential/firmPortal")).currentFirmPayload()} />
    );
  } else if (pending) {
    content = <Waiting config={ready.config} pending={pending} vault={vault} onVault={setVault} onApproved={setApproved} />;
  } else if (!legalSignedIn()) {
    const config = ready.config;
    content = (
      <section className={panel}>
        <p className="mb-4 max-w-[62ch]">{ready.target
          ? "Sign in with the account your organization uses for VERA. Then you will create a key on this device."
          : "Sign in to return to a device that is waiting for approval, or open the join link your steward sent you."}</p>
        <button type="button" className={primaryButton} onClick={() => void beginLegalSignIn(config, "/legal/join")}>Sign in</button>
      </section>
    );
  } else {
    const config = ready.config;
    content = (
      <div className="space-y-8">
        {ready.target ? (
          keyError ? (
            <section className={panel} role="alert">
              <p className="mb-3 text-red-800">{keyError}</p>
              <button type="button" className={secondaryButton} onClick={() => void confirmKey(ready.target!)}>Check again</button>
            </section>
          ) : organizationKey ? (
            <Register config={config} target={ready.target} organizationKey={organizationKey} onRegistered={setPending} />
          ) : <p role="status">Confirming your organization&apos;s key on {ready.target.domain}…</p>
        ) : (
          <p className="max-w-[62ch] text-sm">Joining an organization for the first time? Ask your organization&apos;s steward for the join link.</p>
        )}
        <SavedWorkspaces role="legal" onRecovered={async () => {
          throw new Error("Open a saved workspace from this browser, or use the legal portal to restore a backup.");
        }} onUnlocked={async (saved, signal) => {
          const [{ isPendingDeviceWorkspace }, { readDeviceKey, deviceCode }] = await Promise.all([
            import("@/lib/confidential/firmWorkspace"), import("@/lib/confidential/firmMemberDevices")]);
          const payload = saved.read();
          if (!isPendingDeviceWorkspace(payload)) { saved.lock(); window.location.assign("/legal"); return; }
          const value = payload as PendingDeviceWorkspace;
          const device = await readDeviceKey(value.privateKey);
          signal.throwIfAborted();
          setVault(saved);
          setPending({ target: { organizationId: value.organizationId, domain: value.domain }, memberId: value.memberId, device,
            code: deviceCode(device), registeredAt: value.registeredAt });
        }} />
      </div>
    );
  }
  return (
    <LegalPortalLayout title="Join your organization">
      <p className="mb-6 max-w-[62ch] text-sm">Each lawyer has their own key on their own device. Your organization&apos;s steward approves it,
        and your organization key then arrives encrypted to this device. VERA never sees it.</p>
      {content}
    </LegalPortalLayout>
  );
}

/** Server-rendered so `_document` applies the strict key-page headers. */
export const getServerSideProps = async () => ({ props: {} });
