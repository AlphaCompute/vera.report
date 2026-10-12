import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { AddLawyer } from "@/components/vera/confidential/AddLawyer";
import { LegalGate, LegalPortalLayout, downloadBytes, failureMessage, panel, primaryButton, secondaryButton } from "@/components/vera/confidential/LegalPortal";
import { currentFirmDevice, currentFirmVault, currentSharedList, loadSharedRequests, replaceFirmKeyInWorkspace } from "@/lib/confidential/firmPortal";
import { lockParticipantTabs } from "@/lib/confidential/deviceWorkspace";
import { useLockAwareUnloadPrompt, useParticipantLockHold } from "@/lib/confidential/participantLock";
import { RotationFinish, WORKSPACE_NOT_UPDATED, finishRotation } from "@/components/vera/confidential/RotationFinish";
import type { FirmSession } from "@/lib/confidential/firmCase";
import type { FirmIdentity } from "@/lib/confidential/firmKey";
import type { MemberDevice, RotationResult } from "@/lib/confidential/firmMemberDevices";

/** Steward page: add lawyers, approve their device keys, remove members.
 * Every key operation runs in this browser with the organization key; VERA
 * stores only device public keys, encrypted profiles and encrypted envelopes. */
const date = (value: number) => new Date(value).toLocaleDateString();
const personName = (device: MemberDevice) => device.profile?.name || "Unverified name";
const errorText = (caught: unknown, fallback: string) =>
  caught instanceof Error && caught.name === "FirmMemberError" ? caught.message : failureMessage(caught, fallback);

function Notice({ notice }: { notice: { kind: "status" | "alert"; text: string } | null }) {
  const ref = useRef<HTMLParagraphElement | null>(null);
  useEffect(() => { if (notice) ref.current?.focus(); }, [notice]);
  if (!notice) return null;
  return <p ref={ref} tabIndex={-1} role={notice.kind} className={`border p-4 text-sm ${notice.kind === "alert" ? "border-red-700 text-red-800" : "border-black/20"}`}>{notice.text}</p>;
}

function DeviceCode({ code }: { code: string }) {
  return <p className="break-words font-mono text-base tracking-wide" aria-label={`Device code ${code.split(" ").join(", ")}`}>{code}</p>;
}


function PendingDevice({ device, busy, onApprove, onDecline }: {
  device: MemberDevice; busy: boolean; onApprove: () => void; onDecline: () => void;
}) {
  const [checking, setChecking] = useState(false), [matches, setMatches] = useState(false), [declining, setDeclining] = useState(false);
  const id = `match-${device.memberId.slice(0, 12)}`;
  return (
    <li className="border-t border-black/10 pt-4">
      <p className="font-semibold">{personName(device)}</p>
      {device.profile?.contact && <p className="text-sm text-black/70">{device.profile.contact}</p>}
      {!device.profile && <p className="text-sm text-red-800">This request&apos;s name and contact could not be verified. Confirm who it is before approving.</p>}
      <p className="text-xs text-black/50">Registered {date(device.registeredAt)}</p>
      {!checking && !declining && <div className="mt-3 flex flex-wrap gap-3">
        <button type="button" className={primaryButton} disabled={busy} onClick={() => setChecking(true)}>Review and approve</button>
        <button type="button" className="underline" disabled={busy} onClick={() => setDeclining(true)}>Decline</button>
      </div>}
      {checking && <div className="mt-3 border border-black/20 p-4">
        <p className="mb-2 text-sm">Ask {personName(device)} to read the code shown on their screen, by phone or in person. Do not use
          email or chat for this check. It must match exactly:</p>
        <DeviceCode code={device.deviceCode} />
        <label className="mt-3 flex items-start gap-2 text-sm" htmlFor={id}>
          <input id={id} type="checkbox" className="mt-1" checked={matches} onChange={event => setMatches(event.target.checked)} />
          <span>I compared this code with {personName(device)} directly, and it matches.</span>
        </label>
        <p className="my-3 max-w-[62ch] text-sm text-black/70">Approving gives this device your organization key. It can then open every
          report reporters have shared with your organization.</p>
        <div className="flex flex-wrap gap-3">
          <button type="button" className={primaryButton} disabled={busy || !matches} onClick={onApprove}>{busy ? "Approving…" : "Approve device"}</button>
          <button type="button" className="underline" disabled={busy} onClick={() => { setChecking(false); setMatches(false); }}>Cancel</button>
        </div>
      </div>}
      {declining && <div className="mt-3 border border-black/20 p-4 text-sm">
        <p className="mb-3">Decline this device? The person can register again if this was a mistake.</p>
        <div className="flex flex-wrap gap-3">
          <button type="button" className={secondaryButton} disabled={busy} onClick={onDecline}>Decline device</button>
          <button type="button" className="underline" disabled={busy} onClick={() => setDeclining(false)}>Cancel</button>
        </div>
      </div>}
    </li>
  );
}

type Rotation = RotationResult & {
  removedNames: string[]; recoveryCode: string; binding: string; keyFile: string;
  /** New key sent to every remaining device and the request list moved to it. */
  distributed: boolean; listMoved: boolean; attempted: boolean;
};

function RemovalWizard({ session, devices, removing, keyEpoch, onPrepared, onCancel }: {
  session: FirmSession; devices: MemberDevice[]; removing: MemberDevice[]; keyEpoch: number;
  onPrepared: (rotation: Rotation) => void; onCancel: () => void;
}) {
  const [recoveryCode, setRecoveryCode] = useState("");
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  useEffect(() => { void import("@/lib/confidential/firmKey").then(keys => setRecoveryCode(keys.generateFirmRecoveryCode())); }, []);
  const names = removing.map(personName);
  const remaining = devices.filter(item => item.state === "approved" && !removing.some(other => other.memberId === item.memberId));
  const finishing = removing.length > 0 && removing.every(item => item.state === "removed");
  const run = async () => {
    setBusy(true); setError(null); setProgress([]);
    const step = (text: string) => setProgress(current => [...current, text]);
    try {
      const [members, keys] = await Promise.all([import("@/lib/confidential/firmMemberDevices"), import("@/lib/confidential/firmKey")]);
      if (recoveryCode.trim().length < keys.FIRM_SECRET_MIN_LENGTH) throw new Error("Use the recovery code shown, or a passphrase of at least 16 characters.");
      for (const device of removing.filter(item => item.state !== "removed")) {
        step(`Removing ${personName(device)}…`);
        await members.removeMemberDevice(session, device, Date.now());
      }
      step("Creating the new organization key on this device…");
      const prepared = await members.prepareOrganizationRotation(session, { keyEpoch,
        removedMemberIds: removing.map(item => item.memberId) }, Date.now());
      step("Saving the new key file…");
      const keyFile = await keys.exportFirmIdentity(prepared.next, recoveryCode.trim());
      const binding = await keys.firmBindingDocument(prepared.next, Date.now());
      downloadBytes(keyFile, `vera-legal-key-PRIVATE-${session.firm.domain}-v${prepared.statement.keyEpoch}.txt`, "text/plain;charset=utf-8");
      onPrepared({ ...prepared, missed: remaining.map(item => item.memberId), removedNames: names, recoveryCode: recoveryCode.trim(),
        binding, keyFile, distributed: false, listMoved: false, attempted: false });
    } catch (caught) {
      setError(caught instanceof Error && caught.message.startsWith("Use the recovery code") ? caught.message
        : errorText(caught, "The removal did not finish. Steps listed above as started may have completed. Reload this page to see where it stopped, then try again."));
    } finally { setBusy(false); }
  };
  return (
    <section className={`${panel} border-red-700`} aria-labelledby="removal-title">
      <h2 id="removal-title" ref={heading} tabIndex={-1} className="mb-3 font-semibold">
        {removing.length ? `${finishing ? "Finish removing" : "Remove"} ${names.join(", ")}` : "Replace your organization key"}
      </h2>
      <p className="mb-3 max-w-[62ch] text-sm">
        {removing.length ? `${finishing ? "Their device already stopped working with VERA." : "Their device stops working with VERA now."} Because they held your organization key, ` : ""}
        This page creates a new organization key on this device and replaces the old one. What happens next:
      </p>
      <ul className="mb-4 max-w-[62ch] list-disc space-y-1 pl-5 text-sm">
        <li>You save the new key file first. Only then does the new key go to the {remaining.length} other approved {remaining.length === 1 ? "device" : "devices"}. Each lawyer receives it the next time they unlock VERA.</li>
        <li>Anyone using a copy of the old key file instead of an approved device loses access.</li>
        <li>Submit the new public key for approval here. Approved devices renew membership when they open the new key.</li>
        <li>Every reporter who allowed your organization must allow it again. Your request list will show which reports to ask about.</li>
        <li>It cannot undo anything {removing.length ? "the removed lawyer" : "anyone"} already read or downloaded.</li>
      </ul>
      <label className="mb-1 block text-sm" htmlFor="rotation-code">Recovery code for the new key file (or replace it with a passphrase of at least 16 characters)</label>
      <input id="rotation-code" value={recoveryCode} disabled={busy} autoComplete="off" spellCheck={false}
        onChange={event => { setRecoveryCode(event.target.value); setSaved(false); }}
        className="mb-3 w-full border border-black/30 px-3 py-2 font-mono" />
      <label className="mb-4 flex items-start gap-2 text-sm" htmlFor="rotation-saved">
        <input id="rotation-saved" type="checkbox" className="mt-1" checked={saved} disabled={busy} onChange={event => setSaved(event.target.checked)} />
        <span>I saved this recovery code somewhere other than this device. VERA cannot recover it.</span>
      </label>
      <div className="flex flex-wrap gap-3">
        <button type="button" className={primaryButton} disabled={busy || !saved || !recoveryCode.trim()} onClick={() => void run()}>
          {busy ? "Working…" : removing.length && !finishing ? "Remove and create the new key" : "Create the new key"}
        </button>
        <button type="button" className="underline" disabled={busy} onClick={onCancel}>Cancel</button>
      </div>
      {progress.length > 0 && <ol className="mt-4 list-decimal space-y-1 pl-5 text-sm" aria-live="polite">{progress.map(item => <li key={item}>{item}</li>)}</ol>}
      {error && <p role="alert" className="mt-3 text-red-800">{error}</p>}
    </section>
  );
}

function RotationChecklist({ session, rotation, devices, onDistribute, onFinish }: {
  session: FirmSession; rotation: Rotation; devices: MemberDevice[];
  onDistribute: () => Promise<void>; onFinish: () => Promise<string | null>;
}) {
  const [check, setCheck] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [fileSaved, setFileSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [finishError, setFinishError] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement | null>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  // The new private key lives only in this tab (and the downloaded file) until
  // Finish. Ask before leaving, and keep the idle lock from discarding it while
  // the steward waits for approval; explicit Lock and Finish still lock at once.
  useLockAwareUnloadPrompt(true);
  useParticipantLockHold(true);
  const next: FirmIdentity = rotation.next;
  const missed = devices.filter(item => rotation.missed.includes(item.memberId));
  const lawyers = devices.filter(item => item.state === "approved");
  const sent = rotation.distributed && rotation.listMoved;
  const started = rotation.attempted;
  const verify = async () => {
    setCheck("Checking…");
    try {
      const { checkFirmDomain } = await import("@/lib/confidential/firmOnboarding");
      const result = await checkFirmDomain(next);
      setCheck(result.state === "verified" ? "Your new organization key is approved." : "Your new key is awaiting approval. Keep your backup safe.");
    } catch { setCheck("Approval could not be checked. Try again shortly."); }
  };
  const submitKey = async () => {
    setBusy(true); setCheck(null);
    try {
      const { submitReplacementOrganizationKey } = await import("@/lib/confidential/firmMemberDevices");
      await submitReplacementOrganizationKey(session, next, rotation.binding, rotation.continuity, Date.now());
      setSubmitted(true); setCheck("New public key submitted for approval.");
    } catch (caught) { setCheck(failureMessage(caught, "The key could not be submitted. Try again.")); }
    finally { setBusy(false); }
  };
  const distribute = () => { setBusy(true); void onDistribute().finally(() => setBusy(false)); };
  const downloadKeyFile = () => downloadBytes(rotation.keyFile,
    `vera-legal-key-PRIVATE-${next.domain}-v${rotation.statement.keyEpoch}.txt`, "text/plain;charset=utf-8");
  const finish = () => {
    setBusy(true); setFinishError(null);
    void onFinish().then(setFinishError, () => setFinishError(WORKSPACE_NOT_UPDATED)).finally(() => setBusy(false));
  };
  return (
    <section className={panel} aria-labelledby="checklist-title">
      <h2 id="checklist-title" ref={heading} tabIndex={-1} className="mb-3 font-semibold">New key created. Finish these steps</h2>
      {rotation.removedNames.length > 0 && <p className="mb-3 text-sm">Removed: {rotation.removedNames.join(", ")}.</p>}
      <p className="mb-4 max-w-[62ch] text-sm text-black/70">Keep this page open until you finish. The new key is only on this device and in the downloaded file.</p>
      <ol className="list-decimal space-y-5 pl-5 text-sm">
        <li>
          <p className="mb-2">Keep the new key file safe. It was downloaded to this device. Its recovery code:</p>
          <p className="mb-2 break-all border border-red-700 p-3 font-mono select-all">{rotation.recoveryCode}</p>
          <button type="button" className={secondaryButton} onClick={downloadKeyFile}>Download the key file again</button>
          {!started && <label className="mt-3 flex items-start gap-2" htmlFor="rotation-file-saved">
            <input id="rotation-file-saved" type="checkbox" className="mt-1" checked={fileSaved} onChange={event => setFileSaved(event.target.checked)} />
            <span>The new key file is saved somewhere I can reach without this device.</span>
          </label>}
        </li>
        <li>
          {sent ? <p role="status">The new key was sent to {lawyers.length} approved {lawyers.length === 1 ? "device" : "devices"}, and your request list moved to it.</p> : <>
            <p className="mb-2">Send the new key to the {lawyers.length} approved {lawyers.length === 1 ? "device" : "devices"} and move your organization&apos;s request list to it.</p>
            {started && missed.length > 0 && <p className="mb-2 text-red-800" role="alert">{missed.map(personName).join(", ")} did not receive the new key yet.</p>}
            {started && rotation.distributed && !rotation.listMoved && <p className="mb-2 text-red-800" role="alert">The request list has not moved to the new key yet.</p>}
            <button type="button" className={primaryButton} disabled={busy || (!started && !fileSaved)} onClick={distribute}>
              {busy ? "Sending…" : started ? "Try again" : "Send the new key"}
            </button>
          </>}
        </li>
        <li>
          <p className="mb-2">Submit your new public key for approval. Your private key stays on your device.</p>
          <div className="flex flex-wrap gap-3">
            <button type="button" className={secondaryButton} disabled={busy || submitted} onClick={() => void submitKey()}>
              {submitted ? "Submitted for approval" : "Submit new key"}
            </button>
            <button type="button" className="underline" disabled={busy} onClick={() => void verify()}>Check approval</button>
          </div>
          {check && <p className="mt-2" aria-live="polite">{check}</p>}
        </li>
        <li>Once approved, colleagues unlock their approved devices to receive the new key and renew membership automatically.</li>
        <li>Then, on the <Link className="underline" href="/legal">requests page</Link>, ask each reporter to allow access again.</li>
      </ol>
      <RotationFinish savedWorkspace={Boolean(currentFirmVault())} sent={sent} busy={busy} error={finishError}
        onFinish={finish} onDownloadKey={downloadKeyFile} onLockAnyway={lockParticipantTabs} />
    </section>
  );
}

function Members({ session }: { session: FirmSession }) {
  const [devices, setDevices] = useState<MemberDevice[] | null>(null);
  const [keyEpoch, setKeyEpoch] = useState(1);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ kind: "status" | "alert"; text: string } | null>(null);
  const [removing, setRemoving] = useState<MemberDevice[] | null>(null);
  const [rotation, setRotation] = useState<Rotation | null>(null);
  const [unfinished, setUnfinished] = useState<MemberDevice[]>([]);
  const [keyReplaced, setKeyReplaced] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { listMemberDevices } = await import("@/lib/confidential/firmMemberDevices");
      let replaced = false;
      const [list, shared] = await Promise.all([listMemberDevices(session, Date.now()), loadSharedRequests(session).catch(caught => {
        replaced = caught instanceof Error && caught.message.startsWith("The organization key changed");
        return currentSharedList();
      })]);
      setDevices(list);
      setKeyReplaced(replaced);
      const { knownKeyEpoch, unfinishedRemovals } = await import("@/lib/confidential/firmMemberDevices");
      const epoch = knownKeyEpoch(shared?.list.keyEpoch, currentFirmDevice()?.keyEpoch);
      setKeyEpoch(epoch);
      setUnfinished(replaced ? [] : unfinishedRemovals(list, epoch));
    } catch (caught) {
      setNotice({ kind: "alert", text: errorText(caught, "The list of lawyers could not be loaded. Please try again.") });
    } finally { setLoading(false); }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (run: () => Promise<string>) => {
    setBusy(true); setNotice(null);
    try { setNotice({ kind: "status", text: await run() }); await load(); }
    catch (caught) {
      setNotice({ kind: "alert", text: errorText(caught, "That change was not saved. Reload the list and try again.") });
      await load();
    } finally { setBusy(false); }
  };
  const members = (devices ?? []).filter(item => item.state === "approved");
  const pending = (devices ?? []).filter(item => item.state === "pending");
  const removed = (devices ?? []).filter(item => item.state === "removed");
  const ownMemberId = currentFirmDevice()?.memberId ?? null;

  if (rotation) {
    return <RotationChecklist session={session} rotation={rotation} devices={devices ?? []}
      onDistribute={async () => {
        const [members, shared] = await Promise.all([import("@/lib/confidential/firmMemberDevices"), import("@/lib/confidential/firmSharedRequests")]);
        let next = { ...rotation, attempted: true };
        try {
          const fresh = await members.listMemberDevices(session, Date.now());
          setDevices(fresh);
          const missed = await members.distributeRotatedKey(session, rotation, fresh, Date.now());
          next = { ...next, missed, distributed: missed.length === 0 };
        } catch { next = { ...next, distributed: false }; }
        if (next.distributed && !next.listMoved) {
          try {
            const list = currentSharedList();
            await shared.moveSharedListToKey(session, list?.version ?? 0, { next: rotation.next.privateKey,
              continuity: rotation.continuity, keyEpoch: rotation.statement.keyEpoch }, Date.now());
            next = { ...next, listMoved: true };
          } catch { /* shown as not moved; the steward retries */ }
        }
        setRotation(next);
      }}
      onFinish={() => finishRotation(() => replaceFirmKeyInWorkspace(rotation.next, rotation.statement.keyEpoch), lockParticipantTabs)} />;
  }
  if (removing) {
    return <RemovalWizard session={session} devices={devices ?? []} removing={removing} keyEpoch={keyEpoch}
      onCancel={() => { setRemoving(null); void load(); }}
      onPrepared={result => { setRemoving(null); setRotation(result); }} />;
  }
  return (
    <div className="space-y-8">
      <Notice notice={notice} />
      {keyReplaced && <p role="alert" className="border border-red-700 p-4 text-sm">
        Your organization already replaced its key, and this device still uses the old one. Lock this page and unlock it
        with the new key file (or your saved workspace after it receives the new key) before you approve or remove anyone.
      </p>}
      {unfinished.length > 0 && <div role="alert" className="border border-red-700 p-4 text-sm">
        <p className="mb-3 max-w-[62ch]">The removal of {unfinished.map(personName).join(", ")} is not finished. They held your current
          organization key, so it must be replaced before they are fully removed.</p>
        <button type="button" className={primaryButton} disabled={busy} onClick={() => setRemoving(unfinished)}>Finish the removal…</button>
      </div>}
      <p className="max-w-[62ch] text-sm text-black/70">
        Each lawyer uses their own device key; nobody shares the key file or a login. Anyone holding your organization key
        can approve devices, so agree inside your organization who does this (your steward).
      </p>
      <AddLawyer session={session} />

      <section className={panel} aria-labelledby="pending-title" aria-busy={loading}>
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="pending-title" className="font-semibold">Waiting for approval</h2>
          {/* Reloading the page would lock the organization key; check in place instead. */}
          <button type="button" className="text-sm underline" disabled={loading || busy} onClick={() => void load()}>
            {loading ? "Checking…" : "Check for new devices"}
          </button>
        </div>
        {loading && !devices && <p role="status">Loading…</p>}
        {devices && !pending.length && <p className="text-sm text-black/60">No devices are waiting.</p>}
        <ul className="space-y-4">
          {pending.map(device => <PendingDevice key={device.memberId} device={device} busy={busy || keyReplaced}
            onApprove={() => void act(async () => {
              const { approveMemberDevice } = await import("@/lib/confidential/firmMemberDevices");
              await approveMemberDevice(session, device, keyEpoch, Date.now());
              return `${personName(device)}'s device is approved. It receives the key the next time they open the join page. They still need an invitation from VERA onboarding.`;
            })}
            onDecline={() => void act(async () => {
              const { removeMemberDevice } = await import("@/lib/confidential/firmMemberDevices");
              await removeMemberDevice(session, device, Date.now());
              return "The device was declined.";
            })} />)}
        </ul>
      </section>

      <section className={panel} aria-labelledby="members-title">
        <h2 id="members-title" className="mb-2 font-semibold">Lawyers with an approved device</h2>
        {devices && !members.length && <p className="text-sm text-black/60">No devices are approved yet.</p>}
        <ul className="space-y-4">
          {members.map(device => (
            <li key={device.memberId} className="border-t border-black/10 pt-4">
              <p className="font-semibold">{personName(device)}</p>
              {device.profile?.contact && <p className="text-sm text-black/70">{device.profile.contact}</p>}
              <p className="text-sm text-black/70">
                {device.enrolled ? "Enrolled with VERA." : "Not enrolled yet: needs to accept an invitation from VERA onboarding."}
                {(device.keyEpoch ?? 0) < keyEpoch ? " Has not received the current key." : ""}
              </p>
              <details className="mt-1 text-sm">
                <summary className="cursor-pointer underline">Device code</summary>
                <DeviceCode code={device.deviceCode} />
                <p className="text-xs text-black/50">Approved {date(device.updatedAt)}</p>
              </details>
              {device.memberId === ownMemberId
                ? <p className="mt-3 text-sm text-black/60">This is your device. Another steward must remove it.</p>
                : <button type="button" className={`mt-3 ${secondaryButton}`} disabled={busy || keyReplaced}
                  aria-label={`Remove ${personName(device)}`} onClick={() => setRemoving([device])}>Remove…</button>}
            </li>
          ))}
        </ul>
      </section>

      {removed.length > 0 && <details className="text-sm">
        <summary className="cursor-pointer underline">Removed or declined devices ({removed.length})</summary>
        <ul className="mt-2 space-y-1">{removed.map(device => <li key={device.memberId}>{personName(device)}, {date(device.updatedAt)}</li>)}</ul>
      </details>}

      <details className="text-sm">
        <summary className="cursor-pointer underline">Replace the organization key without removing anyone</summary>
        <p className="my-2 max-w-[62ch]">Do this if a device or key file may have been lost or copied.</p>
        <button type="button" className={secondaryButton} disabled={busy || !devices || keyReplaced} onClick={() => setRemoving([])}>Replace the key…</button>
      </details>
      <p className="text-sm"><Link className="underline" href="/legal">Back to requests and reports</Link></p>
    </div>
  );
}

export default function LegalMembers() {
  return (
    <LegalPortalLayout title="Lawyers and devices">
      <LegalGate returnPath="/legal/members">{({ session }) => <Members session={session} />}</LegalGate>
    </LegalPortalLayout>
  );
}

/** Server-rendered so `_document` applies the strict key-page headers. */
export const getServerSideProps = async () => ({ props: {} });
