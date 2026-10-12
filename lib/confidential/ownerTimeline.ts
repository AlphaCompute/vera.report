import { grantActiveAt, verifyOwnerStatement } from '../../enclave/src/confidential/authorization';
import type { AccessGrant, CaseCheckpoint, CaseManifest, CaseScope, OwnerTrust } from '../../enclave/src/confidential/authorization';
import { caseRecipientKeyId } from '../../enclave/src/confidential/caseObject';
import { formatDay } from './formatDay';
export { formatDay };
import type { CurrentGrantee, OwnerHistoryEntry, OwnerThread, VerifiedReportOpen, VerifiedOrganization, VerifiedRequest } from './ownerCase';

/** The owner's record of what happened to their report, built on this device.
 *
 * Every event comes from something the host cannot forge:
 * - `signed`: a change between two consecutive owner-signed, hash-linked
 *   checkpoints (or a grant they reference). Revoking, adding files, editing or
 *   withdrawing the summary and approving an update each create one, so each
 *   leaves a record the owner can see from any device with the recovery code.
 * - `sealed`: a request or message signed by the legal organization (or the owner)
 *   and encrypted to the owner.
 * Declined requests and unanswered requests that expired are not recorded: the
 * service keeps no owner-signed trace of them. Times are the signer's own clock. */
export type TimelineKind =
  | 'submitted' | 'summary-published' | 'summary-edited' | 'summary-withdrawn' | 'files-added'
  | 'access-allowed' | 'access-changed' | 'access-revoked' | 'access-ended' | 'update-approved'
  | 'report-opened' | 'request' | 'message-received' | 'message-sent';
export type TimelineEvent = {
  id: string; kind: TimelineKind; at: number; title: string; detail?: string;
  record: 'signed' | 'sealed' | 'organization'; organization?: string;
};
export type OwnerTimeline = { events: TimelineEvent[]; incomplete: boolean };
export type OwnerJourney = { submitted: true; visible: boolean; requests: number; sharedWith: number };

const UNKNOWN_ORGANIZATION = 'a legal organization VERA can no longer verify';
const SCOPE_WORDS: Record<CaseScope, string> = { narrative: 'report', evidence: 'files', messages: 'messages',
  identity: 'identity', contact: 'contact details', rewards: 'reward details' };

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;
export function accessUntil(grant: Pick<AccessGrant, 'issuedAt' | 'expiresAt'>): string {
  return grant.expiresAt === null ? 'until you revoke it' : `until ${formatDay(grant.expiresAt)}`;
}
function scopeText(grant: AccessGrant): string {
  const words = grant.scopes.filter(scope => scope !== 'messages').map(scope => SCOPE_WORDS[scope]);
  const list = words.length > 1 ? `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}` : words[0];
  return `Can read your ${list}${grant.objectRevisionLimit === null && grant.scopes.includes('evidence') ? ', including files you add later' : ''}, ${accessUntil(grant)}.`;
}

/** Legal organizations shown by name only when their approved key is the
 * key the grant, request or message was bound to. */
async function organizationNames(roster: readonly VerifiedOrganization[]) {
  const keys = new Map<string, VerifiedOrganization>();
  for (const organization of roster) keys.set(`${organization.organizationId}:${await caseRecipientKeyId(organization.publicKey)}`, organization);
  return (grant: Pick<AccessGrant, 'organizationId' | 'recipientKeyId'>) =>
    keys.get(`${grant.organizationId}:${grant.recipientKeyId}`)?.displayName ?? UNKNOWN_ORGANIZATION;
}

export async function buildOwnerTimeline(input: {
  trust: OwnerTrust; history: readonly OwnerHistoryEntry[]; statements: Readonly<Record<string, string>>;
  opens?: readonly VerifiedReportOpen[]; roster: readonly VerifiedOrganization[]; requests: readonly VerifiedRequest[]; threads: readonly OwnerThread[]; now: number;
}): Promise<OwnerTimeline> {
  const events: TimelineEvent[] = [];
  let incomplete = false;
  const cache = new Map<string, { kind: string; value: unknown } | null>();
  /** A statement the checkpoint names, verified against the owner key and its digest. */
  async function statement<T>(digest: string | null, kind: string): Promise<T | null> {
    if (digest === null) return null;
    if (!cache.has(digest)) {
      let value: { kind: string; value: unknown } | null = null;
      try {
        const wire = input.statements[digest];
        if (wire) {
          const verified = await verifyOwnerStatement(wire, input.trust);
          if (verified.digest === digest) value = { kind: verified.statement.kind, value: verified.statement };
        }
      } catch { /* treated as missing below */ }
      cache.set(digest, value);
    }
    const found = cache.get(digest);
    if (!found || found.kind !== kind) { incomplete = true; return null; }
    return found.value as T;
  }
  const evidenceIds = async (checkpoint: CaseCheckpoint) => {
    const manifest = await statement<CaseManifest>(checkpoint.manifestDigest, 'manifest');
    return new Set((manifest?.objects ?? []).filter(item => item.scope === 'evidence').map(item => item.objectId));
  };
  const nameOf = await organizationNames(input.roster);
  let previous: OwnerHistoryEntry | null = null;
  for (const entry of input.history) {
    const current = entry.checkpoint, at = current.issuedAt, id = (suffix: string) => `${entry.digest}:${suffix}`;
    if (!previous) {
      const files = (await evidenceIds(current)).size;
      events.push({ id: id('submitted'), kind: 'submitted', at, record: 'signed', title: 'You submitted your report',
        detail: files ? `With ${plural(files, 'file')}. Encrypted on your device.` : 'Encrypted on your device.' });
      if (current.listingDigest) {
        events.push({ id: id('summary'), kind: 'summary-published', at, record: 'signed',
          title: 'Your summary was published for legal organizations' });
      }
    } else {
      const before = previous.checkpoint;
      if (before.listingDigest !== current.listingDigest) {
        const kind = current.listingDigest === null ? 'summary-withdrawn' : before.listingDigest === null ? 'summary-published' : 'summary-edited';
        events.push({ id: id('summary'), kind, at, record: 'signed', title: kind === 'summary-withdrawn'
          ? 'You withdrew your summary from the directory' : kind === 'summary-published'
            ? 'You published your summary for legal organizations'
            : 'You edited your summary' });
      }
      if (before.manifestDigest !== current.manifestDigest) {
        const earlier = await evidenceIds(before), added = [...await evidenceIds(current)].filter(item => !earlier.has(item));
        if (added.length) {
          const covered: string[] = [];
          for (const digest of current.grantDigests) {
            const grant = await statement<AccessGrant>(digest, 'grant');
            if (grant && grant.objectRevisionLimit === null && grant.scopes.includes('evidence') &&
                grantActiveAt(grant, at)) covered.push(nameOf(grant));
          }
          const names = [...new Set(covered)];
          events.push({ id: id('files'), kind: 'files-added', at, record: 'signed', title: `You added ${plural(added.length, 'file')}`,
            // The signed record shows only whose access covers files added later.
            // Whether each organization received the key depends on an approved-roster
            // check on the adding device, which leaves no signed trace here.
            detail: names.length ? `Covered by access for ${names.join(', ')}.` : 'Only you can open them.' });
        }
      }
      const removed = before.grantDigests.filter(digest => !current.grantDigests.includes(digest));
      const added = current.grantDigests.filter(digest => !before.grantDigests.includes(digest));
      const removedGrants = (await Promise.all(removed.map(digest => statement<AccessGrant>(digest, 'grant')))).filter(Boolean) as AccessGrant[];
      const addedGrants = (await Promise.all(added.map(digest => statement<AccessGrant>(digest, 'grant')))).filter(Boolean) as AccessGrant[];
      const remaining = (await Promise.all(current.grantDigests.map(digest => statement<AccessGrant>(digest, 'grant'))))
        .filter(Boolean) as AccessGrant[];
      for (const grant of addedGrants) {
        const replaced = removedGrants.some(item => item.organizationId === grant.organizationId);
        const name = nameOf(grant);
        events.push({ id: id(`grant:${grant.grantId}`), kind: replaced ? 'access-changed' : 'access-allowed', at, record: 'signed',
          organization: name, title: replaced ? `You changed access for ${name}` : `You allowed access for ${name}`, detail: scopeText(grant) });
      }
      const revoked = new Set(removedGrants.filter(grant => !remaining.some(item => item.organizationId === grant.organizationId))
        .map(grant => grant.organizationId));
      for (const organizationId of revoked) {
        const grant = removedGrants.find(item => item.organizationId === organizationId)!;
        const name = nameOf(grant);
        events.push({ id: id(`revoke:${organizationId}`), kind: 'access-revoked', at, record: 'signed', organization: name,
          title: `You revoked access for ${name}`, detail: 'New access through the service is revoked. It can keep information it already read or downloaded.' });
      }
      const releases = current.releaseDigests.filter(digest => !before.releaseDigests.includes(digest));
      for (const digest of releases) {
        const release = await statement<{ releaseDigest: string }>(digest, 'release');
        events.push({ id: id(`release:${digest}`), kind: 'update-approved', at, record: 'signed',
          title: 'You approved an update to VERA’s secure service',
          ...(release ? { detail: `Release ID ${release.releaseDigest.slice(0, 12)}…` } : {}) });
      }
    }
    previous = entry;
  }
  // Grants still named by the newest checkpoint but past their end.
  if (previous) {
    for (const digest of previous.checkpoint.grantDigests) {
      const grant = await statement<AccessGrant>(digest, 'grant');
      if (grant && grant.expiresAt !== null && grant.expiresAt <= input.now) {
        const name = nameOf(grant);
        events.push({ id: `${digest}:ended`, kind: 'access-ended', at: grant.expiresAt, record: 'signed', organization: name,
          title: `Access for ${name} ended`, detail: 'The period you allowed is over.' });
      }
    }
  }
  for (const item of input.requests) {
    const name = item.organization.displayName;
    events.push({ id: `request:${item.request.requestId}`, kind: 'request', at: item.request.issuedAt, record: 'sealed',
      organization: name, title: `${name} asked for access`, detail: 'Waiting for your decision.' });
  }
  for (const { organization, receipt } of input.opens ?? []) {
    events.push({ id: `opened:${organization.organizationId}`, kind: 'report-opened', at: receipt.openedAt,
      record: 'organization', organization: organization.displayName,
      title: `${organization.displayName} first opened your report`,
      detail: 'Its browser opened the private report. This does not confirm that a lawyer has reviewed it.' });
  }
  for (const thread of input.threads) {
    const name = thread.organization.displayName;
    for (const message of thread.messages) {
      const received = message.sender === 'organization';
      events.push({ id: `message:${thread.organization.organizationId}:${message.sender}:${message.sequence}`,
        kind: received ? 'message-received' : 'message-sent', at: message.sentAt, record: 'sealed', organization: name,
        title: received ? `Message from ${name}` : `You sent a message to ${name}` });
    }
  }
  // Newest first; stable for events created by one checkpoint.
  const order = new Map(events.map((event, index) => [event.id, index]));
  events.sort((a, b) => b.at - a.at || order.get(b.id)! - order.get(a.id)!);
  return { events, incomplete };
}

/** The four facts in the status page header. */
export function ownerJourney(current: CaseCheckpoint, requests: readonly VerifiedRequest[],
  grantees: readonly CurrentGrantee[], now: number): OwnerJourney {
  return { submitted: true, visible: current.listingDigest !== null, requests: requests.length,
    sharedWith: grantees.filter(item => item.grants.some(grant => grantActiveAt(grant, now))).length };
}
