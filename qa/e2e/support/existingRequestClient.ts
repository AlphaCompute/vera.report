// Test setup for a request sent before the Available reports UI was retired.
// Uses the real signed/encrypted protocol and shared list; never writes the DB.
import { fetchRelay, forgetChannelSessions } from '../../../lib/confidential/client';
import { createFirmSession, readLegalDirectory, requestCaseAccess } from '../../../lib/confidential/firmCase';
import { importFirmIdentity } from '../../../lib/confidential/firmKey';
import { approvedOrganizationProfile } from '../../../lib/confidential/firmMemberDevices';
import { updateSharedList } from '../../../lib/confidential/firmSharedRequests';

export async function seedExistingRequest(input: {
  baseURL: string; releaseManifest: string; token: string;
  keyFile: string; code: string; name: string; summary: string; scopes: ('Report' | 'Files')[];
}) {
  const origin = new URL(input.baseURL);
  if (origin.protocol !== 'http:' || origin.hostname !== 'localhost') throw new Error('Existing request fixture is loopback-only');
  const relay = fetchRelay(`${origin.origin}/api/confidential/channel`, `${origin.origin}/api/confidential/objects`);
  const firm = await importFirmIdentity(input.keyFile, input.code);
  const session = await createFirmSession({ relay, releaseManifest: input.releaseManifest, firm, accessToken: async () => input.token });
  try {
    const now = Date.now();
    const { profile } = await approvedOrganizationProfile(firm, { relay, releaseManifest: input.releaseManifest, accessToken: input.token, now });
    if (!profile) throw new Error('Existing request fixture requires an approved signed profile');
    let cursor: string | null = null;
    do {
      const page = await readLegalDirectory(session, cursor, now);
      const listing = page.listings.find(item => item.summary === input.summary);
      if (listing?.owner) {
        const result = await requestCaseAccess(session, listing, {
          purpose: `${input.name} represents whistleblowers in public procurement matters.`,
          scopes: input.scopes.map(scope => scope === 'Report' ? 'narrative' : 'evidence'),
          details: { kind: 'new', conflictsChecked: true, feeBasis: 'no-fee', responseTime: 'two-days',
            practiceAreas: profile.practiceAreas, jurisdiction: profile.jurisdiction, website: profile.website },
        }, now, async ({ requestId, expiresAt }) => {
          await updateSharedList(session, 0, list => ({ ...list, requests: [...list.requests, {
            caseId: listing.caseId, requestId, ownerPublicKey: listing.owner!.ownerPublicKey.armor(),
            summary: listing.summary, requestedAt: now, expiresAt, recipientKeyId: firm.recipientKeyId,
            state: 'requested', updatedAt: now, grantExpiresAt: null,
          }] }), now);
        });
        return { caseId: listing.caseId, ...result };
      }
      cursor = page.next;
    } while (cursor);
    throw new Error('Existing request fixture report not found');
  } finally { forgetChannelSessions(session); }
}
