import {
  ENDING_SOON, EMPTY_FILTER, RENEW_PURPOSE, accessEnd, calendarDate, latestAccessEnd, canAskToRenew, canRequestAgain, canWithdraw, caseDocument, caseStatus,
  filterActive, firmTimeline, formatBytes, humanLabel, refusedCaseStatus, scopeSentence, statusBadge,
  triageDirectory,
} from '../../../lib/confidential/firmCaseView';
import type { DirectoryListing } from '../../../lib/confidential/firmCase';

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 8, 27, 12);
const id = (n: number) => n.toString(16).padStart(64, '0');
const listing = (n: number, extra: Partial<DirectoryListing> = {}): DirectoryListing =>
  ({ caseId: id(n), summary: `Summary ${n}`, owner: null, ...extra });

describe('access end', () => {
  test('finite expiries remain finite; no expiry means until the reporter revokes it', () => {
    expect(accessEnd(NOW + 20 * 365 * DAY, NOW)).toMatchObject({ kind: 'ends', at: NOW + 20 * 365 * DAY });
    expect(accessEnd(NOW + 20 * DAY, NOW)).toEqual({ kind: 'ends', at: NOW + 20 * DAY, daysLeft: 20, endingSoon: false });
    expect(accessEnd(NOW + ENDING_SOON, NOW)).toMatchObject({ daysLeft: 14, endingSoon: true });
    expect(accessEnd(NOW + 3 * 3_600_000, NOW)).toMatchObject({ daysLeft: 1, endingSoon: true });
    expect(accessEnd(NOW - DAY, NOW)).toMatchObject({ daysLeft: 0, endingSoon: true });
    expect(accessEnd(null, NOW)).toEqual({ kind: 'open-ended' });
  });

  test('all current access ends with the last grant; an unavailable expiry remains unknown', () => {
    expect(latestAccessEnd([{ expiresAt: NOW + DAY }, { expiresAt: NOW + 9 * DAY }])).toBe(NOW + 9 * DAY);
    expect(latestAccessEnd([{ expiresAt: NOW + DAY }, { expiresAt: null }])).toBeNull();
    expect(latestAccessEnd([])).toBeNull();
  });
});

describe('report document', () => {
  test('known fields go to account, dates, place and about; unknown ones are kept, empty ones dropped', () => {
    const document = caseDocument({
      description: 'What happened, in detail.', dateOfIncident: '2026-03-04', location: 'Warehouse district',
      jurisdiction: null, category: 'financial-fraud', urgency: 'high', wantsReward: false, extraNote: 'Kept',
      empty: '  ', flag: 'true',
    }, [
      { scope: 'contact', fields: { contactMethod: 'Signal', contactValue: '+1 555 0100' } },
      { scope: 'identity', fields: { submitterName: '', submitterConsent: 'true' } },
      { scope: 'rewards', fields: { empty: null } },
    ]);
    expect(document.account).toBe('What happened, in detail.');
    expect(document.dates).toEqual([{ label: 'When it happened', value: 'March 4, 2026' }]);
    expect(document.place).toEqual([{ label: 'Place', value: 'Warehouse district' }]);
    expect(document.about).toEqual([
      { label: 'Category', value: 'Financial Fraud' }, { label: 'Urgency', value: 'High' },
      { label: 'Interested in a whistleblower reward', value: 'No' }]);
    expect(document.other).toEqual([{ label: 'Extra note', value: 'Kept' }, { label: 'Flag', value: 'Yes' }]);
    expect(document.records).toEqual([
      { title: 'Contact details shared by the reporter', fields: [
        { label: 'Preferred contact method', value: 'Signal' }, { label: 'Contact', value: '+1 555 0100' }] },
      { title: 'Identity shared by the reporter', fields: [{ label: 'Agreed to be identified', value: 'Yes' }] },
    ]);
  });

  test('no narrative gives an empty document; prototype keys are ordinary unknown fields', () => {
    expect(caseDocument(null, [])).toEqual({ account: null, dates: [], place: [], about: [], other: [], records: [] });
    const document = caseDocument(JSON.parse('{"__proto__":"x","constructor":"y","toString":"z"}'), []);
    expect(document.other.map(item => item.value).sort()).toEqual(['x', 'y', 'z']);
    expect(document.account).toBeNull();
  });

  test('calendar dates do not shift across time zones and free text is kept', () => {
    expect(calendarDate('2026-01-01')).toBe('January 1, 2026');
    expect(calendarDate('2026-02-30')).toBe('2026-02-30');
    expect(calendarDate('last spring')).toBe('last spring');
    expect(humanLabel('someCamelCase_key')).toBe('Some camel case key');
    expect(humanLabel('')).toBe('Detail');
  });
});

describe('timeline', () => {
  test('shows only the firm\'s own request, grants, a later update approval and its messages, in order', () => {
    const events = firmTimeline({ requestedAt: NOW - 10 * DAY,
      grants: [{ issuedAt: NOW - 2 * DAY, expiresAt: NOW + 30 * DAY, scopes: ['messages', 'narrative'] },
        { issuedAt: NOW - 8 * DAY, expiresAt: NOW + 20 * DAY, scopes: ['narrative', 'evidence', 'messages'] }],
      releaseApprovedAt: NOW - 5 * DAY,
      messages: [{ sender: 'owner', sentAt: NOW - 3 * DAY }, { sender: 'organization', sentAt: NOW - 7 * DAY }], now: NOW });
    expect(events.map(event => [event.kind, event.at])).toEqual([
      ['requested', NOW - 10 * DAY], ['allowed', NOW - 8 * DAY], ['message-sent', NOW - 7 * DAY],
      ['update-approved', NOW - 5 * DAY], ['message-received', NOW - 3 * DAY], ['changed', NOW - 2 * DAY],
      ['access-ends', NOW + 30 * DAY]]);
    expect(events[1].detail).toBe('Includes the report and files.');
    expect(events[events.length - 1].upcoming).toBe(true);
  });

  test('distant finite grants still show expiry; unknown expiries add no expiry event', () => {
    const events = firmTimeline({ requestedAt: null, grants: [{ issuedAt: NOW, expiresAt: NOW + 20 * 365 * DAY, scopes: ['narrative'] }],
      releaseApprovedAt: NOW - DAY, messages: [], now: NOW });
    expect(events.map(event => event.kind)).toEqual(['allowed', 'access-ends']);
    expect(firmTimeline({ requestedAt: null, grants: [], releaseApprovedAt: null, messages: [], now: NOW })).toEqual([]);
    expect(firmTimeline({ requestedAt: null, grants: [{ issuedAt: NOW, expiresAt: null, scopes: ['narrative'] },
      { issuedAt: NOW + 1, expiresAt: NOW + DAY, scopes: ['narrative', 'evidence'] }], releaseApprovedAt: null, messages: [], now: NOW })
      .map(event => event.kind)).toEqual(['allowed', 'changed']);
  });

  test('scope sentences', () => {
    expect(scopeSentence(['narrative'])).toBe('the report');
    expect(scopeSentence(['contact', 'narrative'])).toBe('the report and contact details');
    expect(scopeSentence([])).toBe('nothing');
  });
});

describe('request status', () => {
  test('service answers map to badges', () => {
    expect(caseStatus({ access: 'unknown', request: 'expired', requestExpiresAt: null }, true))
      .toEqual({ kind: 'unconfirmed' });
    expect(statusBadge({ kind: 'unconfirmed' }, NOW).description).toContain('verify current access');
    expect(statusBadge({ kind: 'unconfirmed' }, NOW).description).toContain('The secure service has not confirmed your access yet.');
    expect(caseStatus({ access: 'granted', request: 'approved', releaseApproved: true, expiresAt: NOW + DAY }, false))
      .toEqual({ kind: 'granted', expiresAt: NOW + DAY });
    expect(caseStatus({ access: 'granted', request: 'expired', releaseApproved: false, expiresAt: NOW + DAY }, true)).toEqual({ kind: 'update-pending' });
    expect(caseStatus({ access: 'none', request: 'pending', requestExpiresAt: NOW + DAY }, false))
      .toEqual({ kind: 'waiting', requestExpiresAt: NOW + DAY });
    expect(caseStatus({ access: 'none', request: 'declined', requestExpiresAt: null }, true)).toEqual({ kind: 'declined' });
    // A renewal the reporter declined after access ended reads as declined, not as
    // "Access ended" with another "Ask to renew" (the reporter was told they see the decline).
    for (const ended of ['revoked', 'expired'] as const) {
      const declined = caseStatus({ access: 'none', request: 'declined', requestExpiresAt: null, ended }, true);
      expect(declined).toEqual({ kind: 'declined' });
      expect(canAskToRenew(declined, NOW)).toBe(false);
    }
    expect(caseStatus({ access: 'none', request: 'withdrawn', requestExpiresAt: null }, false)).toEqual({ kind: 'withdrawn' });
    expect(caseStatus({ access: 'none', request: 'expired', requestExpiresAt: null }, false)).toEqual({ kind: 'expired' });
    expect(caseStatus({ access: 'none', request: 'expired', requestExpiresAt: null }, true)).toEqual({ kind: 'ended' });
    expect(caseStatus({ access: 'none', request: 'unknown', requestExpiresAt: null }, false)).toEqual({ kind: 'unknown' });
  });

  test('a locked report still shows the request outcome on a device that never opened it', () => {
    // The service reports access as unknown whenever the report is locked; the request row still answers.
    expect(caseStatus({ access: 'unknown', request: 'pending', requestExpiresAt: NOW + DAY }, false))
      .toEqual({ kind: 'waiting', requestExpiresAt: NOW + DAY });
    expect(caseStatus({ access: 'unknown', request: 'declined', requestExpiresAt: null }, false)).toEqual({ kind: 'declined' });
    expect(caseStatus({ access: 'unknown', request: 'expired', requestExpiresAt: null }, false)).toEqual({ kind: 'expired' });
    expect(caseStatus({ access: 'unknown', request: 'withdrawn', requestExpiresAt: null }, false)).toEqual({ kind: 'withdrawn' });
    // Approved or unrecorded requests, and reports opened before, must be verified by opening the report.
    expect(caseStatus({ access: 'unknown', request: 'approved', requestExpiresAt: null }, false)).toEqual({ kind: 'unconfirmed' });
    expect(caseStatus({ access: 'unknown', request: 'unknown', requestExpiresAt: null }, false)).toEqual({ kind: 'unconfirmed' });
    for (const request of ['pending', 'declined', 'expired', 'withdrawn', 'approved'] as const) {
      expect(caseStatus({ access: 'unknown', request, requestExpiresAt: null }, true)).toEqual({ kind: 'unconfirmed' });
    }
    expect(statusBadge(caseStatus({ access: 'unknown', request: 'pending', requestExpiresAt: null }, false), NOW).label)
      .toBe('Waiting for reporter');
  });

  test('ask to renew is offered for ended or soon-ending access, whether or not the reporter key is pinned', () => {
    expect(canAskToRenew({ kind: 'ended' }, NOW)).toBe(true);
    expect(canAskToRenew({ kind: 'granted', expiresAt: NOW + 3 * DAY }, NOW)).toBe(true);
    expect(canAskToRenew({ kind: 'granted', expiresAt: NOW + 30 * DAY }, NOW)).toBe(false);
    expect(canAskToRenew({ kind: 'granted', expiresAt: null }, NOW)).toBe(false);
    for (const kind of ['declined', 'expired', 'withdrawn', 'unconfirmed', 'checking'] as const) expect(canAskToRenew({ kind }, NOW)).toBe(false);
    expect(canAskToRenew(undefined, NOW)).toBe(false);
  });

  test('missing release approval is actionable without claiming current access', () => {
    for (const openedBefore of [false, true]) {
      for (const request of ['unknown', 'approved', 'pending', 'declined'] as const) {
        const status = caseStatus({ access: 'unknown', request, requestExpiresAt: null, releaseApproved: false }, openedBefore);
        expect(status).toEqual({ kind: 'update-pending' });
        expect(canRequestAgain(status)).toBe(false);
        expect(canAskToRenew(status, NOW)).toBe(false);
        expect(canWithdraw(status)).toBe(false);
        expect(statusBadge(status, NOW).description).toContain('Approve update');
        expect(statusBadge(status, NOW).description).not.toContain('You have access');
      }
    }
    expect(caseStatus({ access: 'unknown', request: 'unknown', requestExpiresAt: null }, false)).toEqual({ kind: 'unconfirmed' });
  });

  test('badges carry a label, tone and plain explanation', () => {
    expect(statusBadge({ kind: 'granted', expiresAt: NOW + 3 * DAY }, NOW)).toMatchObject({ label: 'Access ending soon', tone: 'attention' });
    expect(statusBadge({ kind: 'granted', expiresAt: NOW + 30 * DAY }, NOW)).toMatchObject({ label: 'Access allowed', tone: 'positive' });
    expect(statusBadge({ kind: 'granted', expiresAt: NOW + 20 * 365 * DAY }, NOW).description).toMatch(/Access ends .*2046 unless the reporter renews it/);
    expect(statusBadge({ kind: 'granted', expiresAt: null }, NOW).description).toMatch(/until the reporter revokes it/);
    expect(statusBadge({ kind: 'granted', expiresAt: null, contactShared: true }, NOW).description).toMatch(/shared contact details/);
    expect(statusBadge({ kind: 'update-pending' }, NOW).label).toBe('Waiting for reporter to approve update');
    expect(statusBadge({ kind: 'waiting', requestExpiresAt: NOW + DAY }, NOW).description).toMatch(/lapses on/);
    for (const kind of ['declined', 'expired', 'ended'] as const) expect(statusBadge({ kind }, NOW).tone).toBe('negative');
    for (const kind of ['checking', 'error', 'withdrawn', 'unknown'] as const) expect(statusBadge({ kind }, NOW).tone).toBe('neutral');
    const copy = JSON.stringify(['checking', 'error', 'update-pending', 'declined', 'expired', 'withdrawn', 'ended', 'unknown']
      .map(kind => statusBadge({ kind } as never, NOW)));
    expect(copy).not.toMatch(/\b(case|grant|owner)\b/i);
  });

  // These rules used to live only in an unused accessChoices helper (firmOutcome);
  // they are asserted here on the functions /legal actually renders.
  test('a renewal asked for while access continues can be withdrawn and is not asked for twice', () => {
    const renewing = caseStatus({ access: 'granted', request: 'pending', releaseApproved: true, expiresAt: NOW + 3 * DAY }, true);
    expect(renewing).toEqual({ kind: 'granted', expiresAt: NOW + 3 * DAY, renewalPending: true });
    expect(statusBadge(renewing, NOW)).toMatchObject({ label: 'Access ending soon', tone: 'attention' });
    expect(statusBadge(renewing, NOW).description).toMatch(/You asked to renew; waiting for the reporter\.$/);
    expect(canAskToRenew(renewing, NOW)).toBe(false);
    expect(canWithdraw(renewing)).toBe(true);
    expect(canRequestAgain(renewing)).toBe(false);
    // Once the reporter answers, the renewal flag goes away and the usual rules apply.
    const answered = caseStatus({ access: 'granted', request: 'declined', releaseApproved: true, expiresAt: NOW + 3 * DAY }, true);
    expect(answered).not.toHaveProperty('renewalPending');
    expect(canAskToRenew(answered, NOW)).toBe(true);
    expect(canWithdraw(answered)).toBe(false);
  });

  test('withdraw is offered only for a confirmed pending request', () => {
    expect(canWithdraw({ kind: 'waiting', requestExpiresAt: null })).toBe(true);
    expect(canWithdraw({ kind: 'granted', expiresAt: null })).toBe(false);
    for (const kind of ['checking', 'error', 'unconfirmed', 'update-pending', 'declined', 'expired', 'withdrawn', 'ended', 'unknown'] as const) {
      expect(canWithdraw({ kind } as never)).toBe(false);
    }
    expect(canWithdraw(undefined)).toBe(false);
  });

  test('ended access (revoked, expired or an earlier key) can be asked again; a pending new request waits', () => {
    for (const ended of ['revoked', 'expired', 'key-changed'] as const) {
      const status = caseStatus({ access: 'none', request: 'approved', requestExpiresAt: null, ended }, true);
      expect(status).toEqual({ kind: 'ended' });
      expect(statusBadge(status, NOW)).toMatchObject({ label: 'Access ended', tone: 'negative' });
      expect(canRequestAgain(status)).toBe(true);
      expect(canAskToRenew(status, NOW)).toBe(true);
      const again = caseStatus({ access: 'none', request: 'pending', requestExpiresAt: NOW + DAY, ended }, true);
      expect(again).toEqual({ kind: 'waiting', requestExpiresAt: NOW + DAY });
      expect(canWithdraw(again)).toBe(true);
    }
    // Access behind an unapproved secure-service update is still access: the report opens to ask for approval.
    expect(statusBadge(caseStatus({ access: 'granted', request: 'approved', releaseApproved: false, expiresAt: null }, true), NOW))
      .toMatchObject({ label: 'Waiting for reporter to approve update', tone: 'attention' });
  });

  test('only closed requests can be asked again', () => {
    expect(['declined', 'expired', 'withdrawn', 'ended', 'unknown'].every(kind => canRequestAgain({ kind } as never))).toBe(true);
    expect(canRequestAgain({ kind: 'waiting', requestExpiresAt: null })).toBe(false);
    expect(canRequestAgain({ kind: 'granted', expiresAt: null })).toBe(false);
    expect(canRequestAgain({ kind: 'checking' })).toBe(false);
  });
});

describe('directory triage', () => {
  test('direct shares use access independently of request history and fail closed when unconfirmed', () => {
    const shared = caseStatus({ access: 'granted', request: 'unknown', releaseApproved: true, expiresAt: null, contactShared: false }, false, false);
    expect(statusBadge(shared, NOW).label).toBe('Access allowed');
    expect(canRequestAgain(shared)).toBe(false);
    const notShared = caseStatus({ access: 'none', request: 'unknown', requestExpiresAt: null, ended: 'none' }, false, false);
    expect(statusBadge(notShared, NOW).label).toBe('Access not granted');
    expect(canRequestAgain(notShared)).toBe(true);
    const locked = caseStatus({ access: 'unknown', request: 'unknown', requestExpiresAt: null }, false, false);
    expect(locked.kind).toBe('unconfirmed');
    expect(canRequestAgain(locked)).toBe(false);
    for (const ended of ['revoked', 'expired'] as const) {
      expect(caseStatus({ access: 'none', request: 'unknown', requestExpiresAt: null, ended }, false, false)).toEqual({ kind: 'ended' });
    }
  });
  const listings = [listing(1), listing(2), listing(3), listing(4), listing(5)];
  test('request filters and stable sorts', () => {
    const requested = new Set([id(1), id(3)]);
    const ids = (items: DirectoryListing[]) => items.map(item => Number.parseInt(item.caseId, 16));
    expect(ids(triageDirectory(listings, EMPTY_FILTER, 'directory', requested))).toEqual([1, 2, 3, 4, 5]);
    expect(ids(triageDirectory(listings, { ...EMPTY_FILTER, show: 'not-requested' }, 'directory', requested))).toEqual([2, 4, 5]);
    expect(ids(triageDirectory(listings, { ...EMPTY_FILTER, show: 'requested' }, 'directory', requested))).toEqual([1, 3]);
    expect(ids(triageDirectory(listings, EMPTY_FILTER, 'not-requested-first', requested))).toEqual([2, 4, 5, 1, 3]);
    expect(filterActive(EMPTY_FILTER)).toBe(false);
    expect(filterActive({ ...EMPTY_FILTER, show: 'requested' })).toBe(true);
  });
});

describe('file sizes', () => {
  test('sizes read naturally', () => {
    expect(formatBytes(512)).toBe('512 bytes');
    expect(formatBytes(2048)).toBe('2 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
  });
});

describe('renewal message after a key replacement', () => {
  test('does not claim a member left, since the key can be replaced without removing anyone', () => {
    expect(RENEW_PURPOSE).toBe('Our organization replaced its key. Please allow our access again so we can continue working on your report.');
    expect(RENEW_PURPOSE).not.toMatch(/member|left|removed/i);
  });
});

describe('legal organization badge wording', () => {
  test('uses access and report, never grant or case', () => {
    const statuses = [
      { kind: 'unconfirmed' }, { kind: 'checking' }, { kind: 'error' }, { kind: 'update-pending' },
      { kind: 'granted', expiresAt: null }, { kind: 'granted', expiresAt: NOW + 3 * DAY, contactShared: true, renewalPending: true },
      { kind: 'waiting', requestExpiresAt: NOW + DAY }, { kind: 'declined' }, { kind: 'expired' }, { kind: 'ended' },
      { kind: 'withdrawn' }, { kind: 'unknown' },
    ] as const;
    for (const status of statuses) {
      const badge = statusBadge(status as Parameters<typeof statusBadge>[0], NOW);
      expect(`${badge.label} ${badge.description}`).not.toMatch(/\bgrants?\b|\bcases?\b/i);
    }
  });
});

describe('status after the service refused this organization the report', () => {
  // Locked: request-status cannot read the sealed grants and answers `unknown`;
  // the refusal (open-case, or unlock-case with the organization's own key) is the answer.
  test('a report opened before, or an approved request, has access that ended', () => {
    expect(caseStatus({ access: 'unknown', request: 'approved', requestExpiresAt: null }, true)).toEqual({ kind: 'unconfirmed' });
    expect(refusedCaseStatus({ access: 'unknown', request: 'approved', requestExpiresAt: null }, true)).toEqual({ kind: 'ended' });
    expect(refusedCaseStatus({ access: 'unknown', request: 'approved', requestExpiresAt: null }, false)).toEqual({ kind: 'ended' });
    expect(refusedCaseStatus({ access: 'unknown', request: 'unknown', requestExpiresAt: null }, true)).toEqual({ kind: 'ended' });
    expect(statusBadge({ kind: 'ended' }, NOW).label).toBe('Access ended');
  });
  test('request outcomes and known answers are kept as they are', () => {
    expect(refusedCaseStatus({ access: 'unknown', request: 'pending', requestExpiresAt: NOW + DAY }, true))
      .toEqual({ kind: 'waiting', requestExpiresAt: NOW + DAY });
    expect(refusedCaseStatus({ access: 'unknown', request: 'declined', requestExpiresAt: null }, true)).toEqual({ kind: 'declined' });
    expect(refusedCaseStatus({ access: 'unknown', request: 'unknown', requestExpiresAt: null }, false)).toEqual({ kind: 'unknown' });
    expect(refusedCaseStatus({ access: 'none', request: 'approved', requestExpiresAt: null, ended: 'revoked' }, true)).toEqual({ kind: 'ended' });
  });
});
