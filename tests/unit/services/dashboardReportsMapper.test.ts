/**
 * Unit tests for the pure Mongo→dashboard mapper (src/services/dashboardReportsMapper.ts):
 * status mapping, activity synthesis, Shroud labeling, evidence join, and stats.
 */
import { mapReports, buildActivity, mapStatus, computeStats } from '../../../src/services/dashboardReportsMapper';

function report(over: Record<string, any> = {}) {
  return {
    _id: 'oid-1',
    trackingId: 'VRA-AAAA000000000001',
    category: 'cyber-security',
    urgency: 'high',
    status: 'verified',
    createdAt: new Date('2026-07-25T10:00:00Z'),
    updatedAt: new Date('2026-07-25T10:00:05Z'),
    verification: { isLegitimate: true, credibilityScore: 82, spamIndicators: ['looks-clean'], category: 'cyber-security' },
    reward: { wantsReward: true, contactMethod: 'signal' },
    ...over,
  };
}

describe('mapStatus', () => {
  it('maps internal statuses to the dashboard vocabulary', () => {
    expect(mapStatus('processing')).toBe('pending');
    expect(mapStatus('verified')).toBe('pending');
    expect(mapStatus('rejected')).toBe('pending');
    expect(mapStatus('pending')).toBe('pending');
  });
});

describe('buildActivity', () => {
  const base = { trackingId: 'VRA-X', createdAt: new Date('2026-01-01'), updatedAt: new Date('2026-01-02') };
  it('always includes a submit event', () => {
    expect(buildActivity({ ...base, status: 'processing' })[0]).toMatchObject({ type: 'submit' });
  });
  it('does not synthesize human closure for a verified report', () => {
    const a = buildActivity({ ...base, status: 'verified', verification: { credibilityScore: 90 } });
    expect(a.map((e) => e.type)).toEqual(['submit', 'ai']);
    expect(a[1].description).toContain('credibility 90%');
  });
  it('notes unavailable AI when pending with no verification', () => {
    const a = buildActivity({ ...base, status: 'pending' });
    expect(a.map((e) => e.type)).toEqual(['submit', 'note']);
    expect(a[1].description).toBe('AI analysis unavailable');
  });
});

describe('mapReports', () => {
  it('maps a Shroud-scored report (model=shroud, flags from spamIndicators, verified→pending, empty narrative)', () => {
    const [r] = mapReports([report()]);
    expect(r.reportId).toBe('VRA-AAAA000000000001');
    expect(r.status).toBe('pending');
    expect(r.description).toBe('');
    expect(r.aiClassification).toMatchObject({ authenticity: 82, manipulationDetected: false, flags: ['looks-clean'], model: 'shroud' });
    expect(r.activity.map((e) => e.type)).toEqual(['submit', 'ai']);
  });

  it('omits aiClassification when there is no verification', () => {
    const [r] = mapReports([report({ status: 'processing', verification: undefined })]);
    expect(r.aiClassification).toBeUndefined();
    expect(r.status).toBe('pending');
  });

  it('joins the evidence manifest bucketed per report', () => {
    const reports = [report({ trackingId: 'VRA-AAAA000000000001' }), report({ _id: 'oid-2', trackingId: 'VRA-BBBB000000000002' })];
    const evidence = [
      { fileKey: 'VRA-AAAA000000000001/photo.jpg', mimetype: 'image/jpeg', originalCID: 'QmPhoto' },
      { fileKey: 'VRA-AAAA000000000001/report.pdf', mimetype: 'application/pdf', originalCID: 'QmDoc' },
      { fileKey: 'VRA-BBBB000000000002/clip.mp4', mimetype: 'video/mp4', originalCID: 'QmClip' },
    ];
    const mapped = mapReports(reports, evidence);
    const a = mapped.find((m) => m.trackingId === 'VRA-AAAA000000000001')!;
    const b = mapped.find((m) => m.trackingId === 'VRA-BBBB000000000002')!;
    expect(a.evidence).toHaveLength(2);
    expect(a.evidence[0]).toMatchObject({ name: 'photo.jpg', type: 'image', ipfsHash: 'QmPhoto' });
    expect(a.evidence[1]).toMatchObject({ name: 'report.pdf', type: 'document', ipfsHash: 'QmDoc' });
    expect(b.evidence).toEqual([{ id: 'VRA-BBBB000000000002/clip.mp4', name: 'clip.mp4', type: 'video', size: '', ipfsHash: 'QmClip', encryptedUrl: null }]);
  });

  it('leaves evidence empty when there are no manifest docs', () => {
    expect(mapReports([report()])[0].evidence).toEqual([]);
  });
});

describe('computeStats', () => {
  it('returns zeros for no reports', () => {
    expect(computeStats([])).toMatchObject({ total: 0, resolved: 0, averageAuthenticity: 0, scoredCount: 0, scoreBands: { high: 0, medium: 0, flagged: 0 } });
  });

  it('aggregates status/priority/category and averages ONLY reports that were scored', () => {
    const reports = [
      report({ trackingId: 'A', status: 'verified', urgency: 'high', category: 'cyber-security', verification: { credibilityScore: 82, isLegitimate: true } }),
      report({ trackingId: 'B', status: 'rejected', urgency: 'critical', category: 'fraud', verification: { credibilityScore: 10, isLegitimate: false } }),
      // un-scored report (Shroud failed): no verification → must be EXCLUDED from the average
      report({ trackingId: 'C', status: 'pending', urgency: 'low', category: 'fraud', verification: undefined }),
    ];
    const s = computeStats(reports);
    expect(s.total).toBe(3);
    expect(s.resolved).toBe(0);
    expect(s.dismissed).toBe(0);
    expect(s.pending).toBe(3);
    expect(s.critical).toBe(1);
    expect(s.byCategory).toEqual({ 'cyber-security': 1, fraud: 2 });
    // avg over the two SCORED reports only: (82+10)/2 = 46, NOT (82+10+0)/3
    expect(s.averageAuthenticity).toBe(46);
    expect(s.scoredCount).toBe(2);
    // Bands cover the same scored population; the unscored report is in none.
    expect(s.scoreBands).toEqual({ high: 1, medium: 0, flagged: 1 });
  });
});


describe('legacy and human lifecycle compatibility', () => {
  it.each(['reviewing', 'investigating', 'resolved', 'dismissed'])('preserves explicit human %s after serialized reload', (status) => {
    const stored = JSON.parse(JSON.stringify(report({ status, processingStatus: 'completed' })));
    expect(mapReports([stored])[0].status).toBe(status);
    expect(computeStats([stored])[status as 'resolved']).toBe(1);
  });
  it('does not describe in-progress AI as unavailable', () => {
    expect(buildActivity(report({ status: 'pending', processingStatus: 'processing', verification: undefined }))).toHaveLength(1);
  });
});

it('shows saved status transitions with their original timestamps after reopening', () => {
  const statusHistory = [
    { id: 'review', status: 'reviewing', timestamp: '2026-01-03T10:00:00.000Z' },
    { id: 'resolved', status: 'resolved', timestamp: '2026-01-04T10:00:00.000Z' },
    { id: 'reopened', status: 'pending', timestamp: '2026-01-05T10:00:00.000Z' },
  ];
  const events = buildActivity(report({ status: 'pending', statusHistory })).filter(event => event.type === 'status');
  expect(events).toEqual(statusHistory.map(entry => ({
    id: entry.id, type: 'status', description: `Status: ${entry.status}`, timestamp: entry.timestamp,
  })));
});
it.each(['reviewing', 'investigating', 'resolved', 'dismissed'])('shows legacy %s status without stored history', status => {
  expect(buildActivity(report({ status })).filter(event => event.type === 'status')).toEqual([
    expect.objectContaining({ description: `Status: ${status}` }),
  ]);
});
