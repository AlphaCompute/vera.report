/**
 * Pure Mongo→dashboard mapping (no DB access). Lives on the Express side because
 * Express owns the working Mongo connection (reportPersistenceService); the Next
 * admin routes are thin proxies. Maps `whistleblower_reports` docs into the shape
 * the admin dashboard (DashboardReport) expects, joins the evidence manifest, and
 * synthesizes an activity timeline. Unit-testable in isolation (pure functions).
 */

export type DashboardEvidence = {
  id: string;
  name: string;
  type: string;
  size: string;
  ipfsHash: string | null;
  encryptedUrl: string | null;
};

export type DashboardActivity = {
  id: string;
  type: string;
  description: string;
  timestamp: string;
};

export type DashboardReport = {
  _id: string;
  reportId: string;
  trackingId: string;
  category: string;
  description: string;
  submittedAt: string;
  status: string;
  priority: string;
  aiClassification?: {
    authenticity: number;
    manipulationDetected: boolean;
    flags: string[];
    analyzedAt: string;
    model: string;
  };
  evidence: DashboardEvidence[];
  activity: DashboardActivity[];
  urgency?: string;
  location?: string;
  dateOfIncident?: string;
  reward?: { wantsReward: boolean; contactMethod?: string };
};

export type DashboardStats = {
  total: number;
  pending: number;
  reviewing: number;
  investigating: number;
  resolved: number;
  dismissed: number;
  critical: number;
  /** Average over scored reports only; meaningless when scoredCount is 0. */
  averageAuthenticity: number;
  /** Number of reports that have an AI score. */
  scoredCount: number;
  /** Scored reports by band (>70, 41-70, <=40), over the same population as scoredCount. */
  scoreBands: { high: number; medium: number; flagged: number };
  byCategory: Record<string, number>;
  byPriority: Record<string, number>;
  recentTrend: Array<{ date: string; count: number }>;
  lastUpdated: string;
};

/** Map an internal report status to the dashboard's status vocabulary. */
export function mapStatus(status: string): string {
  switch (status) {
    case 'processing': return 'pending';
    case 'verified': return 'pending';
    case 'rejected': return 'pending';
    default: return status;
  }
}

/** Keep malformed historical categories out of React and statistics keys. */
function safeCategory(value: unknown): string {
  return typeof value === 'string' && value ? value : 'other';
}

/**
 * Combine persisted status changes with submission and analysis timestamps.
 * Older reports without history retain a current-status fallback.
 */
export function buildActivity(r: any): DashboardActivity[] {
  const created = (r.createdAt instanceof Date ? r.createdAt : new Date(r.createdAt)).toISOString();
  const updated = (r.updatedAt instanceof Date ? r.updatedAt : new Date(r.updatedAt)).toISOString();
  const events: DashboardActivity[] = [
    { id: `${r.trackingId}-submit`, type: 'submit', description: 'Report submitted', timestamp: created },
  ];
  if (r.verification) {
    events.push({
      id: `${r.trackingId}-ai`,
      type: 'ai',
      description: `AI analysis complete — credibility ${r.verification.credibilityScore}%`,
      timestamp: updated,
    });
  } else if (r.processingStatus === 'failed' || (!r.processingStatus && r.status === 'pending')) {
    events.push({ id: `${r.trackingId}-ai`, type: 'note', description: 'AI analysis unavailable', timestamp: updated });
  }
  const s = mapStatus(r.status);
  if (r.statusHistory?.length) {
    events.push(...r.statusHistory.map((entry: { id: string; status: string; timestamp: string }) => ({
      id: entry.id, type: 'status', description: `Status: ${mapStatus(entry.status)}`, timestamp: entry.timestamp,
    })));
  } else if (['reviewing', 'investigating', 'resolved', 'dismissed'].includes(s)) {
    events.push({ id: `${r.trackingId}-status`, type: 'status', description: `Status: ${s}`, timestamp: updated });
  }
  return events;
}

/** Bucket evidence_decryption_params docs (keyed `${trackingId}/${filename}`) by trackingId. */
function bucketEvidence(evidenceDocs: any[]): Map<string, DashboardEvidence[]> {
  const byTracking = new Map<string, DashboardEvidence[]>();
  for (const d of evidenceDocs || []) {
    const key = String(d.fileKey ?? '');
    const slash = key.indexOf('/');
    if (slash < 0) continue;
    const tid = key.slice(0, slash);
    const name = key.slice(slash + 1);
    const mime: string = d.mimetype || '';
    const type = mime.startsWith('image/') ? 'image' : mime.startsWith('video/') ? 'video' : 'document';
    const arr = byTracking.get(tid) ?? [];
    arr.push({ id: key, name, type, size: '', ipfsHash: d.originalCID ?? null, encryptedUrl: null });
    byTracking.set(tid, arr);
  }
  return byTracking;
}

/**
 * Map raw Mongo report docs (+ their evidence manifest docs) into the dashboard
 * shape. The narrative stays encrypted at rest (revealed on-demand via the
 * narrative endpoint), so `description` is intentionally empty here.
 */
export function mapReports(reports: any[], evidenceDocs: any[] = []): DashboardReport[] {
  const evByTracking = bucketEvidence(evidenceDocs);
  return (reports || []).map((r) => ({
    _id: String(r._id),
    reportId: r.trackingId,
    trackingId: r.trackingId,
    category: safeCategory(r.category),
    description: '',
    submittedAt: (r.createdAt instanceof Date ? r.createdAt : new Date(r.createdAt)).toISOString(),
    status: mapStatus(r.status),
    priority: r.urgency || 'medium',
    aiClassification: r.verification
      ? {
          authenticity: r.verification.credibilityScore,
          manipulationDetected: !r.verification.isLegitimate,
          flags: r.verification.spamIndicators ?? [],
          analyzedAt: (r.updatedAt instanceof Date ? r.updatedAt : new Date(r.updatedAt)).toISOString(),
          model: 'shroud',
        }
      : undefined,
    evidence: evByTracking.get(r.trackingId) ?? [],
    activity: buildActivity(r),
    urgency: r.urgency,
    location: r.location,
    dateOfIncident: r.dateOfIncident,
    reward: r.reward ? { wantsReward: r.reward.wantsReward, contactMethod: r.reward.contactMethod } : undefined,
  }));
}

/** Aggregate dashboard stats from raw Mongo report docs. */
export function computeStats(reports: any[]): DashboardStats {
  const now = new Date().toISOString();
  if (!reports || reports.length === 0) {
    return { total: 0, pending: 0, reviewing: 0, investigating: 0, resolved: 0, dismissed: 0, critical: 0, averageAuthenticity: 0, scoredCount: 0, scoreBands: { high: 0, medium: 0, flagged: 0 }, byCategory: {}, byPriority: {}, recentTrend: [], lastUpdated: now };
  }

  let pending = 0, reviewing = 0, investigating = 0, resolved = 0, dismissed = 0, critical = 0;
  let totalAuthenticity = 0, authenticityCount = 0;
  const scoreBands = { high: 0, medium: 0, flagged: 0 };
  const byCategory: Record<string, number> = Object.create(null);
  const byPriority: Record<string, number> = {};
  const dateCounts: Record<string, number> = {};

  for (const r of reports) {
    switch (mapStatus(r.status)) {
      case 'pending': pending++; break;
      case 'reviewing': reviewing++; break;
      case 'investigating': investigating++; break;
      case 'resolved': resolved++; break;
      case 'dismissed': dismissed++; break;
    }
    if (r.urgency === 'critical') critical++;
    if (r.verification?.credibilityScore != null) {
      const score = r.verification.credibilityScore;
      totalAuthenticity += score;
      authenticityCount++;
      if (score > 70) scoreBands.high++;
      else if (score > 40) scoreBands.medium++;
      else scoreBands.flagged++;
    }
    const cat = safeCategory(r.category);
    byCategory[cat] = (byCategory[cat] || 0) + 1;
    const priority = r.urgency || 'medium';
    byPriority[priority] = (byPriority[priority] || 0) + 1;
    const dateKey = (r.createdAt instanceof Date ? r.createdAt : new Date(r.createdAt)).toISOString().split('T')[0];
    dateCounts[dateKey] = (dateCounts[dateKey] || 0) + 1;
  }

  const recentTrend = Object.entries(dateCounts)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-14)
    .map(([date, count]) => ({ date, count }));

  return {
    total: reports.length,
    pending, reviewing, investigating, resolved, dismissed, critical,
    averageAuthenticity: authenticityCount > 0 ? Math.round(totalAuthenticity / authenticityCount) : 0,
    scoredCount: authenticityCount,
    scoreBands,
    byCategory, byPriority, recentTrend, lastUpdated: now,
  };
}
