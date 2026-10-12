import { useState, useEffect, useCallback, useRef } from 'react';
import { readDashboardResponse } from '../lib/dashboardResponse';
import { ADMIN_SESSION_EXPIRED_MESSAGE, isAdminSessionExpired, noteAdminResponse } from '../lib/adminSession';
import { RateLimitError } from '../lib/rateLimitResponse';

// Admin dashboard data — served by the Next.js proxy → Express (Mongo/Shroud).
const DASHBOARD_API_BASE = '/api/admin/dashboard';

export interface DashboardReport {
  _id: string;
  reportId: string;
  trackingId?: string;
  category: string;
  description: string;
  submittedAt: string;
  status: 'pending' | 'reviewing' | 'investigating' | 'resolved' | 'dismissed';
  priority: 'low' | 'medium' | 'high' | 'critical';
  aiClassification?: {
    authenticity: number;
    manipulationDetected: boolean;
    flags: string[];
    analyzedAt: string;
    model: string;
  };
  evidence?: Array<{
    id: string;
    name: string;
    type: string;
    size: string;
    ipfsHash?: string | null;
    encryptedUrl?: string | null;
  }>;
  activity?: Array<{
    id: string;
    type: string;
    description: string;
    timestamp: string;
    user?: string;
  }>;
  reward?: {
    wantsReward: boolean;
    contactMethod?: string;
    // contactValue is not returned here — fetch via /api/whistleblower/reward-contact/:trackingId
  };
  urgency?: string;
  location?: string;
  dateOfIncident?: string;
}

export interface DashboardStats {
  total: number;
  pending: number;
  reviewing: number;
  investigating: number;
  resolved: number;
  dismissed: number;
  critical: number;
  averageAuthenticity: number;
  /** Reports with an AI score; optional for older backends. */
  scoredCount?: number;
  /** Scored reports by band, over the same population as scoredCount. */
  scoreBands?: { high: number; medium: number; flagged: number };
  byCategory: Record<string, number>;
  byPriority: Record<string, number>;
  recentTrend: Array<{ date: string; count: number }>;
  lastUpdated: string;
}

function isReportStatus(value: unknown): value is DashboardReport['status'] {
  return typeof value === 'string' && ['pending', 'reviewing', 'investigating', 'resolved', 'dismissed'].includes(value);
}

export function useDashboardStats() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const activeRequest = useRef<AbortController | null>(null);
  const retryAt = useRef(0);

  const refetch = useCallback(async () => {
    if (isAdminSessionExpired()) { setError(new Error(ADMIN_SESSION_EXPIRED_MESSAGE)); setLoading(false); return; }
    if (Date.now() < retryAt.current) return;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    try {
      setLoading(true);
      const response = await fetch(`${DASHBOARD_API_BASE}/stats`, { signal: controller.signal });
      const data = await readDashboardResponse(response, 'Report statistics') as DashboardStats;
      if (typeof data.total !== 'number' || !Array.isArray(data.recentTrend)) {
        throw new Error('Report statistics could not be loaded. Try again.');
      }
      if (controller.signal.aborted) return;
      setStats(data);
      setError(null);
    } catch (err) {
      if (!controller.signal.aborted && err instanceof RateLimitError) retryAt.current = err.retryAt;
      if (!controller.signal.aborted) setError(err instanceof Error ? err : new Error('Report statistics could not be loaded. Try again.'));
    } finally {
      if (activeRequest.current === controller) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refetch();
    // Refresh every 30 seconds
    const interval = setInterval(refetch, 30000);
    return () => { clearInterval(interval); activeRequest.current?.abort(); activeRequest.current = null; };
  }, [refetch]);

  return { stats, loading, error, refetch };
}

export function useDashboardReports(limit = 100, search = '') {
  const [reports, setReports] = useState<DashboardReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [hasLoaded, setHasLoaded] = useState(false);
  const [loadedSearch, setLoadedSearch] = useState('');
  const [hasMore, setHasMore] = useState(false);
  const activeRequest = useRef<AbortController | null>(null);
  const retryAt = useRef(0);

  const refetch = useCallback(async () => {
    if (isAdminSessionExpired()) { setError(new Error(ADMIN_SESSION_EXPIRED_MESSAGE)); setLoading(false); return; }
    if (Date.now() < retryAt.current) return;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    try {
      setLoading(true);
      const response = await fetch(search ? `${DASHBOARD_API_BASE}/reports` : `${DASHBOARD_API_BASE}/reports?limit=${limit}`, {
        signal: controller.signal,
        ...(search ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: search }) } : {}),
      });
      const data = await readDashboardResponse(response, 'Reports') as { reports?: DashboardReport[]; hasMore?: boolean };
      if (!Array.isArray(data.reports)) {
        throw new Error('Reports could not be loaded. Try again.');
      }
      if (controller.signal.aborted) return;
      setReports(data.reports);
      setLoadedSearch(search);
      setHasMore(data.hasMore === true);
      setHasLoaded(true);
      setError(null);
    } catch (err) {
      if (!controller.signal.aborted && err instanceof RateLimitError) retryAt.current = err.retryAt;
      if (!controller.signal.aborted) setError(err instanceof Error ? err : new Error('Reports could not be loaded. Try again.'));
    } finally {
      if (activeRequest.current === controller) setLoading(false);
    }
  }, [limit, search]);

  useEffect(() => {
    void refetch();
    // Refresh every 30 seconds
    const interval = setInterval(refetch, 30000);
    return () => { clearInterval(interval); activeRequest.current?.abort(); activeRequest.current = null; };
  }, [refetch]);

  const updateReportStatus = async (reportId: string, newStatus: DashboardReport['status']): Promise<DashboardReport['status'] | false> => {
    try {
      const response = await fetch(`${DASHBOARD_API_BASE}/reports/${reportId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });

      if (response.ok) {
        const result = await response.json();
        if (result?.success !== true) return false;
        // Employee responses intentionally omit the admin-only report data.
        const savedStatus: unknown = result.data === undefined ? newStatus : result.data?.status;
        if (!isReportStatus(savedStatus)) return false;
        // Apply the persisted activity immediately, including while the report is open.
        setReports(prev =>
          prev.map(r => r.reportId === reportId ? { ...r, status: savedStatus, activity: result.data?.activity ?? r.activity } : r)
        );
        return savedStatus;
      }
      return false;
    } catch (err) {
      console.error('Error updating report status:', err);
      return false;
    }
  };

  return { reports: loadedSearch === search ? reports : [], loading, error, hasLoaded, hasMore, refetch, updateReportStatus };
}

export function useDashboardHealth() {
  const [health, setHealth] = useState<{ status: 'active' | 'inactive' }>({ status: 'active' });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkHealth = async () => {
      if (isAdminSessionExpired()) { setLoading(false); return; }
      try {
        const response = await fetch(`${DASHBOARD_API_BASE}/health`);
        await noteAdminResponse(response);
        const result = await response.json();
        setHealth(result.success ? { status: 'active' } : { status: 'inactive' });
      } catch {
        setHealth({ status: 'inactive' });
      } finally {
        setLoading(false);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 60000); // Check every minute
    return () => clearInterval(interval);
  }, []);

  return { health, loading };
}
