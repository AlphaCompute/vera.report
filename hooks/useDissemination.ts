import { useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { disseminationErrorMessage } from '../lib/disseminationErrorMessage';
import { RateLimitError, throwIfRateLimited } from '../lib/rateLimitResponse';
import { ADMIN_SESSION_EXPIRED_MESSAGE, isAdminSessionExpired, noteAdminResponse } from '../lib/adminSession';

/**
 * Admin-side data hook for the dissemination pipeline (VERA-PDR-001).
 * Talks to the Next.js proxy at /api/dissemination/:trackingId/*, which
 * enforces the admin role and forwards to the Express backend.
 */

export interface DisseminationChannel {
  entityId: string;
  entityName: string;
  tier: string;
  state: string;
  attempts: number;
  lastError?: string;
  dispatchedAt?: string;
  sla?: {
    ackDueAt: string | null;
    feedbackDueAt: string | null;
    ackReceivedAt?: string;
    feedbackReceivedAt?: string;
    ackBreached: boolean;
    feedbackBreached: boolean;
  };
  handoff?: { url: string; fields: Record<string, string>; depositBody: string };
  receipts: { type: string; value: string; receivedAt: string; note?: string }[];
}

export interface DisseminationAlert {
  trackingId: string;
  entityId: string;
  entityName: string;
  tier: string;
  state: string;
  kind: 'dead_letter' | 'ack_sla_breached' | 'feedback_sla_breached';
  attempts: number;
  lastError?: string;
  dispatchedAt?: string;
  updatedAt?: string;
}

export interface RoutingRule {
  ruleId: string;
  match: {
    categories?: string[];
    orgType?: string[];
    severity?: string[];
    jurisdiction?: string[];
  };
  route: { entityId: string; tier: string }[];
  version: number;
  active: boolean;
  effectiveFrom: string;
  createdAt: string;
}

export interface RecommendedChannel {
  entityId: string;
  entityName: string;
  tier: string;
  supported: boolean;
  consentSatisfied: boolean;
  reason: string;
  notes?: string;
}

export interface DisseminationPlan {
  trackingId: string;
  categories: string[];
  channels: RecommendedChannel[];
  consent: {
    psst: { granted: boolean; treatment?: string };
    agency: boolean;
    /** Admin-reviewed sharing with trusted legal reviewers (secure packets). */
    legalReview?: boolean;
    capturedAt: string;
    textVersion: string;
  } | null;
  generatedAt: string;
}

export interface DisseminationStatus {
  consent: DisseminationPlan['consent'];
  channels: DisseminationChannel[];
  disposition: {
    approvedBy: string;
    consentSnapshot: DisseminationPlan['consent'];
    narrativeOverride?: {
      narrative: string;
      notes: string[];
      setBy: string;
      setAt: string;
    };
    narrativeReviewedAt?: string;
    narrativeReviewedBy?: string;
    updatedAt: string;
  } | null;
  audit: { event: string; entityId?: string; actor: string; at: string }[];
}

const POLL_INTERVAL_MS = 15_000;

export function useDissemination(trackingId: string | undefined) {
  const [status, setStatus] = useState<DisseminationStatus | null>(null);
  const [plan, setPlan] = useState<DisseminationPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [planLoading, setPlanLoading] = useState(false);
  const [actionPending, setActionPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reportSecurePacketError = useCallback((error: unknown) => {
    const code = typeof error === 'string' ? error : 'Secure packet action failed';
    setError(code);
    toast.error('Unable to generate or send link', {
      description: disseminationErrorMessage(code),
      duration: 10000,
      closeButton: true,
    });
  }, []);

  const [statusError, setStatusError] = useState<string | null>(null);
  const retryAt = useRef(0);
  const fetchStatus = useCallback(async () => {
    if (isAdminSessionExpired()) { setStatusError(ADMIN_SESSION_EXPIRED_MESSAGE); return; }
    if (Date.now() < retryAt.current) return;
    if (!trackingId) return;
    try {
      const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/status`);
      await noteAdminResponse(res);
      if (isAdminSessionExpired()) throw new Error(ADMIN_SESSION_EXPIRED_MESSAGE);
      await throwIfRateLimited(res);
      const data = await res.json();
      if (data.success) {
        setStatus({ consent: data.consent ?? null, channels: data.channels ?? [], disposition: data.disposition ?? null, audit: data.audit ?? [] });
        setStatusError(null);
      } else {
        setStatusError(data.error || 'Failed to load dissemination status');
      }
    } catch (err) {
      if (isAdminSessionExpired()) { setStatusError(ADMIN_SESSION_EXPIRED_MESSAGE); return; }
      if (err instanceof RateLimitError) retryAt.current = err.retryAt;
      setStatusError(err instanceof RateLimitError ? err.message : 'Failed to load dissemination status');
    }
  }, [trackingId]);

  const generatePlan = useCallback(async () => {
    if (!trackingId) return;
    setPlanLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/plan`, { method: 'POST' });
      const data = await res.json();
      if (data.success) setPlan(data.plan);
      else setError(data.error || 'Failed to generate plan');
    } catch {
      setError('Failed to generate plan');
    } finally {
      setPlanLoading(false);
    }
  }, [trackingId]);

  useEffect(() => {
    if (!trackingId) return;
    let cancelled = false;
    setLoading(true);
    fetchStatus().finally(() => {
      if (!cancelled) setLoading(false);
    });

    const timer = setInterval(fetchStatus, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [trackingId, fetchStatus]);

  const approve = useCallback(
    async (entityIds: string[]) => {
      if (!trackingId || entityIds.length === 0) return false;
      setActionPending(true);
      setError(null);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/approve`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entityIds }),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Approval failed');
          return false;
        }
        setPlan(null);
        await fetchStatus();
        return true;
      } catch {
        setError('Approval failed');
        return false;
      } finally {
        setActionPending(false);
      }
    },
    [trackingId, fetchStatus],
  );

  const withdraw = useCallback(
    async (entityId: string) => {
      if (!trackingId) return false;
      setActionPending(true);
      setError(null);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/withdraw`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entityId }),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Withdraw failed');
          return false;
        }
        await fetchStatus();
        return true;
      } catch {
        setError('Withdraw failed');
        return false;
      } finally {
        setActionPending(false);
      }
    },
    [trackingId, fetchStatus],
  );

  const recordReceipt = useCallback(
    async (entityId: string, value: string, kind: 'receipt' | 'ack' | 'feedback', note?: string) => {
      if (!trackingId) return false;
      setActionPending(true);
      setError(null);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/receipts`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entityId, value, kind, note }),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Failed to record receipt');
          return false;
        }
        await fetchStatus();
        return true;
      } catch {
        setError('Failed to record receipt');
        return false;
      } finally {
        setActionPending(false);
      }
    },
    [trackingId, fetchStatus],
  );

  const releaseEscrow = useCallback(
    async (entityId: string): Promise<{ url: string } | false> => {
      if (!trackingId) return false;
      setActionPending(true);
      setError(null);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/escrow-release`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entityId }),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Escrow release failed');
          return false;
        }
        await fetchStatus();
        return { url: data.url };
      } catch {
        setError('Escrow release failed');
        return false;
      } finally {
        setActionPending(false);
      }
    },
    [trackingId, fetchStatus],
  );

  const generateSecurePacket = useCallback(async (): Promise<{ url: string } | false> => {
    if (!trackingId) return false;
    setActionPending(true);
    setError(null);
    try {
      const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/secure-packet-generate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      });
      const data = await res.json();
      if (!res.ok || !data.success || typeof data.url !== 'string') {
        reportSecurePacketError(data.error);
        return false;
      }
      return { url: data.url };
    } catch {
      reportSecurePacketError('Secure packet generation failed');
      return false;
    } finally {
      setActionPending(false);
    }
  }, [trackingId, reportSecurePacketError]);

  const emailSecurePacket = useCallback(
    async (recipientEmail: string): Promise<{ url: string; sentTo: string; mode: string } | false> => {
      if (!trackingId) return false;
      setActionPending(true);
      setError(null);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/secure-packet-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ recipientEmail }),
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          reportSecurePacketError(data.error);
          return false;
        }
        return { url: data.url, sentTo: data.sentTo, mode: data.mode };
      } catch {
        reportSecurePacketError('Secure packet email failed');
        return false;
      } finally {
        setActionPending(false);
      }
    },
    [trackingId, reportSecurePacketError],
  );

  const proposeRedaction = useCallback(async (): Promise<
    { original: string; redacted: string; notes: string[]; clean: boolean } | false
  > => {
    if (!trackingId) return false;
    setActionPending(true);
    setError(null);
    try {
      const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/redact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'propose' }),
      });
      const data = await res.json();
      if (!data.success) {
        setError(data.error || 'Redaction proposal failed');
        return false;
      }
      return { original: data.original, ...data.proposal };
    } catch {
      setError('Redaction proposal failed');
      return false;
    } finally {
      setActionPending(false);
    }
  }, [trackingId]);

  const acceptRedaction = useCallback(
    async (narrative: string, notes: string[]) => {
      if (!trackingId) return false;
      setActionPending(true);
      setError(null);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/redact`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'accept', narrative, notes }),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Failed to save redacted narrative');
          return false;
        }
        await fetchStatus();
        return true;
      } catch {
        setError('Failed to save redacted narrative');
        return false;
      } finally {
        setActionPending(false);
      }
    },
    [trackingId, fetchStatus],
  );

  const clearRedaction = useCallback(async () => {
    if (!trackingId) return false;
    setActionPending(true);
    setError(null);
    try {
      const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/redact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'clear' }),
      });
      const data = await res.json();
      if (!data.success) {
        setError(data.error || 'Failed to clear redaction');
        return false;
      }
      await fetchStatus();
      return true;
    } catch {
      setError('Failed to clear redaction');
      return false;
    } finally {
      setActionPending(false);
    }
  }, [trackingId, fetchStatus]);

  const markNarrativeClean = useCallback(async () => {
    if (!trackingId) return false;
    setActionPending(true);
    setError(null);
    try {
      const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/redact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'mark-clean' }),
      });
      const data = await res.json();
      if (!data.success) {
        setError(data.error || 'Failed to mark narrative reviewed');
        return false;
      }
      await fetchStatus();
      return true;
    } catch {
      setError('Failed to mark narrative reviewed');
      return false;
    } finally {
      setActionPending(false);
    }
  }, [trackingId, fetchStatus]);

  return {
    status,
    plan,
    loading,
    planLoading,
    actionPending,
    error: error ?? statusError,
    refresh: fetchStatus,
    generatePlan,
    approve,
    withdraw,
    recordReceipt,
    releaseEscrow,
    emailSecurePacket,
    generateSecurePacket,
    proposeRedaction,
    acceptRedaction,
    clearRedaction,
    markNarrativeClean,
  };
}

/**
 * Alerts rail (NFR-3 + PDR §8): dead-lettered submissions and SLA-breached
 * channels across all reports, with one-click retry for dead letters.
 */
export function useDisseminationAlerts(enabled = true) {
  const [alerts, setAlerts] = useState<DisseminationAlert[]>([]);
  const [loading, setLoading] = useState(false);
  const [retrying, setRetrying] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const retryAt = useRef(0);
  const fetchAlerts = useCallback(async () => {
    if (isAdminSessionExpired()) { setError(ADMIN_SESSION_EXPIRED_MESSAGE); return; }
    if (Date.now() < retryAt.current) return;
    try {
      const res = await fetch('/api/dissemination/alerts');
      await noteAdminResponse(res);
      if (isAdminSessionExpired()) throw new Error(ADMIN_SESSION_EXPIRED_MESSAGE);
      await throwIfRateLimited(res);
      const data = await res.json();
      if (data.success) {
        setAlerts(data.alerts ?? []);
        setError(null);
      } else {
        setError(data.error || 'Failed to load alerts');
      }
    } catch (err) {
      if (isAdminSessionExpired()) { setError(ADMIN_SESSION_EXPIRED_MESSAGE); return; }
      if (err instanceof RateLimitError) retryAt.current = err.retryAt;
      setError(err instanceof RateLimitError ? err.message : 'Failed to load alerts');
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    setLoading(true);
    fetchAlerts().finally(() => setLoading(false));
    const timer = setInterval(fetchAlerts, POLL_INTERVAL_MS * 2);
    return () => clearInterval(timer);
  }, [enabled, fetchAlerts]);

  const retry = useCallback(
    async (trackingId: string, entityId: string) => {
      setRetrying(`${trackingId}:${entityId}`);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/retry`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entityId }),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Retry failed');
          return false;
        }
        await fetchAlerts();
        return true;
      } catch {
        setError('Retry failed');
        return false;
      } finally {
        setRetrying(null);
      }
    },
    [fetchAlerts],
  );

  return { alerts, loading, retrying, error, refresh: fetchAlerts, retry };
}

/**
 * Routing-rules editor (FR-2, PDR §6): list all rules and upsert without
 * redeploy. Settings-view scoped; no polling (rules change rarely).
 */
export function useRoutingRules(enabled = true) {
  const [rules, setRules] = useState<RoutingRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchRules = useCallback(async () => {
    try {
      const res = await fetch('/api/dissemination/rules');
      const data = await res.json();
      if (data.success) {
        setRules(data.rules ?? []);
        setError(null);
      } else {
        setError(data.error || 'Failed to load routing rules');
      }
    } catch {
      setError('Failed to load routing rules');
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    setLoading(true);
    fetchRules().finally(() => setLoading(false));
  }, [enabled, fetchRules]);

  const saveRule = useCallback(
    async (rule: {
      ruleId: string;
      match: RoutingRule['match'];
      route: { entityId: string }[];
      active: boolean;
    }) => {
      setSaving(true);
      setError(null);
      try {
        const res = await fetch('/api/dissemination/rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(rule),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Failed to save routing rule');
          return false;
        }
        await fetchRules();
        return true;
      } catch {
        setError('Failed to save routing rule');
        return false;
      } finally {
        setSaving(false);
      }
    },
    [fetchRules],
  );

  return { rules, loading, saving, error, refresh: fetchRules, saveRule };
}

export interface RelayThreadMessage {
  messageId: string;
  entityId?: string;
  entityName?: string;
  direction: 'to-reporter' | 'from-reporter';
  body: string;
  createdAt: string;
}

/**
 * Relay thread (Phase 3c): the two-way anonymous follow-up conversation
 * for a report, plus posting agency/counsel questions to the reporter.
 */
export function useRelay(trackingId: string | undefined) {
  const [thread, setThread] = useState<RelayThreadMessage[]>([]);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const retryAt = useRef(0);
  const fetchThread = useCallback(async () => {
    if (isAdminSessionExpired()) { setError(ADMIN_SESSION_EXPIRED_MESSAGE); return; }
    if (Date.now() < retryAt.current) return;
    if (!trackingId) return;
    try {
      const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/relay`);
      await noteAdminResponse(res);
      if (isAdminSessionExpired()) throw new Error(ADMIN_SESSION_EXPIRED_MESSAGE);
      await throwIfRateLimited(res);
      const data = await res.json();
      if (data.success) {
        setThread(data.thread ?? []);
        setError(null);
      }
    } catch (err) {
      if (isAdminSessionExpired()) { setError(ADMIN_SESSION_EXPIRED_MESSAGE); return; }
      if (err instanceof RateLimitError) retryAt.current = err.retryAt;
      setError(err instanceof RateLimitError ? err.message : 'Failed to load relay thread');
    }
  }, [trackingId]);

  useEffect(() => {
    if (!trackingId) return;
    fetchThread();
    const timer = setInterval(fetchThread, POLL_INTERVAL_MS * 2);
    return () => clearInterval(timer);
  }, [trackingId, fetchThread]);

  const send = useCallback(
    async (body: string, entityId?: string) => {
      if (!trackingId || !body.trim()) return false;
      setSending(true);
      setError(null);
      try {
        const res = await fetch(`/api/dissemination/${encodeURIComponent(trackingId)}/relay`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ body, ...(entityId ? { entityId } : {}) }),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Failed to send message');
          return false;
        }
        await fetchThread();
        return true;
      } catch {
        setError('Failed to send message');
        return false;
      } finally {
        setSending(false);
      }
    },
    [trackingId, fetchThread],
  );

  return { thread, sending, error, refresh: fetchThread, send };
}

export interface CounselPartner {
  counselId: string;
  name: string;
  channels: string[];
  contactHandle: string;
  engagementModel: 'psst-legal' | 'panel' | 'reporter-own';
  active: boolean;
}

export function useCounselPartners(enabled = true) {
  const [partners, setPartners] = useState<CounselPartner[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPartners = useCallback(async () => {
    try {
      const res = await fetch('/api/dissemination/counsel');
      const data = await res.json();
      if (data.success) {
        setPartners(data.partners ?? []);
        setError(null);
      } else {
        setError(data.error || 'Failed to load counsel partners');
      }
    } catch {
      setError('Failed to load counsel partners');
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;
    setLoading(true);
    fetchPartners().finally(() => setLoading(false));
  }, [enabled, fetchPartners]);

  const savePartner = useCallback(
    async (partner: Partial<CounselPartner> & { name: string; contactHandle: string }) => {
      setSaving(true);
      setError(null);
      try {
        const res = await fetch('/api/dissemination/counsel', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(partner),
        });
        const data = await res.json();
        if (!data.success) {
          setError(data.error || 'Failed to save counsel partner');
          return false;
        }
        await fetchPartners();
        return true;
      } catch {
        setError('Failed to save counsel partner');
        return false;
      } finally {
        setSaving(false);
      }
    },
    [fetchPartners],
  );

  return { partners, loading, saving, error, refresh: fetchPartners, savePartner };
}
