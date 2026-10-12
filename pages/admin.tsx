import { formatBrowserDateTime } from "@/lib/formatBrowserDateTime";
import type { GetServerSideProps, InferGetServerSidePropsType } from "next";
import Head from "next/head";
import { VeraReportLogo } from "@/components/vera/VeraReportLogo";
import { useState, useCallback, useEffect, useMemo } from "react";
import { useDashboardReports, useDashboardStats, type DashboardReport } from "@/hooks/useDashboardData";
import {
  Search,
  MoreVertical,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileText,
  Eye,
  LogOut,
  ChevronDown,
  ChevronRight,
  Settings,
  Sparkles,
  RefreshCw,
  List,
  LayoutGrid,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { motion, AnimatePresence } from "motion/react";
import { ReportDetail, type ReportData } from "@/components/vera/admin/ReportDetail";
import { PatternsView } from "@/components/vera/admin/PatternsView";
import { SettingsView } from "@/components/vera/admin/SettingsView";
import { DisseminationAlerts } from "@/components/vera/admin/DisseminationAlerts";
import { KanbanBoard } from "@/components/vera/admin/KanbanBoard";
import { ConfidentialListingsView } from "@/components/vera/admin/ConfidentialListingsView";
import { LegalOrganizationsView } from "@/components/vera/admin/LegalOrganizationsView";
import { confidentialCasesEnabled } from "@/lib/confidential/config";
import Link from "next/link";

/* ── Theme helper ── */
const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

const statusConfig: Record<string, { label: string; className: string; icon: typeof Clock }> = {
  pending: { label: "Pending", className: "bg-amber-500/10 text-amber-400 border-amber-500/20", icon: Clock },
  investigating: { label: "Investigating", className: "bg-purple-500/10 text-purple-400 border-purple-500/20", icon: Search },
  reviewing: { label: "Reviewing", className: "bg-blue-500/10 text-blue-400 border-blue-500/20", icon: Eye },
  resolved: { label: "Resolved", className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: CheckCircle2 },
  dismissed: { label: "Dismissed", className: "bg-red-500/10 text-red-400 border-red-500/20", icon: XCircle },
};

const categoryColors: Record<string, string> = {
  Fraud: "bg-amber-400",
  Safety: "bg-emerald-400",
  Policy: "bg-purple-400",
  Ethics: "bg-blue-400",
  Other: "bg-zinc-400",
};

type AdminTab = "dashboard" | "reports" | "confidential" | "legal" | "patterns" | "settings";
type ReportsView = "board" | "list";

export default function Admin({ isAdmin }: InferGetServerSidePropsType<typeof getServerSideProps>) {
  const [activeTab, setActiveTab] = useState<AdminTab>("dashboard");
  // The legal invitation page links back here with #legal-organizations.
  useEffect(() => {
    if (isAdmin && confidentialCasesEnabled() && window.location.hash === "#legal-organizations") setActiveTab("legal");
  }, [isAdmin]);
  const [reportsView, setReportsView] = useState<ReportsView>("board");
  const [searchTerm, setSearchTerm] = useState("");
  const [serverSearch, setServerSearch] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setServerSearch(isAdmin ? searchTerm.trim() : ""), 350);
    return () => clearTimeout(timer);
  }, [searchTerm, isAdmin]);
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedReport, setSelectedReport] = useState<ReportData | null>(null);

  /* ── Dark mode ── */
  const [isDark] = useState(false); // Light mode primary; theme toggle hidden for now

  // Fetch real data from the Express backend (Mongo)
  const { reports: elizaReports, loading: reportsLoading, error: reportsError, hasLoaded: reportsLoaded, refetch: refreshReports, updateReportStatus, hasMore: searchHasMore } = useDashboardReports(100, serverSearch);
  const { stats: elizaStats, loading: statsLoading, error: statsError, refetch: refreshStats } = useDashboardStats();
  const refreshData = () => { void refreshReports(); void refreshStats(); };
  const dataError = reportsError || (activeTab === 'dashboard' ? statsError : null);
  const dataUnavailable = !reportsLoaded || (activeTab === 'dashboard' && !elizaStats);

  // Convert DashboardReport to ReportData format
  const reports = useMemo<ReportData[]>(() => {
    return elizaReports.map((r): ReportData => ({
      id: r.reportId,
      trackingId: r.trackingId,
      title: r.category || "Untitled Report",
      category: r.category,
      status: r.status,
      priority: r.priority === 'critical' ? 'high' : r.priority as 'high' | 'low' | 'medium',
      date: formatBrowserDateTime(r.submittedAt),
      description: r.description,
      aiAnalysis: r.aiClassification ? {
        authenticity: r.aiClassification.authenticity,
        flags: r.aiClassification.flags,
        version: r.aiClassification.model,
        analyzedAt: formatBrowserDateTime(r.aiClassification.analyzedAt),
      } : undefined,
      evidence: r.evidence?.map(e => ({
        name: e.name,
        size: e.size,
        type: e.type.toUpperCase(),
        url: r.trackingId ? `/api/whistleblower/evidence/${r.trackingId}/${encodeURIComponent(e.name)}` : undefined,
      })),
      reward: r.reward,
      urgency: r.urgency,
      location: r.location,
      dateOfIncident: r.dateOfIncident,
      timeline: r.activity?.map(a => ({
        event: a.description,
        time: formatBrowserDateTime(a.timestamp),
        type: (a.type === 'status' || a.type === 'submit' || a.type === 'note' || a.type === 'ai') ? a.type : 'note' as 'status' | 'submit' | 'note' | 'ai',
      })) || [],
    }));
  }, [elizaReports]);

  const filteredReports = reports.filter((report) => {
    if (isAdmin && serverSearch !== searchTerm.trim()) return false;
    const matchesSearch = isAdmin ||
      report.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      report.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus =
      statusFilter === "all" || report.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const stats = elizaStats ? {
    total: elizaStats.total,
    pending: elizaStats.pending,
    active: elizaStats.reviewing + elizaStats.investigating,
    critical: elizaStats.critical,
  } : {
    total: 0,
    pending: 0,
    active: 0,
    critical: 0,
  };

  // AI scoring is optional (deferred to v2; unconfigured in production). Only
  // summarise reports that actually have a score — never present 0% for "not scored".
  const scoredReports = reports.filter((r) => r.aiAnalysis?.authenticity != null);
  const scoredCount = elizaStats?.scoredCount ?? scoredReports.length;
  const avgAuthenticity = elizaStats?.averageAuthenticity ?? 0;
  // Bands must come from the same population as scoredCount and the average:
  // the server's stats cover every report, the loaded list only the first page.
  const scoreBands = elizaStats?.scoreBands ?? {
    high: scoredReports.filter((r) => r.aiAnalysis!.authenticity > 70).length,
    medium: scoredReports.filter((r) => { const a = r.aiAnalysis!.authenticity; return a > 40 && a <= 70; }).length,
    flagged: scoredReports.filter((r) => r.aiAnalysis!.authenticity <= 40).length,
  };
  const recentReports = reports.slice(0, 3);

  const categoryData = useMemo(() => {
    const byCategory = elizaStats?.byCategory || {};
    const total = elizaStats?.total || 1;
    return Object.entries(byCategory).map(([name, count]) => ({
      name,
      count,
      total,
      color: categoryColors[name] || categoryColors.Other,
      barColor: categoryColors[name] || categoryColors.Other,
    }));
  }, [elizaStats]);

  // Calculate percentage change from last period
  const trendChangePercent = useMemo(() => {
    if (!elizaStats?.recentTrend || elizaStats.recentTrend.length < 2) return null;

    const trend = elizaStats.recentTrend;

    // Compare the last two periods in the trend data
    const currentPeriod = trend[trend.length - 1].count;
    const previousPeriod = trend[trend.length - 2].count;

    if (previousPeriod === 0) return null;

    const change = ((currentPeriod - previousPeriod) / previousPeriod) * 100;
    return change;
  }, [elizaStats]);

  // Transform recentTrend data for the chart
  const chartData = useMemo(() => {
    if (!elizaStats?.recentTrend || elizaStats.recentTrend.length === 0) {
      // Fallback: generate minimal chart data from current stats if no trend data
      if (elizaStats?.total) {
        return [{
          month: new Date().toLocaleDateString('en-US', { month: 'short' }),
          reports: elizaStats.total,
          resolved: elizaStats.resolved,
        }];
      }
      return [];
    }

    // Get up to last 7 data points from recentTrend
    const trendData = elizaStats.recentTrend.slice(-7);

    return trendData.map((item) => {
      const date = new Date(item.date);
      const month = date.toLocaleDateString('en-US', { month: 'short' });

      // For resolved count, estimate based on resolved ratio
      // (This is an approximation until we have actual resolution dates in the data)
      const resolvedRatio = elizaStats.total > 0 ? elizaStats.resolved / elizaStats.total : 0;
      const estimatedResolved = Math.round(item.count * resolvedRatio * 0.8); // 80% of submissions

      return {
        month,
        reports: item.count,
        resolved: estimatedResolved,
      };
    });
  }, [elizaStats]);

  const handleViewReport = (report: ReportData) => {
    setSelectedReport(report);
  };

  const handleUpdateStatus = useCallback(
    async (reportId: string, newStatus: ReportData["status"]) => {
      return updateReportStatus(reportId, newStatus);
    },
    [updateReportStatus]
  );

  const headerTabs: { id: AdminTab; label: string }[] = [
    { id: "dashboard", label: "Dashboard" },
    { id: "reports", label: "Reports" },
    // Confidential cases: case reference + owner-published summary fields only, admins only.
    ...(isAdmin && confidentialCasesEnabled() ? [{ id: "confidential" as const, label: "Encrypted" }] : []),
    // Legal organization onboarding roster (no case data), admins only.
    ...(isAdmin && confidentialCasesEnabled() ? [{ id: "legal" as const, label: "Legal organizations" }] : []),
    { id: "patterns", label: "Insights" },
    { id: "settings", label: "Settings" },
  ];

  return (
    <>
      <Head>
        <title>Vera Admin - Dashboard</title>
        <meta name="description" content="Vera Admin Dashboard - Manage whistleblower reports" />
      </Head>

      <a
        href="#main-content"
        className="absolute left-[-9999px] focus:left-4 focus:top-4 focus:z-[100] focus:px-4 focus:py-2 focus:bg-background focus:text-foreground focus:ring-2 focus:ring-[var(--ring)] focus:ring-offset-2 focus:rounded-md focus:overflow-visible focus:w-auto focus:h-auto focus:no-underline"
      >
        Skip to main content
      </a>

      <div className="min-h-screen" style={{ backgroundColor: "var(--vera-paper)" }}>
      {/* ── Header ── */}
      <header
        className="sticky top-0 z-50 backdrop-blur-xl transition-colors duration-500"
        style={{
          borderBottom: `1px solid ${ink(4)}`,
          backgroundColor: "var(--vera-header-bg)",
        }}
      >
        <div
          className="mx-auto max-w-7xl px-7 flex items-center justify-between"
          style={{ paddingTop: "0.85rem", paddingBottom: "0.85rem" }}
        >
          {/* Left: Logo + Tabs */}
          <div className="flex items-center gap-6">
            <Link href="/" className="flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:rounded" style={{ textDecoration: "none" }}>
              <div style={{ width: 90, height: 34, overflow: "hidden" }}>
                <VeraReportLogo style={{ width: "100%", height: "100%", maxWidth: 90, maxHeight: 34, display: "block", color: ink(90) }} aria-hidden />
              </div>
              <span style={{ fontSize: "11px", letterSpacing: "0.08em", color: ink(55), textTransform: "uppercase" }}>Admin</span>
            </Link>
            <div className="hidden md:flex items-center">
              <div className="w-px h-4 mr-5" style={{ backgroundColor: ink(6) }} />
              <div className="flex items-center gap-1">
                {headerTabs.map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(tab.id);
                      setSelectedReport(null);
                    }}
                    className="px-3 py-1.5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:rounded"
                    style={{
                      fontSize: "12px",
                      letterSpacing: "0.05em",
                      backgroundColor: activeTab === tab.id ? ink(6) : "transparent",
                      color: activeTab === tab.id ? ink(80) : ink(55),
                    }}
                    onMouseEnter={(e) => { if (activeTab !== tab.id) e.currentTarget.style.color = ink(70); }}
                    onMouseLeave={(e) => { if (activeTab !== tab.id) e.currentTarget.style.color = ink(55); }}
                    aria-current={activeTab === tab.id ? "page" : undefined}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-3">
            {/* Theme toggle hidden for now — light mode primary */}
            <Button
              variant="ghost"
              size="sm"
              className="hover:!bg-transparent gap-1.5 rounded-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2"
              style={{ fontSize: "11px", color: ink(55) }}
              onMouseEnter={(e) => { e.currentTarget.style.color = ink(70); }}
              onMouseLeave={(e) => { e.currentTarget.style.color = ink(55); }}
              aria-label="Refresh reports"
              onClick={refreshData}
              disabled={reportsLoading || statsLoading}
            >
              <RefreshCw className="size-3.5" aria-hidden />
              <span className="hidden md:inline">Refresh</span>
            </Button>
            <div className="w-px h-4" style={{ backgroundColor: ink(6) }} />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="flex items-center gap-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:rounded"
                  style={{ color: ink(55) }}
                  aria-label="Open account menu"
                >
                  <div
                    className="size-7 flex items-center justify-center"
                    style={{ fontSize: "11px", backgroundColor: ink(6) }}
                  >
                    <span style={{ color: ink(55) }}>A</span>
                  </div>
                  <ChevronDown className="size-3" style={{ color: ink(50) }} aria-hidden />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => { setActiveTab("settings"); setSelectedReport(null); }}>
                  <Settings className="size-3.5 mr-2" />
                  Settings
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => { window.location.href = '/auth/logout'; }}>
                  <LogOut className="size-3.5 mr-2" />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </header>

      {/* Mobile tab selector */}
      <div className="md:hidden transition-colors duration-500" style={{ borderBottom: `1px solid ${ink(4)}`, backgroundColor: "var(--vera-paper)" }}>
        <div className="flex items-center gap-1 px-4 py-2 overflow-x-auto">
          {headerTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id);
                setSelectedReport(null);
              }}
              className="px-4 py-1.5 transition-colors whitespace-nowrap"
              style={{
                fontSize: "12px",
                backgroundColor: activeTab === tab.id ? ink(8) : "transparent",
                color: activeTab === tab.id ? ink(80) : ink(45),
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Main Content ── */}
      <main id="main-content" className="mx-auto max-w-7xl px-6 py-8 scroll-mt-4" tabIndex={-1}>
        {(activeTab === 'dashboard' || activeTab === 'reports') && dataError && (
          <div role="alert" aria-label="Data loading error" className="mb-6 border border-red-300 bg-red-50 p-5 text-red-900">
            <p className="font-medium">Unable to load {activeTab === 'dashboard' ? 'dashboard data' : 'reports'}</p>
            <p className="mt-1 text-sm">{dataError.message}</p>
            <Button variant="outline" className="mt-3" onClick={refreshData} disabled={reportsLoading || statsLoading}>
              {reportsLoading || statsLoading ? 'Retrying…' : 'Retry loading data'}
            </Button>
          </div>
        )}
        {(activeTab === 'dashboard' || activeTab === 'reports') && !dataError && dataUnavailable && (
          <p role="status" className="py-8 text-sm">Loading {activeTab === 'dashboard' ? 'dashboard data' : 'reports'}…</p>
        )}
        <AnimatePresence mode="wait">
          {selectedReport ? (
            <div style={{ maxWidth: "var(--vera-doc-max-w)" }}>
              <ReportDetail
                key="detail"
                report={reports.find(report => report.id === selectedReport.id) ?? selectedReport}
                onBack={() => setSelectedReport(null)}
                onUpdateStatus={handleUpdateStatus}
                isAdmin={isAdmin}
              />
            </div>
          ) : (
            <>
              {/* ═══════ Dashboard ═══════ */}
              {activeTab === "dashboard" && !dataError && !dataUnavailable && (
                <motion.div
                  key="dashboard"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.4 }}
                  className="space-y-6 pb-8"
                >
                  {/* Page title */}
                  <div>
                    <h2 className="mb-1" style={{ fontSize: "1.1rem", fontWeight: 500, color: ink(80) }}>
                      Dashboard
                    </h2>
                    <p style={{ fontSize: "13px", color: ink(45) }}>
                      Overview of reports and activity
                    </p>
                  </div>
                  {/* Stats Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-px overflow-hidden" style={{ backgroundColor: ink(4) }}>
                    {[
                      {
                        label: "Total Reports",
                        value: stats.total,
                        sub: trendChangePercent !== null
                          ? `${trendChangePercent >= 0 ? '+' : ''}${trendChangePercent.toFixed(0)}% from previous period`
                          : "No trend data",
                        subColor: trendChangePercent !== null && trendChangePercent >= 0 ? "text-emerald-400" : "text-red-400",
                        icon: FileText,
                        iconColor: ink(40)
                      },
                      { label: "Pending", value: stats.pending, sub: "Requires attention", subColor: "text-amber-400", icon: Clock, iconColor: "rgba(245,158,11,0.25)" },
                      { label: "Active", value: stats.active, sub: "Being processed", subColor: "text-blue-400", icon: Eye, iconColor: "rgba(96,165,250,0.25)" },
                      { label: "Resolved", value: reports.filter((r) => r.status === "resolved").length, sub: "Successfully closed", subColor: "text-emerald-400", icon: CheckCircle2, iconColor: "rgba(52,211,153,0.25)" },
                    ].map((stat) => (
                      <div key={stat.label} className="p-6 flex flex-col justify-between transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)" }}>
                        <div className="flex items-center justify-between mb-4">
                          <span className="uppercase" style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(45) }}>
                            {stat.label}
                          </span>
                          <stat.icon className="size-4" style={{ color: stat.iconColor }} />
                        </div>
                        <div>
                          <span className="tabular-nums" style={{ fontSize: "2rem", fontWeight: 300, color: ink(85) }} suppressHydrationWarning>
                            {stat.value}
                          </span>
                          <p className={`mt-1 ${stat.subColor}`} style={{ fontSize: "11px" }}>
                            {stat.sub}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Recent Reports */}
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(60) }}>Recent Reports</h3>
                      <button
                        onClick={() => setActiveTab("reports")}
                        className="flex items-center gap-1 transition-colors"
                        style={{ fontSize: "12px", color: ink(45) }}
                        onMouseEnter={(e) => { e.currentTarget.style.color = ink(60); }}
                        onMouseLeave={(e) => { e.currentTarget.style.color = ink(45); }}
                      >
                        View All
                        <ChevronRight className="size-3.5" />
                      </button>
                    </div>
                    <div className="space-y-2">
                      {recentReports.map((report) => {
                        const stCfg = statusConfig[report.status];
                        return (
                          <button
                            key={report.id}
                            onClick={() => handleViewReport(report)}
                            className="w-full text-left flex items-center gap-4 p-4 transition-colors group"
                            style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}
                            onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = ink(2); }}
                            onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "var(--vera-card-bg)"; }}
                          >
                            <div
                              className="size-10 flex items-center justify-center shrink-0"
                              style={{ backgroundColor: ink(6), border: `1px solid ${ink(8)}` }}
                            >
                              <FileText className="size-4" style={{ color: ink(45) }} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-0.5">
                                <span className="truncate" style={{ fontSize: "13px", fontWeight: 500, color: ink(65) }}>{report.title}</span>
                                <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 shrink-0" style={{ fontSize: "10px" }}>
                                  {report.priority.charAt(0).toUpperCase() + report.priority.slice(1)}
                                </Badge>
                              </div>
                              <p className="truncate" style={{ fontSize: "12px", color: ink(45) }}>{report.description}</p>
                              <div className="flex items-center gap-2 mt-1">
                                {stCfg && (
                                  <Badge variant="outline" className={stCfg.className} style={{ fontSize: "10px" }}>
                                    {stCfg.label}
                                  </Badge>
                                )}
                                <span style={{ fontSize: "11px", color: ink(45) }}>{report.date}</span>
                              </div>
                            </div>
                            <ChevronRight className="size-4 shrink-0" style={{ color: ink(40) }} />
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Dissemination alerts rail (dead letters + SLA breaches) */}
                  {isAdmin && <DisseminationAlerts />}

                  {/* Chart + High Priority */}
                  <div className="grid md:grid-cols-5 gap-6">
                    {/* Report Trend Chart */}
                    <div className="md:col-span-3 p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
                      <div className="flex items-center justify-between mb-6">
                        <div>
                          <h3 className="mb-1" style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
                            Report Trend
                          </h3>
                          <p style={{ fontSize: "12px", color: ink(45) }}>
                            Submissions vs. resolutions — recent activity
                          </p>
                        </div>
                        <div className="flex items-center gap-4">
                          <div className="flex items-center gap-1.5">
                            <div className="w-3 h-px" style={{ backgroundColor: ink(50) }} />
                            <span style={{ fontSize: "11px", color: ink(45) }}>Submitted</span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <div className="w-3 h-px bg-emerald-400/60" />
                            <span style={{ fontSize: "11px", color: ink(45) }}>Resolved</span>
                          </div>
                        </div>
                      </div>
                      <ResponsiveContainer width="100%" height={260}>
                        <AreaChart data={chartData}>
                          <defs>
                            <linearGradient id="reportGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="0%" stopColor="var(--vera-chart-fill-start)" stopOpacity={1} />
                              <stop offset="100%" stopColor="var(--vera-chart-fill-end)" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="resolvedGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="0%" stopColor="rgba(52,211,153,0.08)" stopOpacity={1} />
                              <stop offset="100%" stopColor="rgba(52,211,153,0)" stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="var(--vera-chart-grid)" vertical={false} />
                          <XAxis dataKey="month" stroke="var(--vera-chart-axis)" fontSize={11} tickLine={false} axisLine={false} />
                          <YAxis stroke="var(--vera-chart-axis)" fontSize={11} tickLine={false} axisLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: "var(--vera-tooltip-bg)", border: `1px solid var(--vera-tooltip-border)`, borderRadius: "0", color: "var(--vera-tooltip-text)", fontSize: "12px" }} />
                          <Area type="monotone" dataKey="reports" stroke="var(--vera-chart-line)" strokeWidth={1.5} fill="url(#reportGradient)" />
                          <Area type="monotone" dataKey="resolved" stroke="rgba(52,211,153,0.5)" strokeWidth={1.5} fill="url(#resolvedGradient)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>

                    {/* High Priority */}
                    <div className="md:col-span-2 p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
                      <div className="flex items-center justify-between mb-6">
                        <div>
                          <h3 className="mb-1" style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
                            High Priority
                          </h3>
                          <p style={{ fontSize: "12px", color: ink(45) }}>
                            Requires immediate attention
                          </p>
                        </div>
                        <AlertTriangle className="size-4 text-red-400/40" />
                      </div>
                      <div className="space-y-2">
                        {reports
                          .filter((r) => r.priority === "high" && r.status !== "resolved" && r.status !== "dismissed")
                          .map((report) => {
                            const stCfg = statusConfig[report.status];
                            return (
                              <button
                                key={report.id}
                                onClick={() => handleViewReport(report)}
                                className="w-full text-left p-3 transition-colors group"
                                style={{ border: `1px solid ${ink(4)}`, backgroundColor: ink(1.5) }}
                                onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = ink(3); }}
                                onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = ink(1.5); }}
                              >
                                <div className="flex items-center justify-between mb-1.5">
                                  <span className="font-mono" style={{ fontSize: "11px", color: ink(35) }}>{report.id}</span>
                                  {stCfg && (
                                    <Badge variant="outline" className={stCfg.className} style={{ fontSize: "10px" }}>
                                      {stCfg.label}
                                    </Badge>
                                  )}
                                </div>
                                <p className="truncate" style={{ fontSize: "13px", color: ink(60) }}>{report.title}</p>
                                <p className="mt-1" style={{ fontSize: "11px", color: ink(45) }}>{report.date}</p>
                              </button>
                            );
                          })}
                        {reports.filter((r) => r.priority === "high" && r.status !== "resolved" && r.status !== "dismissed").length === 0 && (
                          <p className="text-center py-6" style={{ fontSize: "12px", color: ink(45) }}>No high-priority reports</p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* AI Performance + Category Distribution */}
                  <div className="grid md:grid-cols-5 gap-6">
                    {/* AI Performance */}
                    <div className="md:col-span-2 p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
                      <div className="flex items-center gap-2 mb-5">
                        <Sparkles className="size-4" style={{ color: ink(45) }} />
                        <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>AI Narrative Analysis</h3>
                      </div>
                      {scoredCount === 0 ? (
                        <p style={{ fontSize: "12px", lineHeight: 1.55, color: ink(45) }}>
                          No reports have a model score. Reports are reviewed without one.
                        </p>
                      ) : (
                      <>
                        {/* Avg Authenticity */}
                        <div className="mb-5">
                          <div className="flex items-center justify-between mb-2">
                            <span style={{ fontSize: "11px", color: ink(45) }}>Avg model score</span>
                            <span
                              className={`tabular-nums ${
                                avgAuthenticity > 70 ? "text-emerald-400" :
                                avgAuthenticity > 40 ? "text-amber-400" : "text-red-400"
                              }`}
                              style={{ fontSize: "13px", fontWeight: 500 }}
                            >
                              {avgAuthenticity}%
                            </span>
                          </div>
                          <div className="h-1.5 w-full" style={{ backgroundColor: ink(6) }}>
                            <div
                              className={`h-full transition-all ${
                                avgAuthenticity > 70 ? "bg-emerald-500" :
                                avgAuthenticity > 40 ? "bg-amber-500" : "bg-red-500"
                              }`}
                              style={{ width: `${avgAuthenticity}%` }}
                            />
                          </div>
                        </div>
                        {/* High / Medium / Flagged */}
                        <div className="grid grid-cols-3 gap-px" style={{ backgroundColor: ink(4) }}>
                          {[
                            { label: "High", count: scoreBands.high, color: "text-emerald-400" },
                            { label: "Medium", count: scoreBands.medium, color: "text-amber-400" },
                            { label: "Flagged", count: scoreBands.flagged, color: "text-red-400" },
                          ].map((item) => (
                            <div key={item.label} className="p-4 text-center transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)" }}>
                              <span className={`tabular-nums ${item.color}`} style={{ fontSize: "1.3rem", fontWeight: 400 }}>
                                {item.count}
                              </span>
                              <p className="mt-0.5" style={{ fontSize: "11px", color: ink(45) }}>{item.label}</p>
                            </div>
                          ))}
                        </div>
                        <p className="mt-4" style={{ fontSize: "11px", lineHeight: 1.55, color: ink(45) }}>
                          Average over {scoredCount} scored {scoredCount === 1 ? "report" : "reports"}; unscored reports are excluded. Narrative text only; attachments are not assessed.
                        </p>
                      </>
                      )}
                    </div>

                    {/* Category Distribution */}
                    <div className="md:col-span-3 p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
                      <h3 className="mb-4" style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>Reports by Category</h3>
                      <div className="grid grid-cols-2 gap-3">
                        {categoryData.map((cat) => (
                          <div key={cat.name} className="p-4" style={{ backgroundColor: ink(1.5), border: `1px solid ${ink(4)}` }}>
                            <div className="flex items-center gap-2 mb-2">
                              <div className={`size-1.5 rounded-full ${cat.color}`} />
                              <span style={{ fontSize: "11px", color: ink(35) }}>{cat.name}</span>
                            </div>
                            <span className="tabular-nums" style={{ fontSize: "1.5rem", fontWeight: 300, color: ink(75) }}>
                              {cat.count}
                            </span>
                            <div className="h-1 w-full mt-2" style={{ backgroundColor: ink(6) }}>
                              <div className={`h-full ${cat.barColor}`} style={{ width: `${(cat.count / cat.total) * 100}%` }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* ═══════ Reports ═══════ */}
              {activeTab === "reports" && !dataError && !dataUnavailable && (
                <motion.div
                  key="reports"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.4 }}
                  className="relative pb-8"
                >
                  {/* Atmospheric glow */}
                  <div className="absolute inset-0 pointer-events-none overflow-hidden">
                    <div className="absolute -top-32 left-1/3 w-[500px] h-[500px] rounded-full blur-[140px]" style={{ backgroundColor: ink(0.8) }} />
                  </div>

                  <div className="relative z-10 space-y-6">
                    {/* Page title — same pattern as Dashboard, Patterns, Settings */}
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <h2 className="mb-1" style={{ fontSize: "1.1rem", fontWeight: 500, color: ink(80) }}>
                          Reports
                        </h2>
                        <p style={{ fontSize: "13px", color: ink(45) }}>
                          All submissions under review
                        </p>
                      </div>
                      <span className="tabular-nums hidden md:block shrink-0" style={{ fontSize: "11px", color: ink(45) }}>
                        {reports.length} loaded &middot; {elizaStats && !statsError ? `${stats.pending} pending · ${stats.active} active` : 'Summary unavailable'}
                      </span>
                    </div>

                    {/* ── Toolbar ── */}
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.4, delay: 0.15 }}
                      className="flex flex-col md:flex-row gap-3 items-start md:items-center"
                    >
                      <div className="flex-1 relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4" style={{ color: ink(45) }} />
                        <Input
                          placeholder={isAdmin ? "Search all reports by VRA, full VRC code, or category..." : "Filter loaded reports by ID or category..."}
                          maxLength={128}
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-10 rounded-none"
                          style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}`, color: ink(70) }}
                        />
                      </div>

                      {isAdmin && searchTerm.trim() && (
                        <p role="status" className="text-sm">
                          {serverSearch !== searchTerm.trim() || reportsLoading ? "Searching…" :
                            reportsError ? "Search failed. Please retry." :
                            searchHasMore ? "Showing the first 100 matches. Refine your search." :
                            `${reports.length} matching reports`}
                        </p>
                      )}

                      <div className="flex items-center gap-2">
                        {/* View toggle */}
                        <div className="flex items-center gap-0" style={{ border: `1px solid ${ink(6)}` }}>
                          <button
                            onClick={() => setReportsView("board")}
                            className="p-2 transition-colors"
                            style={{
                              backgroundColor: reportsView === "board" ? ink(8) : "transparent",
                              color: reportsView === "board" ? ink(70) : ink(45),
                            }}
                          >
                            <LayoutGrid className="size-4" />
                          </button>
                          <button
                            onClick={() => setReportsView("list")}
                            className="p-2 transition-colors"
                            style={{
                              backgroundColor: reportsView === "list" ? ink(8) : "transparent",
                              color: reportsView === "list" ? ink(70) : ink(45),
                            }}
                          >
                            <List className="size-4" />
                          </button>
                        </div>

                        {reportsView === "list" && (
                          <Select value={statusFilter} onValueChange={setStatusFilter}>
                            <SelectTrigger className="w-36 rounded-none" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}`, color: ink(50) }}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Status</SelectItem>
                              <SelectItem value="pending">Pending</SelectItem>
                              <SelectItem value="investigating">Investigating</SelectItem>
                              <SelectItem value="reviewing">Reviewing</SelectItem>
                              <SelectItem value="resolved">Resolved</SelectItem>
                              <SelectItem value="dismissed">Dismissed</SelectItem>
                            </SelectContent>
                          </Select>
                        )}

                      </div>
                    </motion.div>

                    {/* ── Board or List ── */}
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ duration: 0.4, delay: 0.25 }}
                    >
                      {reportsView === "board" ? (
                        <KanbanBoard
                          reports={filteredReports}
                          onViewReport={handleViewReport}
                          onUpdateStatus={handleUpdateStatus}
                        />
                      ) : (
                        <>
                          <div className="overflow-hidden transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
                            <Table>
                              <TableHeader>
                                <TableRow className="hover:bg-transparent" style={{ borderColor: ink(4) }}>
                                  <TableHead style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(45) }}>ID</TableHead>
                                  <TableHead style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(45) }}>Title</TableHead>
                                  <TableHead className="hidden md:table-cell" style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(45) }}>Category</TableHead>
                                  <TableHead style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(45) }}>Status</TableHead>
                                  <TableHead className="hidden md:table-cell" style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(45) }}>Priority</TableHead>
                                  <TableHead className="hidden lg:table-cell" style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(45) }}>Date & time</TableHead>
                                  <TableHead className="text-right" style={{ fontSize: "10px", letterSpacing: "0.15em", textTransform: "uppercase", color: ink(45) }}>Actions</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {filteredReports.map((report, i) => {
                                  const stCfg = statusConfig[report.status];
                                  const priorityColor =
                                    report.priority === "high" ? "text-red-400" :
                                    report.priority === "medium" ? "text-amber-400" : undefined;
                                  return (
                                    <motion.tr
                                      key={report.id}
                                      initial={{ opacity: 0, y: 6 }}
                                      animate={{ opacity: 1, y: 0 }}
                                      transition={{ duration: 0.25, delay: 0.3 + i * 0.03 }}
                                      className="cursor-pointer transition-colors"
                                      style={{ borderBottom: `1px solid ${ink(4)}` }}
                                      onClick={() => handleViewReport(report)}
                                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = ink(1.5); }}
                                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
                                    >
                                      <TableCell className="font-mono" style={{ fontSize: "12px", color: ink(40) }}>{report.id}</TableCell>
                                      <TableCell className="max-w-[200px] truncate" style={{ fontSize: "13px", color: ink(60) }}>{report.title}</TableCell>
                                      <TableCell className="hidden md:table-cell">
                                        <span className="px-2 py-0.5" style={{ fontSize: "11px", color: ink(35), backgroundColor: ink(3) }}>{report.category}</span>
                                      </TableCell>
                                      <TableCell>
                                        {stCfg && (
                                          <Badge variant="outline" className={stCfg.className} style={{ fontSize: "11px" }}>{stCfg.label}</Badge>
                                        )}
                                      </TableCell>
                                      <TableCell className="hidden md:table-cell">
                                        <span className={priorityColor} style={{ fontSize: "11px", color: priorityColor ? undefined : ink(40) }}>
                                          {report.priority.charAt(0).toUpperCase() + report.priority.slice(1)}
                                        </span>
                                      </TableCell>
                                      <TableCell className="hidden lg:table-cell" style={{ fontSize: "12px", color: ink(45) }}>{report.date}</TableCell>
                                      <TableCell className="text-right">
                                        <DropdownMenu>
                                          <DropdownMenuTrigger asChild>
                                            <Button
                                              variant="ghost"
                                              size="icon"
                                              className="hover:!bg-transparent"
                                              style={{ color: ink(45) }}
                                              onClick={(e) => e.stopPropagation()}
                                            >
                                              <MoreVertical className="size-4" />
                                            </Button>
                                          </DropdownMenuTrigger>
                                          <DropdownMenuContent align="end">
                                            <DropdownMenuItem onClick={() => handleViewReport(report)}>
                                              <Eye className="size-3.5 mr-2" /> Open Dossier
                                            </DropdownMenuItem>
                                            <DropdownMenuItem onClick={() => handleUpdateStatus(report.id, "resolved")}>
                                              <CheckCircle2 className="size-3.5 mr-2" /> Mark Resolved
                                            </DropdownMenuItem>
                                            <DropdownMenuSeparator />
                                            <DropdownMenuItem className="text-red-400" onClick={() => handleUpdateStatus(report.id, "dismissed")}>
                                              <XCircle className="size-3.5 mr-2" /> Dismiss
                                            </DropdownMenuItem>
                                          </DropdownMenuContent>
                                        </DropdownMenu>
                                      </TableCell>
                                    </motion.tr>
                                  );
                                })}
                              </TableBody>
                            </Table>
                            {filteredReports.length === 0 && (
                              <div className="p-16 text-center">
                                <div className="w-6 h-px mx-auto mb-3" style={{ backgroundColor: ink(6) }} />
                                <p className="font-serif italic" style={{ fontSize: "13px", color: ink(45) }}>
                                  No dossiers match your query
                                </p>
                              </div>
                            )}
                          </div>

                          {/* List footer — Vera watermark */}
                          <div className="flex items-center justify-between pt-2">
                            <span style={{ fontSize: "11px", color: ink(45) }}>
                              Showing {filteredReports.length} of {reports.length} reports
                            </span>
                            <span
                              style={{ fontSize: "9px", letterSpacing: "0.2em", textTransform: "uppercase", color: ink(45) }}
                            >
                              Vera &middot; Confidential
                            </span>
                          </div>
                        </>
                      )}
                    </motion.div>
                  </div>
                </motion.div>
              )}

              {/* ═══════ Confidential (read-only listings) ═══════ */}
              {activeTab === "confidential" && isAdmin && <ConfidentialListingsView key="confidential" />}

              {/* ═══════ Legal organizations (onboarding roster, no case data) ═══════ */}
              {activeTab === "legal" && isAdmin && <LegalOrganizationsView key="legal" />}

              {/* ═══════ Patterns ═══════ */}
              {activeTab === "patterns" && <PatternsView key="patterns" />}

              {/* ═══════ Settings ═══════ */}
              {activeTab === "settings" && <SettingsView key="settings" isAdmin={isAdmin} />}
            </>
          )}
        </AnimatePresence>
      </main>
      </div>
    </>
  );
}

export const getServerSideProps: GetServerSideProps<{ isAdmin: boolean }> = async (ctx) => {
  // The legacy dashboard is retired for every role. Legal onboarding remains
  // available through its separately authorized /legal/organizations page.
  ctx.res.setHeader('Cache-Control', 'private, no-store');
  return { notFound: true };
};
