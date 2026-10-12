import {
  TrendingUp,
  TrendingDown,
  BarChart3,
  AlertTriangle,
  Calendar,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from "recharts";
import { motion } from "motion/react";
import { useDashboardStats, useDashboardReports } from "@/hooks/useDashboardData";
import { useMemo } from "react";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

const tooltipStyle = {
  backgroundColor: "var(--vera-tooltip-bg)",
  border: "1px solid var(--vera-tooltip-border)",
  borderRadius: "0",
  color: "var(--vera-tooltip-text)",
  fontSize: "12px",
};

export function PatternsView() {
  const { stats: elizaStats } = useDashboardStats();
  const { reports: elizaReports } = useDashboardReports();

  // Calculate weekly trend from recent data (last 8 weeks)
  const weeklyTrend = useMemo(() => {
    if (!elizaStats?.recentTrend) return [];

    return elizaStats.recentTrend.slice(-8).map((item) => {
      const date = new Date(item.date);
      const month = date.toLocaleString('en-US', { month: 'short' });
      const week = `W${Math.ceil(date.getDate() / 7)} ${month}`;
      return {
        week,
        reports: item.count,
      };
    });
  }, [elizaStats]);

  // Calculate time of day distribution from reports
  const timeOfDayData = useMemo(() => {
    const hourBuckets = Array(8).fill(0); // 8 buckets for 3-hour intervals

    elizaReports.forEach((report) => {
      const hour = new Date(report.submittedAt).getHours();
      const bucketIndex = Math.floor(hour / 3); // 0-2: 12am-3am, 3-5: 3am-6am, etc.
      if (bucketIndex >= 0 && bucketIndex < 8) {
        hourBuckets[bucketIndex]++;
      }
    });

    return [
      { hour: "12am", count: hourBuckets[0] },
      { hour: "3am", count: hourBuckets[1] },
      { hour: "6am", count: hourBuckets[2] },
      { hour: "9am", count: hourBuckets[3] },
      { hour: "12pm", count: hourBuckets[4] },
      { hour: "3pm", count: hourBuckets[5] },
      { hour: "6pm", count: hourBuckets[6] },
      { hour: "9pm", count: hourBuckets[7] },
    ];
  }, [elizaReports]);

  // Calculate category trend over last 5 months
  const categoryTrend = useMemo(() => {
    const now = new Date();
    const months = [];

    // Generate last 5 months
    for (let i = 4; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthName = date.toLocaleString('en-US', { month: 'short' });

      const monthData: any = { month: monthName, fraud: 0, safety: 0, policy: 0, ethics: 0, other: 0 };

      elizaReports.forEach((report) => {
        const reportDate = new Date(report.submittedAt);
        if (reportDate.getMonth() === date.getMonth() && reportDate.getFullYear() === date.getFullYear()) {
          const category = report.category.toLowerCase();
          if (category.includes('fraud') || category.includes('financial')) {
            monthData.fraud++;
          } else if (category.includes('safety')) {
            monthData.safety++;
          } else if (category.includes('policy')) {
            monthData.policy++;
          } else if (category.includes('ethics')) {
            monthData.ethics++;
          } else {
            monthData.other++;
          }
        }
      });

      months.push(monthData);
    }

    return months;
  }, [elizaReports]);

  // Detect patterns from real data
  const detectedPatterns = useMemo(() => {
    const patterns: Array<{ title: string; description: string; trend: 'up' | 'down'; severity: 'high' | 'medium' | 'low' }> = [];

    // Analyze fraud trend
    if (elizaStats?.byCategory) {
      const fraudCount = Object.entries(elizaStats.byCategory)
        .filter(([cat]) => cat.toLowerCase().includes('fraud') || cat.toLowerCase().includes('financial'))
        .reduce((sum, [, count]) => sum + count, 0);

      const totalReports = elizaStats.total || 1;
      const fraudPct = (fraudCount / totalReports) * 100;

      if (fraudPct > 40) {
        patterns.push({
          title: "Financial reports dominant",
          description: `${fraudPct.toFixed(0)}% of all reports are fraud-related, indicating potential financial irregularities.`,
          trend: "up",
          severity: "high",
        });
      }
    }

    // Analyze time of day pattern
    const eveningReports = timeOfDayData.slice(6).reduce((sum, d) => sum + d.count, 0); // 6pm-12am
    const totalTimeReports = timeOfDayData.reduce((sum, d) => sum + d.count, 0);
    const eveningPct = totalTimeReports > 0 ? (eveningReports / totalTimeReports) * 100 : 0;

    if (eveningPct > 40) {
      patterns.push({
        title: "After-hours submissions",
        description: `${eveningPct.toFixed(0)}% of reports are submitted between 6 PM and midnight, suggesting off-hours activity.`,
        trend: "up",
        severity: "medium",
      });
    }

    // Analyze category trends
    if (categoryTrend.length >= 2) {
      const recentMonth = categoryTrend[categoryTrend.length - 1];
      const prevMonth = categoryTrend[categoryTrend.length - 2];

      const safetyChange = prevMonth.safety > 0
        ? ((recentMonth.safety - prevMonth.safety) / prevMonth.safety) * 100
        : 0;

      if (safetyChange < -30) {
        patterns.push({
          title: "Safety reports declining",
          description: `Safety-related reports have decreased ${Math.abs(safetyChange).toFixed(0)}% — may indicate resolved issues or underreporting.`,
          trend: "down",
          severity: "low",
        });
      }
    }

    // If no patterns detected, show a placeholder
    if (patterns.length === 0) {
      patterns.push({
        title: "No significant patterns detected",
        description: "Report activity appears normal. Continue monitoring for emerging trends.",
        trend: "up",
        severity: "low",
      });
    }

    return patterns;
  }, [elizaStats, timeOfDayData, categoryTrend]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="space-y-6 pb-8"
    >
      {/* Header */}
      <div>
        <h2 className="mb-1" style={{ fontSize: "1.1rem", fontWeight: 500, color: ink(80) }}>
          Patterns & Insights
        </h2>
        <p style={{ fontSize: "13px", color: ink(45) }}>
          Trends calculated from report dates, categories and counts
        </p>
      </div>

      {/* Detected Patterns */}
      <div className="space-y-2">
        <h3
          className="uppercase"
          style={{ fontSize: "10px", letterSpacing: "0.15em", color: ink(50) }}
        >
          Detected Patterns
        </h3>
        {detectedPatterns.map((pattern) => {
          return (
            <div
              key={pattern.title}
              className={`border-l-2 ${
                pattern.severity === "high" ? "border-l-red-400" :
                pattern.severity === "medium" ? "border-l-amber-400" : ""
              } p-4 transition-colors duration-500`}
              style={{
                backgroundColor: "var(--vera-card-bg)",
                border: `1px solid ${ink(4)}`,
                ...(pattern.severity === "low" ? { borderLeftColor: ink(40), borderLeftWidth: 2 } : {}),
              }}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3">
                  {pattern.trend === "up" ? (
                    <TrendingUp className="size-4 text-red-400/60 mt-0.5 shrink-0" />
                  ) : (
                    <TrendingDown className="size-4 text-emerald-400/60 mt-0.5 shrink-0" />
                  )}
                  <div>
                    <p style={{ fontSize: "13px", fontWeight: 500, color: ink(65) }}>
                      {pattern.title}
                    </p>
                    <p className="mt-1" style={{ fontSize: "12px", lineHeight: 1.6, color: ink(50) }}>
                      {pattern.description}
                    </p>
                  </div>
                </div>
                <span
                  className={`shrink-0 px-2 py-0.5 text-[10px] uppercase tracking-wider ${
                    pattern.severity === "high"
                      ? "bg-red-500/10 text-red-400 border border-red-500/15"
                      : pattern.severity === "medium"
                      ? "bg-amber-500/10 text-amber-400 border border-amber-500/15"
                      : ""
                  }`}
                  style={pattern.severity === "low" ? { backgroundColor: ink(4), color: ink(50), border: `1px solid ${ink(6)}` } : {}}
                >
                  {pattern.severity}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts row */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Weekly Submission Trend */}
        <div className="p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
          <div className="flex items-center gap-2 mb-5">
            <Calendar className="size-4" style={{ color: ink(45) }} />
            <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
              Weekly Submission Trend
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={weeklyTrend}>
              <defs>
                <linearGradient id="patternGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--vera-chart-fill-start)" stopOpacity={1} />
                  <stop offset="100%" stopColor="var(--vera-chart-fill-end)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--vera-chart-grid)" vertical={false} />
              <XAxis dataKey="week" stroke="var(--vera-chart-axis)" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis stroke="var(--vera-chart-axis)" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="reports" stroke="var(--vera-chart-line)" strokeWidth={1.5} fill="url(#patternGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Time of Day Distribution */}
        <div className="p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
          <div className="flex items-center gap-2 mb-5">
            <BarChart3 className="size-4" style={{ color: ink(45) }} />
            <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
              Time of Day
            </h3>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={timeOfDayData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--vera-chart-grid)" vertical={false} />
              <XAxis dataKey="hour" stroke="var(--vera-chart-axis)" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis stroke="var(--vera-chart-axis)" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="count" fill="var(--vera-chart-bar)" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Category Trend */}
      <div className="p-6 transition-colors duration-500" style={{ backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}>
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <AlertTriangle className="size-4" style={{ color: ink(45) }} />
            <h3 style={{ fontSize: "14px", fontWeight: 500, color: ink(70) }}>
              Category Trend (5 Months)
            </h3>
          </div>
          <div className="flex items-center gap-4">
            {[
              { label: "Fraud", color: "bg-red-400" },
              { label: "Safety", color: "bg-amber-400" },
              { label: "Policy", color: "bg-violet-400" },
              { label: "Ethics", color: "bg-blue-400" },
              { label: "Other", color: "" },
            ].map((l) => (
              <div key={l.label} className="flex items-center gap-1.5">
                <div className={`size-1.5 rounded-full ${l.color}`} style={l.label === "Other" ? { backgroundColor: ink(50) } : {}} />
                <span style={{ fontSize: "11px", color: ink(50) }}>{l.label}</span>
              </div>
            ))}
          </div>
        </div>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={categoryTrend}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--vera-chart-grid)" vertical={false} />
            <XAxis dataKey="month" stroke="var(--vera-chart-axis)" fontSize={11} tickLine={false} axisLine={false} />
            <YAxis stroke="var(--vera-chart-axis)" fontSize={11} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Bar dataKey="fraud" stackId="a" fill="rgba(248,113,113,0.6)" />
            <Bar dataKey="safety" stackId="a" fill="rgba(251,191,36,0.6)" />
            <Bar dataKey="policy" stackId="a" fill="rgba(167,139,250,0.6)" />
            <Bar dataKey="ethics" stackId="a" fill="rgba(96,165,250,0.6)" />
            <Bar dataKey="other" stackId="a" fill="var(--vera-chart-bar)" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}