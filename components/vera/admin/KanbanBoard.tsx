import { useCallback, useRef } from "react";
import { DndProvider, useDrag, useDrop } from "react-dnd";
import { HTML5Backend } from "react-dnd-html5-backend";
import { ChevronRight, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { motion } from "motion/react";
import type { ReportData } from "./ReportDetail";

const ink = (pct: number) =>
  `color-mix(in srgb, var(--vera-ink) calc(${pct}% * var(--vera-ink-boost)), transparent)`;

const ITEM_TYPE = "REPORT_CARD";

const columnDefs = [
  { status: "pending", label: "Pending", accentColor: "bg-amber-400", borderColor: "border-l-amber-400/60" },
  { status: "reviewing", label: "Reviewing", accentColor: "bg-blue-400", borderColor: "border-l-blue-400/60" },
  { status: "investigating", label: "Investigating", accentColor: "bg-purple-400", borderColor: "border-l-purple-400/60" },
  { status: "resolved", label: "Resolved", accentColor: "bg-emerald-400", borderColor: "border-l-emerald-400/60" },
  { status: "dismissed", label: "Dismissed", accentColor: "bg-red-400", borderColor: "border-l-red-400/60" },
] as const;

const priorityAccent: Record<string, string> = {
  high: "border-l-red-400/80",
  medium: "border-l-amber-400/50",
  low: "",
};

// ── Draggable Card ──

interface CardProps {
  report: ReportData;
  onView: (report: ReportData) => void;
  index: number;
}

function KanbanCard({ report, onView, index }: CardProps) {
  const ref = useRef<HTMLDivElement>(null);

  const [{ isDragging }, drag] = useDrag({
    type: ITEM_TYPE,
    item: { id: report.id },
    collect: (monitor) => ({ isDragging: monitor.isDragging() }),
  });

  drag(ref);

  // Unscored reports (no Shroud result) show no score — never a default 0%.
  const authenticity = report.aiAnalysis?.authenticity;
  const isFlagged = authenticity != null && authenticity <= 40;
  const authColor =
    authenticity == null
      ? ""
      : authenticity > 70
      ? "text-emerald-400"
      : authenticity > 40
      ? "text-amber-400"
      : "text-red-400";

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: index * 0.04 }}
    >
      <div
        ref={ref}
        style={{ opacity: isDragging ? 0.35 : 1, backgroundColor: "var(--vera-card-bg)", border: `1px solid ${ink(4)}` }}
        className={`border-l-2 ${priorityAccent[report.priority] || ""} p-3.5 cursor-grab active:cursor-grabbing mb-2 transition-all group`}
        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = ink(2); e.currentTarget.style.borderColor = ink(8); }}
        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "var(--vera-card-bg)"; e.currentTarget.style.borderColor = ink(4); }}
      >
        {/* ID + Flagged */}
        <div className="flex items-center justify-between mb-2">
          <span
            className="font-mono"
            style={{ fontSize: "10px", letterSpacing: "0.08em", color: ink(50) }}
          >
            {report.id}
          </span>
          {isFlagged && (
            <Badge
              variant="outline"
              className="bg-red-500/[0.06] text-red-400/70 border-red-500/10"
              style={{ fontSize: "9px" }}
            >
              Flagged
            </Badge>
          )}
        </div>

        {/* Title */}
        <p
          className="truncate mb-1 transition-colors"
          style={{ fontSize: "13px", fontWeight: 500, color: ink(70) }}
        >
          {report.title}
        </p>

        {/* Description */}
        <p
          className="mb-3"
          style={{
            fontSize: "11px",
            lineHeight: 1.55,
            color: ink(50),
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
          }}
        >
          {report.description}
        </p>

        {/* AI Score (only when scored) + Date */}
        <div className="flex items-center justify-between pt-2.5" style={{ borderTop: `1px solid ${ink(4)}` }}>
          {authenticity != null ? (
            <div className="flex items-center gap-1.5" title="Narrative model score">
              <Sparkles className="size-3" style={{ color: ink(40) }} />
              <span className={`tabular-nums ${authColor}`} style={{ fontSize: "11px" }}>
                {authenticity}%
              </span>
            </div>
          ) : (
            <span />
          )}
          <span style={{ fontSize: "10px", color: ink(40) }}>
            {report.date}
          </span>
        </div>

        {/* View Details */}
        <button
          onClick={(e) => {
            e.stopPropagation();
            onView(report);
          }}
          className="w-full mt-2.5 flex items-center justify-center gap-1.5 py-1.5 transition-colors"
          style={{ border: `1px solid ${ink(6)}`, fontSize: "10px", letterSpacing: "0.08em", textTransform: "uppercase", color: ink(50) }}
        >
          Open Report
          <ChevronRight className="size-3" />
        </button>
      </div>
    </motion.div>
  );
}

// ── Droppable Column ──

interface ColumnProps {
  status: ReportData["status"];
  label: string;
  accentColor: string;
  cards: ReportData[];
  onDrop: (reportId: string, newStatus: ReportData["status"]) => void;
  onView: (report: ReportData) => void;
  colIndex: number;
}

function KanbanColumn({
  status,
  label,
  accentColor,
  cards,
  onDrop,
  onView,
  colIndex,
}: ColumnProps) {
  const ref = useRef<HTMLDivElement>(null);

  const [{ isOver }, drop] = useDrop({
    accept: ITEM_TYPE,
    drop: (item: { id: string }) => {
      onDrop(item.id, status);
    },
    collect: (monitor) => ({ isOver: monitor.isOver() }),
  });

  drop(ref);

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: colIndex * 0.06 }}
      className="min-w-[220px] flex flex-col"
      style={{ flex: "1 1 0" }}
    >
      {/* Column header */}
      <div className="flex items-center gap-2.5 mb-3 px-1">
        <div className={`w-3 h-px ${accentColor}`} />
        <span
          style={{
            fontSize: "10px",
            letterSpacing: "0.15em",
            textTransform: "uppercase",
            fontFamily: "var(--font-sans)",
            color: ink(50),
          }}
        >
          {label}
        </span>
        <span
          className="tabular-nums"
          style={{ fontSize: "10px", color: ink(50) }}
        >
          {cards.length}
        </span>
      </div>

      {/* Drop zone */}
      <div
        ref={ref}
        className="flex-1 p-1.5 transition-all min-h-[200px]"
        style={{
          backgroundColor: isOver ? ink(3) : ink(1),
          border: isOver ? `1px dashed ${ink(15)}` : "1px solid transparent",
        }}
      >
        {cards.length > 0 ? (
          cards.map((report, i) => (
            <KanbanCard key={report.id} report={report} onView={onView} index={i} />
          ))
        ) : (
          <div className="h-full flex flex-col items-center justify-center gap-2 py-12">
            <div className="w-6 h-px" style={{ backgroundColor: ink(20) }} />
            <p
              className="font-serif italic"
              style={{ fontSize: "12px", color: ink(40) }}
            >
              No reports
            </p>
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ── Board ──

interface KanbanBoardProps {
  reports: ReportData[];
  onViewReport: (report: ReportData) => void;
  onUpdateStatus: (reportId: string, newStatus: ReportData["status"]) => Promise<ReportData["status"] | false>;
}

export function KanbanBoard({
  reports,
  onViewReport,
  onUpdateStatus,
}: KanbanBoardProps) {
  const handleDrop = useCallback(
    (reportId: string, newStatus: ReportData["status"]) => {
      void onUpdateStatus(reportId, newStatus);
    },
    [onUpdateStatus]
  );

  const getColumnCards = (status: ReportData["status"]) =>
    reports.filter((r) => r.status === status);

  return (
    <DndProvider backend={HTML5Backend}>
      <div className="space-y-5">
        {/* Columns */}
        <div className="flex gap-3 overflow-x-auto pb-4">
          {columnDefs.map((col, i) => (
            <KanbanColumn
              key={col.status}
              status={col.status}
              label={col.label}
              accentColor={col.accentColor}
              cards={getColumnCards(col.status)}
              onDrop={handleDrop}
              onView={onViewReport}
              colIndex={i}
            />
          ))}
        </div>

        {/* Footer — Vera watermark style */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="flex flex-col items-center gap-2 pt-4"
        >
          <div className="flex items-center gap-4">
            <div className="w-8 h-px" style={{ backgroundColor: ink(6) }} />
            <div className="flex items-center gap-3">
              {columnDefs.map((col) => {
                const count = getColumnCards(col.status).length;
                return (
                  <div key={col.status} className="flex items-center gap-1.5">
                    <div className={`w-2 h-px ${col.accentColor}`} />
                    <span className="tabular-nums" style={{ fontSize: "10px", color: ink(45) }}>
                      {count}
                    </span>
                  </div>
                );
              })}
            </div>
            <div className="w-8 h-px" style={{ backgroundColor: ink(6) }} />
          </div>
          <p
            style={{
              fontSize: "9px",
              letterSpacing: "0.2em",
              textTransform: "uppercase",
              color: ink(45),
            }}
          >
            Drag to reassign &middot; Vera
          </p>
        </motion.div>
      </div>
    </DndProvider>
  );
}
