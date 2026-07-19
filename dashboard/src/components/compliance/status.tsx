// Shared status vocabulary for the live compliance views.
import type { ControlStatus } from "@/lib/data/types";

export const STATUS_META: Record<
  ControlStatus,
  { label: string; dot: string; text: string; bg: string; ring: string }
> = {
  met: {
    label: "Met",
    dot: "bg-emerald-500",
    text: "text-emerald-700 dark:text-emerald-300",
    bg: "bg-emerald-500/10 border-emerald-500/30",
    ring: "#10b981",
  },
  gap: {
    label: "Gap",
    dot: "bg-rose-500",
    text: "text-rose-700 dark:text-rose-300",
    bg: "bg-rose-500/10 border-rose-500/30",
    ring: "#f43f5e",
  },
  in_progress: {
    label: "In progress",
    dot: "bg-amber-500",
    text: "text-amber-700 dark:text-amber-300",
    bg: "bg-amber-500/10 border-amber-500/30",
    ring: "#f59e0b",
  },
  unknown: {
    label: "No violations observed",
    dot: "bg-sky-500",
    text: "text-sky-700 dark:text-sky-300",
    bg: "bg-sky-500/10 border-sky-500/30",
    ring: "#0ea5e9",
  },
  not_monitored: {
    label: "Not monitored",
    dot: "bg-slate-400",
    text: "text-slate-600 dark:text-slate-300",
    bg: "bg-slate-500/10 border-slate-500/25",
    ring: "#94a3b8",
  },
  not_applicable: {
    label: "N/A (approved)",
    dot: "bg-slate-400",
    text: "text-slate-600 dark:text-slate-300",
    bg: "bg-slate-500/10 border-slate-500/25",
    ring: "#94a3b8",
  },
};

export function StatusPill({ status }: { status: ControlStatus }) {
  const m = STATUS_META[status] ?? STATUS_META.not_monitored;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${m.bg} ${m.text}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  );
}

export function severityColor(sev: string): string {
  switch (sev.toLowerCase()) {
    case "critical":
      return "text-rose-600 dark:text-rose-400";
    case "high":
      return "text-orange-600 dark:text-orange-400";
    case "medium":
      return "text-amber-600 dark:text-amber-400";
    case "low":
      return "text-sky-600 dark:text-sky-400";
    default:
      return "text-slate-500";
  }
}
