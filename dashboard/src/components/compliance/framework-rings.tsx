"use client";

import type { ComplianceFramework } from "@/lib/data/types";

function Donut({ pct, label, color }: { pct: number; label: string; color: string }) {
  const angle = Math.max(0, Math.min(100, pct)) * 3.6;
  return (
    <div
      className="relative h-16 w-16 shrink-0 rounded-full"
      style={{
        background: `conic-gradient(${color} ${angle}deg, rgba(148,163,184,0.22) ${angle}deg 360deg)`,
      }}
    >
      <div className="absolute inset-[6px] flex flex-col items-center justify-center rounded-full bg-[var(--card,#fff)] dark:bg-slate-900">
        <span className="text-sm font-semibold tabular-nums leading-none">{Math.round(pct)}%</span>
        <span className="mt-0.5 text-[8px] uppercase tracking-wide text-slate-400 leading-none">
          {label}
        </span>
      </div>
    </div>
  );
}

// The ring shows COVERAGE (how much we can even see) — the honest headline for
// detection-only evidence. Risk is shown alongside, never hidden inside it.
function coverageColor(pct: number): string {
  if (pct >= 80) return "#10b981"; // emerald
  if (pct >= 50) return "#f59e0b"; // amber
  return "#94a3b8"; // slate — low coverage is a visibility problem, not a fire
}

export function FrameworkRings({
  frameworks,
  selectedId,
  onSelect,
}: {
  frameworks: ComplianceFramework[];
  selectedId?: string;
  onSelect?: (id: string) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {frameworks.map((fw) => {
        const active = fw.id === selectedId;
        return (
          <button
            key={fw.id}
            type="button"
            onClick={() => onSelect?.(fw.id)}
            className={`flex items-center gap-4 rounded-xl border p-4 text-left transition-colors ${
              active
                ? "border-[var(--furix-accent,#c2703d)] bg-[var(--furix-accent,#c2703d)]/5"
                : "border-slate-200 hover:border-slate-300 dark:border-slate-700 dark:hover:border-slate-600"
            }`}
          >
            <Donut pct={fw.coveragePct} label="coverage" color={coverageColor(fw.coveragePct)} />
            <div className="min-w-0">
              <div className="truncate font-medium">{fw.shortName}</div>
              <div className="mt-0.5 text-xs text-slate-500">
                <span className={fw.gapControls > 0 ? "font-medium text-rose-600 dark:text-rose-400" : ""}>
                  {fw.gapControls} at risk
                </span>
                {" · "}
                {fw.unknownControls} monitored
                {" · "}
                {fw.notMonitoredControls} unmonitored
              </div>
              <div className="mt-1 text-[11px] uppercase tracking-wide text-slate-400">
                {fw.totalControls} requirements
                {fw.atRiskPct !== null && ` · ${fw.atRiskPct}% of monitored at risk`}
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}
