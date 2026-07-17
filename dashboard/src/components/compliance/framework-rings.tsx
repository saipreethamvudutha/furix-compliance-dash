"use client";

import type { ComplianceFramework } from "@/lib/data/types";

function Donut({ pct, color }: { pct: number; color: string }) {
  const angle = Math.max(0, Math.min(100, pct)) * 3.6;
  return (
    <div
      className="relative h-16 w-16 shrink-0 rounded-full"
      style={{
        background: `conic-gradient(${color} ${angle}deg, rgba(148,163,184,0.22) ${angle}deg 360deg)`,
      }}
    >
      <div className="absolute inset-[6px] flex items-center justify-center rounded-full bg-[var(--card,#fff)] dark:bg-slate-900">
        <span className="text-sm font-semibold tabular-nums">{Math.round(pct)}%</span>
      </div>
    </div>
  );
}

function ringColor(pct: number): string {
  if (pct >= 80) return "#10b981"; // emerald
  if (pct >= 50) return "#f59e0b"; // amber
  return "#f43f5e"; // rose
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
            <Donut pct={fw.percentage} color={ringColor(fw.percentage)} />
            <div className="min-w-0">
              <div className="truncate font-medium">{fw.shortName}</div>
              <div className="mt-0.5 text-xs text-slate-500">
                {fw.metControls} met · {fw.gapControls} gap · {fw.naControls} n/a
              </div>
              <div className="mt-1 text-[11px] uppercase tracking-wide text-slate-400">
                {fw.totalControls} requirements
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}
