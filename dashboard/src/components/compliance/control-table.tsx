"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, Sparkles } from "lucide-react";
import type { ComplianceControl, ComplianceFramework } from "@/lib/data/types";
import { StatusPill } from "./status";

function ControlRow({ control }: { control: ComplianceControl }) {
  const [open, setOpen] = useState(false);
  const expandable =
    control.systems.length > 0 || Boolean(control.aiRecommendation);

  return (
    <div className="border-b border-slate-100 last:border-0 dark:border-slate-800">
      <button
        type="button"
        onClick={() => expandable && setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-slate-50 dark:hover:bg-slate-800/40"
      >
        <span className="mt-0.5 w-4 shrink-0 text-slate-400">
          {expandable ? (
            open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />
          ) : null}
        </span>
        <span className="w-28 shrink-0 font-mono text-xs text-slate-500">{control.reference}</span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium">{control.title}</span>
          <span className="mt-0.5 block truncate text-xs text-slate-500">{control.plainLanguage}</span>
        </span>
        <StatusPill status={control.status} />
      </button>

      {open && (
        <div className="space-y-3 bg-slate-50/60 px-4 pb-4 pl-11 dark:bg-slate-900/40">
          {control.systems.length > 0 && (
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                Evidence ({control.systems.length})
              </div>
              <ul className="space-y-1">
                {control.systems.map((s, i) => (
                  <li key={i} className="flex gap-2 font-mono text-xs text-slate-600 dark:text-slate-300">
                    <span className="shrink-0 text-slate-400">{s.name}</span>
                    <span className="break-all">{s.detail}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {control.aiRecommendation && (
            <div className="flex gap-2 rounded-lg border border-amber-400/30 bg-amber-400/5 p-3 text-xs text-amber-800 dark:text-amber-200">
              <Sparkles className="h-4 w-4 shrink-0" />
              <span>{control.aiRecommendation}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ControlTable({ framework }: { framework: ComplianceFramework }) {
  // gap first, then in_progress, then met, then n/a — attention at the top.
  const order: Record<string, number> = { gap: 0, in_progress: 1, met: 2, not_applicable: 3 };
  const controls = [...framework.controls].sort(
    (a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9),
  );
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700">
      <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-2.5 text-sm dark:border-slate-700 dark:bg-slate-800/50">
        <span className="font-medium">{framework.name}</span>
        <span className="font-mono text-xs text-slate-500">
          {framework.metControls}/{framework.totalControls} met · {framework.percentage}%
        </span>
      </div>
      <div>
        {controls.map((c) => (
          <ControlRow key={c.id} control={c} />
        ))}
      </div>
    </div>
  );
}
