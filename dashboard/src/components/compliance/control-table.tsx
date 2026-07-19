"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, Sparkles, Crosshair, Link as LinkIcon, Terminal, ClipboardCheck } from "lucide-react";
import type { ComplianceControl, ComplianceFramework } from "@/lib/data/types";
import { StatusPill } from "./status";

const ATTACK_DOT: Record<string, string> = {
  critical: "bg-rose-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-sky-500",
};

function ControlRow({ control }: { control: ComplianceControl }) {
  const [open, setOpen] = useState(false);
  const attack = control.attack ?? [];
  const expandable =
    control.systems.length > 0 || Boolean(control.aiRecommendation) || attack.length > 0;

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
        {control.finding && (
          <span
            className={`hidden shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium sm:inline-flex ${
              control.finding.expired
                ? "border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-300"
                : control.finding.state === "risk_accepted"
                  ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                  : "border-slate-400/30 bg-slate-500/10 text-slate-600 dark:text-slate-300"
            }`}
            title={
              control.finding.exception
                ? `Risk accepted by ${control.finding.exception.approver}, expires ${control.finding.exception.expiry?.slice(0, 10)}`
                : `Finding: ${control.finding.state}`
            }
          >
            <ClipboardCheck className="h-3 w-3" />
            {control.finding.expired
              ? "exception expired"
              : control.finding.state === "risk_accepted"
                ? "risk accepted"
                : control.finding.state.replace("_", " ")}
          </span>
        )}
        {attack.length > 0 && (
          <span className="hidden shrink-0 items-center gap-1 rounded-full border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 font-mono text-[10px] font-medium text-violet-600 dark:text-violet-300 sm:inline-flex">
            <Crosshair className="h-3 w-3" /> {attack.length} ATT&CK
          </span>
        )}
        <StatusPill status={control.status} />
      </button>

      {open && (
        <div className="space-y-3 bg-slate-50/60 px-4 pb-4 pl-11 dark:bg-slate-900/40">
          {attack.length > 0 && (
            <div>
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                MITRE ATT&CK ({attack.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {attack.map((a, i) => (
                  <div
                    key={i}
                    className="rounded-md border border-slate-200 bg-white px-2.5 py-1.5 dark:border-slate-700 dark:bg-slate-900"
                    title={`Detected by Sigma rule ${a.ruleId} (${a.ruleTitle})`}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 rounded-full ${ATTACK_DOT[a.level] ?? "bg-slate-400"}`} />
                      <span className="font-mono text-xs font-semibold">{a.techniqueId}</span>
                      <span className="text-xs text-slate-500">{a.techniqueName}</span>
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] text-slate-400">via {a.ruleId}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {control.systems.length > 0 && (
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                Evidence lineage ({control.systems.length})
              </div>
              <ul className="space-y-2">
                {control.systems.map((s, i) => (
                  <li key={i} className="rounded-md border border-slate-200 bg-white p-2 dark:border-slate-700 dark:bg-slate-900">
                    <div className="flex gap-2 font-mono text-xs text-slate-600 dark:text-slate-300">
                      <span className="shrink-0 text-slate-400">{s.name}</span>
                      <span className="break-all">{s.detail}</span>
                    </div>
                    {s.evidenceUri && (
                      <div className="mt-1 flex items-center gap-1.5 font-mono text-[10px] text-emerald-600 dark:text-emerald-400">
                        <LinkIcon className="h-3 w-3 shrink-0" />
                        <span className="break-all">{s.evidenceUri}</span>
                      </div>
                    )}
                    {s.reproduce && (
                      <div className="mt-1 flex items-center gap-1.5 rounded bg-slate-100 px-1.5 py-1 font-mono text-[10px] text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                        <Terminal className="h-3 w-3 shrink-0" />
                        <span className="break-all">{s.reproduce}</span>
                      </div>
                    )}
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
  // gap first, then unknown, in_progress, met, then unmonitored — attention at the top.
  const order: Record<string, number> = {
    gap: 0, unknown: 1, in_progress: 2, met: 3, not_monitored: 4, not_applicable: 5,
  };
  const controls = [...framework.controls].sort(
    (a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9),
  );
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700">
      <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-2.5 text-sm dark:border-slate-700 dark:bg-slate-800/50">
        <span className="font-medium">{framework.name}</span>
        <span className="font-mono text-xs text-slate-500">
          {framework.gapControls} at risk · {framework.unknownControls} monitored ·{" "}
          {framework.coveragePct}% coverage
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
