"use client";

import { Radio, FlaskConical, AlertTriangle } from "lucide-react";

// One truthful compliance domain (FUR-CMP / FUR-UX-001): the viewer must always
// know whether they are looking at LIVE verified data, DEMO seed data, or a
// DEGRADED live report — a demo percentage must never be mistaken for a
// verified one.
export type DataMode = "live" | "demo" | "degraded" | "loading";

const META: Record<Exclude<DataMode, "loading">, {
  label: string;
  detail: string;
  cls: string;
  Icon: typeof Radio;
}> = {
  live: {
    label: "LIVE",
    detail: "verified data from the ingest engine",
    cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
    Icon: Radio,
  },
  degraded: {
    label: "DEGRADED",
    detail: "live report with incomplete or stale evidence — treat with caution",
    cls: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
    Icon: AlertTriangle,
  },
  demo: {
    label: "DEMO",
    detail: "illustrative seed data — the ingest engine is not reachable",
    cls: "border-slate-400/40 bg-slate-500/10 text-slate-600 dark:text-slate-300",
    Icon: FlaskConical,
  },
};

export function DataModeBadge({ mode, note }: { mode: DataMode; note?: string }) {
  if (mode === "loading") return null;
  const m = META[mode];
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${m.cls}`}
      title={m.detail}
    >
      <m.Icon className="h-3.5 w-3.5" />
      <span className="font-mono tracking-wide">{m.label}</span>
      <span className="opacity-70">· {note ?? m.detail}</span>
    </span>
  );
}
