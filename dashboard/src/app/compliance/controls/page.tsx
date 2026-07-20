"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, RefreshCw, ShieldCheck, ArrowUpRight } from "lucide-react";
import { DataModeBadge, type DataMode } from "@/components/compliance/data-mode-badge";
import { apiHealthy } from "@/lib/data/client";
import { listControlWorkspace, type ControlSummary } from "@/lib/data/furix-api";

// Compliance workspace (Wave-I / Epic 4): every control with its computed verdict
// AND its governance context (owner, applicability, evidence freshness, findings,
// framework coverage). Sourced live from the engine via the BFF.

const STATUS_STYLE: Record<string, string> = {
  compliant: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  at_risk: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  not_monitored: "border-slate-400/30 bg-slate-500/10 text-slate-500",
  unknown: "border-slate-400/30 bg-slate-500/10 text-slate-500",
};
const FRESH_STYLE: Record<string, string> = {
  fresh: "text-emerald-600 dark:text-emerald-400",
  stale: "text-amber-600 dark:text-amber-400",
  unknown: "text-slate-400",
};

export default function ControlWorkspacePage() {
  const [rows, setRows] = useState<ControlSummary[] | null>(null);
  const [mode, setMode] = useState<DataMode>("loading");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      if (!(await apiHealthy())) {
        setMode("demo");
        setRows([]);
        return;
      }
      setRows(await listControlWorkspace());
      setMode("live");
    } catch {
      setMode("demo");
      setRows([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const list = rows ?? [];

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="flex items-center gap-2 text-2xl font-semibold">
              <ShieldCheck className="h-6 w-6" /> Control workspace
            </h1>
            <DataModeBadge
              mode={mode}
              note={loading ? "loading…" : mode === "live" ? `${list.length} controls` : "engine not reachable"}
            />
          </div>
          <p className="mt-1 max-w-2xl text-sm text-slate-500">
            Every control with its computed verdict and its governance context — owner,
            applicability, evidence freshness, linked findings and framework coverage.
            Click a control to edit its profile and trace its evidence lineage.
          </p>
        </div>
        <button
          type="button"
          onClick={load}
          className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50 dark:border-slate-600 dark:hover:bg-slate-800"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </header>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading controls…
        </div>
      )}

      {!loading && mode === "demo" && (
        <div className="rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-500 dark:border-slate-700">
          The engine isn&rsquo;t reachable, so there is no live control workspace to show.
        </div>
      )}

      {!loading && mode === "live" && list.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50 text-[11px] uppercase tracking-wide text-slate-400 dark:border-slate-700 dark:bg-slate-800/50">
                <th className="px-4 py-2.5 text-left">Control</th>
                <th className="px-4 py-2.5 text-left">Status</th>
                <th className="px-4 py-2.5 text-left">Owner</th>
                <th className="px-4 py-2.5 text-left">Applicability</th>
                <th className="px-4 py-2.5 text-left">Evidence</th>
                <th className="px-4 py-2.5 text-left">Findings</th>
                <th className="px-4 py-2.5 text-left">Frameworks</th>
                <th className="px-4 py-2.5"></th>
              </tr>
            </thead>
            <tbody>
              {list.map((r) => (
                <tr
                  key={r.control_id}
                  className="border-b border-slate-100 last:border-0 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/40"
                >
                  <td className="px-4 py-2.5">
                    <div className="font-medium">{r.control_id}</div>
                    <div className="text-xs text-slate-500">{r.title}</div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-block rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                        STATUS_STYLE[r.status] ?? STATUS_STYLE.unknown
                      }`}
                    >
                      {r.status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-slate-600 dark:text-slate-300">
                    {r.owner || <span className="text-slate-400">unassigned</span>}
                  </td>
                  <td className="px-4 py-2.5 text-slate-600 dark:text-slate-300">{r.applicability}</td>
                  <td className={`px-4 py-2.5 ${FRESH_STYLE[r.evidence_freshness] ?? FRESH_STYLE.unknown}`}>
                    {r.evidence_freshness}
                  </td>
                  <td className="px-4 py-2.5">
                    {r.open_findings > 0 ? (
                      <span className="text-rose-600 dark:text-rose-400">{r.open_findings}</span>
                    ) : (
                      <span className="text-slate-400">0</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-slate-500">
                    N{r.framework_counts.nist_csf} · P{r.framework_counts.pci_dss} · H
                    {r.framework_counts.hipaa}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <Link
                      href={`/compliance/controls/${encodeURIComponent(r.control_id)}`}
                      className="inline-flex items-center gap-1 text-[var(--furix-accent,#c2703d)] hover:underline"
                    >
                      Open <ArrowUpRight className="h-3.5 w-3.5" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
