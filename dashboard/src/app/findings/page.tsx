"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, RefreshCw, ArrowUpRight, ClipboardCheck } from "lucide-react";
import { DataModeBadge, type DataMode } from "@/components/compliance/data-mode-badge";
import { getFindings, type Finding } from "@/lib/data/furix-api";
import { apiHealthy } from "@/lib/data/client";

// Live remediation / exception lifecycle (Wave 5), sourced from the durable
// finding store via the BFF. LIVE when the engine is reachable, otherwise a
// clear empty state — no invented finding counts.
const STATE_STYLE: Record<string, string> = {
  open: "border-slate-400/30 bg-slate-500/10 text-slate-600 dark:text-slate-300",
  in_progress: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  remediated: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  retest_pending: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  risk_accepted: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  expired: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  closed: "border-slate-400/30 bg-slate-500/10 text-slate-500",
};

const SEV_STYLE: Record<string, string> = {
  critical: "text-rose-600 dark:text-rose-400",
  high: "text-orange-600 dark:text-orange-400",
  medium: "text-amber-600 dark:text-amber-400",
  low: "text-sky-600 dark:text-sky-400",
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [mode, setMode] = useState<DataMode>("loading");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const healthy = await apiHealthy();
      if (!healthy) {
        setMode("demo");
        setFindings([]);
        return;
      }
      const f = await getFindings(true);
      setMode("live");
      setFindings(f);
    } catch {
      setMode("demo");
      setFindings([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const sorted = [...(findings ?? [])].sort((a, b) => {
    const order = ["critical", "high", "medium", "low", ""];
    return order.indexOf(a.severity ?? "") - order.indexOf(b.severity ?? "");
  });

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold">Findings &amp; Remediation</h1>
            <DataModeBadge
              mode={mode}
              note={
                loading
                  ? "checking engine…"
                  : mode === "live"
                    ? `${findings?.length ?? 0} open · event-sourced lifecycle`
                    : "engine not reachable"
              }
            />
          </div>
          <p className="mt-1 text-sm text-slate-500">
            Every at-risk control becomes a finding with an owner, due date, retest and
            risk-acceptance workflow — nothing is deleted, every transition is logged.
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
          <Loader2 className="h-4 w-4 animate-spin" /> Loading findings…
        </div>
      )}

      {!loading && mode === "demo" && (
        <div className="rounded-xl border border-slate-200 p-8 text-center dark:border-slate-700">
          <p className="text-sm text-slate-500">
            The ingest engine isn&rsquo;t reachable, so there are no live findings to show.
          </p>
          <Link
            href="/ingest"
            className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-[var(--furix-accent,#c2703d)] px-4 py-2 text-sm font-medium text-white"
          >
            Ingest logs <ArrowUpRight className="h-4 w-4" />
          </Link>
        </div>
      )}

      {!loading && mode === "live" && sorted.length === 0 && (
        <div className="rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-500 dark:border-slate-700">
          No open findings — every monitored control is currently clean.
        </div>
      )}

      {!loading && mode === "live" && sorted.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700">
          <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 border-b border-slate-200 bg-slate-50 px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400 dark:border-slate-700 dark:bg-slate-800/50">
            <span>Control</span>
            <span>Severity</span>
            <span>Owner / due</span>
            <span>State</span>
          </div>
          {sorted.map((f) => (
            <div
              key={f.finding_id}
              className="grid grid-cols-[1fr_auto_auto_auto] items-center gap-3 border-b border-slate-100 px-4 py-3 last:border-0 dark:border-slate-800"
            >
              <div className="min-w-0">
                <div className="text-sm font-medium">{f.control_id}</div>
                <div className="truncate text-xs text-slate-500">
                  {f.last_reason ?? f.framework_id}
                  {f.exception?.approver && (
                    <span className="ml-1 text-amber-600 dark:text-amber-400">
                      · accepted by {f.exception.approver}, expires {f.exception.expiry?.slice(0, 10)}
                    </span>
                  )}
                </div>
              </div>
              <span className={`text-xs font-semibold uppercase ${SEV_STYLE[f.severity ?? ""] ?? "text-slate-400"}`}>
                {f.severity ?? "—"}
              </span>
              <span className="whitespace-nowrap text-xs text-slate-500">
                {f.owner ?? "unassigned"}
                {f.due_date && <span className="ml-1 text-slate-400">· {f.due_date.slice(0, 10)}</span>}
              </span>
              <span
                className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                  STATE_STYLE[f.expired ? "expired" : f.state] ?? STATE_STYLE.open
                }`}
              >
                <ClipboardCheck className="h-3 w-3" />
                {(f.expired ? "expired" : f.state).replace(/_/g, " ")}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
