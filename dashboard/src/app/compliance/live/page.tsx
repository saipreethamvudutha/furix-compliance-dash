"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, ArrowUpRight, RefreshCw } from "lucide-react";
import { FrameworkRings } from "@/components/compliance/framework-rings";
import { ControlTable } from "@/components/compliance/control-table";
import { getLiveFrameworks, getLiveSummary, type ReportSummary } from "@/lib/data/furix-api";
import type { ComplianceFramework } from "@/lib/data/types";

export default function LiveCompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[] | null>(null);
  const [summary, setSummary] = useState<ReportSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState("cis");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [fw, sum] = await Promise.all([getLiveFrameworks("latest"), getLiveSummary("latest")]);
      setFrameworks(fw);
      setSummary(sum);
      setSelected(fw[0]?.id ?? "cis");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const selectedFw = frameworks?.find((f) => f.id === selected) ?? frameworks?.[0];

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Live Compliance</h1>
          <p className="mt-1 text-sm text-slate-500">
            Latest ingested report — CIS · NIST CSF · HIPAA · PCI DSS, SCF-derived and verified.
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
          <Loader2 className="h-4 w-4 animate-spin" /> Loading latest report…
        </div>
      )}

      {!loading && error && (
        <div className="rounded-xl border border-slate-200 p-8 text-center dark:border-slate-700">
          <p className="text-sm text-slate-500">No live report available yet.</p>
          <p className="mt-1 text-xs text-slate-400 break-all">{error}</p>
          <Link
            href="/ingest"
            className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-[var(--furix-accent,#c2703d)] px-4 py-2 text-sm font-medium text-white"
          >
            Ingest logs <ArrowUpRight className="h-4 w-4" />
          </Link>
        </div>
      )}

      {!loading && !error && frameworks && selectedFw && (
        <div className="space-y-5">
          {summary && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-slate-500">
              <span>
                {summary.total_logs} log(s) analysed · {summary.total_violations} violation(s)
              </span>
              {summary.population && (
                <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 px-2 py-0.5 text-xs dark:border-slate-700">
                  <span className="font-medium">Source completeness</span>
                  <span className="font-mono">
                    {summary.population.observed}/{summary.population.expected} observed
                    {summary.population.errored > 0 && ` · ${summary.population.errored} errored`}
                  </span>
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      summary.population.reconciled ? "bg-emerald-500" : "bg-amber-500"
                    }`}
                    title={summary.population.reconciled ? "population reconciled" : "population does not reconcile"}
                  />
                </span>
              )}
              <span className="font-mono text-xs">{summary.report_id.slice(0, 8)}</span>
            </div>
          )}
          <FrameworkRings frameworks={frameworks} selectedId={selected} onSelect={setSelected} />
          <ControlTable framework={selectedFw} />
        </div>
      )}
    </div>
  );
}
