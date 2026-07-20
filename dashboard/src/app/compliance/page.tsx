"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Loader2, ArrowUpRight, RefreshCw, ShieldCheck } from "lucide-react";
import { FrameworkRings } from "@/components/compliance/framework-rings";
import { ControlTable } from "@/components/compliance/control-table";
import { DataModeBadge, type DataMode } from "@/components/compliance/data-mode-badge";
import { getComplianceFrameworks } from "@/lib/data/compliance";
import { getLiveFrameworks, getLiveSummary, type ReportSummary } from "@/lib/data/furix-api";
import { apiHealthy } from "@/lib/data/client";
import type { ComplianceFramework } from "@/lib/data/types";

// One compliance domain (FUR-UX-001). It tries the live ingest engine first;
// if unreachable it falls back to DEMO seed data with a loud badge — a demo
// percentage is never silently presented as verified.
export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[] | null>(null);
  const [summary, setSummary] = useState<ReportSummary | null>(null);
  const [mode, setMode] = useState<DataMode>("loading");
  const [selected, setSelected] = useState("cis");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    try {
      const healthy = await apiHealthy();
      if (healthy) {
        const [fw, sum] = await Promise.all([getLiveFrameworks("latest"), getLiveSummary("latest")]);
        if (fw.length > 0) {
          const pop = sum.population;
          // live but incomplete/stale evidence → DEGRADED, not clean LIVE
          const degraded = Boolean(pop && pop.reconciled === false);
          setMode(degraded ? "degraded" : "live");
          setFrameworks(fw);
          setSummary(sum);
          setSelected(fw[0]?.id ?? "cis");
          return;
        }
      }
      // no engine / no report → demo seed
      setMode("demo");
      setSummary(null);
      const seed = await getComplianceFrameworks();
      setFrameworks(seed);
      setSelected(seed[0]?.id ?? "cis");
    } catch {
      setMode("demo");
      setSummary(null);
      const seed = await getComplianceFrameworks();
      setFrameworks(seed);
      setSelected(seed[0]?.id ?? "cis");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const selectedFw = frameworks?.find((f) => f.id === selected) ?? frameworks?.[0];
  const modeNote =
    mode === "live"
      ? `report ${summary?.report_id.slice(0, 8) ?? ""} · independently verified`
      : mode === "degraded"
        ? "incomplete or stale evidence in the latest report"
        : "engine not reachable — showing seed data";

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold">Compliance</h1>
            <DataModeBadge mode={mode} note={loading ? "checking engine…" : modeNote} />
          </div>
          <p className="mt-1 text-sm text-slate-500">
            CIS · NIST CSF · HIPAA · PCI DSS — SCF-derived, deterministically evaluated.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/compliance/controls"
            className="inline-flex items-center gap-1.5 rounded-md bg-[var(--furix-accent,#c2703d)] px-3 py-1.5 text-sm font-medium text-white"
          >
            <ShieldCheck className="h-3.5 w-3.5" /> Control workspace
          </Link>
          <button
            type="button"
            onClick={load}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50 dark:border-slate-600 dark:hover:bg-slate-800"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </header>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Checking the ingest engine…
        </div>
      )}

      {!loading && frameworks && selectedFw && (
        <div className="space-y-5">
          {mode === "demo" && (
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800/40 dark:text-slate-300">
              <div className="flex items-start gap-2">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                <div>
                  <b>Demo data.</b> The ingest engine isn’t reachable, so these figures are
                  illustrative seed values — not verified posture.{" "}
                  <Link href="/ingest" className="underline">
                    Ingest logs or a config snapshot
                  </Link>{" "}
                  to see live, independently-verified compliance.
                </div>
              </div>
            </div>
          )}

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
                  />
                </span>
              )}
              {summary.integrity_sha256 && (
                <span className="font-mono text-xs text-slate-400" title="content SHA-256">
                  ⛓ {summary.integrity_sha256.slice(0, 12)}…
                </span>
              )}
            </div>
          )}

          <FrameworkRings frameworks={frameworks} selectedId={selected} onSelect={setSelected} />
          <ControlTable framework={selectedFw} />
        </div>
      )}

      {!loading && !frameworks && (
        <div className="rounded-xl border border-slate-200 p-8 text-center dark:border-slate-700">
          <p className="text-sm text-slate-500">No compliance data available.</p>
          <Link
            href="/ingest"
            className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-[var(--furix-accent,#c2703d)] px-4 py-2 text-sm font-medium text-white"
          >
            Ingest logs <ArrowUpRight className="h-4 w-4" />
          </Link>
        </div>
      )}
    </div>
  );
}
