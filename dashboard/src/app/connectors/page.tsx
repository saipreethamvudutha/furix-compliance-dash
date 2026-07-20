"use client";

import { useEffect, useState } from "react";
import { Loader2, RefreshCw, Plug, Play, ShieldCheck, ShieldAlert, CircleHelp } from "lucide-react";
import { DataModeBadge, type DataMode } from "@/components/compliance/data-mode-badge";
import { apiHealthy } from "@/lib/data/client";
import {
  getConnectors,
  registerConnector,
  runConnector,
  type Connector,
} from "@/lib/data/furix-api";

// Connector health (Wave-G): scheduled collection connectors (e.g. the AWS
// Organizations/IAM collector) with last-run outcome, population reconciliation,
// signed-manifest status and a derived health state — sourced live from the
// engine via the BFF. No invented connectors when the engine is unreachable.

const HEALTH_STYLE: Record<string, string> = {
  healthy: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  degraded: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  failed: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  unknown: "border-slate-400/30 bg-slate-500/10 text-slate-500 dark:text-slate-300",
};

function HealthIcon({ health }: { health: string }) {
  if (health === "healthy") return <ShieldCheck className="h-4 w-4" />;
  if (health === "failed" || health === "degraded") return <ShieldAlert className="h-4 w-4" />;
  return <CircleHelp className="h-4 w-4" />;
}

function fmt(iso?: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function ConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[] | null>(null);
  const [mode, setMode] = useState<DataMode>("loading");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      if (!(await apiHealthy())) {
        setMode("demo");
        setConnectors([]);
        return;
      }
      setConnectors(await getConnectors());
      setMode("live");
    } catch (e) {
      setMode("demo");
      setConnectors([]);
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function onRegisterDemo() {
    setBusy("register");
    setError(null);
    try {
      await registerConnector("demo-aws", "demo-aws", 86400);
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function onRun(id: string) {
    setBusy(id);
    setError(null);
    try {
      await runConnector(id);
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  const list = connectors ?? [];

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="flex items-center gap-2 text-2xl font-semibold">
              <Plug className="h-6 w-6" /> Connectors
            </h1>
            <DataModeBadge
              mode={mode}
              note={
                loading
                  ? "checking engine…"
                  : mode === "live"
                    ? `${list.length} connector${list.length === 1 ? "" : "s"} · scheduled collection`
                    : "engine not reachable"
              }
            />
          </div>
          <p className="mt-1 max-w-2xl text-sm text-slate-500">
            Scheduled cloud collectors. Each run reconciles the observed population against an
            independently-derived expected count and attaches a mandatory signed manifest —
            health reflects reconciliation, signature and freshness.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRegisterDemo}
            disabled={mode !== "live" || busy !== null}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50 disabled:opacity-40 dark:border-slate-600 dark:hover:bg-slate-800"
          >
            <Plug className="h-3.5 w-3.5" /> Add demo connector
          </button>
          <button
            type="button"
            onClick={load}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50 dark:border-slate-600 dark:hover:bg-slate-800"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </header>

      {error && (
        <div className="mb-4 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading connectors…
        </div>
      )}

      {!loading && mode === "demo" && (
        <div className="rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-500 dark:border-slate-700">
          The ingest engine isn&rsquo;t reachable, so there are no live connectors to show.
        </div>
      )}

      {!loading && mode === "live" && list.length === 0 && (
        <div className="rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-500 dark:border-slate-700">
          No connectors configured yet. Add the demo AWS connector to see the collection +
          health workflow, or register a live <code>aws-org-iam</code> connector via the API.
        </div>
      )}

      {!loading && mode === "live" && list.length > 0 && (
        <div className="space-y-3">
          {list.map((c) => (
            <div
              key={c.connector_id}
              className="rounded-xl border border-slate-200 p-4 dark:border-slate-700"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm font-semibold">{c.connector_id}</span>
                  <span className="rounded-full border border-slate-300 px-2 py-0.5 text-[11px] uppercase tracking-wide text-slate-500 dark:border-slate-600">
                    {c.kind}
                  </span>
                  <span
                    className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
                      HEALTH_STYLE[c.health] ?? HEALTH_STYLE.unknown
                    }`}
                  >
                    <HealthIcon health={c.health} /> {c.health}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => onRun(c.connector_id)}
                  disabled={busy !== null}
                  className="inline-flex items-center gap-1.5 rounded-md bg-[var(--furix-accent,#c2703d)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40"
                >
                  {busy === c.connector_id ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Play className="h-3.5 w-3.5" />
                  )}
                  Run now
                </button>
              </div>

              <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-4">
                <div>
                  <dt className="text-slate-400">Last run</dt>
                  <dd className="text-slate-700 dark:text-slate-200">{fmt(c.last_run_at_iso)}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Next run</dt>
                  <dd className="text-slate-700 dark:text-slate-200">{fmt(c.next_run_at_iso)}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Reconciled</dt>
                  <dd className={c.last_reconciled ? "text-emerald-600" : "text-amber-600"}>
                    {c.last_status ? (c.last_reconciled ? "yes" : "no") : "—"}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400">Manifest signed</dt>
                  <dd className={c.last_signed ? "text-emerald-600" : "text-amber-600"}>
                    {c.last_status ? (c.last_signed ? "yes" : "no") : "—"}
                  </dd>
                </div>
              </dl>

              {c.last_error && (
                <p className="mt-2 rounded-md bg-rose-500/10 px-2 py-1 font-mono text-[11px] text-rose-600 dark:text-rose-300">
                  {c.last_error}
                </p>
              )}
              {c.last_manifest_sha && (
                <p className="mt-2 font-mono text-[11px] text-slate-400">
                  manifest sha256: {c.last_manifest_sha}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
