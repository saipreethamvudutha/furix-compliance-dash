"use client";

import { useEffect, useState } from "react";
import { Loader2, RefreshCw, FileCheck2, Lock, LockOpen, Download, Plus } from "lucide-react";
import { DataModeBadge, type DataMode } from "@/components/compliance/data-mode-badge";
import { apiHealthy } from "@/lib/data/client";
import {
  addEvidenceRequest,
  auditPackageUrl,
  createAuditPeriod,
  listAuditPeriods,
  reopenAuditPeriod,
  signoffAuditPeriod,
  type AuditPeriod,
} from "@/lib/data/furix-api";

const STATUS_STYLE: Record<string, string> = {
  open: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  in_review: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  signed_off: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  reopened: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
};

export default function AuditPage() {
  const [periods, setPeriods] = useState<AuditPeriod[] | null>(null);
  const [mode, setMode] = useState<DataMode>("loading");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", boundary: "", start_date: "", end_date: "" });

  async function load() {
    setLoading(true);
    setError(null);
    try {
      if (!(await apiHealthy())) {
        setMode("demo");
        setPeriods([]);
        return;
      }
      setPeriods(await listAuditPeriods());
      setMode("live");
    } catch (e) {
      setMode("demo");
      setPeriods([]);
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function act(id: string, fn: () => Promise<unknown>) {
    setBusy(id);
    setError(null);
    try {
      await fn();
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function onCreate() {
    if (!form.name || !form.start_date || !form.end_date) {
      setError("name, start and end dates are required");
      return;
    }
    await act("create", () => createAuditPeriod(form));
    setForm({ name: "", boundary: "", start_date: "", end_date: "" });
  }

  const list = periods ?? [];
  const inputCls =
    "rounded-md border border-slate-300 bg-transparent px-2 py-1.5 text-sm dark:border-slate-600";

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="flex items-center gap-2 text-2xl font-semibold">
              <FileCheck2 className="h-6 w-6" /> Audit periods
            </h1>
            <DataModeBadge
              mode={mode}
              note={loading ? "loading…" : mode === "live" ? `${list.length} periods` : "engine not reachable"}
            />
          </div>
          <p className="mt-1 max-w-2xl text-sm text-slate-500">
            Formal assessment windows with a scope boundary, evidence requests, reviewer sign-off,
            and freeze/reopen. Sign-off captures an immutable, content-addressed snapshot; the
            downloadable ZIP is auditor-only.
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

      {error && (
        <div className="mb-4 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      {mode === "live" && (
        <div className="mb-6 rounded-xl border border-slate-200 p-4 dark:border-slate-700">
          <div className="mb-3 flex flex-wrap items-end gap-3">
            <label className="text-xs">
              <span className="mb-1 block text-slate-500">Name</span>
              <input className={inputCls} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Q3 2026 CIS" />
            </label>
            <label className="text-xs">
              <span className="mb-1 block text-slate-500">Boundary</span>
              <input className={inputCls} value={form.boundary} onChange={(e) => setForm({ ...form, boundary: e.target.value })} placeholder="prod AWS · CIS v8" />
            </label>
            <label className="text-xs">
              <span className="mb-1 block text-slate-500">Start</span>
              <input type="date" className={inputCls} value={form.start_date} onChange={(e) => setForm({ ...form, start_date: e.target.value })} />
            </label>
            <label className="text-xs">
              <span className="mb-1 block text-slate-500">End</span>
              <input type="date" className={inputCls} value={form.end_date} onChange={(e) => setForm({ ...form, end_date: e.target.value })} />
            </label>
            <button
              type="button"
              onClick={onCreate}
              disabled={busy !== null}
              className="inline-flex items-center gap-1.5 rounded-md bg-[var(--furix-accent,#c2703d)] px-3 py-2 text-sm font-medium text-white disabled:opacity-40"
            >
              <Plus className="h-3.5 w-3.5" /> New period
            </button>
          </div>
        </div>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      )}

      {!loading && mode === "live" && list.length === 0 && (
        <div className="rounded-xl border border-slate-200 p-8 text-center text-sm text-slate-500 dark:border-slate-700">
          No audit periods yet. Create one above to begin an assessment window.
        </div>
      )}

      <div className="space-y-3">
        {list.map((p) => (
          <div key={p.period_id} className="rounded-xl border border-slate-200 p-4 dark:border-slate-700">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <span className="font-semibold">{p.name}</span>
                <span
                  className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase ${
                    STATUS_STYLE[p.status] ?? STATUS_STYLE.open
                  }`}
                >
                  {p.frozen ? <Lock className="h-3 w-3" /> : <LockOpen className="h-3 w-3" />}
                  {p.status}
                </span>
                <span className="text-xs text-slate-500">
                  {p.start_date} → {p.end_date} · {p.boundary || "no boundary"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {!p.frozen ? (
                  <button
                    type="button"
                    onClick={() => act(p.period_id, () => signoffAuditPeriod(p.period_id))}
                    disabled={busy !== null}
                    className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40"
                  >
                    <Lock className="h-3.5 w-3.5" /> Sign off &amp; freeze
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => act(p.period_id, () => reopenAuditPeriod(p.period_id, "reopened from UI"))}
                    disabled={busy !== null}
                    className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm dark:border-slate-600"
                  >
                    <LockOpen className="h-3.5 w-3.5" /> Reopen
                  </button>
                )}
                <a
                  href={auditPackageUrl(p.period_id)}
                  className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50 dark:border-slate-600 dark:hover:bg-slate-800"
                >
                  <Download className="h-3.5 w-3.5" /> ZIP
                </a>
              </div>
            </div>

            <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
              <div>
                <dt className="text-slate-400">Evidence requests</dt>
                <dd className="text-slate-700 dark:text-slate-200">{p.evidence_requests.length}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Sign-offs</dt>
                <dd className="text-slate-700 dark:text-slate-200">{p.signoffs.length}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Reopenings</dt>
                <dd className="text-slate-700 dark:text-slate-200">{p.reopenings.length}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Created by</dt>
                <dd className="text-slate-700 dark:text-slate-200">{p.created_by}</dd>
              </div>
            </dl>

            {p.signoffs.length > 0 && (
              <p className="mt-2 font-mono text-[11px] text-slate-400">
                signed snapshot sha256: {p.signoffs[p.signoffs.length - 1].snapshot_sha256.slice(0, 32)}…
              </p>
            )}

            {!p.frozen && (
              <EvidenceRequestForm
                disabled={busy !== null}
                onAdd={(cid, note) => act(p.period_id, () => addEvidenceRequest(p.period_id, cid, note))}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function EvidenceRequestForm({
  onAdd,
  disabled,
}: {
  onAdd: (controlId: string, note: string) => void;
  disabled: boolean;
}) {
  const [cid, setCid] = useState("");
  const [note, setNote] = useState("");
  const inputCls =
    "rounded-md border border-slate-300 bg-transparent px-2 py-1 text-xs dark:border-slate-600";
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3 dark:border-slate-800">
      <input className={inputCls} value={cid} onChange={(e) => setCid(e.target.value)} placeholder="Control 6" />
      <input className={`${inputCls} flex-1`} value={note} onChange={(e) => setNote(e.target.value)} placeholder="what evidence to request…" />
      <button
        type="button"
        disabled={disabled || !cid}
        onClick={() => {
          onAdd(cid, note);
          setCid("");
          setNote("");
        }}
        className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-1 text-xs disabled:opacity-40 dark:border-slate-600"
      >
        <Plus className="h-3 w-3" /> Request evidence
      </button>
    </div>
  );
}
