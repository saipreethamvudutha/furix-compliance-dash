"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Loader2, ArrowLeft, Save, GitBranch, ShieldCheck } from "lucide-react";
import { EvidenceLink } from "@/components/compliance/evidence-modal";
import {
  getControlWorkspace,
  updateControlProfile,
  type ControlDetail,
  type ControlProfilePatch,
} from "@/lib/data/furix-api";

const APPLICABILITY = ["applicable", "not_applicable", "inherited"];
const VERIFICATION = ["automated", "manual", "hybrid"];

function Chips({ items }: { items: string[] }) {
  if (!items.length) return <span className="text-xs text-slate-400">none</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((i) => (
        <span
          key={i}
          className="rounded-full border border-slate-300 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:border-slate-600 dark:text-slate-300"
        >
          {i}
        </span>
      ))}
    </div>
  );
}

export default function ControlDetailPage() {
  const params = useParams<{ controlId: string }>();
  const controlId = decodeURIComponent(params.controlId);
  const [d, setD] = useState<ControlDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [form, setForm] = useState<ControlProfilePatch>({});

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const detail = await getControlWorkspace(controlId);
      setD(detail);
      setForm({
        owner: detail.profile.owner,
        applicability: detail.profile.applicability,
        applicability_rationale: detail.profile.applicability_rationale,
        implementation_narrative: detail.profile.implementation_narrative,
        verification_method: detail.profile.verification_method,
        verification_description: detail.profile.verification_description,
        test_cadence_days: detail.profile.test_cadence_days,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [controlId]);

  useEffect(() => {
    load();
  }, [load]);

  async function save() {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      await updateControlProfile(controlId, form);
      setSaved(true);
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  function set<K extends keyof ControlProfilePatch>(k: K, v: ControlProfilePatch[K]) {
    setForm((f) => ({ ...f, [k]: v }));
    setSaved(false);
  }

  if (loading) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-8">
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading control…
        </div>
      </div>
    );
  }
  if (!d) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-8">
        <Link href="/compliance/controls" className="text-sm text-slate-500 hover:underline">
          ← back to workspace
        </Link>
        <p className="mt-4 text-sm text-rose-600">{error ?? "control not found"}</p>
      </div>
    );
  }

  const lin = d.evidence_lineage;
  const inputCls =
    "w-full rounded-md border border-slate-300 bg-transparent px-3 py-1.5 text-sm dark:border-slate-600";

  return (
    <div className="mx-auto max-w-4xl px-6 py-8">
      <Link
        href="/compliance/controls"
        className="inline-flex items-center gap-1 text-sm text-slate-500 hover:underline"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Control workspace
      </Link>

      <header className="mt-3 mb-6">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <ShieldCheck className="h-6 w-6" /> {d.control_id}
        </h1>
        <p className="mt-1 text-sm text-slate-500">{d.title}</p>
        <div className="mt-2 flex flex-wrap gap-2 text-xs">
          <span className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-600">
            status: <b>{d.status}</b>
          </span>
          <span className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-600">
            evidence: <b>{d.evidence_freshness}</b>
          </span>
          {d.last_assessed && (
            <span className="rounded-full border border-slate-300 px-2 py-0.5 dark:border-slate-600">
              last assessed: {new Date(d.last_assessed).toLocaleDateString()}
            </span>
          )}
        </div>
      </header>

      {error && (
        <div className="mb-4 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-300">
          {error}
        </div>
      )}

      {/* ── governance profile (editable) ── */}
      <section className="mb-6 rounded-xl border border-slate-200 p-5 dark:border-slate-700">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Governance profile
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm">
            <span className="mb-1 block text-slate-500">Owner</span>
            <input className={inputCls} value={form.owner ?? ""} onChange={(e) => set("owner", e.target.value)} />
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-slate-500">Applicability</span>
            <select
              className={inputCls}
              value={form.applicability ?? "applicable"}
              onChange={(e) => set("applicability", e.target.value)}
            >
              {APPLICABILITY.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm sm:col-span-2">
            <span className="mb-1 block text-slate-500">Applicability rationale</span>
            <input
              className={inputCls}
              value={form.applicability_rationale ?? ""}
              onChange={(e) => set("applicability_rationale", e.target.value)}
            />
          </label>
          <label className="text-sm sm:col-span-2">
            <span className="mb-1 block text-slate-500">Implementation narrative</span>
            <textarea
              className={`${inputCls} min-h-[80px]`}
              value={form.implementation_narrative ?? ""}
              onChange={(e) => set("implementation_narrative", e.target.value)}
            />
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-slate-500">Verification method</span>
            <select
              className={inputCls}
              value={form.verification_method ?? "automated"}
              onChange={(e) => set("verification_method", e.target.value)}
            >
              {VERIFICATION.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-slate-500">Test cadence (days)</span>
            <input
              type="number"
              min={1}
              className={inputCls}
              value={form.test_cadence_days ?? 90}
              onChange={(e) => set("test_cadence_days", Number(e.target.value))}
            />
          </label>
          <label className="text-sm sm:col-span-2">
            <span className="mb-1 block text-slate-500">Verification description</span>
            <input
              className={inputCls}
              value={form.verification_description ?? ""}
              onChange={(e) => set("verification_description", e.target.value)}
            />
          </label>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <button
            type="button"
            onClick={save}
            disabled={saving}
            className="inline-flex items-center gap-1.5 rounded-md bg-[var(--furix-accent,#c2703d)] px-4 py-2 text-sm font-medium text-white disabled:opacity-40"
          >
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save profile
          </button>
          {saved && <span className="text-sm text-emerald-600">Saved</span>}
          {d.profile.updated_by && (
            <span className="text-xs text-slate-400">
              last edited by {d.profile.updated_by}
            </span>
          )}
        </div>
      </section>

      {/* ── framework mappings ── */}
      <section className="mb-6 rounded-xl border border-slate-200 p-5 dark:border-slate-700">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Framework mappings
        </h2>
        <dl className="space-y-3 text-sm">
          <div className="flex items-start gap-4">
            <dt className="w-24 shrink-0 text-slate-500">NIST CSF</dt>
            <dd>
              <Chips items={d.framework_mappings.nist_csf} />
            </dd>
          </div>
          <div className="flex items-start gap-4">
            <dt className="w-24 shrink-0 text-slate-500">PCI DSS</dt>
            <dd>
              <Chips items={d.framework_mappings.pci_dss} />
            </dd>
          </div>
          <div className="flex items-start gap-4">
            <dt className="w-24 shrink-0 text-slate-500">HIPAA</dt>
            <dd>
              <Chips items={d.framework_mappings.hipaa} />
            </dd>
          </div>
        </dl>
      </section>

      {/* ── per-assertion evidence freshness ── */}
      {d.assertion_freshness && d.assertion_freshness.length > 0 && (
        <section className="mb-6 rounded-xl border border-slate-200 p-5 dark:border-slate-700">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Evidence freshness (per assertion) · oldest{" "}
            {d.oldest_evidence_at ? new Date(d.oldest_evidence_at).toLocaleDateString() : "—"}
          </h2>
          <ul className="space-y-2 text-sm">
            {d.assertion_freshness.map((a) => (
              <li key={a.spec_id} className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-xs">{a.spec_id}</span>
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[11px] ${
                      a.freshness?.stale
                        ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                        : "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    }`}
                  >
                    {a.freshness?.stale ? "stale" : "fresh"}
                  </span>
                  <span className="text-xs text-slate-500">
                    observed{" "}
                    {a.evidence[0]?.observed_at
                      ? new Date(a.evidence[0].observed_at).toLocaleDateString()
                      : "—"}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ── linked findings + exceptions ── */}
      <section className="mb-6 rounded-xl border border-slate-200 p-5 dark:border-slate-700">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">
          Linked findings ({d.linked_findings.length}) · exceptions ({d.exceptions.length})
        </h2>
        {d.linked_findings.length === 0 ? (
          <p className="text-sm text-slate-500">No findings linked to this control.</p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {d.linked_findings.map((f) => (
              <li key={f.finding_id} className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-slate-500">{f.finding_id.slice(0, 20)}…</span>
                <span className="rounded-full border border-slate-300 px-2 py-0.5 text-[11px] dark:border-slate-600">
                  {f.state}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* ── evidence lineage ── */}
      <section className="rounded-xl border border-slate-200 p-5 dark:border-slate-700">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
          <GitBranch className="h-3.5 w-3.5" /> Evidence lineage
        </h2>
        <dl className="grid gap-x-6 gap-y-2 font-mono text-[11px] sm:grid-cols-2">
          <div>
            <dt className="text-slate-400">report</dt>
            <dd className="truncate text-slate-700 dark:text-slate-200">{lin.report_id ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-slate-400">report integrity sha256</dt>
            <dd className="truncate text-slate-700 dark:text-slate-200">
              {lin.report_integrity_sha256?.slice(0, 24) ?? "—"}…
            </dd>
          </div>
          <div>
            <dt className="text-slate-400">config passing / failing</dt>
            <dd className="text-slate-700 dark:text-slate-200">
              {lin.config_passing.length} / {lin.config_failing.length}
            </dd>
          </div>
          <div>
            <dt className="text-slate-400">evidence mode</dt>
            <dd className="text-slate-700 dark:text-slate-200">{lin.evidence_mode ?? "—"}</dd>
          </div>
          {lin.posture_run && (
            <>
              <div>
                <dt className="text-slate-400">posture run</dt>
                <dd className="truncate text-slate-700 dark:text-slate-200">
                  {lin.posture_run.run_id} ({lin.posture_run.data_mode})
                </dd>
              </div>
              <div>
                <dt className="text-slate-400">snapshot evidence</dt>
                <dd className="truncate">
                  <EvidenceLink
                    uri={lin.posture_run.snapshot_uri || lin.posture_run.snapshot_sha256}
                    className="text-emerald-600 hover:underline dark:text-emerald-400"
                  >
                    {lin.posture_run.snapshot_sha256.slice(0, 24)}…
                  </EvidenceLink>
                </dd>
              </div>
            </>
          )}
        </dl>
      </section>
    </div>
  );
}
