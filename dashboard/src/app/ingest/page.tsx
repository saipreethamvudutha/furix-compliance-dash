"use client";

import { useState } from "react";
import { Upload, Play, Loader2, AlertTriangle, FileText, Wand2 } from "lucide-react";
import { FrameworkRings } from "@/components/compliance/framework-rings";
import { ControlTable } from "@/components/compliance/control-table";
import { VerificationBadge } from "@/components/compliance/verification-badge";
import { severityColor } from "@/components/compliance/status";
import {
  ingestLogs,
  ingestFile,
  generateAndIngest,
  pollJob,
  type IngestResult,
  type JobRef,
  type JobStatus,
} from "@/lib/data/furix-api";

const LOG_TYPES = [
  "auto", "cloudtrail", "windows_evtx", "syslog", "okta_sso",
  "azure_ad", "gcp_audit", "wazuh_siem", "microsoft_defender", "o365", "nmap",
];

const SAMPLE = `{"eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Success"},"additionalEventData":{"MFAUsed":"No"},"sourceIPAddress":"45.33.32.156"}
{"eventName":"CreateUser","requestParameters":{"userName":"backdoor_admin"},"sourceIPAddress":"45.33.32.156"}
{"eventName":"AttachUserPolicy","requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","userName":"backdoor_admin"},"sourceIPAddress":"45.33.32.156"}
{"eventName":"GetSecretValue","requestParameters":{"secretId":"prod/db/password"},"sourceIPAddress":"45.33.32.156"}`;

export default function IngestPage() {
  const [text, setText] = useState("");
  const [logType, setLogType] = useState("auto");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);
  const [selected, setSelected] = useState<string>("cis");
  const [progress, setProgress] = useState<JobStatus | null>(null);

  async function run(submit: () => Promise<JobRef>) {
    setBusy(true);
    setError(null);
    setResult(null);
    setProgress(null);
    try {
      const { job_id } = await submit();
      const final = await pollJob(job_id, (j) => setProgress(j));
      if (final.status === "error" || !final.result) {
        throw new Error(final.error || "ingest failed");
      }
      setResult(final.result);
      setSelected(final.result.frameworks[0]?.id ?? "cis");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  const selectedFw = result?.frameworks.find((f) => f.id === selected) ?? result?.frameworks[0];

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold">Ingest Logs</h1>
        <p className="mt-1 text-sm text-slate-500">
          Paste or upload security logs. Furix maps them to CIS · NIST CSF · HIPAA · PCI DSS
          deterministically, then independently verifies the report.
        </p>
      </header>

      <div className="rounded-xl border border-slate-200 p-4 dark:border-slate-700">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="text-xs font-medium text-slate-500">Log type</label>
          <select
            value={logType}
            onChange={(e) => setLogType(e.target.value)}
            className="rounded-md border border-slate-300 bg-transparent px-2 py-1 text-sm dark:border-slate-600"
          >
            {LOG_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => setText(SAMPLE)}
            className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-50 dark:border-slate-600 dark:hover:bg-slate-800"
          >
            <FileText className="h-3.5 w-3.5" /> Load sample
          </button>
        </div>

        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste logs — one event per line…"
          rows={10}
          className="w-full resize-y rounded-lg border border-slate-300 bg-transparent p-3 font-mono text-xs outline-none focus:border-[var(--furix-accent,#c2703d)] dark:border-slate-600"
        />

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={busy || !text.trim()}
            onClick={() => run(() => ingestLogs(text, logType))}
            className="inline-flex items-center gap-2 rounded-md bg-[var(--furix-accent,#c2703d)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {busy ? "Analyzing…" : "Ingest"}
          </button>

          <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-slate-300 px-4 py-2 text-sm hover:bg-slate-50 dark:border-slate-600 dark:hover:bg-slate-800">
            <Upload className="h-4 w-4" />
            Upload file
            <input
              type="file"
              className="hidden"
              disabled={busy}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) run(() => ingestFile(f, logType));
              }}
            />
          </label>

          <button
            type="button"
            disabled={busy}
            onClick={() => run(() => generateAndIngest(50, 0.35, Math.floor(Math.random() * 100000)))}
            className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-4 py-2 text-sm hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:hover:bg-slate-800"
            title="Generate 50 synthetic logs and ingest them"
          >
            <Wand2 className="h-4 w-4" />
            Generate demo logs
          </button>

          <span className="text-xs text-slate-400">
            {text.trim() ? `${text.trim().split("\n").length} line(s)` : "no input"}
          </span>
        </div>

        {busy && progress && (
          <div className="mt-3 rounded-lg border border-slate-200 p-3 dark:border-slate-700">
            <div className="mb-1.5 flex items-center justify-between text-xs">
              <span className="font-medium capitalize">{progress.phase}…</span>
              <span className="font-mono text-slate-500">
                {progress.total > 0
                  ? `${progress.processed.toLocaleString()} / ${progress.total.toLocaleString()} logs · ${progress.percent}%`
                  : "starting…"}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
              <div
                className="h-full rounded-full bg-[var(--furix-accent,#c2703d)] transition-all duration-300"
                style={{ width: `${Math.max(2, progress.percent)}%` }}
              />
            </div>
          </div>
        )}

        {error && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <div className="font-medium">Ingest failed</div>
              <div className="mt-0.5 break-all text-xs opacity-90">{error}</div>
              <div className="mt-1 text-xs opacity-70">
                Is the Furix API running? Set <code>NEXT_PUBLIC_API_URL</code> to its address.
              </div>
            </div>
          </div>
        )}
      </div>

      {result && selectedFw && (
        <section className="mt-8 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">
              Compliance posture
              <span className="ml-2 text-sm font-normal text-slate-500">
                {result.lines_ingested} log(s) · {result.summary.total_violations} violation(s)
              </span>
            </h2>
            <VerificationBadge
              ok={result.verification.ok}
              checksRun={result.verification.checks_run}
              integrityHash={result.summary.integrity_sha256}
            />
          </div>

          <FrameworkRings frameworks={result.frameworks} selectedId={selected} onSelect={setSelected} />

          {result.alerts.length > 0 && (
            <div className="rounded-xl border border-amber-400/30 bg-amber-400/5 p-4">
              <div className="mb-2 text-sm font-medium">Regression alerts ({result.alerts.length})</div>
              <ul className="space-y-1 text-sm">
                {result.alerts.map((a, i) => (
                  <li key={i} className="flex gap-2">
                    <span className={`font-mono text-xs uppercase ${severityColor(a.severity)}`}>
                      {a.severity}
                    </span>
                    <span className="text-slate-600 dark:text-slate-300">{a.message}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <ControlTable framework={selectedFw} />
        </section>
      )}
    </div>
  );
}
