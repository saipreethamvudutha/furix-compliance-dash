"use client";

// Evidence-access audit view (FUR-CMP-008). Read-only surface over the
// evidence.* entries in the tamper-evident admin audit log: who viewed evidence,
// and who placed/released legal holds. Export scope (auditor/admin).

import { useEffect, useState } from "react";
import { Loader2, ScrollText, ShieldCheck, ShieldAlert, Scale } from "lucide-react";
import { EvidenceLink } from "@/components/compliance/evidence-modal";
import { getEvidenceAccessLog, type EvidenceAccessEntry } from "@/lib/data/furix-api";

const ACTION_LABEL: Record<string, string> = {
  "evidence.access": "viewed",
  "evidence.legal_hold.place": "placed hold",
  "evidence.legal_hold.release": "released hold",
};

function ActionBadge({ action }: { action: string }) {
  const label = ACTION_LABEL[action] ?? action;
  const isHold = action.includes("legal_hold");
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${
        isHold
          ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
          : "border-slate-400/30 bg-slate-500/10 text-slate-600 dark:text-slate-300"
      }`}
    >
      {isHold ? <Scale className="h-3 w-3" /> : null}
      {label}
    </span>
  );
}

function DetailCell({ details, action }: { details: Record<string, unknown>; action: string }) {
  if (action === "evidence.access") {
    const ok = details?.integrity_verified;
    return (
      <span className="inline-flex items-center gap-1">
        {ok ? (
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
        ) : (
          <ShieldAlert className="h-3.5 w-3.5 text-rose-600" />
        )}
        {ok ? "integrity ok" : "integrity FAIL"}
        {details?.source ? <span className="opacity-60">· {String(details.source)}</span> : null}
      </span>
    );
  }
  if (details?.reason) return <span>reason: {String(details.reason)}</span>;
  return <span className="opacity-50">—</span>;
}

export default function EvidenceAccessPage() {
  const [rows, setRows] = useState<EvidenceAccessEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getEvidenceAccessLog(300)
      .then(setRows)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <header className="mb-6">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <ScrollText className="h-6 w-6 text-[var(--furix-accent,#c2703d)]" />
          Evidence Access Log
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          Every time evidence is viewed, or a legal hold is placed or released, it is
          recorded in the tamper-evident admin audit log — a &ldquo;who touched which
          evidence, when&rdquo; trail auditors require.
        </p>
      </header>

      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <div className="font-medium">Could not load the access log</div>
            <div className="mt-0.5 break-all text-xs opacity-90">{error}</div>
          </div>
        </div>
      )}

      {!rows && !error && (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      )}

      {rows && rows.length === 0 && (
        <div className="rounded-lg border border-slate-200 p-6 text-center text-sm text-slate-500 dark:border-slate-700">
          No evidence has been accessed yet. Open an evidence chip on the Compliance
          page and it will appear here.
        </div>
      )}

      {rows && rows.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 dark:bg-slate-800/50">
              <tr>
                <th className="px-4 py-2.5 font-medium">When (UTC)</th>
                <th className="px-4 py-2.5 font-medium">Actor</th>
                <th className="px-4 py-2.5 font-medium">Action</th>
                <th className="px-4 py-2.5 font-medium">Evidence</th>
                <th className="px-4 py-2.5 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.seq} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-slate-500">
                    {r.at.replace("T", " ").replace("+00:00", "")}
                  </td>
                  <td className="px-4 py-2.5">{r.actor}</td>
                  <td className="px-4 py-2.5">
                    <ActionBadge action={r.action} />
                  </td>
                  <td className="px-4 py-2.5">
                    {r.target ? (
                      <EvidenceLink
                        uri={r.target}
                        className="font-mono text-[11px] text-emerald-600 hover:underline dark:text-emerald-400"
                      >
                        {r.target.slice(0, 16)}…
                      </EvidenceLink>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">
                    <DetailCell details={r.details} action={r.action} />
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
