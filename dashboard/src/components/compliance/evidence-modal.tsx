"use client";

// Evidence viewer (FUR-CMP-007). Resolves a furix-evidence://<sha> URI through
// the BFF to its sealed original event + provenance envelope, and shows a live
// integrity verdict. Every open is recorded server-side in the admin audit log.

import { useEffect, useState, type ReactNode } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { ShieldCheck, ShieldAlert, Loader2, FileText, Lock, Clock, GitBranch, Hash } from "lucide-react";
import { getEvidence, evidenceSha, type EvidenceObject } from "@/lib/data/furix-api";

function prettyRaw(raw: string): string {
  const t = raw.trim();
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try {
      return JSON.stringify(JSON.parse(t), null, 2);
    } catch {
      /* not JSON — show as-is */
    }
  }
  return raw;
}

export function EvidenceModal({
  uri,
  open,
  onClose,
}: {
  uri: string | null;
  open: boolean;
  onClose: () => void;
}) {
  const [data, setData] = useState<EvidenceObject | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !uri) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    setData(null);
    getEvidence(uri)
      .then((d) => !cancelled && setData(d))
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [open, uri]);

  const sha = uri ? evidenceSha(uri) : "";
  const env = data?.envelope;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5 text-[var(--furix-accent,#c2703d)]" />
            Evidence
          </DialogTitle>
          <DialogDescription className="break-all font-mono text-[11px]">
            furix-evidence://{sha}
          </DialogDescription>
        </DialogHeader>

        <div className="max-h-[65vh] space-y-4 overflow-y-auto pr-2">
          {loading && (
            <div className="flex items-center gap-2 text-sm text-slate-500">
              <Loader2 className="h-4 w-4 animate-spin" /> Retrieving sealed evidence…
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <div className="font-medium">Could not load evidence</div>
                <div className="mt-0.5 break-all text-xs opacity-90">{error}</div>
              </div>
            </div>
          )}

          {data && env && (
            <>
              <div
                className={`flex items-center gap-2 rounded-lg border p-3 text-sm ${
                  data.integrity_verified
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    : "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300"
                }`}
              >
                {data.integrity_verified ? (
                  <ShieldCheck className="h-5 w-5 shrink-0" />
                ) : (
                  <ShieldAlert className="h-5 w-5 shrink-0" />
                )}
                <div>
                  <div className="font-medium">
                    {data.integrity_verified ? "Integrity verified" : "Integrity check FAILED"}
                  </div>
                  <div className="text-xs opacity-80">
                    {data.integrity_verified
                      ? "The stored bytes re-hash to this exact SHA-256 — untampered."
                      : "The stored bytes do not match the address — possible tampering."}
                  </div>
                </div>
              </div>

              <div>
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                  Original event
                </div>
                <pre className="max-h-64 overflow-auto rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs dark:border-slate-700 dark:bg-slate-900">
                  {prettyRaw(data.raw)}
                </pre>
              </div>

              <div>
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                  Provenance
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <Meta icon={<FileText className="h-3.5 w-3.5" />} label="Source" value={env.source} />
                  <Meta icon={<Hash className="h-3.5 w-3.5" />} label="Size" value={`${data.size_bytes} bytes`} />
                  <Meta icon={<Clock className="h-3.5 w-3.5" />} label="Observed at (event)" value={env.observed_at ?? "—"} />
                  <Meta icon={<Clock className="h-3.5 w-3.5" />} label="Collected at (ingest)" value={env.collected_at} />
                  <Meta icon={<GitBranch className="h-3.5 w-3.5" />} label="Collector / parser" value={`${env.collector_version} / ${env.parser_version}`} />
                  <Meta icon={<Lock className="h-3.5 w-3.5" />} label="Encrypted at rest" value={env.encryption?.encrypted ? "Yes (AES-256-GCM)" : "No"} />
                  <Meta icon={<FileText className="h-3.5 w-3.5" />} label="Tenant / boundary" value={`${env.tenant} / ${env.boundary}`} />
                  <Meta icon={<FileText className="h-3.5 w-3.5" />} label="Schema" value={env.schema_version} />
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 bg-slate-50 p-2 font-mono text-[10px] text-slate-500 dark:border-slate-700 dark:bg-slate-900">
                Content-addressed · write-once · this view was recorded in the admin audit log.
              </div>
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Meta({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md border border-slate-200 p-2 dark:border-slate-700">
      <div className="flex items-center gap-1.5 text-slate-400">
        {icon}
        <span>{label}</span>
      </div>
      <div className="mt-0.5 break-all font-medium text-slate-700 dark:text-slate-200">{value}</div>
    </div>
  );
}
