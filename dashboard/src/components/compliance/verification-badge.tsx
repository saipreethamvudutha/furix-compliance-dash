"use client";

import { ShieldCheck, ShieldAlert } from "lucide-react";

// Furix's trust wedge: every report is independently recomputed and hash-sealed.
// No black-box SaaS competitor can show this. Make it prominent.
export function VerificationBadge({
  ok,
  checksRun,
  integrityHash,
}: {
  ok: boolean;
  checksRun?: number;
  integrityHash?: string;
}) {
  return (
    <div
      className={`flex items-center gap-2.5 rounded-lg border px-3 py-2 text-sm ${
        ok
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
          : "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300"
      }`}
    >
      {ok ? <ShieldCheck className="h-4 w-4" /> : <ShieldAlert className="h-4 w-4" />}
      <span className="font-medium">
        {ok ? "Independently verified" : "Verification failed"}
      </span>
      {typeof checksRun === "number" && (
        <span className="text-xs opacity-80">· {checksRun} checks recomputed from raw logs</span>
      )}
      {integrityHash && (
        <span className="ml-auto font-mono text-[11px] opacity-70" title="content SHA-256">
          {integrityHash.slice(0, 12)}…
        </span>
      )}
    </div>
  );
}
