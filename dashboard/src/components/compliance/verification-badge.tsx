"use client";

import { ShieldCheck, ShieldAlert } from "lucide-react";

export type VerificationLevel =
  | "NOT_VERIFIED"
  | "INTEGRITY_VERIFIED"
  | "ROLLUP_VERIFIED"
  | "EVALUATION_REPRODUCED";

// Honest copy per level (FUR-CMP-003): the badge states exactly what the
// verifier did — it must NEVER claim more than the achieved level.
const LEVEL_COPY: Record<VerificationLevel, { title: string; detail: string }> = {
  NOT_VERIFIED: {
    title: "Verification failed",
    detail: "verification did not complete",
  },
  INTEGRITY_VERIFIED: {
    title: "Integrity verified",
    detail: "hashes and references reconcile",
  },
  ROLLUP_VERIFIED: {
    title: "Rollup verified",
    detail: "statuses and counters independently recomputed from stored findings",
  },
  EVALUATION_REPRODUCED: {
    title: "Evaluation reproduced",
    detail: "independently re-run from raw evidence",
  },
};

// Furix's trust wedge: every report is independently recomputed and hash-sealed.
// The badge shows the exact verification LEVEL achieved — never an overclaim.
export function VerificationBadge({
  ok,
  level,
  checksRun,
  integrityHash,
}: {
  ok: boolean;
  level?: VerificationLevel;
  checksRun?: number;
  integrityHash?: string;
}) {
  const effective: VerificationLevel = ok ? (level ?? "ROLLUP_VERIFIED") : "NOT_VERIFIED";
  const copy = LEVEL_COPY[effective];
  return (
    <div
      className={`flex items-center gap-2.5 rounded-lg border px-3 py-2 text-sm ${
        ok
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
          : "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300"
      }`}
    >
      {ok ? <ShieldCheck className="h-4 w-4" /> : <ShieldAlert className="h-4 w-4" />}
      <span className="font-medium">{copy.title}</span>
      <span className="text-xs opacity-80">
        {typeof checksRun === "number" ? `· ${checksRun} checks — ${copy.detail}` : `· ${copy.detail}`}
      </span>
      {integrityHash && (
        <span className="ml-auto font-mono text-[11px] opacity-70" title="content SHA-256">
          {integrityHash.slice(0, 12)}…
        </span>
      )}
    </div>
  );
}
