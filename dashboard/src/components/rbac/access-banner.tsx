"use client";

import { ShieldCheck } from "lucide-react";
import { useRole } from "@/lib/rbac/context";
import { ROLES } from "@/lib/rbac/permissions";
import {
  SENSITIVITY_META,
  maxAllowedSensitivity,
} from "@/lib/rbac/sensitivity";

/* Compact banner shown at the top of a page summarizing what the user can see. */
export function AccessBanner({ pageLabel }: { pageLabel?: string }) {
  const { activeRole, scopes, jitActive } = useRole();
  const allowed = scopes[activeRole].sensitivities;
  const max = maxAllowedSensitivity(allowed);
  const meta = SENSITIVITY_META[max];
  const role = ROLES[activeRole];

  return (
    <div
      className="mb-4 flex items-center gap-3 rounded-xl px-4 py-2.5"
      style={{
        background: "linear-gradient(180deg, var(--drilldown-grad-top), var(--drilldown-grad-bot))",
        border: `1px solid ${meta.border}`,
      }}
    >
      <ShieldCheck className="h-4 w-4" style={{ color: meta.color }} />
      <p className="text-[12px]" style={{ color: "var(--panel-text)" }}>
        {pageLabel ? <strong>{pageLabel}</strong> : null}
        {pageLabel ? " — " : ""}
        Viewing as{" "}
        <strong style={{ color: "var(--section-heading)" }}>{role.label}</strong>.
        You can see data classified up to{" "}
        <strong style={{ color: meta.color }}>{meta.label}</strong>.
        {jitActive && (
          <span style={{ color: "var(--crit-red)" }}>
            {" "}
            • Temporary Admin Mode is ON
          </span>
        )}
      </p>
      <span
        className="ml-auto rounded-sm px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider"
        style={{
          background: meta.bg,
          color: meta.color,
          border: `1px solid ${meta.border}`,
        }}
      >
        Scope: {meta.label}
      </span>
    </div>
  );
}
