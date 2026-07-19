"use client";

import { EyeOff } from "lucide-react";
import { useRole } from "@/lib/rbac/context";

type Props = {
  count: number;
  resourceLabel?: string; // e.g. "assets", "rows", "findings"
  onRequest?: () => void;
};

/* Footer notice shown when scope filtering hid records from the list. */
export function HiddenItemsNotice({ count, resourceLabel = "items", onRequest }: Props) {
  const { elevate, tiers, activeRole, jitActive } = useRole();
  if (count <= 0) return null;

  const handle =
    onRequest ??
    (() => {
      if (tiers[activeRole].jitMinutes > 0) elevate();
    });

  return (
    <div
      className="mt-3 flex items-center gap-2 rounded-lg px-3 py-2"
      style={{
        background: "rgba(212,106,94,0.08)",
        border: "1px dashed rgba(212,106,94,0.35)",
      }}
    >
      <EyeOff className="h-3.5 w-3.5" style={{ color: "var(--crit-red)" }} />
      <p className="text-[11.5px]" style={{ color: "var(--panel-text)" }}>
        <strong>{count}</strong> {resourceLabel} hidden because your role&rsquo;s scope
        doesn&rsquo;t include the required data sensitivity.
      </p>
      {!jitActive && (
        <button
          onClick={handle}
          className="ml-auto rounded-md px-2.5 py-1 text-[10.5px] font-semibold"
          style={{
            background: "rgba(255,255,255,0.06)",
            color: "var(--panel-text)",
            border: "1px solid var(--row-border)",
          }}
        >
          Request elevated access
        </button>
      )}
    </div>
  );
}
