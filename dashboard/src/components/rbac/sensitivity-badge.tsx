"use client";

import type { DataSensitivity } from "@/lib/rbac/permissions";
import { SENSITIVITY_META } from "@/lib/rbac/sensitivity";

type Props = {
  level: DataSensitivity;
  size?: "xs" | "sm";
  variant?: "chip" | "dot";
  title?: string;
};

/* Color-coded sensitivity badge — used on rows, KPIs, charts, page headers. */
export function SensitivityBadge({ level, size = "xs", variant = "chip", title }: Props) {
  const meta = SENSITIVITY_META[level];

  if (variant === "dot") {
    return (
      <span
        title={title ?? `${meta.label} data`}
        className="inline-block h-1.5 w-1.5 rounded-full"
        style={{ background: meta.dot, boxShadow: `0 0 4px ${meta.dot}` }}
      />
    );
  }

  const pad = size === "sm" ? "px-2 py-0.5 text-[10.5px]" : "px-1.5 py-px text-[9.5px]";
  return (
    <span
      title={title ?? `${meta.label} data`}
      className={`inline-flex items-center gap-1 rounded-sm font-bold uppercase tracking-wider ${pad}`}
      style={{
        background: meta.bg,
        color: meta.color,
        border: `1px solid ${meta.border}`,
        lineHeight: 1.1,
      }}
    >
      <span
        className="h-1 w-1 rounded-full"
        style={{ background: meta.dot, boxShadow: `0 0 3px ${meta.dot}` }}
      />
      {size === "sm" ? meta.label : meta.short}
    </span>
  );
}
