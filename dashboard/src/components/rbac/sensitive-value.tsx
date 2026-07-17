"use client";

import { Lock } from "lucide-react";
import { useRole } from "@/lib/rbac/context";
import type { DataSensitivity } from "@/lib/rbac/permissions";
import {
  SENSITIVITY_META,
  canSeeSensitivity,
} from "@/lib/rbac/sensitivity";

type Props = {
  level: DataSensitivity;
  children: React.ReactNode;
  /** What to show when masked. Defaults to dots. */
  maskedAs?: "dots" | "lock" | "dash";
  /** Custom tooltip text. */
  title?: string;
  className?: string;
};

/* Wraps any value. If user's scope doesn't include `level`, renders a mask. */
export function SensitiveValue({
  level,
  children,
  maskedAs = "dots",
  title,
  className,
}: Props) {
  const { scopes, activeRole, jitActive } = useRole();
  const allowed = scopes[activeRole].sensitivities;
  const visible = canSeeSensitivity(allowed, level) || jitActive;
  const meta = SENSITIVITY_META[level];

  if (visible) return <span className={className}>{children}</span>;

  const tip =
    title ??
    `This value is ${meta.label}. Your role's scope doesn't include ${meta.label} data — request elevated access.`;

  if (maskedAs === "lock") {
    return (
      <span
        title={tip}
        className={`inline-flex items-center gap-1 ${className ?? ""}`}
        style={{ color: meta.color }}
      >
        <Lock className="h-3 w-3" /> {meta.label}
      </span>
    );
  }

  if (maskedAs === "dash") {
    return (
      <span
        title={tip}
        className={className}
        style={{ color: "var(--panel-text-muted)" }}
      >
        —
      </span>
    );
  }

  return (
    <span
      title={tip}
      className={`font-mono tracking-widest ${className ?? ""}`}
      style={{ color: meta.color, opacity: 0.85 }}
    >
      ••••••
    </span>
  );
}
