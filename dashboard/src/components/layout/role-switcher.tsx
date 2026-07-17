"use client";

import { useRole } from "@/lib/rbac/context";
import { ROLES, type RoleId } from "@/lib/rbac/permissions";
import { Shield, Search, FileCheck2, Network } from "lucide-react";

const ICONS: Record<RoleId, React.ReactNode> = {
  admin: <Shield className="h-3.5 w-3.5" />,
  analyst: <Search className="h-3.5 w-3.5" />,
  auditor: <FileCheck2 className="h-3.5 w-3.5" />,
  mssp: <Network className="h-3.5 w-3.5" />,
};

export function RoleSwitcher() {
  const { activeRole } = useRole();
  const r = ROLES[activeRole];

  return (
    <div
      className="flex items-center gap-2 rounded-xl px-3 py-1.5"
      style={{
        background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
        color: "var(--disc-text)",
        border: "1px solid rgba(224,160,99,0.45)",
        boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5), 0 0 10px rgba(224,160,99,0.3)",
      }}
      title={`Signed in as ${r.label}`}
    >
      {ICONS[activeRole]}
      <span className="text-[11px] font-semibold uppercase tracking-wide">{r.label}</span>
    </div>
  );
}
