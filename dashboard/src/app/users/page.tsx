"use client";

import { PageShell } from "@/components/layout/page-shell";
import { Shield, KeyRound, Clock, Lock, UserPlus } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";
import { settingsSections } from "@/app/settings/page";

type Role = "analyst" | "compliance_admin" | "risk_analyst" | "executive_viewer" | "admin";
const roleTone: Record<Role, { bg: string; fg: string }> = {
  analyst:          { bg: "rgba(111,214,196,0.15)", fg: "#6fd6c4" },
  compliance_admin: { bg: "rgba(225,192,105,0.18)", fg: "#e1c069" },
  risk_analyst:     { bg: "rgba(224,160,99,0.18)",  fg: "#e0a063" },
  executive_viewer: { bg: "rgba(255,255,255,0.08)", fg: "var(--panel-text)" as any },
  admin:            { bg: "rgba(212,106,94,0.18)",  fg: "#d46a5e" },
};

const users: {
  email: string; role: Role; mfa: boolean; lastLogin: string; subnet: string;
  mfaFresh: boolean; tenant: string; status: "active" | "locked";
}[] = [
  { email: "infosec_lead@coventra.com",   role: "admin",            mfa: true,  lastLogin: "1m ago",   subnet: "10.10.5.0/24",  mfaFresh: true,  tenant: "Coventra HQ",  status: "active" },
  { email: "hipaa_officer@coventra.com",  role: "compliance_admin", mfa: true,  lastLogin: "2h ago",   subnet: "10.10.4.0/24",  mfaFresh: true,  tenant: "Coventra HQ",  status: "active" },
  { email: "soc_analyst_01@coventra.com", role: "analyst",          mfa: true,  lastLogin: "14m ago",  subnet: "10.10.5.0/24",  mfaFresh: true,  tenant: "Coventra HQ",  status: "active" },
  { email: "risk_analyst_01@coventra.com",role: "risk_analyst",     mfa: true,  lastLogin: "1d ago",   subnet: "10.10.4.0/24",  mfaFresh: false, tenant: "Coventra HQ",  status: "active" },
  { email: "audit_mgr_01@coventra.com",   role: "executive_viewer", mfa: false, lastLogin: "5d ago",   subnet: "—",             mfaFresh: false, tenant: "Coventra Audit",status: "active" },
  { email: "vendor_it_support@coventra.com",role: "analyst",        mfa: true,  lastLogin: "—",        subnet: "10.40.1.0/24",  mfaFresh: false, tenant: "Coventra HQ",  status: "locked" },
];

export default function UsersPage() {
  return (
    <PageShell drillTitle="Settings" sections={settingsSections}>
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Kpi label="Total Users" value="64" sub="Coventra HQ Columbus OH" tone="copper" />
        <Kpi label="MFA Enrolled" value="60 / 64" sub="93.7%" />
        <Kpi label="Active Sessions" value="48" sub="last 24h" tone="copper" />
        <Kpi label="Locked Accounts" value="1" sub="5+ fails / 5 min" />
      </div>

      {/* Policy panel */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <PolicyCard icon={<Shield />} label="MFA (TOTP)" value="REQUIRED" sec="SEC-1" />
        <PolicyCard icon={<KeyRound />} label="CSRF Double-Submit" value="ENFORCED" sec="SEC-3" />
        <PolicyCard icon={<Clock />} label="MFA Freshness" value="8 hours" sec="SEC-4" />
        <PolicyCard icon={<Lock />} label="Cookie HttpOnly+Secure" value="ON" sec="SEC-2" />
      </div>

      {/* Users table */}
      <div className="skeuo-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Users</h3>
          <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
            <UserPlus className="h-3.5 w-3.5" /> Add User
          </button>
        </div>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["Email", "Role", "Tenant", "MFA", "MFA Fresh (8h)", "IP Subnet", "Last Login", "Status", "Actions"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map((u, i) => (
                <tr key={u.email} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3 font-semibold">{u.email}</td>
                  <td className="px-3 py-3">
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                      style={{ background: roleTone[u.role].bg, color: roleTone[u.role].fg as string }}>
                      {u.role}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{u.tenant}</td>
                  <td className="px-3 py-3 text-[11px]" style={{ color: u.mfa ? "#6fd6c4" : "#d46a5e" }}>
                    {u.mfa ? "✓ TOTP" : "✗ Not enrolled"}
                  </td>
                  <td className="px-3 py-3 text-[11px]" style={{ color: u.mfaFresh ? "#6fd6c4" : "var(--panel-text-muted)" }}>
                    {u.mfaFresh ? "Fresh" : "Stale"}
                  </td>
                  <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{u.subnet}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{u.lastLogin}</td>
                  <td className="px-3 py-3 text-[11px]" style={{ color: u.status === "locked" ? "#d46a5e" : "#6fd6c4" }}>
                    {u.status}
                  </td>
                  <td className="px-3 py-3">
                    <div className="flex gap-1.5">
                      <RowBtn label="Revoke" />
                      <RowBtn label="Reset MFA" />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Multi-tenant via PostgreSQL Row-Level Security on <code>tenant_id</code> (SEC-7). 5+ auth fails in 5 min = automatic lock.
        </p>
      </div>
    </PageShell>
  );
}

function Kpi({ label, value, sub, tone = "teal" }: { label: string; value: string; sub: string; tone?: "teal" | "copper" }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[28px] font-light leading-none" style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}>{value}</p>
          <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}

function PolicyCard({ icon, label, value, sec }: { icon: React.ReactNode; label: string; value: string; sec: string }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center gap-2 mb-1" style={{ color: "var(--section-heading)" }}>
        <span className="[&_svg]:h-3.5 [&_svg]:w-3.5">{icon}</span>
        <p className="text-[11px] uppercase tracking-wider">{label}</p>
      </div>
      <p className="text-[18px] font-semibold" style={{ color: "var(--panel-text)" }}>{value}</p>
      <p className="text-[10px] font-mono mt-1" style={{ color: "#e0a063" }}>{sec}</p>
    </div>
  );
}

function RowBtn({ label }: { label: string }) {
  return (
    <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
      style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
      {label}
    </button>
  );
}
