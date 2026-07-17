"use client";

import { useEffect, useState } from "react";
import {
  User as UserIcon,
  Mail,
  Shield,
  Clock,
  KeyRound,
  Smartphone,
  LogIn,
  Activity,
  CheckCircle2,
  Globe,
  Building2,
  ChevronRight,
  Lock,
} from "lucide-react";
import { useRole } from "@/lib/rbac/context";
import { ROLES } from "@/lib/rbac/permissions";

function Section({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="skeuo-panel p-5">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>{title}</h3>
        {right}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2" style={{ borderTop: "1px solid var(--row-border)" }}>
      <span className="text-[11.5px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</span>
      <span className={`text-[12.5px] ${mono ? "font-mono" : "font-semibold"}`} style={{ color: "var(--panel-text)" }}>{value}</span>
    </div>
  );
}

export default function ProfilePage() {
  const { activeRole } = useRole();
  const [email, setEmail] = useState("admin@byoc.com");
  const [roleLabel, setRoleLabel] = useState(ROLES[activeRole].label);

  useEffect(() => {
    try {
      const e = localStorage.getItem("byoc-user-email");
      const r = localStorage.getItem("byoc-user-role");
      if (e) setEmail(e);
      if (r) setRoleLabel(r);
    } catch {}
  }, []);

  const initials = roleLabel.split(/\s+/).map((p) => p[0]).filter(Boolean).slice(0, 2).join("").toUpperCase();
  const accentByRole = ROLES[activeRole].accent;

  return (
    <main className="px-6 py-6">
      {/* identity + quick stats — single row */}
      <div className="mb-5 grid grid-cols-12 gap-4">
        <div
          className="col-span-4 flex items-center gap-3 rounded-2xl px-4 py-3"
          style={{
            background: "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
            border: "1px solid rgba(224,160,99,0.25)",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05), inset 0 -2px 6px rgba(0,0,0,0.35)",
          }}
        >
          <div
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-[14px] font-bold"
            style={{
              background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 75%)",
              color: "var(--disc-text)",
              boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
            }}
          >
            {initials}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h1 className="truncate text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>{roleLabel}</h1>
              <span className="rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide"
                style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>
                ● Active
              </span>
            </div>
            <p className="truncate text-[11.5px] font-mono" style={{ color: "var(--panel-text-muted)" }}>{email}</p>
          </div>
        </div>

        <div className="col-span-2"><StatCard label="Sessions (30d)" value="42" icon={<LogIn className="h-full w-full" />} /></div>
        <div className="col-span-2"><StatCard label="Last Login" value="2m ago" icon={<Clock className="h-full w-full" />} tone="copper" /></div>
        <div className="col-span-2"><StatCard label="MFA Status" value="Enrolled" icon={<Smartphone className="h-full w-full" />} /></div>
        <div className="col-span-2"><StatCard label="Permissions" value={ROLES[activeRole].label.split(" ")[0]} icon={<Shield className="h-full w-full" />} tone="copper" /></div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Account */}
        <Section
          title="Account"
          right={<button className="text-[11px] font-semibold" style={{ color: "var(--section-heading)" }}>Edit →</button>}
        >
          <Row label="Email" value={email} mono />
          <Row label="Role" value={roleLabel} />
          <Row label="Tenant" value="Coventra Health Insurance" />
          <Row label="Department" value={activeRole === "auditor" ? "Compliance" : activeRole === "analyst" ? "Security Operations" : "Office of the CISO"} />
          <Row label="Member Since" value="Mar 12, 2024" mono />
          <Row label="User ID" value={`usr_${activeRole}_${initials.toLowerCase()}01`} mono />
        </Section>

        {/* Security */}
        <Section title="Security">
          <Row label="MFA (TOTP)" value={<span className="flex items-center gap-1" style={{ color: "#6fd6c4" }}><CheckCircle2 className="h-3.5 w-3.5" /> Enrolled</span>} />
          <Row label="MFA Freshness" value={<span style={{ color: "#6fd6c4" }}>Fresh (8h window)</span>} />
          <Row label="Hardware Key" value={<span style={{ color: "var(--panel-text-muted)" }}>Not registered</span>} />
          <Row label="Password Age" value={<span className="font-mono">38 days</span>} mono />
          <Row label="Last Rotation" value="May 03, 2026" mono />
          <Row label="IP Subnet Bind" value="10.10.5.0/24" mono />
          <div className="mt-3 flex gap-2">
            <button className="flex-1 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
              style={{
                background: "rgba(255,255,255,0.06)",
                color: "var(--panel-text)",
                border: "1px solid var(--row-border)",
              }}>
              <KeyRound className="mr-1 inline h-3.5 w-3.5" /> Change password
            </button>
            <button className="flex-1 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
              style={{
                background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                color: "var(--disc-text)",
                boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
              }}>
              <Smartphone className="mr-1 inline h-3.5 w-3.5" /> Reset MFA
            </button>
          </div>
        </Section>

        {/* Preferences */}
        <Section title="Preferences">
          <Row label="Time Zone" value="UTC-05:00 (EST)" mono />
          <Row label="Notifications" value="Critical + High" />
          <Row label="Default View" value="Overview" />
          <Row label="Theme" value="System" />
          <Row label="Density" value="Comfortable" />
          <Row label="Telemetry Opt-in" value={<span style={{ color: "var(--crit-red)" }}>OFF</span>} />
        </Section>
      </div>

      {/* Recent activity */}
      <div className="mt-5 grid grid-cols-3 gap-4">
        <div className="col-span-2 skeuo-panel p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>Recent Activity</h3>
            <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>last 24h</span>
          </div>
          <ul className="space-y-2.5 text-[12.5px]">
            {[
              { icon: <Activity className="h-3.5 w-3.5" />,    txt: "Signed in",                          when: "2m ago",   ip: "10.10.5.42"  },
              { icon: <CheckCircle2 className="h-3.5 w-3.5" />, txt: "Marked F-90412 remediation applied", when: "14m ago",  ip: "10.10.5.42"  },
              { icon: <Activity className="h-3.5 w-3.5" />,    txt: "Ran AD-DC-01 authenticated scan",     when: "1h ago",   ip: "10.10.5.42"  },
              { icon: <CheckCircle2 className="h-3.5 w-3.5" />, txt: "Approved 3 AI triage suggestions",   when: "3h ago",   ip: "10.10.5.42"  },
              { icon: <Activity className="h-3.5 w-3.5" />,    txt: "Exported SOC 2 evidence bundle",      when: "yesterday", ip: "10.10.5.42" },
            ].map((e, i) => (
              <li key={i} className="flex items-center gap-3 rounded-lg px-3 py-2"
                style={{ background: "var(--inset-base)", border: "1px solid var(--row-border)" }}>
                <span style={{ color: "var(--section-heading)" }}>{e.icon}</span>
                <span className="flex-1" style={{ color: "var(--panel-text)" }}>{e.txt}</span>
                <span className="font-mono text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>{e.ip}</span>
                <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{e.when}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Org card */}
        <div className="skeuo-panel p-5">
          <div className="mb-3 flex items-center gap-2">
            <Building2 className="h-4 w-4" style={{ color: "var(--section-heading)" }} />
            <h3 className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>Organization</h3>
          </div>
          <p className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>Coventra Health Insurance</p>
          <p className="mt-1 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>HIPAA-covered entity · Columbus, OH</p>

          <ul className="mt-4 space-y-2 text-[11.5px]">
            <li className="flex items-center gap-2" style={{ color: "var(--panel-text)" }}>
              <Globe className="h-3.5 w-3.5" style={{ color: "var(--section-heading)" }} />
              coventra.com
            </li>
            <li className="flex items-center gap-2" style={{ color: "var(--panel-text)" }}>
              <Mail className="h-3.5 w-3.5" style={{ color: "var(--section-heading)" }} />
              soc@coventra.com
            </li>
            <li className="flex items-center gap-2" style={{ color: "var(--panel-text)" }}>
              <UserIcon className="h-3.5 w-3.5" style={{ color: "var(--section-heading)" }} />
              CISO: Riya Patel
            </li>
            <li className="flex items-center gap-2" style={{ color: "var(--panel-text)" }}>
              <Lock className="h-3.5 w-3.5" style={{ color: "var(--section-heading)" }} />
              SOC 2 Type II · NCQA accredited
            </li>
          </ul>

          <button className="mt-4 flex w-full items-center justify-between rounded-lg px-3 py-2 text-[12px] font-semibold"
            style={{
              background: "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
              color: "var(--tile-text)",
              border: "1px solid var(--tile-border)",
            }}>
            Manage organization <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </main>
  );
}

function StatCard({ label, value, icon, tone = "teal" }: { label: string; value: string; icon: React.ReactNode; tone?: "teal" | "copper" }) {
  const color = tone === "copper" ? "var(--metric-copper)" : "var(--metric-teal)";
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[22px] font-light leading-none" style={{ color }}>{value}</p>
        </div>
        <div className="shrink-0" style={{ width: 38, height: 38, color, opacity: 0.28 }}>
          {icon}
        </div>
      </div>
    </div>
  );
}
