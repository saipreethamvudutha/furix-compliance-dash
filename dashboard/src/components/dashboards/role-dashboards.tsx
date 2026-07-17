"use client";

import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  FileCheck2,
  Gauge,
  Layers,
  Network,
  Radar,
  Server,
  Shield,
  Users,
  Building2,
  Receipt,
  FileSignature,
  Lock,
  ScanLine,
  Database,
} from "lucide-react";
import { ROLES, type RoleId } from "@/lib/rbac/permissions";
import { useCoventraStats } from "@/lib/data/use-coventra-stats";
import { KpiBgIcon } from "@/lib/kpi-icon";

/* ─────────────────────── shared bits ─────────────────────── */

function Hero({ role, title, sub }: { role: RoleId; title: string; sub: string }) {
  const r = ROLES[role];
  return (
    <div
      className="mb-5 flex items-center justify-between rounded-2xl px-5 py-4"
      style={{
        background:
          "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
        border: "1px solid rgba(224,160,99,0.25)",
        boxShadow:
          "inset 0 1px 0 rgba(255,255,255,0.05), inset 0 -2px 6px rgba(0,0,0,0.35), 0 8px 24px rgba(0,0,0,0.25)",
      }}
    >
      <div className="flex items-center gap-4">
        <div
          className="flex h-12 w-12 items-center justify-center rounded-xl"
          style={{
            background:
              "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 75%)",
            color: "var(--disc-text)",
            boxShadow:
              "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5), 0 0 14px rgba(224,160,99,0.35)",
          }}
        >
          <Shield className="h-6 w-6" strokeWidth={1.8} />
        </div>
        <div>
          <p
            className="text-[10.5px] font-semibold uppercase tracking-[0.25em]"
            style={{ color: "var(--section-heading)" }}
          >
            {r.label} · {r.scope}
          </p>
          <h1
            className="mt-1 text-[22px] font-semibold"
            style={{ color: "var(--panel-text)" }}
          >
            {title}
          </h1>
          <p className="mt-0.5 text-[12px]" style={{ color: "var(--panel-text-muted)" }}>
            {sub}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <span
          className="rounded-full px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wide"
          style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}
        >
          ● Online
        </span>
        <span
          className="rounded-full px-2.5 py-1 text-[10.5px] font-mono"
          style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text-muted)" }}
        >
          {r.members} members
        </span>
      </div>
    </div>
  );
}

function K({
  label,
  value,
  sub,
  tone = "teal",
  icon,
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "teal" | "copper" | "red";
  icon?: React.ReactNode;
}) {
  const color =
    tone === "copper" ? "var(--metric-copper)" : tone === "red" ? "var(--crit-red)" : "var(--metric-teal)";
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p
            className="text-[10.5px] font-semibold uppercase tracking-wider"
            style={{ color: "var(--panel-text-muted)" }}
          >
            {label}
          </p>
          <p
            className="numeric-glow mt-1.5 text-[26px] font-light leading-none"
            style={{ color }}
          >
            {value}
          </p>
          {sub && (
            <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>
              {sub}
            </p>
          )}
        </div>
        <KpiBgIcon
          label={label}
          tone={tone === "copper" ? "copper" : tone === "red" ? "red" : "teal"}
          size={44}
          opacity={0.28}
        />
      </div>
    </div>
  );
}

function Panel({
  title,
  children,
  right,
}: {
  title: string;
  children: React.ReactNode;
  right?: React.ReactNode;
}) {
  return (
    <div className="skeuo-panel p-5">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>
          {title}
        </h3>
        {right}
      </div>
      {children}
    </div>
  );
}

function Row({
  left,
  right,
  tone,
}: {
  left: React.ReactNode;
  right: React.ReactNode;
  tone?: "ok" | "warn" | "crit";
}) {
  const dot =
    tone === "crit" ? "var(--crit-red)" : tone === "warn" ? "#e1c069" : "#6fd6c4";
  return (
    <div
      className="flex items-center justify-between gap-3 py-2"
      style={{ borderTop: "1px solid var(--row-border)" }}
    >
      <div className="flex items-center gap-2 text-[12.5px]" style={{ color: "var(--panel-text)" }}>
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: dot, boxShadow: `0 0 6px ${dot}` }}
        />
        {left}
      </div>
      <div className="text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
        {right}
      </div>
    </div>
  );
}

/* ─────────────────────── ANALYST ─────────────────────── */

export function AnalystDashboard() {
  const s = useCoventraStats();
  return (
    <>
      <div className="mb-5 grid grid-cols-4 gap-4">
        <K label="Open Alerts" value={s ? String(s.openAlerts) : "—"} tone="red" sub={s ? `${s.vulns.critical} critical · ${s.vulns.high} high` : "loading"} icon={<AlertTriangle className="h-4 w-4" />} />
        <K label="In My Queue" value={s ? String(Math.round(s.openAlerts / 4)) : "—"} tone="copper" sub="3 awaiting your action" icon={<Bot className="h-4 w-4" />} />
        <K label="Active Scans" value={s ? String(s.activeScans) : "—"} sub={s ? `${s.scheduledScans} scheduled` : "loading"} icon={<Radar className="h-4 w-4" />} />
        <K label="MTTR (24h)" value="12m" tone="copper" sub="↓ 3m vs yesterday" icon={<Gauge className="h-4 w-4" />} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 space-y-4">
          <Panel
            title="Live Alert Queue"
            right={
              <Link
                href="/alerts"
                className="rounded-md px-2 py-1 text-[11px] font-semibold"
                style={{ background: "rgba(224,160,99,0.18)", color: "var(--section-heading)" }}
              >
                Open queue →
              </Link>
            }
          >
            <div className="space-y-0">
              <Row left="EDR · Suspicious PowerShell — host-pwa-03" right="2m ago · P1" tone="crit" />
              <Row left="IDS · DNS tunneling pattern — egress-fw-1" right="4m ago · P2" tone="warn" />
              <Row left="Cloud · IAM privilege escalation — aws/prod" right="11m ago · P2" tone="warn" />
              <Row left="EDR · Credential dumping — host-app-12" right="22m ago · P1" tone="crit" />
              <Row left="Vuln · CVE-2026-13219 exploit attempt" right="34m ago · P3" tone="ok" />
            </div>
          </Panel>

          <Panel title="My Scans in Flight">
            <div className="space-y-0">
              <Row left="Authenticated scan — vlan-finance" right="78% · 4m left" tone="ok" />
              <Row left="External attack surface — corp.byoc.com" right="42% · 11m left" tone="ok" />
              <Row left="Container scan — k8s/prod-east" right="91% · 1m left" tone="ok" />
              <Row left="Cloud config audit — gcp/billing" right="Queued" tone="warn" />
            </div>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel title="Quick Actions">
            <div className="grid grid-cols-2 gap-2">
              {[
                { l: "Run Scan", h: "/scans", i: <ScanLine className="h-4 w-4" /> },
                { l: "AI Triage", h: "/ai-actions", i: <Bot className="h-4 w-4" /> },
                { l: "Top Risks", h: "/risk-scoring", i: <Gauge className="h-4 w-4" /> },
                { l: "SIEM Query", h: "/siem", i: <Activity className="h-4 w-4" /> },
              ].map((a) => (
                <Link
                  key={a.l}
                  href={a.h}
                  className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-[12px] font-semibold"
                  style={{
                    background: "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
                    color: "var(--tile-text)",
                    border: "1px solid var(--tile-border)",
                    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.07), inset 0 -2px 4px rgba(0,0,0,0.35)",
                  }}
                >
                  <span style={{ color: "var(--section-heading)" }}>{a.i}</span>
                  {a.l}
                </Link>
              ))}
            </div>
          </Panel>

          <Panel title="AI Suggestions">
            <div className="space-y-2 text-[12px]" style={{ color: "var(--panel-text)" }}>
              <div className="rounded-lg p-2.5" style={{ background: "rgba(111,214,196,0.08)", border: "1px solid rgba(111,214,196,0.2)" }}>
                <p className="font-semibold" style={{ color: "#6fd6c4" }}>Auto-isolate host-pwa-03</p>
                <p className="text-[11px] mt-0.5" style={{ color: "var(--panel-text-muted)" }}>Confidence 94% · Linked to alert #3811</p>
              </div>
              <div className="rounded-lg p-2.5" style={{ background: "rgba(224,160,99,0.08)", border: "1px solid rgba(224,160,99,0.2)" }}>
                <p className="font-semibold" style={{ color: "var(--metric-copper)" }}>Tune DNS detection rule</p>
                <p className="text-[11px] mt-0.5" style={{ color: "var(--panel-text-muted)" }}>3 false positives in last 24h</p>
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

/* ─────────────────────── AUDITOR ─────────────────────── */

export function AuditorDashboard() {
  const s = useCoventraStats();
  return (
    <>
      <div className="mb-5 grid grid-cols-4 gap-4">
        <K label="Chain Integrity" value="✓ OK" sub="Last verified 42m ago" tone="teal" icon={<Lock className="h-4 w-4" />} />
        <K label="Frameworks Tracked" value="6" sub="SOC2 · ISO27001 · PCI · HIPAA · NIST · CIS" tone="copper" icon={<FileCheck2 className="h-4 w-4" />} />
        <K label="Evidence Items" value={s ? s.evidenceItems.toLocaleString() : "—"} sub={s ? `${s.total.toLocaleString()} assets in scope` : "loading"} icon={<Database className="h-4 w-4" />} />
        <K label="Open Findings" value={s ? String(s.vulns.critical + s.vulns.high) : "—"} tone="copper" sub="awaiting attestation" icon={<FileSignature className="h-4 w-4" />} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Panel title="Framework Coverage">
          <div className="space-y-3">
            {[
              { f: "SOC 2 Type II", pct: 98 },
              { f: "ISO 27001:2022", pct: 94 },
              { f: "PCI DSS 4.0", pct: 89 },
              { f: "HIPAA Security", pct: 96 },
              { f: "NIST CSF 2.0", pct: 91 },
            ].map((r) => (
              <div key={r.f}>
                <div className="mb-1 flex justify-between text-[11.5px]">
                  <span style={{ color: "var(--panel-text)" }}>{r.f}</span>
                  <span style={{ color: "var(--metric-teal)" }}>{r.pct}%</span>
                </div>
                <div className="h-1.5 rounded-full" style={{ background: "rgba(0,0,0,0.35)" }}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${r.pct}%`,
                      background: "linear-gradient(90deg, #6fd6c4, var(--metric-copper))",
                      boxShadow: "0 0 8px rgba(111,214,196,0.5)",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Audit Hash Chain" right={<span className="text-[10px] font-mono" style={{ color: "#6fd6c4" }}>SEC-17</span>}>
          <p className="text-[10.5px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>Last verified chain hash</p>
          <p className="mt-1 break-all font-mono text-[11.5px]" style={{ color: "#6fd6c4" }}>
            0x9a4f12e8c3b701d4…ae84c1f0e9d7b842
          </p>
          <div className="mt-3 rounded-lg p-2.5" style={{ background: "rgba(111,214,196,0.08)", border: "1px solid rgba(111,214,196,0.2)" }}>
            <p className="flex items-center gap-1.5 text-[12px] font-semibold" style={{ color: "#6fd6c4" }}>
              <CheckCircle2 className="h-3.5 w-3.5" /> Counter-signed by Furix Cloud
            </p>
            <p className="mt-0.5 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
              2026-06-10 16:05:18 UTC · 2.81M rows · 7-year retention
            </p>
          </div>
        </Panel>

        <Panel title="Pending Attestations">
          <div className="space-y-2">
            {[
              { t: "Q2 access review", who: "12 privileged accounts", d: "Due in 6 days" },
              { t: "Vendor SOC2 acknowledgment", who: "3 vendors", d: "Due in 14 days" },
            ].map((a) => (
              <div
                key={a.t}
                className="rounded-lg p-2.5"
                style={{ background: "rgba(224,160,99,0.08)", border: "1px solid rgba(224,160,99,0.2)" }}
              >
                <p className="text-[12px] font-semibold" style={{ color: "var(--panel-text)" }}>{a.t}</p>
                <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{a.who} · {a.d}</p>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel
          title="Recent Evidence Exports"
          right={
            <Link href="/reports" className="rounded-md px-2 py-1 text-[11px] font-semibold" style={{ background: "rgba(224,160,99,0.18)", color: "var(--section-heading)" }}>
              All exports →
            </Link>
          }
        >
          <div className="space-y-0">
            <Row left="SOC2 Q2 evidence bundle · signed" right="Today 09:14 · 84 MB" tone="ok" />
            <Row left="PCI DSS scope review · signed" right="Yesterday · 22 MB" tone="ok" />
            <Row left="Access review – privileged accounts" right="3d ago · 4 MB" tone="ok" />
            <Row left="ISO 27001 Annex A controls" right="6d ago · 18 MB" tone="ok" />
          </div>
        </Panel>
      </div>
    </>
  );
}

/* ─────────────────────── MSSP ─────────────────────── */

export function MsspDashboard() {
  const s = useCoventraStats();
  const tenants = [
    { name: "Acme Financial", health: 97, alerts: 4, mttr: "8m", sla: "ok",   plan: "Enterprise" },
    { name: "Northwind Logistics", health: 84, alerts: 11, mttr: "21m", sla: "warn", plan: "Pro" },
    { name: "Globex Manufacturing", health: 91, alerts: 6, mttr: "14m", sla: "ok",   plan: "Pro" },
    { name: "Initech Cloud", health: 72, alerts: 18, mttr: "38m", sla: "crit", plan: "Enterprise" },
    { name: "Umbrella Health", health: 95, alerts: 2, mttr: "6m", sla: "ok",   plan: "Pro" },
    { name: "Vandelay Trade", health: 88, alerts: 7, mttr: "16m", sla: "ok",   plan: "Standard" },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-4 gap-4">
        <K label="Active Tenants" value="6" sub={s ? `${s.total.toLocaleString()} fleet assets` : "Coventra + 5 more"} icon={<Building2 className="h-4 w-4" />} />
        <K label="Fleet Alerts (24h)" value={s ? String(s.openAlerts + 80) : "—"} tone="copper" sub={s ? `${s.byStatus.critical} SLA breaches` : "loading"} icon={<AlertTriangle className="h-4 w-4" />} />
        <K label="Avg Tenant Health" value={s ? `${s.riskScore}%` : "—"} tone="teal" sub="↑ 2% w/w" icon={<Gauge className="h-4 w-4" />} />
        <K label="MRR Rollup" value="$184k" tone="copper" sub="June projection" icon={<Receipt className="h-4 w-4" />} />
      </div>

      <Panel title="Tenant Fleet" right={<span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>Click a tenant to switch context</span>}>
        <div className="grid grid-cols-3 gap-3">
          {tenants.map((t) => {
            const slaColor = t.sla === "crit" ? "var(--crit-red)" : t.sla === "warn" ? "#e1c069" : "#6fd6c4";
            return (
              <div
                key={t.name}
                className="cursor-pointer rounded-xl p-3.5 transition-all hover:scale-[1.01]"
                style={{
                  background: "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
                  border: `1px solid ${t.sla === "crit" ? "rgba(212,106,94,0.4)" : "var(--tile-border)"}`,
                  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06), inset 0 -2px 4px rgba(0,0,0,0.35)",
                }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4" style={{ color: "var(--section-heading)" }} />
                    <p className="text-[13px] font-semibold" style={{ color: "var(--panel-text)" }}>
                      {t.name}
                    </p>
                  </div>
                  <span
                    className="rounded-full px-1.5 py-0.5 text-[9px] font-bold uppercase"
                    style={{ background: `${slaColor}22`, color: slaColor }}
                  >
                    {t.sla === "crit" ? "SLA Breach" : t.sla === "warn" ? "At Risk" : "OK"}
                  </span>
                </div>
                <div className="mt-2 grid grid-cols-3 gap-2 text-[11px]">
                  <div>
                    <p style={{ color: "var(--panel-text-muted)" }}>Health</p>
                    <p className="font-mono" style={{ color: "var(--metric-teal)" }}>{t.health}%</p>
                  </div>
                  <div>
                    <p style={{ color: "var(--panel-text-muted)" }}>Alerts</p>
                    <p className="font-mono" style={{ color: "var(--metric-copper)" }}>{t.alerts}</p>
                  </div>
                  <div>
                    <p style={{ color: "var(--panel-text-muted)" }}>MTTR</p>
                    <p className="font-mono" style={{ color: "var(--panel-text)" }}>{t.mttr}</p>
                  </div>
                </div>
                <div className="mt-2 flex items-center justify-between text-[10.5px]">
                  <span style={{ color: "var(--panel-text-muted)" }}>{t.plan}</span>
                  <span style={{ color: "var(--section-heading)" }}>Switch →</span>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      <div className="mt-4 grid grid-cols-2 gap-4">
        <Panel title="SLA Breach Watch">
          <div className="space-y-0">
            <Row left="Initech Cloud · P1 alert age 47m" right="SLA 30m" tone="crit" />
            <Row left="Northwind · Backup overdue" right="SLA 4h" tone="warn" />
            <Row left="Globex · Vuln scan slipped" right="SLA 24h" tone="warn" />
          </div>
        </Panel>
        <Panel title="Billing Rollup (June)">
          <div className="space-y-0">
            <Row left="Enterprise tier · 14 tenants" right="$112,000" tone="ok" />
            <Row left="Pro tier · 17 tenants" right="$58,650" tone="ok" />
            <Row left="Standard tier · 3 tenants" right="$13,500" tone="ok" />
          </div>
        </Panel>
      </div>
    </>
  );
}

/* ─────────────────────── ADMIN (light) ─────────────────────── */
/* The existing rich `/` page already represents admin scope. We expose
 * a slim header strip + a few admin-specific KPIs so role identity is
 * visible at the top, then defer to the full overview content. */

export function AdminDashboardHeader() {
  const s = useCoventraStats();
  return (
    <>
      <div className="mb-5 grid grid-cols-4 gap-4">
        <K label="Total Assets" value={s ? s.total.toLocaleString() : "—"} tone="copper" sub={s ? `${s.byDeployment.cloud} cloud · ${s.byDeployment.onPrem} on-prem` : "Coventra Health"} icon={<Server className="h-4 w-4" />} />
        <K label="Critical Findings" value={s ? String(s.vulns.critical) : "—"} tone="red" sub={s ? `${s.vulns.high} high · ${s.vulns.medium} medium` : "loading"} icon={<Activity className="h-4 w-4" />} />
        <K label="Risk Score" value={s ? `${s.riskScore}` : "—"} tone="teal" sub={s ? `${s.byStatus.healthy} healthy · ${s.byStatus.critical} critical` : "loading"} icon={<Layers className="h-4 w-4" />} />
        <K label="Active Users" value="39" sub="4 admins · 18 analysts" icon={<Users className="h-4 w-4" />} />
      </div>
    </>
  );
}
