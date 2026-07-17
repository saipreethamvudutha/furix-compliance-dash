"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  CheckCircle2,
  Tag,
  FileText,
  ArrowRight,
  Shield,
  Clock,
  Timer,
  Activity,
  AlertOctagon,
  Globe,
  Lock,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  ResponsiveContainer,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { commonViews } from "@/lib/mock/views";
import { useRole } from "@/lib/rbac/context";
import { useCoventraStats } from "@/lib/data/use-coventra-stats";
import {
  AnalystDashboard,
  AuditorDashboard,
  MsspDashboard,
  AdminDashboardHeader,
} from "@/components/dashboards/role-dashboards";

const sections = [
  {
    title: "Overview",
    defaultOpen: true,
    items: [
      { label: "Security Posture Summary", href: "/" },
      { label: "Geographic Mapping View", href: "/?view=geo" },
      { label: "Live Threat Feed", href: "/?view=live", badge: "Live" },
      { label: "Compliance Pulse", href: "/?view=compliance-map" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/?view=asset-vuln" },
      { label: "Scan Operations", href: "/?view=scan-down" },
      { label: "Alert Logs Summary", href: "/?view=alert-summary" },
      { label: "Top Risk Reports", href: "/?view=top-risks" },
      { label: "AI Remediation Queue", href: "/?view=ai-remediation", badge: "12" },
      { label: "Security Improvement Analysis", href: "/?view=improvement" },
    ],
  },
  {
    title: "Quick Access",
    defaultOpen: false,
    items: [
      { label: "Reports Archive", href: "/?view=reports-summary" },
      { label: "Help & Docs", href: "/?view=help" },
    ],
  },
];

const overviewViews = {
  geo:               commonViews["compliance-map"], // re-uses asset/framework table as a stand-in
  live:              commonViews["live-threat-feed"],
  "compliance-map":  commonViews["compliance-map"],
  "asset-vuln":      commonViews["asset-vuln"],
  "scan-down":       commonViews["scan-down"],
  "alert-summary":   commonViews["alert-summary"],
  "top-risks":       commonViews["top-risks"],
  "ai-remediation":  commonViews["ai-remediation"],
  improvement:       commonViews.improvement,
  "reports-summary": commonViews["reports-summary"],
  help:              commonViews.help,
};

const scanDataByRange: Record<"Week" | "Month" | "Year", { m: string; a: number; b: number }[]> = {
  Week: [
    { m: "Mon", a: 42, b: 18 },
    { m: "Tue", a: 58, b: 24 },
    { m: "Wed", a: 71, b: 31 },
    { m: "Thu", a: 63, b: 27 },
    { m: "Fri", a: 88, b: 35 },
    { m: "Sat", a: 34, b: 12 },
    { m: "Sun", a: 29, b: 9  },
  ],
  Month: [
    { m: "W1", a: 245, b: 96  },
    { m: "W2", a: 312, b: 124 },
    { m: "W3", a: 287, b: 108 },
    { m: "W4", a: 358, b: 141 },
  ],
  Year: [
    { m: "Jan", a: 22, b: 18 },
    { m: "Feb", a: 35, b: 28 },
    { m: "Mar", a: 30, b: 38 },
    { m: "Apr", a: 50, b: 35 },
    { m: "May", a: 45, b: 48 },
    { m: "Jun", a: 60, b: 40 },
    { m: "Jul", a: 55, b: 50 },
    { m: "Aug", a: 70, b: 42 },
    { m: "Sep", a: 65, b: 52 },
    { m: "Oct", a: 80, b: 48 },
    { m: "Nov", a: 85, b: 55 },
    { m: "Dec", a: 92, b: 54 },
  ],
};

export default function OverviewPage() {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const [range, setRange] = useState<"Week" | "Month" | "Year">("Month");
  const sp = useSearchParams();
  const view = sp.get("view");
  const subBlock = view ? overviewViews[view as keyof typeof overviewViews] : null;
  const { activeRole } = useRole();
  const cstats = useCoventraStats();

  if (!subBlock && activeRole === "analyst") {
    return <PageShell drillTitle="Overview Details" sections={sections}><AnalystDashboard /></PageShell>;
  }
  if (!subBlock && activeRole === "auditor") {
    return <PageShell drillTitle="Overview Details" sections={sections}><AuditorDashboard /></PageShell>;
  }
  if (!subBlock && activeRole === "mssp") {
    return <PageShell drillTitle="Overview Details" sections={sections}><MsspDashboard /></PageShell>;
  }

  return (
    <PageShell drillTitle="Overview Details" sections={sections}>
      {subBlock ? <ViewBlockView block={subBlock} /> : (
      <>
      <AdminDashboardHeader />
      {/* Live WS feed + Pressure Gauge (build items #10, #11) */}
      <div className="mb-5 grid grid-cols-3 gap-4">
        <div className="skeuo-panel col-span-2 p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full animate-pulse" style={{ background: "#6fd6c4", boxShadow: "0 0 8px #6fd6c4" }} />
              <h3 className="text-[13px] font-semibold" style={{ color: "var(--panel-text)" }}>Live Stream (WebSocket)</h3>
            </div>
            <span className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>tenant-scoped · 6 channels</span>
          </div>
          <div className="space-y-1.5 font-mono text-[11.5px]">
            {[
              { ch: "alert.new",         t: "16:48:22", txt: "ALT-90412 Critical — bulk PHI query on phi-db-01 (svc_etl_phi)" },
              { ch: "finding.scored",    t: "16:48:18", txt: "F-90412 AI risk: 96 (HIPAA breach risk + PHI exfil)" },
              { ch: "scan.progress",     t: "16:48:14", txt: "scan SC-12 → 78% (101/130 endpoints)" },
              { ch: "finding.created",   t: "16:48:09", txt: "F-90411 BEC lookalike coventra-hr.com targeting cfo_williams" },
              { ch: "health.changed",    t: "16:48:02", txt: "C7 vLLM → UP (queue drained)" },
              { ch: "scan.completed",    t: "16:47:55", txt: "scan SC-11 done — 142 findings, 4 critical (PHI zone)" },
            ].map((e, i) => (
              <div key={i} className="flex gap-2">
                <span style={{ color: "var(--panel-text-muted)" }}>{e.t}</span>
                <span className="rounded px-1.5 text-[10px]"
                  style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>{e.ch}</span>
                <span style={{ color: "var(--panel-text)" }}>{e.txt}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="skeuo-panel p-4">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-[13px] font-semibold" style={{ color: "var(--panel-text)" }}>Pressure Gauge</h3>
            <a href="/system-health" className="text-[10.5px]" style={{ color: "#e0a063" }}>Open dashboard →</a>
          </div>
          <div className="flex items-baseline gap-2">
            <p className="numeric-glow text-[48px] font-light leading-none" style={{ color: "var(--metric-copper)" }}>38</p>
            <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>/100 healthy</p>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1 text-[10.5px]">
            {[
              { k: "Pipeline", v: 18 }, { k: "vLLM Q", v: 42 },
              { k: "DB pool", v: 31 },  { k: "Disk", v: 22 },
              { k: "Memory", v: 48 },   { k: "Workers", v: 64 },
            ].map((s) => (
              <div key={s.k} className="flex items-center gap-1.5">
                <span className="w-12 shrink-0" style={{ color: "var(--panel-text-muted)" }}>{s.k}</span>
                <div className="flex-1 h-1 rounded-full" style={{ background: "rgba(0,0,0,0.35)" }}>
                  <div className="h-full rounded-full"
                    style={{
                      width: `${s.v}%`,
                      background: "linear-gradient(90deg, #6fd6c4, var(--metric-copper))",
                      boxShadow: "0 0 6px rgba(111,214,196,0.5)",
                    }} />
                </div>
                <span className="w-5 text-right font-mono" style={{ color: "var(--panel-text)" }}>{s.v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top: glass metrics strip — SOC KPIs */}
      <div className="glass-panel mb-5 grid grid-cols-6 divide-x divide-white/10 px-2 py-4">
        <MetricCell label="Assets Monitored" value="162"   tone="teal"   spark={[148,152,155,158,160,162]} delta="130 endpoints · 28 servers" />
        <MetricCell label="Events / Day"     value="810k"  tone="copper" spark={[760,775,782,795,802,810]} delta="Splunk-fed" />
        <MetricCell label="HIPAA Posture"    value="76"    tone="teal"   spark={[71,73,72,74,75,76]} delta="Gaps · review" />
        <MetricCell label="PHI Risk Flags"   value="23"    tone="copper" spark={[10,14,17,19,21,23]} delta="+4 today" />
        <MetricCell label="MTTD"             value="14m"   tone="teal"   spark={[22,20,18,17,15,14]} delta="-36% MoM" />
        <MetricCell label="MTTR"             value="2.3h"  tone="copper" spark={[4.1,3.8,3.2,2.9,2.5,2.3]} delta="-44% MoM" />
      </div>

      <div className="grid grid-cols-5 gap-5">
        {/* Scan Activity */}
        <div className="skeuo-panel col-span-3 p-5">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
                Scan Activity
              </h3>
              <div className="flex items-center gap-3 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: "#6fd6c4" }} />
                  Completed
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: "#e0a063" }} />
                  Findings
                </span>
              </div>
            </div>
            <div
              className="flex items-center rounded-full p-1"
              style={{
                background:
                  "linear-gradient(180deg, var(--pill-track-grad-top), var(--pill-track-grad-bot))",
                boxShadow:
                  "inset 0 2px 4px var(--pill-shadow-inset), inset 0 -1px 0 rgba(255,255,255,0.04)",
              }}
            >
              {(["Week", "Month", "Year"] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setRange(r)}
                  className="rounded-full px-3 py-1 text-xs font-medium"
                  style={
                    range === r
                      ? {
                          background:
                            "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                          color: "var(--disc-text)",
                          boxShadow:
                            "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
                        }
                      : { color: "var(--panel-text-muted)" }
                  }
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

          {mounted && (
            <ResponsiveContainer width="100%" height={230}>
              <AreaChart data={scanDataByRange[range]} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="g-teal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6fd6c4" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#6fd6c4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="g-copper" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#e0a063" stopOpacity={0.55} />
                    <stop offset="100%" stopColor="#e0a063" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="m" tick={{ fill: "var(--panel-text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "var(--panel-text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, "auto"]} />
                <Tooltip
                  contentStyle={{
                    background: "var(--tooltip-bg)",
                    border: "1px solid var(--tooltip-border)",
                    borderRadius: 10,
                    color: "var(--panel-text)",
                  }}
                />
                <Area type="monotone" dataKey="a" stroke="#6fd6c4" strokeWidth={2.5} fill="url(#g-teal)" />
                <Area type="monotone" dataKey="b" stroke="#e0a063" strokeWidth={2.5} fill="url(#g-copper)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Risk Distribution: multi-ring radial with legend */}
        {(() => {
          const v = cstats?.vulns;
          const total = v?.total ?? 487;
          const pct = (n: number) => total ? Math.round((n / total) * 100) : 0;
          const c = v?.critical ?? 23;
          const h = v?.high     ?? 68;
          const m = v?.medium   ?? 184;
          const l = v?.low      ?? 212;
          return (
        <div className="skeuo-panel col-span-2 flex flex-col p-5">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
              Risk Distribution
            </h3>
            <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
              {total.toLocaleString()} findings
            </span>
          </div>
          {/* Stacked proportion bar */}
          <div
            className="mb-3 flex h-2 w-full overflow-hidden rounded-full"
            style={{
              background: "var(--progress-track-bg)",
              boxShadow: "inset 0 1px 2px rgba(0,0,0,0.5)",
            }}
          >
            <div style={{ width: `${pct(c)}%`, background: "#d46a5e" }} />
            <div style={{ width: `${pct(h)}%`, background: "#d59a52" }} />
            <div style={{ width: `${pct(m)}%`, background: "#e1c069" }} />
            <div style={{ width: `${pct(l)}%`, background: "#7eaeae" }} />
          </div>

          <div className="flex flex-1 items-center gap-4">
            <RadialCluster critical={pct(c)} high={pct(h)} medium={pct(m)} low={pct(l)} total={total} />
            <ul className="flex flex-1 flex-col gap-2 text-[12px]">
              <RiskLegendItem color="#d46a5e" label="Critical" count={c} pct={pct(c)} />
              <RiskLegendItem color="#d59a52" label="High"     count={h} pct={pct(h)} />
              <RiskLegendItem color="#e1c069" label="Medium"   count={m} pct={pct(m)} />
              <RiskLegendItem color="#7eaeae" label="Low"      count={l} pct={pct(l)} />
            </ul>
          </div>

          {/* Footer trend strip */}
          <div
            className="mt-3 grid grid-cols-3 gap-2 border-t pt-3 text-[11px]"
            style={{ borderColor: "var(--divider)" }}
          >
            <div>
              <p style={{ color: "var(--panel-text-muted)" }}>New (7d)</p>
              <p className="mt-0.5 font-semibold" style={{ color: "var(--crit-red)" }}>
                +31 <span className="opacity-70" style={{ color: "var(--panel-text-muted)" }}>▲ 8%</span>
              </p>
            </div>
            <div>
              <p style={{ color: "var(--panel-text-muted)" }}>Resolved (7d)</p>
              <p className="mt-0.5 font-semibold" style={{ color: "var(--status-ok)" }}>
                −58 <span className="opacity-70" style={{ color: "var(--panel-text-muted)" }}>▼ 12%</span>
              </p>
            </div>
            <div>
              <p style={{ color: "var(--panel-text-muted)" }}>SLA Breached</p>
              <p className="mt-0.5 font-semibold" style={{ color: "var(--crit-orange)" }}>
                {cstats?.byStatus.critical ?? 7} <span className="opacity-70" style={{ color: "var(--panel-text-muted)" }}>open</span>
              </p>
            </div>
          </div>
        </div>
        );
        })()}

        {/* Top Risks */}
        <div className="skeuo-panel col-span-3 p-5">
          <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Top Risks
          </h3>
          <div className="space-y-3">
            {(cstats?.topRiskAssets.slice(0, 4) ?? []).map((a) => {
              const tone: "crit" | "high" | "med" = a.vulnerabilities.critical > 0 ? "crit" : a.vulnerabilities.high > 0 ? "high" : "med";
              const badge = tone === "crit" ? "Critical" : tone === "high" ? "High" : "Medium";
              const score = (tone === "crit" ? 9 : tone === "high" ? 7.5 : 6) + Math.random();
              return (
                <RiskPlaque
                  key={a.id}
                  tone={tone}
                  asset={a.name}
                  cve={`${a.vulnerabilities.critical}C · ${a.vulnerabilities.high}H · ${a.businessRole}`}
                  score={score.toFixed(1)}
                  badge={badge}
                />
              );
            })}
            {!cstats && (
              <>
                <RiskPlaque tone="crit"  asset="phi-db-01"         cve="Bulk PHI query · 42 CFR Part 2" score="9.8" badge="Critical" />
                <RiskPlaque tone="crit"  asset="member-portal-01"  cve="CVE-2024-21413" score="9.2" badge="Critical" />
                <RiskPlaque tone="high"  asset="pam-vault-01"      cve="Off-window checkout" score="8.1" badge="High" />
                <RiskPlaque tone="med"   asset="ec2-claims-api"    cve="CVE-2024-4577"  score="7.4" badge="Medium" />
              </>
            )}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="skeuo-panel col-span-2 p-5">
          <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Recent Activity
          </h3>
          <ul className="space-y-3.5 text-[13px]">
            <ActivityItem
              icon={<CheckCircle2 className="h-4 w-4" />}
              title="Imperva DAM scan completed — 130 endpoints"
              sub="14 min ago · Secure_Data_Zone (10.30.0.0/16)"
              arrow
            />
            <ActivityItem
              icon={<AlertOctagon className="h-4 w-4" />}
              title="BEC lookalike blocked: coventra-hr.com"
              sub="38 min ago · Proofpoint → cfo_williams"
            />
            <ActivityItem
              icon={<Tag className="h-4 w-4" />}
              title="PAM rotation: 18 DB credentials (phi-db-01/02)"
              sub="2 hrs ago · CyberArk vault"
            />
            <ActivityItem
              icon={<FileText className="h-4 w-4" />}
              title="HIPAA Security Rule control updated: 164.312"
              sub="3 hrs ago · synced to Splunk"
            />
            <ActivityItem
              icon={<Lock className="h-4 w-4" />}
              title="MFA forced on 4 service accounts (svc_etl_phi)"
              sub="5 hrs ago · Okta policy v2.14"
            />
          </ul>
        </div>
      </div>

      {/* SOC Standard Widgets Row */}
      <div className="mt-5 grid grid-cols-6 gap-5">
        {/* Vulnerability Severity Breakdown */}
        {(() => {
          const v = cstats?.vulns ?? { critical: 23, high: 68, medium: 184, low: 212, total: 487 };
          return (
        <div className="skeuo-panel col-span-2 p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
              Vulnerability Severity
            </h3>
            <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
              {v.total.toLocaleString()} open
            </span>
          </div>
          <SeverityBar label="Critical" count={v.critical} total={v.total} color="var(--crit-red)" />
          <SeverityBar label="High"     count={v.high}     total={v.total} color="var(--crit-orange)" />
          <SeverityBar label="Medium"   count={v.medium}   total={v.total} color="var(--crit-yellow)" />
          <SeverityBar label="Low"      count={v.low}      total={v.total} color="var(--teal-glow)" />
        </div>
        );
        })()}

        {/* Compliance Posture */}
        <div className="skeuo-panel col-span-2 p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
              Compliance Posture
            </h3>
            <Shield className="h-4 w-4" style={{ color: "var(--section-heading)" }} />
          </div>
          <div className="space-y-2.5">
            <ComplianceRow framework="HIPAA Security Rule"   pct={87} status="Compliant" />
            <ComplianceRow framework="HIPAA Privacy Rule"    pct={91} status="Compliant" />
            <ComplianceRow framework="42 CFR Part 2"         pct={76} status="Gaps" />
            <ComplianceRow framework="HITECH Act"            pct={88} status="Compliant" />
            <ComplianceRow framework="NCQA Accreditation"    pct={82} status="Review" />
            <ComplianceRow framework="PCI-DSS (member pay)"  pct={89} status="Compliant" />
          </div>
        </div>

        {/* MITRE ATT&CK Coverage */}
        <div className="skeuo-panel col-span-2 p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
              MITRE ATT&amp;CK Coverage
            </h3>
            <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
              v15.1
            </span>
          </div>
          <MitreTactic name="Initial Access"        techniques="9/12"  pct={75} />
          <MitreTactic name="Execution"             techniques="11/14" pct={79} />
          <MitreTactic name="Persistence"           techniques="14/19" pct={74} />
          <MitreTactic name="Privilege Escalation"  techniques="10/13" pct={77} />
          <MitreTactic name="Defense Evasion"       techniques="22/42" pct={52} />
          <MitreTactic name="Credential Access"     techniques="13/17" pct={76} />
          <MitreTactic name="Lateral Movement"      techniques="6/9"   pct={67} />
        </div>
      </div>

      {/* Threat Intel + Geographic row */}
      <div className="mt-5 grid grid-cols-5 gap-5">
        {/* Live Threat Intelligence Feed */}
        <div className="skeuo-panel col-span-3 p-5">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
              Threat Intelligence Feed
            </h3>
            <span className="flex items-center gap-1.5 text-[11px]" style={{ color: "var(--teal-glow)" }}>
              <span
                className="h-2 w-2 rounded-full"
                style={{ background: "var(--teal-glow)", boxShadow: "0 0 8px var(--teal-glow)" }}
              />
              Live · MISP + AlienVault OTX
            </span>
          </div>
          <div className="space-y-2">
            <IocRow type="IP"     value="185.220.101.45"  tag="KP node · Operation Silent Claim" severity="crit" age="2m"  />
            <IocRow type="DOMAIN" value="coventra-hr[.]com" tag="BEC lookalike · cfo_williams target" severity="crit" age="11m" />
            <IocRow type="USER"   value="svc_etl_phi"      tag="Bulk PHI query anomaly" severity="crit" age="18m" />
            <IocRow type="BUCKET" value="coventra-phi-backup" tag="Anomalous S3 GetObject volume" severity="crit" age="1h"  />
            <IocRow type="IP"     value="91.219.236.18"   tag="RU C2 · DNS tunneling"  severity="high" age="2h"  />
            <IocRow type="DOMAIN" value="coventra-portal[.]xyz" tag="Member portal phish" severity="med"  age="4h"  />
          </div>
        </div>

        {/* SOC Operations */}
        <div className="skeuo-panel col-span-2 p-5">
          <h3 className="mb-3 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            SOC Operations
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <StatTile icon={<Activity className="h-4 w-4" />} label="Open Incidents"      value="17"   accent="copper" />
            <StatTile icon={<AlertOctagon className="h-4 w-4" />} label="P1 / P2"          value="2 / 5" accent="red" />
            <StatTile icon={<Clock className="h-4 w-4" />}    label="Avg. Dwell Time"   value="3.1d"  accent="teal" />
            <StatTile icon={<Timer className="h-4 w-4" />}    label="SLA Compliance"    value="96.4%" accent="teal" />
            <StatTile icon={<Globe className="h-4 w-4" />}    label="Blocked (24h)"     value="14.2k" accent="copper" />
            <StatTile icon={<Shield className="h-4 w-4" />}   label="Falcon Agents"     value="158"   accent="teal" />
          </div>
        </div>
      </div>
      </>
      )}
    </PageShell>
  );
}

function MetricCell({
  label,
  value,
  tone,
  spark,
  delta,
}: {
  label: string;
  value: string;
  tone: "teal" | "copper";
  spark: number[];
  delta?: string;
}) {
  const color = tone === "teal" ? "#6fd6c4" : "#e0a063";
  const gradId = `mc-${label.replace(/\W/g, "")}`;
  const data = spark.map((v, i) => ({ i, v }));
  return (
    <div className="flex items-center justify-between px-4 py-2">
      <div>
        <p className="text-[11px] tracking-wide" style={{ color: "var(--panel-text-muted)" }}>
          {label}
        </p>
        <p
          className="numeric-glow mt-1 text-[28px] font-light leading-none"
          style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}
        >
          {value}
        </p>
        {delta && (
          <p className="mt-1 text-[10px]" style={{ color: "var(--panel-text-muted)" }}>
            {delta}
          </p>
        )}
      </div>
      <div className="h-10 w-16">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 0, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"  stopColor={color} stopOpacity={0.85} />
                <stop offset="60%" stopColor={color} stopOpacity={0.25} />
                <stop offset="100%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <Area
              type="monotone"
              dataKey="v"
              stroke={color}
              strokeWidth={2}
              fill={`url(#${gradId})`}
              fillOpacity={1}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function RadialCluster({
  critical = 5, high = 14, medium = 38, low = 44, total = 487,
}: { critical?: number; high?: number; medium?: number; low?: number; total?: number } = {}) {
  const segments = [
    { label: "Critical", pct: critical, color: "#d46a5e" },
    { label: "High",     pct: high,     color: "#d59a52" },
    { label: "Medium",   pct: medium,   color: "#e1c069" },
    { label: "Low",      pct: low,      color: "#7eaeae" },
  ];
  const r = 80;
  const C = 2 * Math.PI * r;
  const gap = 4;
  let offset = 0;

  return (
    <svg viewBox="0 0 220 220" className="h-[180px] w-[180px] shrink-0">
      <defs>
        <filter id="risk-soft" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="1.2" />
        </filter>
        {segments.map((s) => (
          <linearGradient key={s.label} id={`grad-${s.label}`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%"   stopColor={s.color} stopOpacity={0.95} />
            <stop offset="100%" stopColor={s.color} stopOpacity={0.55} />
          </linearGradient>
        ))}
      </defs>

      <circle cx="110" cy="110" r={r}
        fill="none"
        stroke="rgba(0,0,0,0.35)"
        strokeWidth={20}
      />

      <g transform="translate(110,110) rotate(-90)" filter="url(#risk-soft)" opacity={0.55}>
        {segments.map((s) => {
          const len = (s.pct / 100) * C - gap;
          const dasharray = `${Math.max(0, len)} ${C}`;
          const el = (
            <circle key={`g-${s.label}`} r={r} cx={0} cy={0}
              fill="none"
              stroke={s.color}
              strokeWidth={22}
              strokeDasharray={dasharray}
              strokeDashoffset={-offset}
            />
          );
          offset += (s.pct / 100) * C;
          return el;
        })}
      </g>

      <g transform="translate(110,110) rotate(-90)">
        {(() => {
          let off = 0;
          return segments.map((s) => {
            const len = (s.pct / 100) * C - gap;
            const dasharray = `${Math.max(0, len)} ${C}`;
            const el = (
              <circle key={s.label} r={r} cx={0} cy={0}
                fill="none"
                stroke={`url(#grad-${s.label})`}
                strokeWidth={20}
                strokeLinecap="butt"
                strokeDasharray={dasharray}
                strokeDashoffset={-off}
              />
            );
            off += (s.pct / 100) * C;
            return el;
          });
        })()}
      </g>

      <g transform="translate(110,110)" opacity={0.25}>
        {Array.from({ length: 20 }).map((_, i) => {
          const a = (i / 20) * Math.PI * 2 - Math.PI / 2;
          const x1 = Math.cos(a) * 92;
          const y1 = Math.sin(a) * 92;
          const x2 = Math.cos(a) * 96;
          const y2 = Math.sin(a) * 96;
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--panel-text-muted)" strokeWidth={1} />;
        })}
      </g>

      <text x="110" y="106" textAnchor="middle"
        fill="var(--panel-text)"
        style={{ fontSize: 28, fontWeight: 300, letterSpacing: "0.02em" }}
      >
        {total}
      </text>
      <text x="110" y="124" textAnchor="middle"
        fill="var(--panel-text-muted)"
        style={{ fontSize: 9, letterSpacing: "0.25em", textTransform: "uppercase" }}
      >
        findings
      </text>
    </svg>
  );
}

function RiskLegendItem({
  color,
  label,
  count,
  pct,
}: {
  color: string;
  label: string;
  count: number;
  pct: number;
}) {
  return (
    <li className="flex items-center justify-between gap-2">
      <span className="flex items-center gap-2">
        <span
          className="h-2.5 w-2.5 rounded-sm"
          style={{ background: color, boxShadow: `0 0 6px ${color}80` }}
        />
        <span style={{ color: "var(--panel-text)" }}>{label}</span>
      </span>
      <span style={{ color: "var(--panel-text-muted)" }}>
        {count} <span className="opacity-60">· {pct}%</span>
      </span>
    </li>
  );
}

function RiskPlaque({
  tone,
  asset,
  score,
  badge,
  cve,
}: {
  tone: "crit" | "high" | "med";
  asset: string;
  score: string;
  badge: string;
  cve?: string;
}) {
  const toneClass =
    tone === "crit" ? "plaque-crit" : tone === "high" ? "plaque-high" : "plaque-med";
  const dotColor =
    tone === "crit" ? "#d46a5e" : tone === "high" ? "#e1c069" : "#e1c069";

  return (
    <div className={`plaque ${toneClass} flex items-center justify-between px-5 py-3.5`}>
      <div>
        <p className="text-[15px] font-bold tracking-wide" style={{ color: "var(--plaque-text)" }}>
          {asset}
        </p>
        <p className="text-[11px] tracking-wide" style={{ color: "var(--plaque-text-muted)" }}>
          {cve ? `${cve} · CVSS ${score}` : `CVSS ${score}`}
        </p>
      </div>
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1.5 text-[12px] font-medium" style={{ color: "var(--plaque-text)" }}>
          <span
            className="h-2 w-2 rounded-full"
            style={{
              background: dotColor,
              boxShadow: `0 0 8px ${dotColor}`,
            }}
          />
          {badge}
        </span>
        <span className="text-[14px] font-semibold" style={{ color: "var(--plaque-text)" }}>
          {score} CVSS
        </span>
      </div>
    </div>
  );
}

function ActivityItem({
  icon,
  title,
  sub,
  arrow,
}: {
  icon: React.ReactNode;
  title: string;
  sub: string;
  arrow?: boolean;
}) {
  return (
    <li className="flex items-start gap-3 border-l border-[#1f4148] pl-3">
      <span style={{ color: "#6fd6c4" }}>{icon}</span>
      <div className="flex-1">
        <div className="flex items-center justify-between">
          <p className="leading-tight" style={{ color: "var(--panel-text)" }}>
            {title}
          </p>
          {arrow && <ArrowRight className="h-3.5 w-3.5" style={{ color: "#6fd6c4" }} />}
        </div>
        {sub && (
          <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
            {sub}
          </p>
        )}
      </div>
    </li>
  );
}

function SeverityBar({
  label,
  count,
  total,
  color,
}: {
  label: string;
  count: number;
  total: number;
  color: string;
}) {
  const pct = Math.round((count / total) * 100);
  return (
    <div className="mb-2.5">
      <div className="mb-1 flex items-center justify-between text-[11px]">
        <span style={{ color: "var(--panel-text)" }}>{label}</span>
        <span style={{ color: "var(--panel-text-muted)" }}>
          {count} · {pct}%
        </span>
      </div>
      <div
        className="h-2 w-full overflow-hidden rounded-full"
        style={{
          background: "var(--progress-track-bg)",
          boxShadow: "inset 0 1px 3px rgba(0,0,0,0.6)",
        }}
      >
        <div
          className="h-full rounded-full"
          style={{
            width: `${pct}%`,
            background: "linear-gradient(90deg, #6fd6c4, var(--metric-copper))",
            boxShadow: "0 0 8px rgba(111,214,196,0.5)",
          }}
        />
      </div>
    </div>
  );
}

function ComplianceRow({
  framework,
  pct,
  status,
}: {
  framework: string;
  pct: number;
  status: "Compliant" | "Review" | "Gaps";
}) {
  const statusColor =
    status === "Compliant"
      ? "var(--status-ok)"
      : status === "Review"
      ? "var(--crit-yellow)"
      : "var(--crit-orange)";
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1">
        <div className="mb-1 flex items-center justify-between text-[11px]">
          <span style={{ color: "var(--panel-text)" }}>{framework}</span>
          <span style={{ color: statusColor }}>{pct}%</span>
        </div>
        <div
          className="h-1.5 overflow-hidden rounded-full"
          style={{
            background: "var(--progress-track-bg)",
            boxShadow: "inset 0 1px 2px rgba(0,0,0,0.6)",
          }}
        >
          <div
            className="h-full rounded-full"
            style={{
              width: `${pct}%`,
              background: "linear-gradient(90deg, #6fd6c4, var(--metric-copper))",
              boxShadow: "0 0 6px rgba(111,214,196,0.5)",
            }}
          />
        </div>
      </div>
    </div>
  );
}

function MitreTactic({
  name,
  techniques,
  pct,
}: {
  name: string;
  techniques: string;
  pct: number;
}) {
  const color =
    pct >= 75 ? "var(--status-ok)" : pct >= 60 ? "var(--crit-yellow)" : "var(--crit-orange)";
  return (
    <div className="mb-2 flex items-center gap-3">
      <span className="w-[140px] text-[11px]" style={{ color: "var(--panel-text)" }}>
        {name}
      </span>
      <div
        className="h-1.5 flex-1 overflow-hidden rounded-full"
        style={{
          background: "var(--progress-track-bg)",
          boxShadow: "inset 0 1px 2px rgba(0,0,0,0.6)",
        }}
      >
        <div
          className="h-full rounded-full"
          style={{
            width: `${pct}%`,
            background: "linear-gradient(90deg, #6fd6c4, var(--metric-copper))",
            boxShadow: "0 0 6px rgba(111,214,196,0.5)",
          }}
        />
      </div>
      <span className="w-[44px] text-right text-[10px]" style={{ color: "var(--panel-text-muted)" }}>
        {techniques}
      </span>
    </div>
  );
}

function IocRow({
  type,
  value,
  tag,
  severity,
  age,
}: {
  type: string;
  value: string;
  tag: string;
  severity: "crit" | "high" | "med";
  age: string;
}) {
  const sevColor =
    severity === "crit"
      ? "var(--crit-red)"
      : severity === "high"
      ? "var(--crit-orange)"
      : "var(--crit-yellow)";
  return (
    <div
      className="flex items-center gap-3 rounded-lg px-3 py-2"
      style={{
        background: "rgba(0,0,0,0.22)",
        border: "1px solid var(--divider)",
      }}
    >
      <span
        className="ioc-type-chip w-[60px] rounded px-1.5 py-0.5 text-center text-[9px] font-bold tracking-wider"
        style={{
          background: "rgba(111,214,196,0.10)",
          color: "var(--teal-glow)",
          border: "1px solid rgba(111,214,196,0.25)",
        }}
      >
        {type}
      </span>
      <span
        className="flex-1 truncate font-mono text-[12px]"
        style={{ color: "var(--panel-text)" }}
      >
        {value}
      </span>
      <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
        {tag}
      </span>
      <span
        className="h-2 w-2 rounded-full"
        style={{ background: sevColor, boxShadow: `0 0 6px ${sevColor}` }}
      />
      <span className="w-[28px] text-right text-[10px]" style={{ color: "var(--panel-text-muted)" }}>
        {age}
      </span>
    </div>
  );
}

function StatTile({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  accent: "teal" | "copper" | "red";
}) {
  const color =
    accent === "teal"
      ? "var(--teal-glow)"
      : accent === "red"
      ? "var(--crit-red)"
      : "var(--copper-bright)";
  return (
    <div
      className="rounded-xl px-3 py-3"
      style={{
        background:
          "linear-gradient(180deg, rgba(255,255,255,0.03), rgba(0,0,0,0.25))",
        border: "1px solid var(--divider)",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)",
      }}
    >
      <div className="flex items-center gap-2">
        <span style={{ color }}>{icon}</span>
        <span className="text-[10px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>
          {label}
        </span>
      </div>
      <p
        className="stat-tile-value numeric-glow mt-1.5 text-[22px] font-light leading-none"
        style={{ color }}
      >
        {value}
      </p>
    </div>
  );
}
