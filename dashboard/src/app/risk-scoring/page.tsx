"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { riskViews, commonViews } from "@/lib/mock/views";
import {
  Fingerprint,
  Smartphone,
  Network as NetworkIcon,
  Boxes,
  Database as DbIcon,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...riskViews,
  "asset-vuln": commonViews["asset-vuln"],
  "scan-ops": commonViews["scan-down"],
  "alert-summary": commonViews["alert-summary"],
  "top-risks-report": commonViews["top-risks"],
  "improvement": commonViews.improvement,
  "ai-remediation": commonViews["ai-remediation"],
  "compliance-map": commonViews["compliance-map"],
};

const sections = [
  {
    title: "Risk Cluster",
    defaultOpen: true,
    items: [
      { label: "Top Risks", href: "/risk-scoring/top-risks", badge: "10" },
      { label: "Risk Matrix", href: "/risk-scoring?view=matrix" },
      { label: "Risk Trends", href: "/risk-scoring?view=trends" },
      { label: "Zero Trust Posture", href: "/risk-scoring?view=zero-trust", badge: "ZT" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/risk-scoring?view=asset-vuln" },
      { label: "Scan Operations", href: "/risk-scoring?view=scan-ops" },
      { label: "Alert Logs Summary", href: "/risk-scoring?view=alert-summary" },
      { label: "Top Risk Reports", href: "/risk-scoring?view=top-risks-report" },
      { label: "Security Improvement Analysis", href: "/risk-scoring?view=improvement" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "AI Remediation", href: "/risk-scoring?view=ai-remediation" },
      { label: "Compliance Map", href: "/risk-scoring?view=compliance-map" },
    ],
  },
];

export default function RiskScoringPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "matrix";

  if (view === "zero-trust") {
    return (
      <PageShell drillTitle="Risk Posture" sections={sections}>
        <ZeroTrustPosture />
      </PageShell>
    );
  }

  const block = localViews[view as keyof typeof localViews] ?? localViews.matrix;

  return (
    <PageShell drillTitle="Risk Posture" sections={sections}>
      <ViewBlockView block={block} />

      {/* Risk Scoring with EPSS + KEV columns (#18) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-1 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Composite Risk Scoring · with EPSS + KEV
        </h3>
        <p className="mb-4 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          EPSS from FIRST.org (exploitation probability). KEV from CISA Known Exploited Vulnerabilities. Both cross-referenced to CVE nodes via AFFECTS edges in C9 AGE graph.
        </p>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["CVE", "Asset", "CVSS", "Criticality", "Data Sens.", "EPSS %", "KEV", "Composite"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { cve: "CVE-2025-1042", a: "fin-db-01",   cvss: 9.8, crit: "Critical", sens: "PII+PCI",  epss: 97, kev: true,  comp: 96 },
              { cve: "CVE-2024-3094", a: "web-edge-2",  cvss: 8.4, crit: "High",     sens: "PII",      epss: 88, kev: true,  comp: 89 },
              { cve: "CVE-2025-0871", a: "k8s-node-7",  cvss: 9.1, crit: "High",     sens: "Internal", epss: 91, kev: true,  comp: 92 },
              { cve: "CVE-2025-2104", a: "wks-1042",    cvss: 7.5, crit: "Medium",   sens: "Internal", epss: 42, kev: false, comp: 71 },
              { cve: "CVE-2024-9821", a: "srv-app-3",   cvss: 6.8, crit: "Medium",   sens: "Public",   epss: 18, kev: false, comp: 62 },
              { cve: "CVE-2024-4488", a: "iot-cam-12",  cvss: 5.4, crit: "Low",      sens: "Public",   epss: 8,  kev: false, comp: 41 },
            ].map((r, i) => (
              <tr key={r.cve} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{r.cve}</td>
                <td className="px-3 py-3 font-semibold">{r.a}</td>
                <td className="px-3 py-3 font-mono" style={{ color: r.cvss >= 9 ? "#d46a5e" : r.cvss >= 7 ? "#e09650" : "var(--panel-text)" }}>{r.cvss.toFixed(1)}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.crit}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.sens}</td>
                <td className="px-3 py-3 font-mono" style={{ color: r.epss > 70 ? "#d46a5e" : r.epss > 30 ? "#e1c069" : "var(--panel-text)" }}>{r.epss}%</td>
                <td className="px-3 py-3">
                  {r.kev ? (
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                      style={{ background: "rgba(212,106,94,0.18)", color: "#d46a5e" }}>KEV</span>
                  ) : <span style={{ color: "var(--panel-text-muted)" }}>—</span>}
                </td>
                <td className="px-3 py-3 font-mono font-semibold" style={{ color: r.comp >= 80 ? "#d46a5e" : r.comp >= 50 ? "#e1c069" : "var(--panel-text)" }}>{r.comp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </PageShell>
  );
}

/* ─────────── Zero Trust Posture ─────────── */

type ZTMaturity = "Traditional" | "Initial" | "Advanced" | "Optimal";

const MATURITY_LEVEL: Record<ZTMaturity, number> = {
  Traditional: 1,
  Initial: 2,
  Advanced: 3,
  Optimal: 4,
};

const ZT_PILLARS: {
  id: string;
  label: string;
  icon: React.ReactNode;
  score: number;
  maturity: ZTMaturity;
  controls: { name: string; state: "ok" | "partial" | "gap" }[];
}[] = [
  {
    id: "identity",
    label: "Identity",
    icon: <Fingerprint className="h-5 w-5" />,
    score: 86,
    maturity: "Advanced",
    controls: [
      { name: "MFA enforced (TOTP/WebAuthn)", state: "ok" },
      { name: "Conditional access policies",  state: "ok" },
      { name: "Risk-based step-up auth",      state: "partial" },
      { name: "Passwordless rollout",         state: "gap" },
    ],
  },
  {
    id: "devices",
    label: "Devices",
    icon: <Smartphone className="h-5 w-5" />,
    score: 72,
    maturity: "Initial",
    controls: [
      { name: "Device inventory completeness", state: "ok" },
      { name: "Posture check at access",       state: "partial" },
      { name: "EDR coverage",                  state: "ok" },
      { name: "Unmanaged device quarantine",   state: "gap" },
    ],
  },
  {
    id: "networks",
    label: "Networks",
    icon: <NetworkIcon className="h-5 w-5" />,
    score: 64,
    maturity: "Initial",
    controls: [
      { name: "Micro-segmentation (east-west)", state: "partial" },
      { name: "Encrypted internal traffic",     state: "partial" },
      { name: "Software-defined perimeter",     state: "gap" },
      { name: "Egress filtering",               state: "ok" },
    ],
  },
  {
    id: "apps",
    label: "Applications & Workloads",
    icon: <Boxes className="h-5 w-5" />,
    score: 78,
    maturity: "Advanced",
    controls: [
      { name: "Workload identity (SPIFFE)",    state: "ok" },
      { name: "Per-request authorization",     state: "ok" },
      { name: "Continuous workload scanning",  state: "ok" },
      { name: "Service mesh mTLS",             state: "partial" },
    ],
  },
  {
    id: "data",
    label: "Data",
    icon: <DbIcon className="h-5 w-5" />,
    score: 81,
    maturity: "Advanced",
    controls: [
      { name: "Data classification",        state: "ok" },
      { name: "Encryption at rest",         state: "ok" },
      { name: "DLP on egress",              state: "partial" },
      { name: "Just-in-time data access",   state: "partial" },
    ],
  },
];

function ZeroTrustPosture() {
  const overall = Math.round(ZT_PILLARS.reduce((s, p) => s + p.score, 0) / ZT_PILLARS.length);
  const avgLevel = ZT_PILLARS.reduce((s, p) => s + MATURITY_LEVEL[p.maturity], 0) / ZT_PILLARS.length;
  const overallMaturity: ZTMaturity =
    avgLevel >= 3.5 ? "Optimal" : avgLevel >= 2.5 ? "Advanced" : avgLevel >= 1.5 ? "Initial" : "Traditional";
  const gaps = ZT_PILLARS.flatMap((p) =>
    p.controls.filter((c) => c.state === "gap").map((c) => ({ pillar: p.label, name: c.name }))
  );

  return (
    <>
      <div className="mb-5 flex items-baseline gap-3">
        <h1 className="text-[22px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Zero Trust Posture
        </h1>
        <span className="rounded-full px-2 py-0.5 text-[10px] font-mono uppercase"
          style={{ background: "rgba(212,106,94,0.18)", color: "#d46a5e" }}>CISA ZTMM 2.0</span>
      </div>

      {/* KPIs */}
      <div className="mb-5 grid grid-cols-4 gap-4">
        <ZTKpi label="Overall Score" value={`${overall}`} sub="across 5 pillars" tone="copper" />
        <ZTKpi label="Maturity Level" value={overallMaturity} sub={`avg ${avgLevel.toFixed(1)} / 4`} />
        <ZTKpi label="Strong Pillars" value={String(ZT_PILLARS.filter((p) => p.score >= 80).length)} sub="≥ 80 score" tone="copper" />
        <ZTKpi label="Open Gaps" value={String(gaps.length)} sub="control gaps to close" />
      </div>

      {/* Pillars */}
      <div className="mb-5 grid grid-cols-5 gap-3">
        {ZT_PILLARS.map((p) => (
          <div key={p.id} className="skeuo-panel p-4">
            <div className="mb-3 flex items-center gap-2.5">
              <div
                className="flex h-9 w-9 items-center justify-center rounded-xl"
                style={{
                  background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                  color: "var(--disc-text)",
                  boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
                }}
              >
                {p.icon}
              </div>
              <div>
                <p className="text-[12.5px] font-semibold" style={{ color: "var(--panel-text)" }}>{p.label}</p>
                <p className="text-[10px] font-mono uppercase tracking-wider" style={{ color: "var(--section-heading)" }}>
                  {p.maturity}
                </p>
              </div>
            </div>

            {/* gauge */}
            <div className="mb-2 flex items-end gap-2">
              <p className="numeric-glow text-[28px] font-light leading-none"
                style={{ color: p.score >= 80 ? "var(--metric-teal)" : p.score >= 60 ? "var(--metric-copper)" : "var(--crit-red)" }}>
                {p.score}
              </p>
              <p className="pb-1 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>/ 100</p>
            </div>
            <div className="mb-3 h-1.5 rounded-full" style={{ background: "rgba(0,0,0,0.4)" }}>
              <div className="h-full rounded-full"
                style={{
                  width: `${p.score}%`,
                  background: "linear-gradient(90deg, var(--metric-teal), var(--metric-copper))",
                  boxShadow: "0 0 8px rgba(111,214,196,0.4)",
                }}
              />
            </div>

            {/* maturity stages */}
            <div className="mb-3 flex gap-1">
              {(["Traditional", "Initial", "Advanced", "Optimal"] as ZTMaturity[]).map((m) => {
                const on = MATURITY_LEVEL[m] <= MATURITY_LEVEL[p.maturity];
                return (
                  <span key={m}
                    title={m}
                    className="h-1.5 flex-1 rounded-full"
                    style={{
                      background: on ? "var(--metric-copper)" : "rgba(255,255,255,0.08)",
                      boxShadow: on ? "0 0 4px var(--metric-copper)" : "none",
                    }}
                  />
                );
              })}
            </div>

            {/* controls */}
            <ul className="space-y-1">
              {p.controls.map((c) => {
                const color = c.state === "ok" ? "#6fd6c4" : c.state === "partial" ? "#e1c069" : "#d46a5e";
                const icon = c.state === "ok"
                  ? <CheckCircle2 className="h-3 w-3" />
                  : c.state === "partial"
                    ? <ShieldCheck className="h-3 w-3" />
                    : <AlertTriangle className="h-3 w-3" />;
                return (
                  <li key={c.name} className="flex items-center gap-1.5 text-[10.5px]">
                    <span style={{ color }}>{icon}</span>
                    <span className="truncate" style={{ color: "var(--panel-text)" }}>{c.name}</span>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>

      {/* Gaps + Principles */}
      <div className="grid grid-cols-2 gap-4">
        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Top Control Gaps
          </h3>
          <ul className="space-y-2">
            {gaps.map((g, i) => (
              <li key={i} className="flex items-center gap-2 text-[12px]"
                style={{ borderTop: i ? "1px solid var(--row-border)" : "none", paddingTop: i ? 8 : 0 }}>
                <span className="h-1.5 w-1.5 rounded-full"
                  style={{ background: "var(--crit-red)", boxShadow: "0 0 4px var(--crit-red)" }} />
                <span style={{ color: "var(--panel-text)" }}>{g.name}</span>
                <span className="ml-auto rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                  style={{ background: "rgba(224,160,99,0.18)", color: "#e0a063" }}>{g.pillar}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Zero Trust Principles
          </h3>
          <ul className="space-y-2 text-[11.5px]" style={{ color: "var(--panel-text)" }}>
            <li>• <strong>Never trust, always verify</strong> — authenticate &amp; authorize on every access request</li>
            <li>• <strong>Assume breach</strong> — minimize blast radius via segmentation</li>
            <li>• <strong>Least privilege</strong> — just-enough &amp; just-in-time access</li>
            <li>• <strong>Verify explicitly</strong> — use all available signals (identity, device, location, behavior)</li>
            <li>• <strong>Continuous evaluation</strong> — re-evaluate trust throughout the session</li>
          </ul>
        </div>
      </div>
    </>
  );
}

function ZTKpi({ label, value, sub, tone = "teal" }: { label: string; value: string; sub: string; tone?: "teal" | "copper" }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[26px] font-light leading-none"
            style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}>
            {value}
          </p>
          <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}
