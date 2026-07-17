"use client";

import { PageShell } from "@/components/layout/page-shell";
import { GitBranch, AlertTriangle, ShieldOff, Brain } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "State Machine",
    defaultOpen: true,
    items: [
      { label: "NEW", href: "/findings?s=new", badge: "142" },
      { label: "RECURRING", href: "/findings?s=rec", badge: "412" },
      { label: "CLOSED", href: "/findings?s=closed", badge: "8,184" },
    ],
  },
  {
    title: "Filters",
    defaultOpen: true,
    items: [
      { label: "KEV-listed", href: "/findings?f=kev", badge: "24" },
      { label: "EPSS > 0.7", href: "/findings?f=epss" },
      { label: "AI Risk > 80", href: "/findings?f=ai" },
      { label: "Similar Clusters", href: "/findings?f=clusters" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Alerts & Incidents", href: "/alerts" },
      { label: "Risk Scoring", href: "/risk-scoring" },
      { label: "Detection Rules", href: "/detection-rules" },
    ],
  },
];

type State = "NEW" | "RECURRING" | "CLOSED";
const stateTone: Record<State, { bg: string; fg: string }> = {
  NEW:       { bg: "rgba(212,106,94,0.18)",  fg: "#d46a5e" },
  RECURRING: { bg: "rgba(225,192,105,0.18)", fg: "#e1c069" },
  CLOSED:    { bg: "rgba(111,214,196,0.15)", fg: "#6fd6c4" },
};

const findings: {
  id: string; cve: string; asset: string; cvss: number; epss: number; kev: boolean;
  aiScore: number; state: State; ttr: string; owner: string;
}[] = [
  { id: "F-90412", cve: "CVE-2025-1042", asset: "phi-db-01",      cvss: 9.8, epss: 0.97, kev: true,  aiScore: 96, state: "NEW",       ttr: "2h SLA", owner: "—" },
  { id: "F-90411", cve: "CVE-2025-0871", asset: "hsm-01",         cvss: 9.1, epss: 0.91, kev: true,  aiScore: 92, state: "NEW",       ttr: "2h SLA", owner: "soc_analyst_03" },
  { id: "F-90408", cve: "CVE-2024-3094", asset: "member-portal-01",cvss: 8.4, epss: 0.88, kev: true,  aiScore: 89, state: "RECURRING", ttr: "8d open", owner: "infosec_lead" },
  { id: "F-90404", cve: "CVE-2025-2104", asset: "claims-proc-01", cvss: 7.5, epss: 0.42, kev: false, aiScore: 71, state: "NEW",       ttr: "7d SLA", owner: "—" },
  { id: "F-90397", cve: "CVE-2024-9821", asset: "email-gw-01",    cvss: 6.8, epss: 0.18, kev: false, aiScore: 62, state: "RECURRING", ttr: "14d open", owner: "soc_analyst_03" },
  { id: "F-90390", cve: "CVE-2024-4488", asset: "edi-srv-01",     cvss: 5.4, epss: 0.08, kev: false, aiScore: 41, state: "RECURRING", ttr: "21d open", owner: "—" },
  { id: "F-90382", cve: "CVE-2024-0024", asset: "splunk-hf-01",   cvss: 3.1, epss: 0.02, kev: false, aiScore: 18, state: "CLOSED",    ttr: "auto-closed", owner: "—" },
];

export default function FindingsPage() {
  return (
    <PageShell drillTitle="Findings Triage" sections={sections}>
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Kpi label="Open Findings" value="554" sub="142 NEW · 412 RECURRING" tone="copper" />
        <Kpi label="KEV-listed" value="24" sub="actively exploited" />
        <Kpi label="EPSS > 0.7" value="58" sub="high exploit prob." tone="copper" />
        <Kpi label="Avg Time-to-Remediate" value="6.4d" sub="P50 trailing 30d" />
      </div>

      {/* Similar finding clusters */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <ClusterCard count="14" desc="Bulk PHI query patterns on phi-db-01/02" sim="0.94 cosine sim" />
        <ClusterCard count="8" desc="BEC lookalike domain campaigns (coventra-*)" sim="0.91 cosine sim" />
        <ClusterCard count="6" desc="Service account interactive logins (svc_etl_phi)" sim="0.88 cosine sim" />
      </div>

      {/* Bulk actions */}
      <div className="mb-3 flex items-center gap-3 rounded-xl border px-4 py-2.5"
        style={{ borderColor: "var(--row-border)", background: "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(0,0,0,0.15))" }}>
        <span className="text-[12px]" style={{ color: "var(--panel-text-muted)" }}>Bulk triage:</span>
        <div className="ml-auto flex gap-2">
          <BulkBtn label="Accept Risk" />
          <BulkBtn label="Assign Owner" />
          <BulkBtn label="Suppress (with reason)" />
        </div>
      </div>

      {/* Findings table */}
      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Findings</h3>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["ID", "CVE", "Asset", "CVSS v3.1", "EPSS", "KEV", "AI Risk", "State", "TTR", "Owner", "Actions"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={f.id} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{f.id}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{f.cve}</td>
                  <td className="px-3 py-3 font-semibold">{f.asset}</td>
                  <td className="px-3 py-3 font-mono" style={{ color: f.cvss >= 9 ? "#d46a5e" : f.cvss >= 7 ? "#e09650" : "var(--panel-text)" }}>{f.cvss.toFixed(1)}</td>
                  <td className="px-3 py-3 font-mono" style={{ color: f.epss > 0.7 ? "#d46a5e" : f.epss > 0.3 ? "#e1c069" : "var(--panel-text)" }}>{(f.epss * 100).toFixed(0)}%</td>
                  <td className="px-3 py-3">
                    {f.kev && <ShieldOff className="h-3.5 w-3.5" style={{ color: "#d46a5e" }} />}
                  </td>
                  <td className="px-3 py-3">
                    <div className="flex items-center gap-1.5">
                      <Brain className="h-3 w-3" style={{ color: "var(--section-heading)" }} />
                      <span className="font-mono">{f.aiScore}</span>
                    </div>
                  </td>
                  <td className="px-3 py-3">
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                      style={{ background: stateTone[f.state].bg, color: stateTone[f.state].fg }}>
                      {f.state}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{f.ttr}</td>
                  <td className="px-3 py-3 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{f.owner}</td>
                  <td className="px-3 py-3">
                    <div className="flex gap-1.5">
                      <RowBtn label="Triage" />
                      <RowBtn label="History" />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          State machine: NEW → RECURRING (after 2nd scan) → CLOSED. Similar findings clustered via <code>pgvector</code> cosine similarity.
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

function ClusterCard({ count, desc, sim }: { count: string; desc: string; sim: string }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center gap-2" style={{ color: "var(--section-heading)" }}>
        <GitBranch className="h-3.5 w-3.5" />
        <p className="text-[11px] uppercase tracking-wider">Similar Cluster</p>
      </div>
      <p className="numeric-glow mt-1 text-[22px] font-light leading-none" style={{ color: "var(--metric-copper)" }}>{count}</p>
      <p className="text-[12px] mt-1" style={{ color: "var(--panel-text)" }}>{desc}</p>
      <p className="text-[10.5px] font-mono mt-1" style={{ color: "var(--panel-text-muted)" }}>{sim}</p>
    </div>
  );
}

function BulkBtn({ label }: { label: string }) {
  return (
    <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
      style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
      {label}
    </button>
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
