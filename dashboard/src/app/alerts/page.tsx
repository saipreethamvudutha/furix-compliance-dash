"use client";

import { useState } from "react";
import { PageShell } from "@/components/layout/page-shell";
import { KpiBgIcon } from "@/lib/kpi-icon";
import {
  AlertTriangle,
  CheckCircle2,
  ArrowUpRight,
  Bell,
  Clock,
  Filter,
} from "lucide-react";

const sections = [
  {
    title: "Inbox",
    defaultOpen: true,
    items: [
      { label: "All Alerts", href: "/alerts", badge: "47" },
      { label: "Critical", href: "/alerts?sev=crit", badge: "8" },
      { label: "High", href: "/alerts?sev=high", badge: "14" },
      { label: "Medium", href: "/alerts?sev=med", badge: "19" },
      { label: "Low", href: "/alerts?sev=low", badge: "6" },
    ],
  },
  {
    title: "Triage",
    defaultOpen: true,
    items: [
      { label: "Unacknowledged", href: "/alerts?view=unack" },
      { label: "Escalated", href: "/alerts?view=esc" },
      { label: "Suppressed", href: "/alerts?view=supp" },
      { label: "Closed (24h)", href: "/alerts?view=closed" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Detection Rules", href: "/detection-rules" },
      { label: "Findings Triage", href: "/findings" },
      { label: "Threat Intel", href: "/threat-intel" },
    ],
  },
];

type Sev = "Critical" | "High" | "Medium" | "Low";
const sevTone: Record<Sev, { bg: string; fg: string }> = {
  Critical: { bg: "rgba(212,106,94,0.18)", fg: "#d46a5e" },
  High:     { bg: "rgba(225,150,82,0.18)", fg: "#e09650" },
  Medium:   { bg: "rgba(225,192,105,0.18)", fg: "#e1c069" },
  Low:      { bg: "rgba(111,214,196,0.15)", fg: "#6fd6c4" },
};

const alerts: {
  id: string;
  fingerprint: string;
  severity: Sev;
  rule: string;
  asset: string;
  dedup: number;
  state: "Open" | "Ack" | "Escalated" | "Suppressed";
  suppressUntil: string;
  age: string;
}[] = [
  { id: "ALT-90412", fingerprint: "fp_a8b1c2",  severity: "Critical", rule: "RL-027 Bulk PHI query (mental_health_records)", asset: "phi-db-01",  dedup: 24, state: "Open",       suppressUntil: "—", age: "2m" },
  { id: "ALT-90411", fingerprint: "fp_3f2e91",  severity: "Critical", rule: "RL-014 HSM wrong-actor (non svc_cyberark_pam)", asset: "hsm-01", dedup: 6,  state: "Ack",        suppressUntil: "—", age: "8m" },
  { id: "ALT-90408", fingerprint: "fp_77adc1",  severity: "High",     rule: "RL-052 Impossible travel Columbus→Pyongyang (cfo_williams)", asset: "okta-tenant",   dedup: 11, state: "Escalated",  suppressUntil: "—", age: "14m" },
  { id: "ALT-90404", fingerprint: "fp_212ba8",  severity: "High",     rule: "RL-033 BEC lookalike domain coventra-finance.net", asset: "email-gw-01",  dedup: 3,  state: "Open",       suppressUntil: "—", age: "27m" },
  { id: "ALT-90397", fingerprint: "fp_ce0f4b",  severity: "Medium",   rule: "RL-061 PAM checkout outside business window", asset: "pam-vault-01",  dedup: 7,  state: "Open",       suppressUntil: "1h",  age: "41m" },
  { id: "ALT-90390", fingerprint: "fp_4a98e2",  severity: "Medium",   rule: "RL-078 DNS tunneling to C2 lookalike", asset: "fw-perimeter-01", dedup: 19, state: "Suppressed", suppressUntil: "4h",  age: "1h 12m" },
  { id: "ALT-90382", fingerprint: "fp_b03ee9",  severity: "Low",      rule: "RL-103 Audit log integrity gap (splunk-idx-01)", asset: "splunk-idx-01",  dedup: 2,  state: "Open",       suppressUntil: "—", age: "2h" },
  { id: "ALT-90379", fingerprint: "fp_91cc12",  severity: "High",     rule: "RL-009 S3 bulk download coventra-phi-backup", asset: "ec2-claims-api", dedup: 4,  state: "Escalated",  suppressUntil: "—", age: "2h 8m" },
];

export default function AlertsPage() {
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <PageShell drillTitle="Alerts & Incidents" sections={sections}>
      {/* KPIs */}
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Kpi icon={<AlertTriangle className="h-4 w-4" />} label="Open Alerts" value="47" sub="−12 vs 24h" tone="copper" />
        <Kpi icon={<Bell className="h-4 w-4" />} label="Critical" value="8" sub="3 escalated" tone="copper" />
        <Kpi icon={<Clock className="h-4 w-4" />} label="Avg Time-to-Ack" value="4m 12s" sub="P50" />
        <Kpi icon={<CheckCircle2 className="h-4 w-4" />} label="Closed 24h" value="118" sub="auto + manual" />
      </div>

      {/* Bulk action bar */}
      <div className="mb-3 flex items-center gap-3 rounded-xl border px-4 py-2.5"
        style={{
          borderColor: "var(--row-border)",
          background: "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(0,0,0,0.15))",
        }}
      >
        <Filter className="h-4 w-4" style={{ color: "var(--section-heading)" }} />
        <span className="text-[12px]" style={{ color: "var(--panel-text-muted)" }}>
          {selected.size > 0 ? `${selected.size} selected` : "Select rows for bulk triage"}
        </span>
        <div className="ml-auto flex gap-2">
          <BulkBtn label="Acknowledge" />
          <BulkBtn label="Close" />
          <BulkBtn label="Escalate" primary />
        </div>
      </div>

      {/* Alert inbox table */}
      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Alert Inbox
        </h3>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{
                background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))",
                color: "var(--section-heading)",
              }}>
                <th className="w-8 px-3 py-2.5"></th>
                {["ID", "Sev", "Detection Rule", "Asset", "Fingerprint", "Dedup ×", "Suppress", "Age", "State", "Actions"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map((a, i) => (
                <tr key={a.id} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3">
                    <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} className="h-3.5 w-3.5 accent-current" />
                  </td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{a.id}</td>
                  <td className="px-3 py-3">
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                      style={{ background: sevTone[a.severity].bg, color: sevTone[a.severity].fg }}>
                      {a.severity}
                    </span>
                  </td>
                  <td className="px-3 py-3">{a.rule}</td>
                  <td className="px-3 py-3 font-semibold">{a.asset}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{a.fingerprint}</td>
                  <td className="px-3 py-3 font-mono">{a.dedup}</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{a.suppressUntil}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{a.age}</td>
                  <td className="px-3 py-3 text-[11.5px]">{a.state}</td>
                  <td className="px-3 py-3">
                    <div className="flex gap-1.5">
                      <RowBtn label="Ack" />
                      <RowBtn label="Close" />
                      <RowBtn label="Esc" icon={<ArrowUpRight className="h-3 w-3" />} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Timeline */}
      <div className="mt-6 skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Alert Timeline (last 6 hours)
        </h3>
        <div className="space-y-2.5">
          {[
            { t: "16:42", sev: "Critical" as Sev, txt: "RL-027 triggered on phi-db-01 — bulk_phi_query on mental_health_records (42 CFR Part 2), 24× dedup" },
            { t: "16:34", sev: "Critical" as Sev, txt: "RL-014 triggered on hsm-01 — wrong-actor key access (caller != svc_cyberark_pam)" },
            { t: "16:28", sev: "High" as Sev,     txt: "RL-052 impossible travel for cfo_williams: Columbus OH → Pyongyang KP in 14 min" },
            { t: "16:01", sev: "High" as Sev,     txt: "ALT-90379 escalated to on-call (S3 bulk download from coventra-phi-backup via ec2-claims-api)" },
            { t: "15:18", sev: "Medium" as Sev,   txt: "RL-078 suppression window opened for fw-perimeter-01 DNS tunneling (4h)" },
            { t: "14:50", sev: "Low" as Sev,      txt: "Splunk audit_integrity tick: 2 gaps on splunk-idx-01 chain-of-custody" },
          ].map((e, i) => (
            <div key={i} className="flex items-start gap-3 text-[12.5px]">
              <span className="font-mono w-12 shrink-0" style={{ color: "var(--panel-text-muted)" }}>{e.t}</span>
              <span className="rounded-full px-2 py-0.5 text-[9.5px] font-semibold uppercase shrink-0"
                style={{ background: sevTone[e.sev].bg, color: sevTone[e.sev].fg }}>
                {e.sev}
              </span>
              <span style={{ color: "var(--panel-text)" }}>{e.txt}</span>
            </div>
          ))}
        </div>
      </div>
    </PageShell>
  );
}

function Kpi({ icon, label, value, sub, tone = "teal" }: { icon: React.ReactNode; label: string; value: string; sub: string; tone?: "teal" | "copper" }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5" style={{ color: "var(--panel-text-muted)" }}>
            {icon}
            <p className="text-[11px] uppercase tracking-wider">{label}</p>
          </div>
          <p className="numeric-glow mt-1.5 text-[28px] font-light leading-none" style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}>{value}</p>
          <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}

function BulkBtn({ label, primary }: { label: string; primary?: boolean }) {
  return (
    <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
      style={primary
        ? { background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }
        : { background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
      {label}
    </button>
  );
}

function RowBtn({ label, icon }: { label: string; icon?: React.ReactNode }) {
  return (
    <button className="flex items-center gap-1 rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
      style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
      {icon}{label}
    </button>
  );
}
