"use client";

import { PageShell } from "@/components/layout/page-shell";
import { Plus, Power, Beaker, History, Search } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "Rule Library",
    defaultOpen: true,
    items: [
      { label: "All Rules", href: "/detection-rules", badge: "284" },
      { label: "Signature", href: "/detection-rules?type=sig", badge: "162" },
      { label: "Threshold", href: "/detection-rules?type=thr", badge: "78" },
      { label: "Behavioral", href: "/detection-rules?type=bhv", badge: "44" },
    ],
  },
  {
    title: "State",
    defaultOpen: true,
    items: [
      { label: "Enabled", href: "/detection-rules?state=on", badge: "241" },
      { label: "Disabled", href: "/detection-rules?state=off", badge: "29" },
      { label: "Shadow Mode", href: "/detection-rules?state=shadow", badge: "14" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Alerts & Incidents", href: "/alerts" },
      { label: "Threat Intel Feeds", href: "/threat-intel" },
    ],
  },
];

type RType = "Signature" | "Threshold" | "Behavioral";

const rules: {
  id: string; name: string; type: RType; scope: string; lastTrig: string;
  matches: number; enabled: boolean; shadow: boolean; version: number;
}[] = [
  { id: "RL-009", name: "bulk_phi_query on COVENTRA_PHI tables",   type: "Behavioral", scope: "phi-db-01/02 (Imperva DAM)",  lastTrig: "2m ago",  matches: 18,   enabled: true,  shadow: false, version: 7 },
  { id: "RL-014", name: "hsm_wrong_actor — non svc_cyberark_pam",  type: "Signature",  scope: "hsm-01 (1 asset)",            lastTrig: "8m ago",  matches: 2,    enabled: true,  shadow: false, version: 3 },
  { id: "RL-027", name: "bulk_phi_query mental_health (42 CFR Pt2)", type: "Behavioral", scope: "phi-db-01/02 schema",       lastTrig: "1m ago",  matches: 24,   enabled: true,  shadow: false, version: 12 },
  { id: "RL-033", name: "bec_phishing — coventra-* lookalike domain", type: "Signature",scope: "email-gw-01 Proofpoint",      lastTrig: "27m ago", matches: 9,    enabled: true,  shadow: false, version: 4 },
  { id: "RL-052", name: "impossible_travel (Okta auth events)",    type: "Threshold",  scope: "okta-tenant (64 users)",      lastTrig: "14m ago", matches: 142,  enabled: true,  shadow: false, version: 2 },
  { id: "RL-061", name: "pam_outside_window — CyberArk checkout",  type: "Behavioral", scope: "pam-vault-01",                lastTrig: "41m ago", matches: 5,    enabled: true,  shadow: false, version: 8 },
  { id: "RL-078", name: "DNS tunneling to C2 lookalike (entropy)", type: "Behavioral", scope: "fw-perimeter-01/02 PAN logs", lastTrig: "1h ago",  matches: 19,   enabled: true,  shadow: true,  version: 1 },
  { id: "RL-103", name: "audit_integrity gap on splunk-idx-01",    type: "Threshold",  scope: "splunk indexer chain",        lastTrig: "2h ago",  matches: 2,    enabled: false, shadow: false, version: 5 },
  { id: "RL-118", name: "svc_etl_phi interactive login (svc abuse)", type: "Behavioral", scope: "ad-dc-01/02 Okta",          lastTrig: "—",       matches: 0,    enabled: true,  shadow: true,  version: 1 },
];

const typeTone: Record<RType, { bg: string; fg: string }> = {
  Signature:  { bg: "rgba(111,214,196,0.15)", fg: "#6fd6c4" },
  Threshold:  { bg: "rgba(225,192,105,0.18)", fg: "#e1c069" },
  Behavioral: { bg: "rgba(224,160,99,0.18)",  fg: "#e0a063" },
};

export default function DetectionRulesPage() {
  return (
    <PageShell drillTitle="Detection Rules" sections={sections}>
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Kpi label="Total Rules" value="284" sub="241 enabled" tone="copper" />
        <Kpi label="Shadow Mode" value="14" sub="A/B testing" />
        <Kpi label="Matches 24h" value="3,184" sub="aggregated" tone="copper" />
        <Kpi label="Avg Eval Time" value="42 ms" sub="per-rule budget 100ms" />
      </div>

      {/* Toolbar */}
      <div className="mb-3 flex items-center gap-3 rounded-xl border px-4 py-2.5"
        style={{ borderColor: "var(--row-border)", background: "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(0,0,0,0.15))" }}>
        <Search className="h-4 w-4" style={{ color: "var(--section-heading)" }} />
        <input placeholder="Search rules, IOCs, ATT&CK techniques…"
          className="flex-1 bg-transparent text-[12.5px] outline-none"
          style={{ color: "var(--panel-text)" }} />
        <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
          style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
          <Plus className="h-3.5 w-3.5" /> New Rule
        </button>
      </div>

      {/* Rules table */}
      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Rule Library</h3>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["ID", "Name", "Type", "Scope", "Last Triggered", "Matches", "Version", "Shadow", "Enabled", "Actions"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => (
                <tr key={r.id} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{r.id}</td>
                  <td className="px-3 py-3 font-semibold">{r.name}</td>
                  <td className="px-3 py-3">
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                      style={{ background: typeTone[r.type].bg, color: typeTone[r.type].fg }}>
                      {r.type}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.scope}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{r.lastTrig}</td>
                  <td className="px-3 py-3 font-mono">{r.matches}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>v{r.version}</td>
                  <td className="px-3 py-3">
                    {r.shadow ? (
                      <span className="flex items-center gap-1 text-[11px]" style={{ color: "#e1c069" }}>
                        <Beaker className="h-3 w-3" /> A/B
                      </span>
                    ) : <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>—</span>}
                  </td>
                  <td className="px-3 py-3">
                    <span className="flex items-center gap-1 text-[11px]" style={{ color: r.enabled ? "#6fd6c4" : "var(--panel-text-muted)" }}>
                      <Power className="h-3 w-3" /> {r.enabled ? "ON" : "OFF"}
                    </span>
                  </td>
                  <td className="px-3 py-3">
                    <div className="flex gap-1.5">
                      <RowBtn label="Edit" />
                      <RowBtn label="Disable" />
                      <RowBtn label="Shadow" icon={<Beaker className="h-3 w-3" />} />
                      <RowBtn label="History" icon={<History className="h-3 w-3" />} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Rule type explainers */}
      <div className="mt-6 grid grid-cols-3 gap-4">
        <ExplainerCard
          title="Signature Rules"
          body="IOC match against IP, hash, domain or CVE. Hot-reloaded from detection_rules. Sub-millisecond per-event check."
        />
        <ExplainerCard
          title="Threshold Rules"
          body="Count-based windows (e.g. failed logins > 5 in 1 min). Backed by Valkey sliding counters. Per-rule 100ms timeout."
        />
        <ExplainerCard
          title="Behavioral Rules"
          body="Thread Weaver features (velocity, entropy, escalation). Versioned with shadow-mode toggle for safe rollout."
        />
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

function ExplainerCard({ title, body }: { title: string; body: string }) {
  return (
    <div className="skeuo-panel p-4">
      <h4 className="text-[13px] font-semibold mb-2" style={{ color: "var(--section-heading)" }}>{title}</h4>
      <p className="text-[12px] leading-relaxed" style={{ color: "var(--panel-text-muted)" }}>{body}</p>
    </div>
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
