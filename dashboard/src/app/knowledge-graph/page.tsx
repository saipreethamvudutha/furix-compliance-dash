"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { Network, Search, Lock } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";
import { useCoventraStats } from "@/lib/data/use-coventra-stats";

const fmt = (n: number) => n.toLocaleString();
const fmtCompact = (n: number) =>
  n >= 1_000_000 ? `${(n / 1_000_000).toFixed(2)}M`
  : n >= 1_000   ? `${(n / 1_000).toFixed(1)}K`
  : String(n);

function makeSections(total: number, findings: number, alerts: number) {
  // Users scale with workstation count, events ~ ingestion rate
  const users = Math.round(total * 0.5);
  const events = total * 15_000; // log-volume model from the Coventra spec (~810k/day baseline ×18)
  return [
  {
    title: "Node Types (9)",
    defaultOpen: true,
    items: [
      { label: "Asset",       href: "/knowledge-graph?n=asset",   badge: fmt(total) },
      { label: "User",        href: "/knowledge-graph?n=user",    badge: fmt(users) },
      { label: "Finding",     href: "/knowledge-graph?n=finding", badge: fmt(findings) },
      { label: "Alert",       href: "/knowledge-graph?n=alert",   badge: fmt(alerts) },
      { label: "Event",       href: "/knowledge-graph?n=event",   badge: fmtCompact(events) },
      { label: "CVE",         href: "/knowledge-graph?n=cve",     badge: "248K" },
      { label: "CPE",         href: "/knowledge-graph?n=cpe",     badge: "1.2M" },
      { label: "ATT&CK",      href: "/knowledge-graph?n=attack",  badge: "212" },
      { label: "Pattern",     href: "/knowledge-graph?n=pattern", badge: "88" },
    ],
  },
  {
    title: "Edge Types (7)",
    defaultOpen: true,
    items: [
      { label: "AFFECTS", href: "/knowledge-graph?e=AFFECTS" },
      { label: "TRIGGERED", href: "/knowledge-graph?e=TRIGGERED" },
      { label: "OBSERVED_ON", href: "/knowledge-graph?e=OBSERVED_ON" },
      { label: "EXPLOITS", href: "/knowledge-graph?e=EXPLOITS" },
      { label: "MAPS_TO", href: "/knowledge-graph?e=MAPS_TO", badge: "🔒" },
      { label: "DERIVED_FROM", href: "/knowledge-graph?e=DERIVED_FROM" },
      { label: "SCORED_BY", href: "/knowledge-graph?e=SCORED_BY" },
    ],
  },
  ];
}

type NodeMeta = {
  label: string;
  color: string;
  desc: string;
  props: string[];
  sample: { id: string; meta: string }[];
  query: string;
};

function getNodeMeta(key: string): NodeMeta {
  switch (key) {
    case "asset":   return {
      label: "Asset", color: "#6fd6c4",
      desc: "Compute, network, storage and identity assets in the Coventra fleet.",
      props: ["id", "name", "ip", "os", "deployment", "dataSensitivity", "healthScore"],
      sample: [
        { id: "phi-db-01",   meta: "Oracle DB · 10.30.1.10 · restricted" },
        { id: "claims-proc-01", meta: "Ubuntu 22.04 · 10.20.1.10 · confidential" },
        { id: "member-portal-01", meta: "Nginx · 172.16.1.10 · DMZ" },
        { id: "ec2-claims-api", meta: "Amazon Linux 2023 · cloud · confidential" },
      ],
      query: "MATCH (a:Asset)-[:AFFECTS]-(c:CVE) WHERE a.dataSensitivity = 'restricted' RETURN a, c LIMIT 25",
    };
    case "user":    return {
      label: "User", color: "#e1c069",
      desc: "Workforce identities synced from Okta · Azure AD.",
      props: ["id", "email", "role", "department", "mfa_enrolled", "risk_score"],
      sample: [
        { id: "ciso_patel@coventra.com",    meta: "Chief Information Security Officer" },
        { id: "hipaa_officer@coventra.com", meta: "Compliance · MFA fresh" },
        { id: "soc_analyst_01@coventra.com",meta: "SOC Tier 1 · 10.10.5.0/24" },
        { id: "claims_adjuster_31@coventra.com", meta: "Claims · 47 PHI queries 24h" },
      ],
      query: "MATCH (u:User)-[:TRIGGERED]->(al:Alert) WHERE al.severity = 'Critical' RETURN u, al LIMIT 25",
    };
    case "finding": return {
      label: "Finding", color: "#e0a063",
      desc: "Open vulnerability findings raised by scanners and AI analysis.",
      props: ["id", "cve", "cvss", "epss", "kev", "status", "first_seen"],
      sample: [
        { id: "F-90412", meta: "CVE-2024-21287 · phi-db-01 · 9.8 · KEV" },
        { id: "F-90408", meta: "CVE-2024-3094 · web-edge-2 · 8.4 · KEV" },
        { id: "F-90401", meta: "CVE-2025-0871 · k8s-node-7 · 9.1 · KEV" },
      ],
      query: "MATCH (f:Finding)-[:AFFECTS]->(a:Asset) WHERE f.cvss >= 8 RETURN f, a LIMIT 25",
    };
    case "alert":   return {
      label: "Alert", color: "#d46a5e",
      desc: "Detections from SIEM (Splunk), EDR (Falcon) and IDS sensors.",
      props: ["id", "rule", "mitre", "severity", "asset_id", "ts"],
      sample: [
        { id: "ALT-3811", meta: "EDR · Suspicious PowerShell · host-pwa-03" },
        { id: "ALT-3810", meta: "IDS · DNS tunneling · egress-fw-1" },
        { id: "ALT-3809", meta: "Cloud · IAM privesc · aws/prod" },
      ],
      query: "MATCH (al:Alert)-[:OBSERVED_ON]->(a:Asset) WHERE al.severity = 'Critical' RETURN al, a LIMIT 25",
    };
    case "event":   return {
      label: "Event", color: "#7eaeae",
      desc: "Raw telemetry events — firewall, EDR, auth, cloud audit.",
      props: ["ts", "src", "dst", "action", "asset_id"],
      sample: [
        { id: "evt-firewall",  meta: "320,253 / 39.5% — Palo Alto syslog" },
        { id: "evt-database",  meta: "150,004 / 18.5% — Oracle audit" },
        { id: "evt-endpoint",  meta: "101,348 / 12.5% — CrowdStrike Falcon" },
        { id: "evt-auth",      meta: " 81,082 / 10.0% — Okta + AD" },
      ],
      query: "MATCH (e:Event {action: 'auth.fail'})-[:OBSERVED_ON]->(a:Asset) WHERE e.ts > datetime() - duration('PT1H') RETURN e LIMIT 100",
    };
    case "cve":     return {
      label: "CVE", color: "#e0a063",
      desc: "Common Vulnerabilities and Exposures — NVD + KEV enrichment.",
      props: ["id", "cvss", "epss", "kev", "published"],
      sample: [
        { id: "CVE-2024-21287", meta: "Oracle DB · 9.8 · KEV" },
        { id: "CVE-2024-3094",  meta: "xz-utils · 8.4 · KEV" },
        { id: "CVE-2025-1042",  meta: "PostgreSQL · 9.8 · KEV" },
      ],
      query: "MATCH (c:CVE {kev: true})-[:AFFECTS]->(a:Asset) RETURN c, a LIMIT 25",
    };
    case "cpe":     return {
      label: "CPE", color: "#d59a52",
      desc: "Common Platform Enumeration — product / vendor identifiers.",
      props: ["uri", "vendor", "product", "version"],
      sample: [
        { id: "cpe:/a:oracle:database:19c", meta: "Oracle Database 19c" },
        { id: "cpe:/a:postgresql:postgresql:16.3", meta: "PostgreSQL 16.3" },
        { id: "cpe:/a:nginx:nginx:1.27.1", meta: "Nginx 1.27.1" },
      ],
      query: "MATCH (cpe:CPE)<-[:MAPS_TO]-(a:Asset {id: 'phi-db-01'}) RETURN cpe",
    };
    case "attack":  return {
      label: "ATT&CK", color: "#d46a5e",
      desc: "MITRE ATT&CK techniques mapped to detections.",
      props: ["id", "name", "tactic", "platform"],
      sample: [
        { id: "T1003.001", meta: "OS Credential Dumping: LSASS Memory" },
        { id: "T1068",     meta: "Exploitation for Privilege Escalation" },
        { id: "T1190",     meta: "Exploit Public-Facing Application" },
      ],
      query: "MATCH (a:Asset)-[*1..4]->(t:ATT_CK_Technique {id: 'T1068'}) RETURN path",
    };
    case "pattern": return {
      label: "Pattern", color: "#6fd6c4",
      desc: "Compiled detection patterns promoted from CI traces.",
      props: ["id", "rule", "confidence", "tenant"],
      sample: [
        { id: "PTN-014", meta: "Bulk PHI query > 10k rows · confidence 0.94" },
        { id: "PTN-009", meta: "Off-window PAM checkout · confidence 0.91" },
      ],
      query: "MATCH (p:Pattern)-[:DERIVED_FROM]->(t) RETURN p, t LIMIT 25",
    };
    default: return getNodeMeta("asset");
  }
}

function getEdgeMeta(key: string) {
  const map: Record<string, { desc: string; query: string; from: string; to: string }> = {
    AFFECTS:      { desc: "CVE affects Asset (via CPE match).",                    from: "CVE",     to: "Asset",  query: "MATCH (c:CVE)-[:AFFECTS]->(a:Asset) WHERE c.kev = true RETURN c, a LIMIT 25" },
    TRIGGERED:    { desc: "User or Event triggered an Alert.",                    from: "User",    to: "Alert",  query: "MATCH (u:User)-[:TRIGGERED]->(al:Alert) RETURN u, al LIMIT 25" },
    OBSERVED_ON:  { desc: "Event or Alert observed on a specific Asset.",          from: "Event",   to: "Asset",  query: "MATCH (e:Event)-[:OBSERVED_ON]->(a:Asset {id:'phi-db-01'}) RETURN e LIMIT 50" },
    EXPLOITS:     { desc: "CVE exploits an ATT&CK technique (KEV chain).",         from: "CVE",     to: "ATT&CK", query: "MATCH (c:CVE)-[:EXPLOITS]->(t:ATT_CK_Technique) RETURN c, t LIMIT 25" },
    MAPS_TO:      { desc: "Immutable mapping — Asset → CPE. SEC-15 enforced.",     from: "Asset",   to: "CPE",    query: "MATCH (a:Asset)-[:MAPS_TO]->(cpe:CPE) WHERE a.dataSensitivity = 'restricted' RETURN a, cpe" },
    DERIVED_FROM: { desc: "Pattern derived from CI traces.",                       from: "Pattern", to: "CI",     query: "MATCH (p:Pattern)-[:DERIVED_FROM]->(t) RETURN p, t LIMIT 25" },
    SCORED_BY:    { desc: "Finding scored by AI / scanner / EPSS model.",         from: "Finding", to: "Model",  query: "MATCH (f:Finding)-[:SCORED_BY]->(m) RETURN f, m LIMIT 25" },
  };
  return map[key] ?? map.AFFECTS;
}

export default function KnowledgeGraphPage() {
  const stats = useCoventraStats();
  const sp = useSearchParams();
  const selNode = sp.get("n");
  const selEdge = sp.get("e");
  const total = stats?.total ?? 830;
  const findings = stats?.vulns.total ?? 0;
  const alerts = stats?.openAlerts ?? 0;

  // Realistic edge counts derived from fleet size
  const nodes = total + Math.round(total * 0.5) + findings + alerts + 248_000 + 1_200_000 + 212 + 88;
  const edges = Math.round(nodes * 3.3);
  const mapsTo = Math.round(total * 50); // ~50 MAPS_TO per asset for compliance traceability
  const pathQueries24h = Math.round(total * 1.5);

  const node = selNode ? getNodeMeta(selNode) : null;
  const edge = selEdge ? getEdgeMeta(selEdge) : null;
  const cypher = node?.query ?? edge?.query ?? `MATCH path = (a:Asset {id: 'phi-db-01'})-[*1..4]->(t:ATT_CK_Technique)
WHERE EXISTS { (a)-[:AFFECTS]-(c:CVE) WHERE c.kev = true }
RETURN path LIMIT 25`;

  return (
    <PageShell drillTitle="Knowledge Graph Explorer" sections={makeSections(total, findings, alerts)}>
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Kpi label="Nodes" value={fmtCompact(nodes)} sub="across 9 labels" tone="copper" />
        <Kpi label="Edges" value={fmtCompact(edges)} sub="7 labels" />
        <Kpi label="MAPS_TO (immutable)" value={fmt(mapsTo)} sub="SEC-15 enforced" tone="copper" />
        <Kpi label="Path Queries 24h" value={fmt(pathQueries24h)} sub="avg 38ms" />
      </div>

      {/* Cypher query box */}
      <div className="mb-4 rounded-xl border p-4"
        style={{ borderColor: "var(--row-border)", background: "var(--inset-base)" }}>
        <div className="mb-2 flex items-center gap-2 text-[11px] uppercase tracking-wider" style={{ color: "var(--section-heading)" }}>
          <Search className="h-3.5 w-3.5" /> Path Query (Cypher)
          {(node || edge) && (
            <span className="ml-auto rounded-full px-2 py-0.5 text-[10px] font-mono normal-case"
              style={{ background: "rgba(224,160,99,0.18)", color: "#e0a063" }}>
              {node ? `Node: ${node.label}` : `Edge: ${selEdge}`}
            </span>
          )}
        </div>
        <pre className="font-mono text-[12px] p-3 rounded-lg whitespace-pre-wrap" style={{ background: "#0d1117", color: "#6fd6c4", border: "1px solid #1f2933" }}>
{cypher}
        </pre>
        <div className="mt-2 flex gap-2">
          <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
            Run Query
          </button>
          <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
            Load Example Path
          </button>
        </div>
      </div>

      {/* Selected node / edge detail */}
      {(node || edge) && (
        <div className="skeuo-panel p-5 mb-4">
          <div className="mb-3 flex items-baseline gap-3">
            <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
              {node ? `${node.label} Node` : `${selEdge} Edge`}
            </h3>
            <span className="text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
              {node?.desc ?? edge?.desc}
            </span>
            {edge && (
              <span className="ml-auto rounded-full px-2 py-0.5 text-[10px] font-mono"
                style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>
                {edge.from} → {edge.to}
              </span>
            )}
          </div>

          {node && (
            <>
              <div className="mb-3 flex flex-wrap gap-1.5">
                {node.props.map((p) => (
                  <span key={p} className="rounded-md px-2 py-0.5 text-[10.5px] font-mono"
                    style={{ background: "rgba(255,255,255,0.06)", border: "1px solid var(--row-border)", color: "var(--panel-text-muted)" }}>
                    {p}
                  </span>
                ))}
              </div>
              <p className="mb-2 text-[10.5px] uppercase tracking-wider" style={{ color: "var(--section-heading)" }}>
                Sample {node.label} nodes
              </p>
              <ul className="space-y-1">
                {node.sample.map((s) => (
                  <li key={s.id} className="flex items-center gap-3 rounded-lg px-2 py-1.5"
                    style={{ background: "var(--inset-base)", border: "1px solid var(--row-border)" }}>
                    <span className="font-mono text-[11.5px]" style={{ color: node.color }}>{s.id}</span>
                    <span className="text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{s.meta}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {/* Graph canvas placeholder */}
      <div className="skeuo-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Graph Canvas
            {(node || edge) && (
              <span className="ml-2 text-[12px] font-normal" style={{ color: "var(--panel-text-muted)" }}>
                · filtered to {node?.label ?? selEdge}
              </span>
            )}
          </h3>
          <div className="flex gap-1.5 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
            <Filter label="Asset" color="#6fd6c4" />
            <Filter label="CVE" color="#e0a063" />
            <Filter label="Finding" color="#e1c069" />
            <Filter label="ATT&CK" color="#d46a5e" />
          </div>
        </div>
        <div className="relative h-[420px] rounded-xl overflow-hidden"
          style={{
            background: "#0d1117",
            border: "1px solid #1f2933",
            backgroundImage:
              "radial-gradient(circle at 30% 40%, rgba(111,214,196,0.12), transparent 60%), radial-gradient(circle at 70% 60%, rgba(224,160,99,0.12), transparent 60%)",
          }}>
          <Network className="h-20 w-20 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-20" style={{ color: "#7eaeae" }} />
          <svg className="absolute inset-0 w-full h-full" viewBox="0 0 800 420">
            <line x1="200" y1="120" x2="380" y2="210" stroke="#6fd6c4" strokeWidth="1.5" opacity="0.7" />
            <line x1="380" y1="210" x2="560" y2="120" stroke="#e0a063" strokeWidth="1.5" opacity="0.7" />
            <line x1="380" y1="210" x2="220" y2="320" stroke="#e1c069" strokeWidth="1.5" opacity="0.7" />
            <line x1="380" y1="210" x2="580" y2="320" stroke="#d46a5e" strokeWidth="1.5" opacity="0.7" />
            <line x1="560" y1="120" x2="700" y2="60"  stroke="#e0a063" strokeWidth="1.5" opacity="0.7" />
            <Node cx={200} cy={120} label="phi-db-01" color="#6fd6c4" />
            <Node cx={380} cy={210} label="CVE-2024-21287" color="#e0a063" />
            <Node cx={560} cy={120} label="EXPLOITS" color="#e0a063" sub />
            <Node cx={220} cy={320} label="F-90412" color="#e1c069" />
            <Node cx={580} cy={320} label="T1068" color="#d46a5e" />
            <Node cx={700} cy={60}  label="KEV" color="#e0a063" sub />
          </svg>
        </div>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          <Lock className="inline h-3 w-3 mr-1" /> MAPS_TO edges are immutable (SEC-15) — cannot be deleted for compliance traceability.
        </p>
      </div>
    </PageShell>
  );
}

function Node({ cx, cy, label, color, sub }: { cx: number; cy: number; label: string; color: string; sub?: boolean }) {
  return (
    <g>
      <circle cx={cx} cy={cy} r={sub ? 14 : 22} fill={color} opacity={sub ? 0.4 : 0.18} />
      <circle cx={cx} cy={cy} r={sub ? 14 : 22} fill="none" stroke={color} strokeWidth="1.5" />
      <text x={cx} y={cy + (sub ? 28 : 38)} textAnchor="middle" fontSize="10" fontFamily="monospace" fill={color}>{label}</text>
    </g>
  );
}

function Filter({ label, color }: { label: string; color: string }) {
  return (
    <span className="flex items-center gap-1 rounded-md px-2 py-0.5"
      style={{ background: "rgba(255,255,255,0.05)", border: "1px solid var(--row-border)" }}>
      <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      {label}
    </span>
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
