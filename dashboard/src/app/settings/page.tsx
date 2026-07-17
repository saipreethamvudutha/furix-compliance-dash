"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { settingsViews, commonViews } from "@/lib/mock/views";
import { CheckCircle2, ShieldCheck, Eye, EyeOff } from "lucide-react";
import { PermissionsConsole } from "@/components/settings/permissions-console";
import { KpiBgIcon } from "@/lib/kpi-icon";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...settingsViews,
  "audit-log": commonViews["alert-summary"],
  "rule-updates": commonViews["alert-summary"],
  "improvement": commonViews.improvement,
  "compliance-map": commonViews["compliance-map"],
  "help": commonViews.help,
};

export const settingsSections = [
  {
    title: "Settings Cluster",
    defaultOpen: true,
    items: [
      { label: "Workspace", href: "/settings?view=workspace" },
      { label: "Security", href: "/settings?view=security" },
      { label: "Integrations", href: "/settings?view=integrations", badge: "12" },
    ],
  },
  {
    title: "Platform Sub-Sections",
    defaultOpen: true,
    items: [
      { label: "Schema Registry & Parser", href: "/settings?view=schema-registry", badge: "SEC-13" },
      { label: "Audit Hash Chain", href: "/settings?view=audit-chain", badge: "SEC-17" },
      { label: "Query Anomaly Monitor", href: "/settings?view=query-anomaly", badge: "SEC-18" },
      { label: "Telemetry & Opt-In", href: "/settings?view=telemetry" },
    ],
  },
  {
    title: "Admin",
    defaultOpen: true,
    items: [
      { label: "Roles & Permissions", href: "/settings?view=permissions", badge: "RBAC" },
      { label: "Users & Roles", href: "/users" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: false,
    items: [
      { label: "Audit Log", href: "/settings?view=audit-log" },
      { label: "Rule Updates", href: "/settings?view=rule-updates" },
      { label: "Security Improvement", href: "/settings?view=improvement" },
      { label: "Compliance Center", href: "/settings?view=compliance-map" },
      { label: "Help & Docs", href: "/settings?view=help" },
    ],
  },
];

export default function SettingsPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "workspace";

  if (view === "permissions")     return <PageShell drillTitle="Settings" sections={settingsSections}><PermissionsConsole /></PageShell>;
  if (view === "schema-registry") return <PageShell drillTitle="Settings" sections={settingsSections}><SchemaRegistry /></PageShell>;
  if (view === "audit-chain")     return <PageShell drillTitle="Settings" sections={settingsSections}><AuditChain /></PageShell>;
  if (view === "query-anomaly")   return <PageShell drillTitle="Settings" sections={settingsSections}><QueryAnomaly /></PageShell>;
  if (view === "telemetry")       return <PageShell drillTitle="Settings" sections={settingsSections}><Telemetry /></PageShell>;

  const block = localViews[view as keyof typeof localViews] ?? localViews.workspace;
  return (
    <PageShell drillTitle="Settings" sections={settingsSections}>
      <ViewBlockView block={block} />
    </PageShell>
  );
}

/* ─────────── #27 Schema Registry & Parser Management ─────────── */
function SchemaRegistry() {
  return (
    <>
      <PageHeader title="Schema Registry & Parser Management" sec="SEC-13" />
      <div className="grid grid-cols-4 gap-4 mb-6">
        <K label="Registered Source Types" value="42" tone="copper" />
        <K label="Parser Versions Live" value="48" />
        <K label="schema_unknown DLQ" value="4" tone="copper" />
        <K label="Pending Dual-Approval" value="2" />
      </div>

      <div className="skeuo-panel p-5 mb-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Source Types & Schemas</h3>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Source Type", "Parser Version", "Schema Checksum (SHA-256)", "Cache Hit", "Last Updated", "Actions"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { type: "palo-pan-os",      v: "1.4.2", sum: "a8b1c2d3…e4f5", hit: "99.8%", upd: "12d ago" },
              { type: "fortigate",        v: "2.0.1", sum: "3f2e9112…7a01", hit: "99.9%", upd: "30d ago" },
              { type: "windows-events",   v: "3.2.0", sum: "77adc18b…2c4e", hit: "99.7%", upd: "8d ago" },
              { type: "aws-cloudtrail",   v: "1.1.0", sum: "212ba8c4…91d0", hit: "99.6%", upd: "60d ago" },
              { type: "k8s-audit",        v: "0.9.4", sum: "ce0f4b22…8a32", hit: "99.5%", upd: "2d ago" },
            ].map((r, i) => (
              <tr key={r.type} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-semibold">{r.type}</td>
                <td className="px-3 py-3 font-mono">v{r.v}</td>
                <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "#e0a063" }}>{r.sum}</td>
                <td className="px-3 py-3 font-mono">{r.hit}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.upd}</td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold mr-1" style={btn}>View</button>
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>Bump (needs 2)</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Schema checksum (SHA-256 over node/edge labels + properties) cached in Valkey 5 min. Any mismatch halts write and alerts.
        </p>
      </div>

      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          schema_unknown DLQ
        </h3>
        <div className="space-y-2 text-[11.5px] font-mono">
          {[
            { t: "16:42", source: "10.9.12.4 (unregistered)", proto: "Syslog UDP", reason: "no matching schema", replay: true },
            { t: "14:18", source: "vendor-x v2.5",             proto: "Syslog TCP+TLS", reason: "fields drifted", replay: true },
            { t: "12:01", source: "edge-fw-7",                 proto: "Syslog TCP+TLS", reason: "missing required field", replay: false },
          ].map((d, i) => (
            <div key={i} className="flex gap-3 items-center">
              <span style={{ color: "var(--panel-text-muted)" }}>{d.t}</span>
              <span style={{ color: "var(--panel-text)" }}>{d.source}</span>
              <span style={{ color: "var(--panel-text-muted)" }}>·</span>
              <span style={{ color: "var(--panel-text-muted)" }}>{d.proto}</span>
              <span className="ml-auto" style={{ color: "#e1c069" }}>{d.reason}</span>
              {d.replay && <button className="rounded-md px-2 py-0.5 text-[10px]" style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>Replay</button>}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* ─────────── #28 Audit Hash Chain Verification ─────────── */
function AuditChain() {
  return (
    <>
      <PageHeader title="Audit Hash Chain Verification" sec="SEC-17" />
      <div className="grid grid-cols-4 gap-4 mb-6">
        <K label="Last Verified Hash" value="✓ OK" sub="42m ago" tone="copper" />
        <K label="Chain Length" value="2.81M rows" />
        <K label="Retention" value="7 years" tone="copper" />
        <K label="Cloud Counter-Sign" value="42m ago" />
      </div>

      <div className="skeuo-panel p-5 mb-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Chain Walk Status (B5 Verifier)</h3>
        <div className="grid grid-cols-2 gap-4">
          <div className="rounded-xl border p-4" style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
            <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>Last verified chain hash</p>
            <p className="mt-1 font-mono text-[12px] break-all" style={{ color: "#6fd6c4" }}>
              0x9a4f12e8c3b701d4...ae84c1f0e9d7b842
            </p>
            <p className="mt-2 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
              Hash formula: <code className="font-mono text-[10px]">SHA-256(prev_hash || batch)</code>
            </p>
          </div>
          <div className="rounded-xl border p-4" style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
            <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>Furix Cloud counter-signature</p>
            <p className="mt-1 text-[12px] font-mono" style={{ color: "#6fd6c4" }}>
              <CheckCircle2 className="inline h-3.5 w-3.5 mr-1" /> 2026-06-10 16:05:18 UTC
            </p>
            <p className="mt-2 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
              Cloud acts as external witness — a fully-compromised appliance cannot rewrite history without Cloud signature mismatching.
            </p>
          </div>
        </div>
        <div className="mt-4 flex gap-2">
          <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
            <ShieldCheck className="inline h-3.5 w-3.5 mr-1" /> Trigger Manual Chain Walk
          </button>
          <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold" style={btn}>
            Export Compliance Bundle (signed by Cloud · SEC-16)
          </button>
        </div>
      </div>

      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Chain Break History</h3>
        <p className="text-[12.5px]" style={{ color: "#6fd6c4" }}>
          <CheckCircle2 className="inline h-4 w-4 mr-1" /> No chain breaks detected in trailing 90 days.
        </p>
        <p className="mt-2 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          If a break is detected, the specific row range is identified here and ops alert is raised immediately.
        </p>
      </div>
    </>
  );
}

/* ─────────── #29 Query Anomaly Monitor ─────────── */
function QueryAnomaly() {
  return (
    <>
      <PageHeader title="Query Anomaly Monitor" sec="SEC-18" />
      <div className="grid grid-cols-4 gap-4 mb-6">
        <K label="Baseline Days" value="30" tone="copper" />
        <K label="Users Profiled" value="33" />
        <K label="Anomalies 7d" value="2" tone="copper" />
        <K label="Detection Engine" value="B6" />
      </div>

      <div className="skeuo-panel p-5 mb-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Flagged Anomalous Queries (last 30d)</h3>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["When", "User", "Engine", "Reason", "Query Shape", "Action"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { t: "Today 11:42", u: "intern@byoc.com",  eng: "SQL",    why: "Access to tables outside normal pattern (audit_log)", shape: "SELECT * FROM audit_log JOIN users …" },
              { t: "3d ago",      u: "priya.m@byoc.com", eng: "Cypher", why: "Unusual JOIN combination — 4 unrelated node labels", shape: "MATCH (u)-[*1..6]-(s:Secret)…" },
            ].map((r, i) => (
              <tr key={i} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono text-[11.5px]">{r.t}</td>
                <td className="px-3 py-3 font-semibold">{r.u}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.eng}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "#e1c069" }}>{r.why}</td>
                <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{r.shape}</td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold mr-1" style={btn}>Investigate</button>
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>Whitelist</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="skeuo-panel p-5">
        <h3 className="mb-3 text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>Baseline composition (per user)</h3>
        <ul className="text-[11.5px] space-y-1" style={{ color: "var(--panel-text-muted)" }}>
          <li>Typical JOIN patterns — 30-day moving baseline</li>
          <li>Query rates (per minute, per hour)</li>
          <li>Table access patterns (which tables a user normally touches)</li>
          <li>SQL <em>and</em> Cypher pattern tracking</li>
          <li>Alerts raised to ops channel <strong>before</strong> reaching the main alerts inbox — helps detect database-layer compromise or insider threat.</li>
        </ul>
      </div>
    </>
  );
}

/* ─────────── #30 Telemetry & Aggregate Opt-In ─────────── */
function Telemetry() {
  return (
    <>
      <PageHeader title="Telemetry & Aggregate Opt-In" sec="" />
      <div className="rounded-xl border p-5 mb-6"
        style={{ borderColor: "rgba(212,106,94,0.35)", background: "linear-gradient(180deg, rgba(212,106,94,0.08), rgba(0,0,0,0.15))" }}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Furix Cloud Aggregate Telemetry</p>
            <p className="text-[11.5px] mt-1" style={{ color: "var(--panel-text-muted)" }}>
              OFF by default per the sovereignty mandate. Toggle ON only with informed consent.
            </p>
          </div>
          <label className="flex items-center gap-2">
            <span className="text-[11px]" style={{ color: "#d46a5e" }}>OFF</span>
            <input type="checkbox" className="h-4 w-4 accent-current" />
          </label>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[14px] font-semibold" style={{ color: "#6fd6c4" }}>
            <Eye className="inline h-4 w-4 mr-1" /> What would be shared
          </h3>
          <ul className="text-[11.5px] space-y-1" style={{ color: "var(--panel-text)" }}>
            <li>• Anonymised event counts</li>
            <li>• Lane mix ratios (HOT/WARM/COLD %)</li>
            <li>• Alert type ratios</li>
            <li>• Average scan duration</li>
          </ul>
        </div>
        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[14px] font-semibold" style={{ color: "#d46a5e" }}>
            <EyeOff className="inline h-4 w-4 mr-1" /> Sovereignty Manifest — NEVER shared
          </h3>
          <ul className="text-[11.5px] space-y-1" style={{ color: "var(--panel-text)" }}>
            <li>✗ Customer logs</li>
            <li>✗ Scan results</li>
            <li>✗ Asset names</li>
            <li>✗ Finding details</li>
            <li>✗ Any PII whatsoever</li>
          </ul>
        </div>
      </div>

      <div className="skeuo-panel p-5">
        <h3 className="mb-3 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Support Bundle Send History</h3>
        <p className="text-[11.5px] mb-3" style={{ color: "var(--panel-text-muted)" }}>
          Operator-initiated only via <code className="font-mono text-[10px]">furixctl support-bundle send</code>. Auto-scrubbed of PII before transmission (24h snapshot).
        </p>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Sent At", "Operator", "Bundle ID", "Size", "Reason", "Receipt"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { t: "12d ago", op: "vijaychand@exargen.com", id: "sup_a8b1c2", sz: "84 MB",  why: "Vector parser crash investigation", rcpt: "ack OK" },
              { t: "47d ago", op: "admin@byoc.com",          id: "sup_3f2e91", sz: "112 MB", why: "ClickHouse insert backlog spike",   rcpt: "ack OK" },
            ].map((r) => (
              <tr key={r.id} style={{
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono text-[11.5px]">{r.t}</td>
                <td className="px-3 py-3 font-semibold">{r.op}</td>
                <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "#e0a063" }}>{r.id}</td>
                <td className="px-3 py-3 font-mono">{r.sz}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.why}</td>
                <td className="px-3 py-3 text-[11px]" style={{ color: "#6fd6c4" }}>{r.rcpt}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ─────────── shared bits ─────────── */
const btn: React.CSSProperties = { background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" };

function PageHeader({ title, sec }: { title: string; sec: string }) {
  return (
    <div className="mb-5 flex items-baseline gap-3">
      <h1 className="text-[22px] font-semibold" style={{ color: "var(--panel-text)" }}>{title}</h1>
      {sec && <span className="rounded-full px-2 py-0.5 text-[10px] font-mono uppercase" style={{ background: "rgba(212,106,94,0.18)", color: "#d46a5e" }}>{sec}</span>}
    </div>
  );
}
function K({ label, value, sub, tone = "teal" }: { label: string; value: string; sub?: string; tone?: "teal" | "copper" }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[26px] font-light leading-none" style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}>{value}</p>
          {sub && <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>}
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}
