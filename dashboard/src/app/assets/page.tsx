"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { assetsViews, commonViews } from "@/lib/mock/views";
import { getAssets } from "@/lib/data/assets";
import type { Asset } from "@/lib/data/types";
import { Search, Download, Server, Cloud, Monitor, Network as NetIcon, Database, ChevronLeft, ChevronRight, Trash2, AlertTriangle } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";
import { useRole } from "@/lib/rbac/context";
import { canSeeSensitivity } from "@/lib/rbac/sensitivity";
import { SensitivityBadge } from "@/components/rbac/sensitivity-badge";
import { SensitiveValue } from "@/components/rbac/sensitive-value";
import { HiddenItemsNotice } from "@/components/rbac/hidden-items-notice";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...assetsViews,
  "asset-vuln": commonViews["asset-vuln"],
  "scan-down": commonViews["scan-down"],
  "alert-summary": commonViews["alert-summary"],
  "top-risks": commonViews["top-risks"],
  "improvement": commonViews.improvement,
  "compliance-map": commonViews["compliance-map"],
  "ai-remediation": commonViews["ai-remediation"],
  "reports": commonViews["reports-summary"],
};

const sections = [
  {
    title: "Asset Cluster",
    defaultOpen: true,
    items: [
      { label: "All Assets", href: "/assets?view=all", badge: "830" },
      { label: "Cloud", href: "/assets?view=cloud", badge: "150" },
      { label: "Endpoints", href: "/assets?view=endpoints", badge: "380" },
      { label: "Servers", href: "/assets?view=servers", badge: "260" },
      { label: "Network", href: "/assets?view=network", badge: "30" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/assets?view=asset-vuln" },
      { label: "Scan Down Reports", href: "/assets?view=scan-down" },
      { label: "Alert Logs Summary", href: "/assets?view=alert-summary" },
      { label: "Top Risk Reports", href: "/assets?view=top-risks" },
      { label: "Security Improvement Analysis", href: "/assets?view=improvement" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Compliance Map", href: "/assets?view=compliance-map" },
      { label: "AI Remediation", href: "/assets?view=ai-remediation" },
      { label: "Reports", href: "/assets?view=reports" },
    ],
  },
];

export default function AssetsPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "all";

  const isRegistryView = ["all", "cloud", "endpoints", "servers", "network"].includes(view);

  return (
    <PageShell drillTitle="Asset Registry" sections={sections}>
      {isRegistryView ? (
        <CoventraAssetRegistry filter={view as RegistryFilter} />
      ) : (
        <ViewBlockView block={localViews[view as keyof typeof localViews] ?? localViews.all} />
      )}

      {/* Per-asset extras row (#16 ZT/CIS/OWASP/PCI columns surface) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Asset Posture (Zero-Trust · CIS v8.1 · OWASP · PCI DSS)
        </h3>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Asset", "ZT Posture", "CIS v8.1", "OWASP Grade", "PCI DSS Scope", "Health"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { a: "phi-db-01",       zt: 78, cis: "Scored",     owasp: "—",  pci: "In-scope",     h: 92 },
              { a: "member-portal-01", zt: 84, cis: "Scored",     owasp: "A−", pci: "Out-of-scope", h: 88 },
              { a: "claims-proc-01",   zt: 62, cis: "Scored",     owasp: "—",  pci: "Out-of-scope", h: 71 },
              { a: "WS-CLM-003",       zt: 51, cis: "Not Scored", owasp: "—",  pci: "Out-of-scope", h: 64 },
              { a: "ec2-etl-worker",   zt: 28, cis: "Exempt",     owasp: "—",  pci: "Out-of-scope", h: 42 },
            ].map((r, i) => (
              <tr key={r.a} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-semibold">{r.a}</td>
                <td className="px-3 py-3 font-mono" style={{ color: r.zt >= 70 ? "#6fd6c4" : r.zt >= 50 ? "#e1c069" : "#d46a5e" }}>{r.zt}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.cis}</td>
                <td className="px-3 py-3 font-mono" style={{ color: "#e0a063" }}>{r.owasp}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.pci}</td>
                <td className="px-3 py-3 font-mono">{r.h}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Log Source Registration (#15) */}
      <div className="skeuo-panel p-5 mt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Log Source Registration (per asset)
          </h3>
          <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
            + Register Source
          </button>
        </div>
        <div className="grid grid-cols-4 gap-3 mb-4">
          {[
            { proto: "Syslog UDP 514",      note: "legacy, lossy" },
            { proto: "Syslog TCP+TLS 6514", note: "reliable · optional mTLS" },
            { proto: "WEF HTTPS 5986",      note: "Windows Event Forwarding" },
            { proto: "Cloud Audit Pull",    note: "AWS / Azure / GCP · 60s" },
          ].map((p) => (
            <div key={p.proto} className="rounded-lg border px-3 py-2.5"
              style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
              <p className="text-[12px] font-semibold" style={{ color: "var(--panel-text)" }}>{p.proto}</p>
              <p className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>{p.note}</p>
            </div>
          ))}
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Asset", "Protocol", "Source IP (allowlist)", "Ingest Rate", "Tamper Events", "Last Event"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { a: "fw-perimeter-01", p: "Syslog TCP+TLS 6514", ip: "10.0.1.1",  rate: "8,142 e/s", tamper: 0, last: "0s ago" },
              { a: "ad-dc-01",        p: "WEF HTTPS 5986",       ip: "10.10.5.10", rate: "412 e/s",   tamper: 0, last: "2s ago" },
              { a: "aws-acct-coventra", p: "Cloud Audit Pull",   ip: "—",          rate: "224 e/s",   tamper: 0, last: "58s ago" },
              { a: "fw-internal-01",  p: "Syslog UDP 514",       ip: "10.0.1.3",   rate: "1,184 e/s", tamper: 2, last: "0s ago" },
            ].map((r, i) => (
              <tr key={r.a} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-semibold">{r.a}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.p}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.ip}</td>
                <td className="px-3 py-3 font-mono">{r.rate}</td>
                <td className="px-3 py-3 font-mono" style={{ color: r.tamper > 0 ? "#d46a5e" : "var(--panel-text-muted)" }}>{r.tamper}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.last}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          SEC-9 Hardened mode disables UDP 514. SEC-10 per-source 10K msg/s. SEC-11 mTLS optional on TCP+TLS 6514. Allowlist in <code className="font-mono text-[10px]">sources.yaml</code>.
        </p>
      </div>

      {/* Asset Event Timeline (#17) */}
      <div className="skeuo-panel p-5 mt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Event Timeline · <span style={{ color: "var(--panel-text-muted)" }}>phi-db-01</span>
          </h3>
          <div className="flex gap-1 text-[11px]">
            {["HOT (90d)", "WARM (60d)", "COLD"].map((l, i) => (
              <span key={l} className="rounded-full px-2 py-0.5"
                style={{ background: i === 0 ? "rgba(212,106,94,0.15)" : i === 1 ? "rgba(225,150,82,0.15)" : "rgba(126,174,174,0.15)",
                         color: i === 0 ? "#d46a5e" : i === 1 ? "#e09650" : "#7eaeae" }}>
                {l}
              </span>
            ))}
          </div>
        </div>
        <div className="space-y-1.5 text-[11.5px]">
          {[
            { t: "16:42 today",     lane: "HOT",  txt: "alerts_timeline · bulk_phi_query × 12,400 rows from sjohnson_clm" },
            { t: "15:12 today",     lane: "HOT",  txt: "events_HOT · Okta auth.fail × 24 burst on dba_oracle_01" },
            { t: "11:08 today",     lane: "HOT",  txt: "scan_timeline · F-90412 CVE-2024-21287 (Oracle DB) found" },
            { t: "Yesterday 04:30", lane: "WARM", txt: "events_WARM · pam-vault-01 checkout outside window" },
            { t: "2 days ago",      lane: "WARM", txt: "scan_timeline · 3 HIPAA Security Rule violations resolved" },
            { t: "30 days ago",     lane: "COLD", txt: "events_COLD · Imperva DAM baseline snapshot" },
          ].map((e, i) => (
            <div key={i} className="flex items-center gap-3">
              <span className="font-mono w-28 shrink-0" style={{ color: "var(--panel-text-muted)" }}>{e.t}</span>
              <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase w-14 text-center"
                style={{ background: e.lane === "HOT" ? "rgba(212,106,94,0.15)" : e.lane === "WARM" ? "rgba(225,150,82,0.15)" : "rgba(126,174,174,0.15)",
                         color: e.lane === "HOT" ? "#d46a5e" : e.lane === "WARM" ? "#e09650" : "#7eaeae" }}>
                {e.lane}
              </span>
              <span style={{ color: "var(--panel-text)" }}>{e.txt}</span>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          ClickHouse-backed · partitioned by <code className="font-mono text-[10px]">(asset_id, timestamp)</code> · 4 materialized views for sub-second response.
        </p>
      </div>
    </PageShell>
  );
}

/* ─────────── Coventra Asset Registry ─────────── */

type RegistryFilter = "all" | "cloud" | "endpoints" | "servers" | "network";

function typeIcon(t: Asset["type"]) {
  if (t === "cloud") return <Cloud className="h-3.5 w-3.5" />;
  if (t === "workstation") return <Monitor className="h-3.5 w-3.5" />;
  if (t === "network") return <NetIcon className="h-3.5 w-3.5" />;
  if (t === "server" && /db|database/i.test("")) return <Database className="h-3.5 w-3.5" />;
  return <Server className="h-3.5 w-3.5" />;
}

const statusColor: Record<Asset["status"], string> = {
  healthy: "var(--metric-teal)",
  warning: "#e1c069",
  critical: "var(--crit-red)",
  unknown: "var(--panel-text-muted)",
};

function CoventraAssetRegistry({ filter }: { filter: RegistryFilter }) {
  const [all, setAll] = useState<Asset[]>([]);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<"any" | "critical" | "warning" | "healthy">("any");
  const [page, setPage] = useState(1);
  const [deletedIds, setDeletedIds] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState<Asset | null>(null);
  const PER_PAGE = 25;

  useEffect(() => {
    getAssets().then(setAll);
  }, []);

  const { scopes, activeRole, jitActive } = useRole();
  const allowedSens = scopes[activeRole].sensitivities;

  const undeleted = useMemo(() => all.filter((a) => !deletedIds.has(a.id)), [all, deletedIds]);

  // Tier-3 (Scope) filter — strip rows whose dataSensitivity is outside the role's scope.
  // JIT elevation temporarily reveals everything.
  const scopeHidden = useMemo(
    () =>
      jitActive
        ? 0
        : undeleted.filter((a) => !canSeeSensitivity(allowedSens, a.dataSensitivity)).length,
    [undeleted, allowedSens, jitActive]
  );
  const visible = useMemo(
    () =>
      jitActive
        ? undeleted
        : undeleted.filter((a) => canSeeSensitivity(allowedSens, a.dataSensitivity)),
    [undeleted, allowedSens, jitActive]
  );

  const byType = useMemo(() => {
    switch (filter) {
      case "cloud":      return visible.filter((a) => a.type === "cloud");
      case "endpoints":  return visible.filter((a) => a.type === "workstation");
      case "servers":    return visible.filter((a) => a.type === "server");
      case "network":    return visible.filter((a) => a.type === "network");
      default:           return visible;
    }
  }, [visible, filter]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return byType.filter((a) => {
      if (sev !== "any" && a.status !== sev) return false;
      if (!needle) return true;
      return (
        a.name.toLowerCase().includes(needle) ||
        a.businessLabel.toLowerCase().includes(needle) ||
        a.businessRole.toLowerCase().includes(needle) ||
        a.ip.toLowerCase().includes(needle) ||
        a.os.toLowerCase().includes(needle)
      );
    });
  }, [byType, q, sev]);

  useEffect(() => setPage(1), [q, sev, filter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const slice = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE);

  const kpis = useMemo(() => {
    const crit = byType.filter((a) => a.status === "critical").length;
    const warn = byType.filter((a) => a.status === "warning").length;
    const ok = byType.filter((a) => a.status === "healthy").length;
    const cloud = byType.filter((a) => a.deployment === "cloud").length;
    return { total: byType.length, crit, warn, ok, cloud };
  }, [byType]);

  const exportCsv = () => {
    const rows = filtered.map((a) => ({
      id: a.id,
      name: a.name,
      role: a.businessRole,
      label: a.businessLabel,
      type: a.type,
      deployment: a.deployment,
      ip: a.ip,
      os: a.os,
      status: a.status,
      health: a.healthScore,
      critical: a.vulnerabilities.critical,
      high: a.vulnerabilities.high,
      medium: a.vulnerabilities.medium,
      low: a.vulnerabilities.low,
      sensitivity: a.dataSensitivity,
      frameworks: a.complianceFrameworks.join("|"),
      lastScanned: a.lastScanned,
    }));
    if (rows.length === 0) return;
    const headers = Object.keys(rows[0]);
    const escape = (v: unknown) => {
      const s = String(v ?? "");
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const csv = [headers.join(","), ...rows.map((r) => headers.map((h) => escape((r as Record<string, unknown>)[h])).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `coventra-assets-${filter}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="mb-5 flex items-baseline gap-3">
        <h1 className="text-[22px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Coventra Health Insurance — Asset Registry
        </h1>
      </div>

      <div className="mb-5 grid grid-cols-5 gap-4">
        <AKpi label="Total" value={String(kpis.total)} tone="copper" sub="in scope" />
        <AKpi label="Healthy" value={String(kpis.ok)} tone="teal" sub={`${Math.round((kpis.ok / Math.max(1, kpis.total)) * 100)}%`} />
        <AKpi label="Warning" value={String(kpis.warn)} sub="needs review" />
        <AKpi label="Critical" value={String(kpis.crit)} tone="red" sub="immediate" />
        <AKpi label="Cloud" value={String(kpis.cloud)} tone="copper" sub="AWS + Azure" />
      </div>

      <div className="skeuo-panel p-5">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <div className="flex flex-1 items-center gap-2 rounded-lg px-3 py-1.5"
            style={{
              background: "var(--inset-base)",
              border: "1px solid var(--row-border)",
            }}>
            <Search className="h-4 w-4" style={{ color: "var(--panel-text-muted)" }} />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search by name, role, IP, OS…"
              className="h-7 flex-1 bg-transparent text-sm outline-none"
              style={{ color: "var(--panel-text)" }}
            />
          </div>
          <div className="flex items-center gap-1">
            {(["any", "critical", "warning", "healthy"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSev(s)}
                className="rounded-lg px-2.5 py-1.5 text-[11px] font-semibold uppercase"
                style={{
                  background: sev === s ? "rgba(224,160,99,0.18)" : "var(--inset-base)",
                  color: sev === s ? "var(--section-heading)" : "var(--panel-text-muted)",
                  border: `1px solid ${sev === s ? "rgba(224,160,99,0.4)" : "var(--row-border)"}`,
                }}
              >
                {s}
              </button>
            ))}
          </div>
          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}
          >
            <Download className="h-3.5 w-3.5" /> Export CSV
          </button>
        </div>

        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["", "Asset", "Role / Zone", "Sensitivity", "IP", "OS", "Vulns (C/H/M/L)", "Frameworks", "Health", "Status", "Actions"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {slice.map((a, i) => (
                <tr key={a.id} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-2.5" style={{ color: "var(--section-heading)" }}>
                    {typeIcon(a.type)}
                  </td>
                  <td className="px-3 py-2.5">
                    <p className="font-semibold">{a.name}</p>
                    <p className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>{a.businessLabel}</p>
                  </td>
                  <td className="px-3 py-2.5 text-[11.5px]">{a.businessRole}</td>
                  <td className="px-3 py-2.5">
                    <SensitivityBadge level={a.dataSensitivity} size="xs" />
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                    <SensitiveValue level={a.dataSensitivity}>{a.ip}</SensitiveValue>
                  </td>
                  <td className="px-3 py-2.5 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{a.os}</td>
                  <td className="px-3 py-2.5 font-mono text-[11px]">
                    <span style={{ color: a.vulnerabilities.critical ? "var(--crit-red)" : "var(--panel-text-muted)" }}>{a.vulnerabilities.critical}</span>
                    {" / "}
                    <span style={{ color: a.vulnerabilities.high ? "#e09650" : "var(--panel-text-muted)" }}>{a.vulnerabilities.high}</span>
                    {" / "}
                    <span style={{ color: a.vulnerabilities.medium ? "#e1c069" : "var(--panel-text-muted)" }}>{a.vulnerabilities.medium}</span>
                    {" / "}
                    <span style={{ color: "var(--panel-text-muted)" }}>{a.vulnerabilities.low}</span>
                  </td>
                  <td className="px-3 py-2.5 text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>
                    {a.complianceFrameworks.join(" · ") || "—"}
                  </td>
                  <td className="px-3 py-2.5 font-mono">{a.healthScore}</td>
                  <td className="px-3 py-2.5">
                    <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase"
                      style={{ color: statusColor[a.status] }}>
                      <span className="h-1.5 w-1.5 rounded-full"
                        style={{ background: statusColor[a.status], boxShadow: `0 0 4px ${statusColor[a.status]}` }} />
                      {a.status}
                    </span>
                  </td>
                  <td className="px-3 py-2.5">
                    <button
                      onClick={() => setConfirmDelete(a)}
                      title="Delete asset"
                      className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[10.5px] font-semibold"
                      style={{
                        background: "rgba(212,106,94,0.12)",
                        color: "var(--crit-red)",
                        border: "1px solid rgba(212,106,94,0.3)",
                      }}
                    >
                      <Trash2 className="h-3 w-3" /> Delete
                    </button>
                  </td>
                </tr>
              ))}
              {slice.length === 0 && (
                <tr><td colSpan={11} className="px-3 py-10 text-center text-[12px]" style={{ color: "var(--panel-text-muted)" }}>
                  No assets match the current filter.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        <HiddenItemsNotice count={scopeHidden} resourceLabel="assets" />

        <div className="mt-3 flex items-center justify-between text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          <span>
            Showing {slice.length === 0 ? 0 : (page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, filtered.length)} of {filtered.length.toLocaleString()}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="rounded-md p-1.5 disabled:opacity-40"
              style={{ background: "rgba(255,255,255,0.06)", border: "1px solid var(--row-border)" }}
            >
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <span className="px-2 font-mono">Page {page} / {totalPages}</span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="rounded-md p-1.5 disabled:opacity-40"
              style={{ background: "rgba(255,255,255,0.06)", border: "1px solid var(--row-border)" }}
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {confirmDelete && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)" }}
          onClick={() => setConfirmDelete(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="max-w-md rounded-2xl p-6"
            style={{
              background: "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
              border: "1px solid rgba(212,106,94,0.5)",
              boxShadow: "0 20px 60px rgba(0,0,0,0.6), 0 0 30px rgba(212,106,94,0.2)",
            }}
          >
            <div className="mb-3 flex items-center gap-3">
              <div
                className="flex h-12 w-12 items-center justify-center rounded-xl"
                style={{
                  background: "radial-gradient(circle at 35% 25%, rgba(212,106,94,0.4), rgba(80,30,25,0.6))",
                  color: "var(--crit-red)",
                  boxShadow: "inset 0 1px 0 rgba(255,180,170,0.3), inset 0 -2px 4px rgba(0,0,0,0.5)",
                }}
              >
                <AlertTriangle className="h-6 w-6" />
              </div>
              <div>
                <p className="text-[10.5px] font-semibold uppercase tracking-[0.25em]" style={{ color: "var(--crit-red)" }}>
                  Delete Asset
                </p>
                <p className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
                  {confirmDelete.name}
                </p>
              </div>
            </div>
            <p className="mb-1 text-[12.5px]" style={{ color: "var(--panel-text)" }}>
              {confirmDelete.businessLabel}
            </p>
            <p className="mb-4 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
              Removes the asset from the registry, scans, alerts and reports. This action is logged. You can undo within this session.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setConfirmDelete(null)}
                className="flex-1 rounded-lg px-4 py-2 text-[12px] font-semibold"
                style={{
                  background: "rgba(255,255,255,0.06)",
                  color: "var(--panel-text)",
                  border: "1px solid var(--row-border)",
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  setDeletedIds((prev) => {
                    const next = new Set(prev);
                    next.add(confirmDelete.id);
                    return next;
                  });
                  setConfirmDelete(null);
                }}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2 text-[12px] font-semibold"
                style={{
                  background: "linear-gradient(180deg, rgba(212,106,94,0.4), rgba(150,50,40,0.6))",
                  color: "#fff",
                  border: "1px solid rgba(212,106,94,0.6)",
                  boxShadow: "inset 0 1px 0 rgba(255,180,170,0.3), 0 0 14px rgba(212,106,94,0.4)",
                }}
              >
                <Trash2 className="h-3.5 w-3.5" /> Delete Asset
              </button>
            </div>
          </div>
        </div>
      )}

      {deletedIds.size > 0 && (
        <div
          className="fixed bottom-6 left-1/2 z-40 flex -translate-x-1/2 items-center gap-3 rounded-full px-4 py-2 text-[12px] font-semibold"
          style={{
            background: "rgba(0,0,0,0.85)",
            color: "#fff",
            border: "1px solid rgba(224,160,99,0.5)",
            boxShadow: "0 6px 24px rgba(0,0,0,0.5)",
          }}
        >
          <Trash2 className="h-3.5 w-3.5" style={{ color: "var(--crit-red)" }} />
          {deletedIds.size} asset{deletedIds.size > 1 ? "s" : ""} deleted this session
          <button
            onClick={() => setDeletedIds(new Set())}
            className="rounded-md px-2 py-0.5 text-[11px] font-semibold"
            style={{ background: "rgba(224,160,99,0.18)", color: "var(--section-heading)" }}
          >
            Undo all
          </button>
        </div>
      )}
    </>
  );
}

function AKpi({ label, value, sub, tone = "teal" }: { label: string; value: string; sub: string; tone?: "teal" | "copper" | "red" }) {
  const color = tone === "red" ? "var(--crit-red)" : tone === "copper" ? "var(--metric-copper)" : "var(--metric-teal)";
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[26px] font-light leading-none" style={{ color }}>{value}</p>
          <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
        </div>
        <KpiBgIcon label={label} tone={tone} size={44} opacity={0.28} />
      </div>
    </div>
  );
}
