"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { reportsViews, commonViews } from "@/lib/mock/views";
import { Download } from "lucide-react";

function downloadCsv(filename: string, rows: Record<string, string | number | boolean>[]) {
  if (rows.length === 0) return;
  const headers = Object.keys(rows[0]);
  const escape = (v: unknown) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => escape(r[h])).join(",")),
  ].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const SCHEDULED_REPORTS = [
  { name: "Compliance Report (CIS/NIST/PCI)",  cadence: "Weekly · Mon 06:00 UTC",  scope: "All assets",    role: "compliance_admin", next: "in 3d",     last: "5d ago" },
  { name: "Executive Summary",                 cadence: "Weekly · Mon 07:00 UTC",  scope: "Tenant-wide",   role: "executive_viewer", next: "in 3d",     last: "5d ago" },
  { name: "Technical Vulnerability Assessment",cadence: "Daily · 02:00 UTC",       scope: "prod tag",      role: "risk_analyst",     next: "in 9h 12m", last: "14h ago" },
  { name: "Risk Assessment Report",            cadence: "Monthly · 1st 06:00 UTC", scope: "All scopes",    role: "risk_analyst",     next: "in 21d",    last: "10d ago" },
  { name: "SOC 2 Readiness Assessment",        cadence: "Monthly · 1st 08:00 UTC", scope: "in-scope only", role: "compliance_admin", next: "in 21d",    last: "10d ago" },
];

const ENCRYPTED_DOWNLOADS = [
  { r: "Compliance · SOC 2", fmt: "PDF + CSV", enc: "AES-256-GCM", wm: "Visible + invisible", ttl: "HMAC URL · 15min TTL · single-use", mfa: true },
  { r: "Executive Summary",  fmt: "PDF + CSV", enc: "AES-256-GCM", wm: "Visible + invisible", ttl: "HMAC URL · 15min TTL",             mfa: false },
  { r: "Technical Vuln",     fmt: "PDF + CSV", enc: "AES-256-GCM", wm: "Visible + invisible", ttl: "HMAC URL · 15min TTL",             mfa: false },
];

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...reportsViews,
  "asset-vuln": commonViews["asset-vuln"],
  "scan-down": commonViews["scan-down"],
  "alert-summary": commonViews["alert-summary"],
  "top-risks": commonViews["top-risks"],
  "improvement": commonViews.improvement,
};

const sections = [
  {
    title: "Archives",
    defaultOpen: true,
    items: [
      { label: "Executive Volumes", href: "/reports?view=executive", badge: "12" },
      { label: "Technical Volumes", href: "/reports/technical-volumes", badge: "48" },
      { label: "Custom Exports", href: "/reports?view=custom" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/reports?view=asset-vuln" },
      { label: "Scan Down Reports", href: "/reports?view=scan-down" },
      { label: "Alert Logs Summary", href: "/reports?view=alert-summary" },
      { label: "Top Risk Reports", href: "/reports?view=top-risks" },
      { label: "Security Improvement Analysis", href: "/reports?view=improvement" },
    ],
  },
];

export default function ReportsPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "executive";
  const block = localViews[view as keyof typeof localViews] ?? localViews.executive;

  return (
    <PageShell drillTitle="Archives Cluster" sections={sections}>
      <ViewBlockView block={block} />

      {/* Scheduled Report Configuration (#25) */}
      <div className="skeuo-panel p-5 mt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Scheduled Reports <span className="text-[11px] font-normal" style={{ color: "var(--panel-text-muted)" }}>(systemd timers)</span>
          </h3>
          <div className="flex items-center gap-2">
            <button
              onClick={() => downloadCsv("scheduled-reports.csv", SCHEDULED_REPORTS)}
              className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
              style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}
            >
              <Download className="h-3.5 w-3.5" /> Download all CSV
            </button>
            <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
              style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
              + New Schedule
            </button>
          </div>
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Report Type", "Cadence", "Scope", "Role Entitlement", "Next Run", "Last Run", "Actions"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {SCHEDULED_REPORTS.map((r, i) => (
              <tr key={r.name} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-semibold">{r.name}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]">{r.cadence}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.scope}</td>
                <td className="px-3 py-3">
                  <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                    style={{ background: "rgba(224,160,99,0.18)", color: "#e0a063" }}>{r.role}</span>
                </td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#6fd6c4" }}>{r.next}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.last}</td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold mr-1"
                    style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>Edit</button>
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold mr-1"
                    style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>Run now</button>
                  <button
                    onClick={() => downloadCsv(`${slug(r.name)}.csv`, [r])}
                    className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
                    style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4", border: "1px solid rgba(111,214,196,0.3)" }}
                  >
                    <Download className="h-3 w-3" /> CSV
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Watermarked PDF Download (#26) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-1 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Encrypted PDF Downloads
          <span className="ml-2 text-[10px] font-mono align-middle" style={{ color: "#e0a063" }}>SEC-26 · SEC-27 · SEC-28</span>
        </h3>
        <p className="mb-4 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          WeasyPrint HTML→PDF. Sensitive reports (Compliance, SOC 2) require MFA re-authentication before generation.
        </p>
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="rounded-xl border p-4"
            style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
            <p className="text-[13px] font-semibold mb-2" style={{ color: "var(--panel-text)" }}>SEC-27 · AES-256-GCM Envelope</p>
            <ul className="text-[11.5px] space-y-1" style={{ color: "var(--panel-text-muted)" }}>
              <li>Per-report key derived via HKDF</li>
              <li>Tenant master key TPM-sealed</li>
              <li>DEK destroyed after delivery</li>
            </ul>
          </div>
          <div className="rounded-xl border p-4"
            style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
            <p className="text-[13px] font-semibold mb-2" style={{ color: "var(--panel-text)" }}>SEC-26 · Watermarking</p>
            <ul className="text-[11.5px] space-y-1" style={{ color: "var(--panel-text-muted)" }}>
              <li>Visible: tenant + report ID + timestamp diagonal overlay</li>
              <li>Invisible: kerning-encoded user ID (steganographic)</li>
              <li>Forensic leak attribution</li>
            </ul>
          </div>
        </div>

        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Report", "Format", "Encryption", "Watermark", "Download URL", "MFA Required", "CSV"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {ENCRYPTED_DOWNLOADS.map((r, i) => (
              <tr key={r.r} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-semibold">{r.r}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.fmt}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#6fd6c4" }}>{r.enc}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.wm}</td>
                <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{r.ttl}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: r.mfa ? "#d46a5e" : "var(--panel-text-muted)" }}>
                  {r.mfa ? "Yes (re-auth)" : "No"}
                </td>
                <td className="px-3 py-3">
                  <button
                    onClick={() => downloadCsv(`${slug(r.r)}.csv`, [r])}
                    className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
                    style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4", border: "1px solid rgba(111,214,196,0.3)" }}
                  >
                    <Download className="h-3 w-3" /> CSV
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-3 flex justify-end">
          <button
            onClick={() => downloadCsv("encrypted-downloads.csv", ENCRYPTED_DOWNLOADS)}
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}
          >
            <Download className="h-3.5 w-3.5" /> Download all CSV
          </button>
        </div>
      </div>
    </PageShell>
  );
}
