"use client";

import { PageShell } from "@/components/layout/page-shell";
import { technicalVolumes } from "@/lib/mock/fixtures";
import { Download } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";

function downloadCsv(filename: string, rows: Record<string, string | number | boolean>[]) {
  if (rows.length === 0) return;
  const headers = Object.keys(rows[0]);
  const escape = (v: unknown) => {
    const s = String(v ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [headers.join(","), ...rows.map((r) => headers.map((h) => escape(r[h])).join(","))].join("\n");
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

const sections = [
  {
    title: "Archives",
    defaultOpen: true,
    items: [
      { label: "Executive Volumes", href: "/reports?view=executive", badge: "12" },
      { label: "Technical Volumes", href: "/reports/technical-volumes", badge: "48" },
      { label: "Compliance Volumes", href: "/compliance", badge: "9" },
      { label: "Custom Exports", href: "/reports?view=custom" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/vulnerabilities" },
      { label: "Scan Down Reports", href: "/scans" },
      { label: "Alert Logs Summary", href: "/siem" },
      { label: "Top Risk Reports", href: "/risk-scoring/top-risks" },
      { label: "Security Improvement Analysis", href: "/security-score" },
    ],
  },
];

const statusColor: Record<string, { bg: string; fg: string }> = {
  Draft:     { bg: "rgba(225,192,105,0.18)", fg: "#e1c069" },
  Reviewed:  { bg: "rgba(213,154,82,0.18)",  fg: "#d59a52" },
  Published: { bg: "rgba(111,214,196,0.15)", fg: "#6fd6c4" },
};

export default function TechnicalVolumesPage() {
  return (
    <PageShell drillTitle="Archives Cluster" sections={sections}>
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Kpi label="Volumes" value={String(technicalVolumes.length)} sub="this quarter" />
        <Kpi label="Published" value={String(technicalVolumes.filter(v => v.status === "Published").length)} sub="ready to share" />
        <Kpi label="Drafts" value={String(technicalVolumes.filter(v => v.status === "Draft").length)} sub="awaiting review" tone="copper" />
        <Kpi label="Avg. CVSS" value={(technicalVolumes.reduce((s, v) => s + parseFloat(v.cvss), 0) / technicalVolumes.length).toFixed(1)} sub="across volumes" tone="copper" />
      </div>

      <div className="skeuo-panel p-6">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Technical Volumes
          </h3>
          <button
            onClick={() => downloadCsv("technical-volumes.csv", technicalVolumes as unknown as Record<string, string | number | boolean>[])}
            className="csv-btn rounded-lg px-3 py-1.5 text-[12px] font-semibold inline-flex items-center gap-2"
          >
            <Download className="h-3.5 w-3.5" /> Export CSV
          </button>
        </div>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["ID", "Title", "Asset", "CVSS", "Framework", "Author", "Pages", "Format", "Size", "Date", "Status", ""].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {technicalVolumes.map((v, i) => (
                <tr
                  key={v.id}
                  style={{
                    background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                    color: "var(--panel-text)",
                    borderTop: "1px solid var(--row-border)",
                  }}
                >
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{v.id}</td>
                  <td className="px-3 py-3 font-semibold">{v.title}</td>
                  <td className="px-3 py-3">{v.asset}</td>
                  <td className="px-3 py-3 font-mono" style={{ color: "#e0a063" }}>{v.cvss}</td>
                  <td className="px-3 py-3">{v.framework}</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{v.author}</td>
                  <td className="px-3 py-3 font-mono">{v.pages}</td>
                  <td className="px-3 py-3 text-[11.5px]">{v.format}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{v.size}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{v.date}</td>
                  <td className="px-3 py-3">
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase" style={{ background: statusColor[v.status].bg, color: statusColor[v.status].fg }}>
                      {v.status}
                    </span>
                  </td>
                  <td className="px-3 py-3">
                    <button
                      onClick={() => downloadCsv(`${v.id}.csv`, [v as unknown as Record<string, string | number | boolean>])}
                      className="inline-flex items-center gap-1 text-[11.5px] font-semibold"
                      style={{ color: "#e0a063" }}
                    >
                      <Download className="h-3 w-3" /> CSV
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
