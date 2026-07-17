"use client";

import { PageShell } from "@/components/layout/page-shell";
import { databaseAssets } from "@/lib/mock/fixtures";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "Asset Cluster",
    defaultOpen: true,
    items: [
      { label: "All Assets", href: "/assets?view=all", badge: "156" },
      { label: "Cloud", href: "/assets?view=cloud", badge: "82" },
      { label: "Endpoints", href: "/assets?view=endpoints", badge: "44" },
      { label: "Databases", href: "/assets/databases", badge: "18" },
      { label: "Network", href: "/assets?view=network", badge: "12" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/vulnerabilities" },
      { label: "Scan Operations", href: "/scans" },
      { label: "Alert Logs Summary", href: "/siem" },
      { label: "Top Risk Reports", href: "/risk-scoring/top-risks" },
      { label: "Security Improvement Analysis", href: "/security-score" },
    ],
  },
];

function sevColor(c: number): string {
  if (c >= 9) return "#d46a5e";
  if (c >= 7) return "#d59a52";
  if (c >= 4) return "#e1c069";
  return "#6fd6c4";
}

export default function DatabaseAssetsPage() {
  return (
    <PageShell drillTitle="Asset Registry" sections={sections}>
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Kpi label="Databases" value="18" sub="across 4 clouds" />
        <Kpi label="At-Risk" value="6" sub="CVSS ≥ 7.0" tone="copper" />
        <Kpi label="Unencrypted" value="1" sub="MYSQL-LEGACY-01" tone="copper" />
        <Kpi label="EoL Engines" value="1" sub="MySQL 5.7" />
      </div>

      <div className="skeuo-panel p-6">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Database Assets ({databaseAssets.length})
          </h3>
          <span className="text-[12px]" style={{ color: "var(--panel-text-muted)" }}>
            Live · last sync 12:42 UTC
          </span>
        </div>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr
                style={{
                  background:
                    "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))",
                  color: "var(--section-heading)",
                }}
              >
                {["ID", "Name", "Engine", "Version", "Cloud", "Region", "IP", "Env", "Encryption", "Findings", "CVSS", "Last Scan"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {databaseAssets.map((d, i) => (
                <tr
                  key={d.id}
                  style={{
                    background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                    color: "var(--panel-text)",
                    borderTop: "1px solid var(--row-border)",
                  }}
                >
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{d.id}</td>
                  <td className="px-3 py-3 font-semibold">{d.name}</td>
                  <td className="px-3 py-3">{d.engine}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{d.version}</td>
                  <td className="px-3 py-3">{d.cloud}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{d.region}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{d.ip}</td>
                  <td className="px-3 py-3 uppercase text-[10.5px]" style={{ color: d.env === "prod" ? "#e0a063" : "var(--panel-text-muted)" }}>{d.env}</td>
                  <td className="px-3 py-3">
                    <span
                      className="rounded-full px-2 py-0.5 text-[10px] font-semibold"
                      style={{
                        background: d.encryption === "None" ? "rgba(212,106,94,0.18)" : "rgba(111,214,196,0.15)",
                        color: d.encryption === "None" ? "#d46a5e" : "#6fd6c4",
                      }}
                    >
                      {d.encryption}
                    </span>
                  </td>
                  <td className="px-3 py-3">{d.openFindings}</td>
                  <td className="px-3 py-3 font-semibold" style={{ color: sevColor(d.cvssMax) }}>{d.cvssMax.toFixed(1)}</td>
                  <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{d.lastScan}</td>
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
          <p
            className="numeric-glow mt-1.5 text-[28px] font-light leading-none"
            style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}
          >
            {value}
          </p>
          <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}
