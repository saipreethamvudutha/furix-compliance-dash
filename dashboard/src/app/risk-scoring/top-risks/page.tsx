"use client";

import { PageShell } from "@/components/layout/page-shell";
import { topRisks, type Severity } from "@/lib/mock/fixtures";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "Risk Cluster",
    defaultOpen: true,
    items: [
      { label: "Top Risks", href: "/risk-scoring/top-risks", badge: "10" },
      { label: "Risk Matrix", href: "/risk-scoring?view=matrix" },
      { label: "Risk Trends", href: "/risk-scoring?view=trends" },
      { label: "Score Composition", href: "/security-score" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/vulnerabilities" },
      { label: "Scan Operations", href: "/scans" },
      { label: "Alert Logs Summary", href: "/siem" },
      { label: "Top Risk Reports", href: "/reports/technical-volumes" },
      { label: "Security Improvement Analysis", href: "/security-score" },
    ],
  },
];

const sevTint: Record<Severity, { bg: string; fg: string }> = {
  Critical: { bg: "rgba(212,106,94,0.18)",  fg: "#d46a5e" },
  High:     { bg: "rgba(213,154,82,0.18)",  fg: "#d59a52" },
  Medium:   { bg: "rgba(225,192,105,0.18)", fg: "#e1c069" },
  Low:      { bg: "rgba(111,214,196,0.15)", fg: "#6fd6c4" },
};

export default function TopRisksPage() {
  const exploited = topRisks.filter(r => r.exploited).length;
  const internet  = topRisks.filter(r => r.exposure === "Internet").length;

  return (
    <PageShell drillTitle="Risk Posture" sections={sections}>
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Kpi label="Top Risks" value="10" sub="curated by AI" />
        <Kpi label="Actively Exploited" value={String(exploited)} sub="in the wild" tone="copper" />
        <Kpi label="Internet-Facing" value={String(internet)} sub="hardening priority" tone="copper" />
        <Kpi label="Mean CVSS" value={(topRisks.reduce((s, r) => s + r.cvss, 0) / topRisks.length).toFixed(1)} sub="across top-10" />
      </div>

      <div className="skeuo-panel p-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Top 10 Risks — prioritized action queue
        </h3>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["#", "Asset", "CVSS", "Severity", "Category", "Exposure", "Exploited", "Age", "Owner", "Recommended Remediation"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {topRisks.map((r, i) => (
                <tr
                  key={r.rank}
                  style={{
                    background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                    color: "var(--panel-text)",
                    borderTop: "1px solid var(--row-border)",
                  }}
                >
                  <td className="px-3 py-3 font-mono text-[13px]" style={{ color: "#e0a063" }}>{r.rank}</td>
                  <td className="px-3 py-3 font-semibold">{r.asset}</td>
                  <td className="px-3 py-3 font-mono font-semibold" style={{ color: sevTint[r.severity].fg }}>{r.cvss.toFixed(1)}</td>
                  <td className="px-3 py-3">
                    <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase" style={{ background: sevTint[r.severity].bg, color: sevTint[r.severity].fg }}>
                      {r.severity}
                    </span>
                  </td>
                  <td className="px-3 py-3">{r.category}</td>
                  <td className="px-3 py-3 text-[11.5px]">{r.exposure}</td>
                  <td className="px-3 py-3">
                    {r.exploited ? (
                      <span className="rounded-full px-2 py-0.5 text-[10px] font-bold uppercase" style={{ background: "rgba(212,106,94,0.25)", color: "#d46a5e" }}>
                        Active
                      </span>
                    ) : (
                      <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>—</span>
                    )}
                  </td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{r.age}</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.owner}</td>
                  <td className="px-3 py-3">{r.remediation}</td>
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
