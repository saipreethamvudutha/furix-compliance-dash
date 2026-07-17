"use client";

import { PageShell } from "@/components/layout/page-shell";
import { liveThreats, type Severity } from "@/lib/mock/fixtures";

const sections = [
  {
    title: "Overview",
    defaultOpen: true,
    items: [
      { label: "Security Posture Summary", href: "/" },
      { label: "Geographic Mapping View", href: "/assets" },
      { label: "Live Threat Feed", href: "/live-threat-feed", badge: "Live" },
      { label: "Compliance Pulse", href: "/compliance" },
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
      { label: "AI Remediation Queue", href: "/ai-actions/triage-queue", badge: "12" },
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

export default function LiveThreatFeedPage() {
  const counts = liveThreats.reduce<Record<Severity, number>>(
    (acc, t) => { acc[t.severity] = (acc[t.severity] || 0) + 1; return acc; },
    { Critical: 0, High: 0, Medium: 0, Low: 0 }
  );

  return (
    <PageShell drillTitle="Overview Details" sections={sections}>
      <div className="mb-6 flex items-center gap-3">
        <span
          className="inline-flex items-center gap-2 rounded-full px-3 py-1 text-[12px] font-semibold uppercase tracking-wider"
          style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#6fd6c4] opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-[#6fd6c4]" />
          </span>
          Live · streaming
        </span>
        <span className="text-[12px]" style={{ color: "var(--panel-text-muted)" }}>
          12 events / minute · 4 sensors active
        </span>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        {(["Critical", "High", "Medium", "Low"] as Severity[]).map((s) => (
          <div key={s} className="skeuo-panel p-4">
            <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{s}</p>
            <p className="numeric-glow mt-2 text-[32px] font-light leading-none" style={{ color: sevTint[s].fg }}>
              {counts[s]}
            </p>
            <p className="mt-1 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>last 15 minutes</p>
          </div>
        ))}
      </div>

      <div className="skeuo-panel p-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Live Threat Stream
        </h3>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["Time", "Source", "Src IP", "Geo", "Detection", "MITRE", "Asset", "Conf.", "State", "Severity"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {liveThreats.map((t, i) => (
                <tr
                  key={`${t.ts}-${i}`}
                  style={{
                    background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                    color: "var(--panel-text)",
                    borderTop: "1px solid var(--row-border)",
                  }}
                >
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{t.ts}</td>
                  <td className="px-3 py-3">{t.src}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{t.srcIp}</td>
                  <td className="px-3 py-3 text-[11.5px]">{t.geo}</td>
                  <td className="px-3 py-3">{t.detection}</td>
                  <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "#e0a063" }}>{t.mitre}</td>
                  <td className="px-3 py-3 font-semibold">{t.asset}</td>
                  <td className="px-3 py-3 font-mono">{t.confidence}%</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{t.state}</td>
                  <td className="px-3 py-3">
                    <span
                      className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                      style={{ background: sevTint[t.severity].bg, color: sevTint[t.severity].fg }}
                    >
                      {t.severity}
                    </span>
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
