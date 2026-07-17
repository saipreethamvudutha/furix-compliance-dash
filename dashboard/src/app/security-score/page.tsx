"use client";

import { PageShell } from "@/components/layout/page-shell";
import { ConsolidatedMetric } from "@/components/ui/consolidated-metric";

export default function SecurityScorePage() {
  return (
    <PageShell
      drillTitle="Security Score Cluster"
      sections={[
        {
          title: "Score",
          defaultOpen: true,
          items: [
            { label: "Overall Score", href: "/security-score" },
            { label: "Pillar Breakdown", href: "/security-score" },
            { label: "Historic Trend", href: "/security-score" },
          ],
        },
        {
          title: "Drill-down",
          defaultOpen: true,
          items: [
            { label: "Failing Controls", href: "/compliance", badge: "7" },
            { label: "Top Risk Reports", href: "/risk-scoring" },
            { label: "Security Improvement Analysis", href: "/security-score" },
            { label: "Vulnerability Triage", href: "/vulnerabilities" },
          ],
        },
      ]}
    >
      <ConsolidatedMetric />
      <div className="grid grid-cols-3 gap-5">
        <div className="skeuo-panel col-span-1 flex flex-col items-center justify-center p-8">
          <p className="text-[12px] uppercase tracking-widest" style={{ color: "var(--panel-text-muted)" }}>
            Composite Score
          </p>
          <p className="numeric-glow mt-4 text-[88px] font-extralight leading-none" style={{ color: "var(--metric-teal)" }}>
            72
          </p>
          <p className="mt-2 text-[12px]" style={{ color: "var(--section-heading)" }}>
            +5 this month
          </p>
        </div>
        <div className="skeuo-panel col-span-2 p-5">
          <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Pillar Breakdown
          </h3>
          <div className="space-y-3">
            {[
              ["Identity", 84],
              ["Network", 78],
              ["Endpoint", 71],
              ["Data", 66],
              ["Application", 59],
            ].map(([k, v]) => (
              <div key={k as string} className="skeuo-inset px-4 py-3">
                <div className="flex items-center justify-between text-[13px]">
                  <span style={{ color: "var(--panel-text)" }}>{k}</span>
                  <span style={{ color: "#e0a063" }}>{v}</span>
                </div>
                <div
                  className="mt-2 h-2 w-full rounded-full"
                  style={{
                    background: "var(--progress-track-bg)",
                    boxShadow: "inset 0 1px 3px var(--progress-track-shadow)",
                  }}
                >
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${v}%`,
                      background: "linear-gradient(90deg, #6fd6c4, #e0a063)",
                      boxShadow: "0 0 8px rgba(111,214,196,0.6)",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </PageShell>
  );
}
