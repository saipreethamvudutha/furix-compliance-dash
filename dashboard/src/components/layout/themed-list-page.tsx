"use client";

import { PageShell } from "./page-shell";
import { ConsolidatedMetric } from "@/components/ui/consolidated-metric";
import type { DrillSection } from "./drill-down";

export function ThemedListPage({
  drillTitle,
  sections,
  panelTitle,
  rows,
  columns,
}: {
  drillTitle: string;
  sections: DrillSection[];
  panelTitle: string;
  rows: Record<string, string>[];
  columns: { key: string; label: string; align?: "left" | "right" }[];
}) {
  return (
    <PageShell drillTitle={drillTitle} sections={sections}>
      <ConsolidatedMetric />
      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          {panelTitle}
        </h3>
        <div className="overflow-hidden rounded-xl">
          <table className="w-full text-[13px]">
            <thead>
              <tr
                style={{
                  background:
                    "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))",
                  color: "var(--section-heading)",
                }}
              >
                {columns.map((c) => (
                  <th
                    key={c.key}
                    className={`px-4 py-2.5 text-${c.align ?? "left"} text-[11px] uppercase tracking-wider`}
                  >
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr
                  key={i}
                  style={{
                    background:
                      i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                    color: "var(--panel-text)",
                    borderTop: "1px solid var(--row-border)",
                  }}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className={`px-4 py-3 text-${c.align ?? "left"}`}
                    >
                      {r[c.key]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </PageShell>
  );
}
