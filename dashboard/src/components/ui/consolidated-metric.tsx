"use client";

import { AreaChart, Area, ResponsiveContainer } from "recharts";

export function ConsolidatedMetric({
  totalAssetsLabel = "Total Assets",
  totalAssetsValue = "156",
  activeScansLabel = "Active Scans",
  activeScansValue = "8",
  extraLeft,
  extraRight,
}: {
  totalAssetsLabel?: string;
  totalAssetsValue?: string;
  activeScansLabel?: string;
  activeScansValue?: string;
  extraLeft?: { label: string; value: string }[];
  extraRight?: { label: string; value: string }[];
}) {
  const cols = [
    ...(extraLeft ?? []),
    { label: totalAssetsLabel, value: totalAssetsValue, tone: "teal" as const },
    { label: activeScansLabel, value: activeScansValue, tone: "copper" as const },
    ...(extraRight ?? []),
  ];
  return (
    <div className="glass-panel mb-5 grid divide-x divide-white/10 px-2 py-4"
      style={{ gridTemplateColumns: `repeat(${cols.length}, minmax(0,1fr))` }}
    >
      {cols.map((c, i) => {
        const isCopper = (c as any).tone === "copper";
        const tone = isCopper ? "#e0a063" : "#6fd6c4";
        const valColor = isCopper ? "var(--metric-copper)" : "var(--metric-teal)";
        const data = Array.from({ length: 6 }, (_, k) => ({ v: 8 + Math.sin(k + i) * 4 + k }));
        return (
          <div
            key={c.label}
            className="flex items-center justify-between px-5 py-2"
          >
            <div>
              <p className="text-[12px]" style={{ color: "var(--panel-text-muted)" }}>
                {c.label}
              </p>
              <p className="numeric-glow mt-1 text-[34px] font-light leading-none" style={{ color: valColor }}>
                {c.value}
              </p>
            </div>
            <div className="h-12 w-24">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data} margin={{ top: 6, right: 0, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id={`cm-${i}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%"  stopColor={tone} stopOpacity={0.85} />
                      <stop offset="60%" stopColor={tone} stopOpacity={0.25} />
                      <stop offset="100%" stopColor={tone} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area
                    type="monotone"
                    dataKey="v"
                    stroke={tone}
                    strokeWidth={2}
                    fill={`url(#cm-${i})`}
                    fillOpacity={1}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        );
      })}
    </div>
  );
}
