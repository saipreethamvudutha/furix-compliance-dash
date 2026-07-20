"use client";

import type { ViewBlock } from "@/lib/mock/views";
import { useCoventraStats } from "@/lib/data/use-coventra-stats";
import { KpiBgIcon } from "@/lib/kpi-icon";

/**
 * Substitute well-known KPI labels with live Coventra fleet values so every
 * module reports the same totals as the asset registry.
 */
function patchKpi(label: string, value: string, sub: string | undefined, s: ReturnType<typeof useCoventraStats>) {
  if (!s) return { value, sub };
  const l = label.toLowerCase();
  const fmt = (n: number) => n.toLocaleString();
  if (l === "total assets" || l === "total" || l === "assets" || l === "managed assets" || l === "assets monitored") {
    return { value: fmt(s.total), sub: sub ?? `${s.byStatus.healthy} healthy · ${s.byStatus.critical} critical` };
  }
  if (l === "vulnerable assets") {
    return { value: fmt(s.byStatus.warning + s.byStatus.critical), sub: `of ${fmt(s.total)}` };
  }
  if (l === "critical" || l === "critical findings") {
    return { value: fmt(s.vulns.critical), sub: sub ?? "open" };
  }
  if (l === "high") {
    return { value: fmt(s.vulns.high), sub: sub ?? "open" };
  }
  if (l === "medium") {
    return { value: fmt(s.vulns.medium), sub: sub ?? "open" };
  }
  if (l === "low") {
    return { value: fmt(s.vulns.low), sub: sub ?? "open" };
  }
  if (l === "open findings" || l === "open vulnerabilities" || l === "total findings") {
    return { value: fmt(s.vulns.total), sub: sub ?? "all severities" };
  }
  if (l === "cloud" || l === "cloud assets") {
    return { value: fmt(s.byDeployment.cloud), sub: sub ?? "AWS + Azure" };
  }
  if (l === "compliance score" || l === "compliance posture") {
    return { value: `${s.complianceScore}`, sub: sub ?? "across frameworks" };
  }
  if (l === "risk score") {
    return { value: `${s.riskScore}`, sub: sub ?? "fleet average" };
  }
  if (l === "active scans") {
    return { value: fmt(s.activeScans), sub: sub ?? "in flight" };
  }
  return { value, sub };
}

function sevColor(v: string): string {
  const n = parseFloat(v);
  if (isNaN(n)) {
    if (/critical/i.test(v)) return "#d46a5e";
    if (/high|fail/i.test(v)) return "#d59a52";
    if (/medium|warn|tuning|drift|degraded/i.test(v)) return "#e1c069";
    if (/low|pass|healthy|connected|active|enabled|enforced|paid|included/i.test(v)) return "#6fd6c4";
    return "var(--panel-text)";
  }
  if (n >= 9) return "#d46a5e";
  if (n >= 7) return "#d59a52";
  if (n >= 4) return "#e1c069";
  return "#6fd6c4";
}

function cellStyle(tone?: string, value?: string | number): React.CSSProperties {
  if (tone === "mono") return { fontFamily: "ui-monospace, monospace", fontSize: 11.5, color: "var(--panel-text)" };
  if (tone === "muted") return { color: "var(--panel-text-muted)", fontSize: 11.5 };
  if (tone === "copper") return { color: "#e0a063", fontWeight: 600 };
  if (tone === "teal") return { color: "#6fd6c4" };
  if (tone === "sev") return { color: sevColor(String(value ?? "")), fontWeight: 600 };
  return { color: "var(--panel-text)" };
}

export function ViewBlockView({
  block,
  kpiRightSlot,
}: {
  block: ViewBlock;
  kpiRightSlot?: React.ReactNode;
}) {
  const kpiCols = kpiRightSlot ? "grid-cols-5" : "grid-cols-4";
  const stats = useCoventraStats();
  return (
    <>
      {/* Honesty label (FUR-UX-001): these modules render illustrative sample
          data, not verified posture. Only /compliance and /findings are live. */}
      <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-slate-400/40 bg-slate-500/10 px-3 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-300">
        <span className="font-mono tracking-wide">DEMO</span>
        <span className="opacity-70">· sample data — see Compliance &amp; Findings for live, verified posture</span>
      </div>
      {block.intro && (
        <p className="mb-4 text-[13px]" style={{ color: "var(--panel-text-muted)" }}>
          {block.intro}
        </p>
      )}

      <div className={`mb-6 grid ${kpiCols} gap-4`}>
        {block.kpis.map((kRaw, idx) => {
          const patched = patchKpi(kRaw.label, kRaw.value, kRaw.sub, stats);
          const k = { ...kRaw, value: patched.value, sub: patched.sub ?? kRaw.sub };
          return (
          <div
            key={k.label}
            className="skeuo-panel p-4"
          >
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0 flex-1">
                <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{k.label}</p>
                <p
                  className="numeric-glow mt-1.5 text-[28px] font-light leading-none"
                  style={{ color: k.tone === "copper" ? "var(--metric-copper)" : "var(--metric-teal)" }}
                >
                  {k.value}
                </p>
                <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{k.sub}</p>
              </div>
              <KpiBgIcon label={k.label} tone={k.tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
            </div>
          </div>
          );
        })}
        {kpiRightSlot && <div className="col-start-5">{kpiRightSlot}</div>}
      </div>

      <div className="skeuo-panel p-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          {block.title} <span className="ml-2 text-[12px] font-normal" style={{ color: "var(--panel-text-muted)" }}>({block.rows.length})</span>
        </h3>
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
                {block.columns.map((c) => (
                  <th
                    key={c.key}
                    className={`px-3 py-2.5 text-${c.align ?? "left"} text-[10.5px] uppercase tracking-wider`}
                  >
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((r, i) => (
                <tr
                  key={i}
                  style={{
                    background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                    borderTop: "1px solid var(--row-border)",
                  }}
                >
                  {block.columns.map((c) => (
                    <td
                      key={c.key}
                      className={`px-3 py-3 text-${c.align ?? "left"}`}
                      style={cellStyle(c.tone, r[c.key])}
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
    </>
  );
}
