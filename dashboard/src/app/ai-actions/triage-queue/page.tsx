"use client";

import { PageShell } from "@/components/layout/page-shell";
import { triageItems } from "@/lib/mock/fixtures";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "Operations",
    defaultOpen: true,
    items: [
      { label: "Triage Queue", href: "/ai-actions/triage-queue", badge: "12" },
      { label: "Patch Proposals", href: "/ai-actions", badge: "5" },
      { label: "Policy Drafts", href: "/ai-actions" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Action Logs", href: "/siem" },
      { label: "Approval History", href: "/reports" },
      { label: "Rule Updates", href: "/ai-actions" },
      { label: "Top Risk Reports", href: "/risk-scoring/top-risks" },
      { label: "Security Improvement Analysis", href: "/security-score" },
    ],
  },
];

const stateColor: Record<string, { bg: string; fg: string }> = {
  Pending:        { bg: "rgba(225,192,105,0.18)", fg: "#e1c069" },
  Approved:       { bg: "rgba(111,214,196,0.15)", fg: "#6fd6c4" },
  "Awaiting Eval":{ bg: "rgba(213,154,82,0.18)",  fg: "#d59a52" },
  "Auto-applied": { bg: "rgba(111,214,196,0.20)", fg: "#6fd6b3" },
};

export default function TriageQueuePage() {
  const totalDelta = triageItems.reduce((s, t) => s + (t.riskBefore - t.riskAfter), 0).toFixed(1);

  return (
    <PageShell drillTitle="AI Operations" sections={sections}>
      <div className="grid grid-cols-4 gap-4 mb-6">
        <Kpi label="Items In Queue"  value={String(triageItems.length)} sub="auto-triaged"     tone="copper" />
        <Kpi label="Auto-applied"    value={String(triageItems.filter(t => t.state === "Auto-applied").length)} sub="last 24h" />
        <Kpi label="Pending Review"  value={String(triageItems.filter(t => t.state === "Pending" || t.state === "Awaiting Eval").length)} sub="human-in-loop" tone="copper" />
        <Kpi label="Aggregate Risk ↓" value={totalDelta} sub="CVSS reduced" />
      </div>

      <div className="skeuo-panel p-6">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            AI Triage Queue
          </h3>
          <button
            className="rounded-lg px-3 py-1.5 text-[12px] font-semibold"
            style={{
              background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
              color: "var(--disc-text)",
              boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
            }}
          >
            Approve All Low-Blast
          </button>
        </div>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["ID", "CVE", "Asset", "Proposal", "Risk Before", "Risk After", "Δ", "Confidence", "Blast", "ETA", "Owner", "State"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {triageItems.map((t, i) => {
                const delta = (t.riskBefore - t.riskAfter).toFixed(1);
                return (
                  <tr
                    key={t.id}
                    style={{
                      background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                      color: "var(--panel-text)",
                      borderTop: "1px solid var(--row-border)",
                    }}
                  >
                    <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{t.id}</td>
                    <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{t.cve}</td>
                    <td className="px-3 py-3 font-semibold">{t.asset}</td>
                    <td className="px-3 py-3">{t.proposal}</td>
                    <td className="px-3 py-3 font-mono" style={{ color: "#d59a52" }}>{t.riskBefore.toFixed(1)}</td>
                    <td className="px-3 py-3 font-mono" style={{ color: "#6fd6c4" }}>{t.riskAfter.toFixed(1)}</td>
                    <td className="px-3 py-3 font-semibold" style={{ color: "#6fd6c4" }}>−{delta}</td>
                    <td className="px-3 py-3 font-mono">{t.confidence}%</td>
                    <td className="px-3 py-3 text-[11.5px]">{t.blastRadius}</td>
                    <td className="px-3 py-3 font-mono text-[11.5px]">{t.eta}</td>
                    <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{t.owner}</td>
                    <td className="px-3 py-3">
                      <span
                        className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                        style={{
                          background: stateColor[t.state]?.bg ?? "rgba(255,255,255,0.08)",
                          color: stateColor[t.state]?.fg ?? "var(--panel-text)",
                        }}
                      >
                        {t.state}
                      </span>
                    </td>
                  </tr>
                );
              })}
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
