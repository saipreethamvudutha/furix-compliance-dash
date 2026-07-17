"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { siemViews, commonViews } from "@/lib/mock/views";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...siemViews,
  "alert-summary": commonViews["alert-summary"],
  "top-risks": commonViews["top-risks"],
  "rule-updates": commonViews["alert-summary"],
  "improvement": commonViews.improvement,
  "asset-vuln": commonViews["asset-vuln"],
  "compliance-map": commonViews["compliance-map"],
};

const sections = [
  {
    title: "Streams",
    defaultOpen: true,
    items: [
      { label: "Live Alerts", href: "/siem?view=live", badge: "Live" },
      { label: "Sources", href: "/siem?view=sources", badge: "18" },
      { label: "Detection Rules", href: "/siem?view=rules", badge: "204" },
      { label: "Forwarders", href: "/siem?view=forwarders" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Alert Logs Summary", href: "/siem?view=alert-summary" },
      { label: "Top Risk Reports", href: "/siem?view=top-risks" },
      { label: "Rule Updates", href: "/siem?view=rule-updates" },
      { label: "Security Improvement Analysis", href: "/siem?view=improvement" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Asset Vulnerabilities", href: "/siem?view=asset-vuln" },
      { label: "Compliance Map", href: "/siem?view=compliance-map" },
    ],
  },
];

export default function SiemPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "live";
  const block = localViews[view as keyof typeof localViews] ?? localViews.live;

  return (
    <PageShell drillTitle="Data Streams" sections={sections}>
      <ViewBlockView block={block} />

      {/* Event Lane Breakdown (#21) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Event Lane Breakdown (HOT / WARM / COLD)
        </h3>
        <div className="grid grid-cols-3 gap-4">
          {[
            { name: "HOT", desc: "Palo Alto / CrowdStrike / Okta",  rate: "8,142 e/s", lag: "62 ms",  target: "<100ms", partitions: 24, color: "#d46a5e", bg: "rgba(212,106,94,0.10)", consumers: 4 },
            { name: "WARM", desc: "Imperva DAM / CloudTrail / Nginx", rate: "12,408 e/s", lag: "412 ms", target: "<2s", partitions: 16, color: "#e09650", bg: "rgba(225,150,82,0.10)", consumers: 2 },
            { name: "COLD", desc: "Proofpoint / Splunk forwarders", rate: "24,712 e/s", lag: "1.8s",   target: "<10s", partitions: 8,  color: "#7eaeae", bg: "rgba(126,174,174,0.10)", consumers: 1 },
          ].map((l) => (
            <div key={l.name} className="rounded-xl border p-4"
              style={{ borderColor: "var(--row-border)", background: l.bg }}>
              <div className="flex items-baseline justify-between">
                <p className="text-[14px] font-semibold" style={{ color: l.color }}>{l.name}</p>
                <p className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>{l.consumers} consumers</p>
              </div>
              <p className="text-[10.5px] mb-3" style={{ color: "var(--panel-text-muted)" }}>{l.desc}</p>
              <div className="space-y-1 text-[11.5px]">
                <Row label="Rate" value={l.rate} mono />
                <Row label="Consumer lag" value={l.lag} color="#6fd6c4" mono />
                <Row label="Target" value={l.target} mono />
                <Row label="Kafka partitions" value={String(l.partitions)} mono />
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 rounded-xl border p-4"
          style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
          <p className="text-[12px] font-semibold mb-2" style={{ color: "var(--panel-text)" }}>
            Thread Weaver active threads
          </p>
          <div className="grid grid-cols-4 gap-3 text-[11.5px]">
            <Row label="Velocity" value="412 e/s" mono />
            <Row label="Pattern entropy" value="2.84" mono />
            <Row label="Escalation score" value="0.61" color="#e1c069" mono />
            <Row label="Active threads" value="18" mono />
          </div>
        </div>
      </div>

      {/* Log Source Configuration & Allowlist (#19) */}
      <div className="skeuo-panel p-5 mt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Log Sources · Allowlist Manager
          </h3>
          <label className="flex items-center gap-2 text-[11.5px]" style={{ color: "var(--panel-text)" }}>
            <input type="checkbox" defaultChecked className="h-3.5 w-3.5 accent-current" />
            Hardened Mode (SEC-9 — disable UDP 514, force mTLS)
          </label>
        </div>
        <div className="grid grid-cols-3 gap-3 mb-4">
          <KpiSmall label="Default per-source" value="10K msg/s" sub="SEC-10 token bucket" />
          <KpiSmall label="Global cap" value="50K msg/s" sub="aggregate ceiling" />
          <KpiSmall label="Unknown-source attempts" value="42 / 24h" sub="dropped at edge" />
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Source IP", "Protocol", "Rate (e/s)", "Tamper Events", "Unknown Attempts", "Actions"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { ip: "10.2.4.18",  p: "Syslog TCP+TLS 6514 (mTLS)", r: "8,142", tamper: 0, unk: 0 },
              { ip: "10.2.0.1",   p: "Syslog UDP 514",              r: "1,184", tamper: 2, unk: 0 },
              { ip: "10.2.6.42",  p: "WEF HTTPS 5986",              r: "412",   tamper: 0, unk: 0 },
              { ip: "10.4.0.0/24", p: "Cloud Audit Pull",            r: "224",   tamper: 0, unk: 0 },
              { ip: "10.9.12.4",  p: "—", r: "0", tamper: 0, unk: 42 },
            ].map((s, i) => (
              <tr key={s.ip + i} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono">{s.ip}</td>
                <td className="px-3 py-3 text-[11.5px]">{s.p}</td>
                <td className="px-3 py-3 font-mono">{s.r}</td>
                <td className="px-3 py-3 font-mono" style={{ color: s.tamper > 0 ? "#d46a5e" : "var(--panel-text-muted)" }}>{s.tamper}</td>
                <td className="px-3 py-3 font-mono" style={{ color: s.unk > 0 ? "#e1c069" : "var(--panel-text-muted)" }}>{s.unk}</td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
                    style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
                    {s.unk > 0 ? "Add to allowlist" : "Remove"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* DLQ Monitor (#20) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Dead-Letter Queues (8 failure queues)
          <span className="ml-2 text-[10px] font-mono align-middle" style={{ color: "#e0a063" }}>SEC-21 · spike alert &gt;5%</span>
        </h3>
        <div className="grid grid-cols-4 gap-2">
          {[
            { q: "parser_failure",        depth: 184, growth: "+12/m", replay: true },
            { q: "schema_unknown",        depth: 4,   growth: "0/m",   replay: true },
            { q: "field_mismatch",        depth: 0,   growth: "0/m",   replay: false },
            { q: "tamper.detected",       depth: 2,   growth: "0/m",   replay: false },
            { q: "enrichment_failure",    depth: 41,  growth: "+2/m",  replay: false },
            { q: "ai_parse_failure",      depth: 8,   growth: "+1/m",  replay: false },
            { q: "dlq.intel_parse",       depth: 0,   growth: "0/m",   replay: false },
            { q: "dlq.discovery_unreach", depth: 12,  growth: "0/m",   replay: false },
          ].map((d) => (
            <div key={d.q} className="rounded-lg border px-3 py-2.5"
              style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
              <p className="font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{d.q}</p>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-[20px] font-light" style={{ color: d.depth > 100 ? "#d46a5e" : d.depth > 0 ? "#e1c069" : "var(--panel-text)" }}>{d.depth}</span>
                <span className="text-[10.5px] font-mono" style={{ color: "var(--panel-text-muted)" }}>{d.growth}</span>
                {d.replay && (
                  <button className="ml-auto rounded-md px-1.5 py-0 text-[10px] font-semibold"
                    style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>Replay</button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </PageShell>
  );
}

function Row({ label, value, mono, color }: { label: string; value: string; mono?: boolean; color?: string }) {
  return (
    <div className="flex justify-between">
      <span style={{ color: "var(--panel-text-muted)" }}>{label}</span>
      <span className={mono ? "font-mono" : ""} style={{ color: color ?? "var(--panel-text)" }}>{value}</span>
    </div>
  );
}
function KpiSmall({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="rounded-lg border px-3 py-2" style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
      <p className="text-[10.5px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
      <p className="mt-1 text-[18px] font-semibold" style={{ color: "var(--panel-text)" }}>{value}</p>
      <p className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
    </div>
  );
}
