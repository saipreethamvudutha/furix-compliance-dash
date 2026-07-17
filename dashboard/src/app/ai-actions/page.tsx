"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { aiViews, commonViews } from "@/lib/mock/views";
import { CheckCircle2, RefreshCw, ChevronDown, ChevronRight, Terminal, ShieldCheck, Loader2 } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...aiViews,
  "action-logs": commonViews["alert-summary"],
  "approval-history": commonViews["reports-summary"],
  "rule-updates": commonViews["alert-summary"],
  "top-risks": commonViews["top-risks"],
  "improvement": commonViews.improvement,
  "asset-vuln": commonViews["asset-vuln"],
  "compliance-map": commonViews["compliance-map"],
};

const sections = [
  {
    title: "Operations",
    defaultOpen: true,
    items: [
      { label: "Remediation Steps", href: "/ai-actions?view=remediation", badge: "6" },
      { label: "Triage Queue", href: "/ai-actions/triage-queue", badge: "12" },
      { label: "Patch Proposals", href: "/ai-actions?view=patches", badge: "5" },
      { label: "Policy Drafts", href: "/ai-actions?view=policies" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Action Logs", href: "/ai-actions?view=action-logs" },
      { label: "Approval History", href: "/ai-actions?view=approval-history" },
      { label: "Rule Updates", href: "/ai-actions?view=rule-updates" },
      { label: "Top Risk Reports", href: "/ai-actions?view=top-risks" },
      { label: "Security Improvement Analysis", href: "/ai-actions?view=improvement" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Asset Vulnerabilities", href: "/ai-actions?view=asset-vuln" },
      { label: "Compliance Map", href: "/ai-actions?view=compliance-map" },
    ],
  },
];

function SafetyKpi({ label, value, sec, sub }: { label: string; value: string; sec: string; sub: string }) {
  return (
    <div className="rounded-xl border p-4" style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
      <div className="flex items-baseline justify-between">
        <p className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>{label}</p>
        <span className="text-[10px] font-mono" style={{ color: "#e0a063" }}>{sec}</span>
      </div>
      <p className="mt-1 text-[16px] font-semibold" style={{ color: "var(--metric-teal)" }}>{value}</p>
      <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
    </div>
  );
}
function DaemonCard({ name, cadence, last, desc }: { name: string; cadence: string; last: string; desc: string }) {
  return (
    <div className="rounded-xl border p-3" style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
      <p className="text-[13px] font-semibold" style={{ color: "var(--panel-text)" }}>{name}</p>
      <p className="text-[10.5px] font-mono" style={{ color: "#6fd6c4" }}>{cadence} · last: {last}</p>
      <p className="mt-1 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{desc}</p>
    </div>
  );
}

export default function AIActionsPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "auto";

  if (view === "remediation") {
    return (
      <PageShell drillTitle="AI Operations" sections={sections}>
        <RemediationSteps />
      </PageShell>
    );
  }

  const block = localViews[view as keyof typeof localViews] ?? localViews.auto;

  return (
    <PageShell drillTitle="AI Operations" sections={sections}>
      <ViewBlockView block={block} />

      {/* Instinct vs LLM Decision Path (#22) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-1 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Instinct vs LLM — Decision Path Breakdown
        </h3>
        <p className="mb-4 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Veracity cross-check shows agreement between Instinct and LLM. Click any decision to open its CI trace.
        </p>
        <div className="grid grid-cols-4 gap-3 mb-4">
          {[
            { name: "CTG Match",           pct: "34%", t: "<50ms",  desc: "Compiled Task Graph cache hit · deterministic replay" },
            { name: "Customer Instinct",   pct: "27%", t: "<5ms",   desc: "Per-tenant GBDT · customer-specific patterns" },
            { name: "System 1 Instinct",   pct: "29%", t: "<5ms",   desc: "Generic GBDT (XGBoost) · ~90% of decisions" },
            { name: "LLM Path (vLLM)",     pct: "10%", t: "~600ms", desc: "System 2 · ambiguous decisions only" },
          ].map((p) => (
            <div key={p.name} className="rounded-xl border p-3"
              style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
              <p className="text-[12px] font-semibold" style={{ color: "var(--panel-text)" }}>{p.name}</p>
              <p className="numeric-glow mt-1 text-[24px] font-light leading-none" style={{ color: "var(--metric-copper)" }}>{p.pct}</p>
              <p className="text-[10px] font-mono mt-1" style={{ color: "#6fd6c4" }}>{p.t}</p>
              <p className="text-[10.5px] mt-1" style={{ color: "var(--panel-text-muted)" }}>{p.desc}</p>
            </div>
          ))}
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Decision ID", "Asset", "Path", "Confidence", "Veracity Δ", "Latency", "CI Trace"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { id: "DEC-44892", a: "fin-db-01",  path: "CTG Match",         conf: 99, delta: "0.00", t: "12ms" },
              { id: "DEC-44891", a: "web-edge-2", path: "Customer Instinct", conf: 94, delta: "0.02", t: "4ms" },
              { id: "DEC-44890", a: "wks-1042",   path: "System 1 Instinct", conf: 88, delta: "0.04", t: "5ms" },
              { id: "DEC-44889", a: "k8s-node-7", path: "LLM Path",          conf: 82, delta: "0.11", t: "614ms" },
            ].map((d, i) => (
              <tr key={d.id} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{d.id}</td>
                <td className="px-3 py-3 font-semibold">{d.a}</td>
                <td className="px-3 py-3 text-[11.5px]">{d.path}</td>
                <td className="px-3 py-3 font-mono">{d.conf}%</td>
                <td className="px-3 py-3 font-mono" style={{ color: parseFloat(d.delta) > 0.1 ? "#e1c069" : "#6fd6c4" }}>{d.delta}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]">{d.t}</td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
                    style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
                    View trace →
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* LLM Safety Controls (#23) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          LLM Safety Controls
        </h3>
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div className="rounded-xl border p-4"
            style={{ borderColor: "rgba(212,106,94,0.35)", background: "rgba(212,106,94,0.08)" }}>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>Global LLM Kill Switch</p>
                <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>SEC-22 · falls back to Instinct Layer immediately</p>
              </div>
              <label className="flex items-center gap-2">
                <span className="text-[11px]" style={{ color: "#6fd6c4" }}>LLM ENABLED</span>
                <input type="checkbox" defaultChecked className="h-4 w-4 accent-current" />
              </label>
            </div>
          </div>
          <div className="rounded-xl border p-4"
            style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
            <p className="text-[14px] font-semibold mb-2" style={{ color: "var(--panel-text)" }}>Per-Tenant Prompt Policy <span className="text-[10px] font-mono ml-1" style={{ color: "#e0a063" }}>SEC-23</span></p>
            <ul className="space-y-1 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
              <li>Furix HQ — allow: remediation, summary · deny: external URLs</li>
              <li>Tenant-2 — allow: summary · deny: code generation</li>
            </ul>
          </div>
          <SafetyKpi label="Prompt Size Limit" value="50 KB" sec="SEC-24" sub="configurable per tenant" />
          <SafetyKpi label="Residual PII Scan" value="LAST: 14m ago · 0 hits" sec="SEC-25" sub="dlq.ai_parse_failure: 8" />
        </div>
        <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
          All changes audit-logged. Use the kill switch to instantly route every decision through the Instinct Layer.
        </p>
      </div>

      {/* CI Trace Viewer (#24) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-1 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Compiled Intelligence (CI) Trace Viewer
        </h3>
        <p className="mb-4 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Review every AI decision. Promote high-confidence patterns to <code className="font-mono text-[10px]">compiled_rules</code>.
        </p>
        <div className="grid grid-cols-3 gap-3 mb-4">
          <DaemonCard name="Consolidator" cadence="every 5 min" last="2m ago" desc="merges duplicate verdicts" />
          <DaemonCard name="Simulator" cadence="every 1 hour" last="14m ago" desc="counterfactual blind-spot detection" />
          <DaemonCard name="Sentinel" cadence="every 15 min" last="8m ago" desc="graph-shape anomaly detection" />
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Trace ID", "Prompt (PII-tokenized)", "Model", "Confidence", "Outcome", "Promote?"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { id: "CI-8841", prompt: "Score finding[F-90412] for asset[<PII>] with CVE[CVE-2025-1042]", model: "llm-v6.2", conf: 0.96, outcome: "Critical · escalate" },
              { id: "CI-8840", prompt: "Cluster similar findings for tenant[<PII>] using pgvector",     model: "instinct-c1", conf: 0.92, outcome: "14 grouped" },
              { id: "CI-8839", prompt: "Suggest remediation for finding[F-90408]",                     model: "llm-v6.2", conf: 0.88, outcome: "Patch v1.4.2" },
            ].map((r, i) => (
              <tr key={r.id} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{r.id}</td>
                <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{r.prompt}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.model}</td>
                <td className="px-3 py-3 font-mono">{r.conf.toFixed(2)}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.outcome}</td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
                    style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>
                    → compiled_rules
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Nightly Instinct model retrain pulls validated patterns from <code className="font-mono text-[10px]">ci_traces</code>.
        </p>
      </div>
    </PageShell>
  );
}

/* ─────────── Remediation Steps + Rerun Scan ─────────── */

type FindingStatus = "open" | "applied" | "scanning" | "verified" | "failed";

type Finding = {
  id: string;
  cve: string;
  title: string;
  asset: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  detected: string;
  steps: { label: string; cmd?: string; detail?: string }[];
};

const FINDINGS: Finding[] = [
  {
    id: "F-90412",
    cve: "CVE-2025-1042",
    title: "PostgreSQL CVE-2025-1042 — authenticated RCE",
    asset: "fin-db-01",
    severity: "Critical",
    detected: "12m ago",
    steps: [
      { label: "Snapshot the database volume",   cmd: "aws ec2 create-snapshot --volume-id vol-0a8b…",                 detail: "Rollback safety net before patching." },
      { label: "Upgrade Postgres to 16.4-r2",    cmd: "sudo apt-get install postgresql-16=16.4-r2",                   detail: "Vendor patch addresses CVE-2025-1042." },
      { label: "Restart and verify version",     cmd: "sudo systemctl restart postgresql && psql -c 'SHOW server_version;'" },
      { label: "Re-run authenticated DB scan to confirm fix" },
    ],
  },
  {
    id: "F-90408",
    cve: "CVE-2024-3094",
    title: "xz-utils backdoor (liblzma)",
    asset: "web-edge-2",
    severity: "High",
    detected: "1h ago",
    steps: [
      { label: "Downgrade xz to 5.4.6",          cmd: "sudo apt-get install xz-utils=5.4.6-0.1" },
      { label: "Pin package against re-upgrade",  cmd: "sudo apt-mark hold xz-utils" },
      { label: "Audit recent sshd auth attempts", cmd: "journalctl -u ssh --since '7 days ago' | grep -i preauth" },
      { label: "Re-run external attack surface scan" },
    ],
  },
  {
    id: "F-90401",
    cve: "CVE-2025-0871",
    title: "containerd privilege escalation",
    asset: "k8s-node-7",
    severity: "High",
    detected: "3h ago",
    steps: [
      { label: "Drain the node",                  cmd: "kubectl drain k8s-node-7 --ignore-daemonsets --delete-emptydir-data" },
      { label: "Update containerd to 1.7.22",     cmd: "sudo apt-get install containerd.io=1.7.22-1" },
      { label: "Restart kubelet",                 cmd: "sudo systemctl restart kubelet" },
      { label: "Uncordon and re-run cluster scan", cmd: "kubectl uncordon k8s-node-7" },
    ],
  },
  {
    id: "F-90395",
    cve: "CVE-2025-2104",
    title: "Windows SMB null session enumeration",
    asset: "wks-1042",
    severity: "Medium",
    detected: "1d ago",
    steps: [
      { label: "Disable SMB1 protocol",            cmd: "Set-SmbServerConfiguration -EnableSMB1Protocol $false" },
      { label: "Block anonymous enumeration",      cmd: "secedit /export /cfg sec.cfg  # enable RestrictAnonymous=2" },
      { label: "Re-run authenticated workstation scan" },
    ],
  },
  {
    id: "F-90388",
    cve: "CVE-2024-9821",
    title: "Apache outdated mod_ssl ciphers",
    asset: "srv-app-3",
    severity: "Medium",
    detected: "2d ago",
    steps: [
      { label: "Update ssl.conf to TLS 1.2+ only", detail: "Disable TLSv1.0, TLSv1.1, and CBC ciphers." },
      { label: "Reload Apache",                    cmd: "sudo systemctl reload apache2" },
      { label: "Re-run TLS configuration scan" },
    ],
  },
  {
    id: "F-90377",
    cve: "CVE-2024-4488",
    title: "IoT camera default credentials",
    asset: "iot-cam-12",
    severity: "Low",
    detected: "4d ago",
    steps: [
      { label: "Rotate device admin password",    detail: "Use device management portal · enforce 16+ chars." },
      { label: "Move device into IoT VLAN",       cmd: "switchctl move-port gi0/24 --vlan iot-isolated" },
      { label: "Re-run discovery scan" },
    ],
  },
];

const sevColor: Record<Finding["severity"], string> = {
  Critical: "var(--crit-red)",
  High: "#e09650",
  Medium: "#e1c069",
  Low: "var(--metric-teal)",
};

function RemediationSteps() {
  const [statuses, setStatuses] = useState<Record<string, FindingStatus>>(
    Object.fromEntries(FINDINGS.map((f) => [f.id, "open"]))
  );
  const [openIds, setOpenIds] = useState<Record<string, boolean>>({ [FINDINGS[0].id]: true });

  const setStatus = (id: string, s: FindingStatus) =>
    setStatuses((prev) => ({ ...prev, [id]: s }));

  const rerunScan = (id: string) => {
    setStatus(id, "scanning");
    setTimeout(() => {
      // 85% success rate to make it feel real
      const ok = Math.random() < 0.85;
      setStatus(id, ok ? "verified" : "failed");
    }, 1800);
  };

  const open    = FINDINGS.filter((f) => statuses[f.id] === "open").length;
  const applied = FINDINGS.filter((f) => statuses[f.id] === "applied").length;
  const verified= FINDINGS.filter((f) => statuses[f.id] === "verified").length;

  return (
    <>
      <div className="mb-5 flex items-baseline gap-3">
        <h1 className="text-[22px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Remediation Steps
        </h1>
        <span className="text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Manual review · apply the steps, then re-run the scan to confirm the finding is closed.
        </span>
      </div>

      <div className="mb-5 grid grid-cols-4 gap-4">
        <RKpi label="Open Findings" value={String(open)} sub="awaiting action" />
        <RKpi label="Steps Applied" value={String(applied)} sub="pending verification" tone="copper" />
        <RKpi label="Verified Fixes" value={String(verified)} sub="closed by rescan" />
        <RKpi label="Avg. Verification" value="~2m" sub="rescan turnaround" tone="copper" />
      </div>

      <div className="space-y-3">
        {FINDINGS.map((f) => {
          const status = statuses[f.id];
          const isOpen = openIds[f.id];
          return (
            <div key={f.id} className="skeuo-panel p-0 overflow-hidden">
              <button
                onClick={() => setOpenIds((o) => ({ ...o, [f.id]: !o[f.id] }))}
                className="flex w-full items-center gap-3 px-4 py-3 text-left"
              >
                {isOpen ? (
                  <ChevronDown className="h-4 w-4" style={{ color: "var(--section-heading)" }} />
                ) : (
                  <ChevronRight className="h-4 w-4" style={{ color: "var(--section-heading)" }} />
                )}
                <span
                  className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                  style={{ background: `${sevColor[f.severity]}22`, color: sevColor[f.severity] }}
                >
                  {f.severity}
                </span>
                <span className="font-mono text-[11.5px]" style={{ color: "var(--section-heading)" }}>{f.cve}</span>
                <span className="text-[13px] font-semibold" style={{ color: "var(--panel-text)" }}>
                  {f.title}
                </span>
                <span className="text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
                  · {f.asset} · {f.detected}
                </span>
                <span className="ml-auto">
                  <StatusBadge status={status} />
                </span>
              </button>

              {isOpen && (
                <div className="border-t px-4 py-4" style={{ borderColor: "var(--row-border)" }}>
                  <ol className="space-y-2">
                    {f.steps.map((s, i) => (
                      <li key={i} className="flex gap-3">
                        <span
                          className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-bold"
                          style={{
                            background:
                              "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                            color: "var(--disc-text)",
                            boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
                          }}
                        >
                          {i + 1}
                        </span>
                        <div className="flex-1">
                          <p className="text-[12.5px] font-semibold" style={{ color: "var(--panel-text)" }}>
                            {s.label}
                          </p>
                          {s.cmd && (
                            <pre
                              className="mt-1.5 overflow-x-auto rounded-lg px-3 py-2 font-mono text-[11.5px]"
                              style={{
                                background: "#0d1117",
                                color: "#6fd6c4",
                                border: "1px solid #1f2933",
                              }}
                            >
                              <Terminal className="mr-2 inline h-3 w-3" />
                              {s.cmd}
                            </pre>
                          )}
                          {s.detail && (
                            <p className="mt-1 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                              {s.detail}
                            </p>
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>

                  <div className="mt-4 flex items-center justify-end gap-2">
                    <button
                      onClick={() => setStatus(f.id, "applied")}
                      disabled={status === "applied" || status === "scanning" || status === "verified"}
                      className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold disabled:opacity-50"
                      style={{
                        background: "rgba(255,255,255,0.06)",
                        color: "var(--panel-text)",
                        border: "1px solid var(--row-border)",
                      }}
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" /> Mark steps applied
                    </button>
                    <button
                      onClick={() => rerunScan(f.id)}
                      disabled={status === "scanning" || status === "verified"}
                      className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold disabled:opacity-60"
                      style={{
                        background:
                          "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                        color: "var(--disc-text)",
                        boxShadow:
                          "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5), 0 0 12px rgba(224,160,99,0.25)",
                        border: "1px solid rgba(224,160,99,0.45)",
                      }}
                    >
                      {status === "scanning" ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3.5 w-3.5" />
                      )}
                      {status === "scanning" ? "Scanning…" : "Re-run scan to verify"}
                    </button>
                  </div>

                  {status === "verified" && (
                    <div
                      className="mt-3 flex items-center gap-2 rounded-lg px-3 py-2 text-[12px]"
                      style={{
                        background: "rgba(111,214,196,0.1)",
                        border: "1px solid rgba(111,214,196,0.3)",
                        color: "#6fd6c4",
                      }}
                    >
                      <ShieldCheck className="h-4 w-4" />
                      Rescan confirmed the vulnerability is no longer present. Finding closed.
                    </div>
                  )}
                  {status === "failed" && (
                    <div
                      className="mt-3 flex items-center gap-2 rounded-lg px-3 py-2 text-[12px]"
                      style={{
                        background: "rgba(212,106,94,0.1)",
                        border: "1px solid rgba(212,106,94,0.3)",
                        color: "var(--crit-red)",
                      }}
                    >
                      Rescan still detects the issue — review the steps and try again.
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}

function StatusBadge({ status }: { status: FindingStatus }) {
  const map: Record<FindingStatus, { label: string; bg: string; fg: string }> = {
    open:     { label: "Open",        bg: "rgba(255,255,255,0.06)",    fg: "var(--panel-text-muted)" },
    applied:  { label: "Steps Applied", bg: "rgba(224,160,99,0.18)",   fg: "var(--metric-copper)" },
    scanning: { label: "Scanning…",   bg: "rgba(111,214,196,0.15)",    fg: "#6fd6c4" },
    verified: { label: "Verified ✓",  bg: "rgba(111,214,196,0.2)",     fg: "#6fd6c4" },
    failed:   { label: "Still Open",  bg: "rgba(212,106,94,0.18)",     fg: "var(--crit-red)" },
  };
  const s = map[status];
  return (
    <span
      className="rounded-full px-2.5 py-1 text-[10.5px] font-semibold uppercase tracking-wide"
      style={{ background: s.bg, color: s.fg }}
    >
      {s.label}
    </span>
  );
}

function RKpi({ label, value, sub, tone = "teal" }: { label: string; value: string; sub: string; tone?: "teal" | "copper" }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[26px] font-light leading-none"
            style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}>
            {value}
          </p>
          <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}
