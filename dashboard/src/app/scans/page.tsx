"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { NewScanDial } from "@/components/ui/new-scan-dial";
import { scansViews, commonViews } from "@/lib/mock/views";
import { Play, CalendarClock, Target, Radar, X, ChevronRight } from "lucide-react";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...scansViews,
  "asset-vuln": commonViews["asset-vuln"],
  "scan-down": commonViews["scan-down"],
  "alert-summary": commonViews["alert-summary"],
  "top-risks": commonViews["top-risks"],
  "improvement": commonViews.improvement,
};

const sections = [
  {
    title: "Scan Cluster",
    defaultOpen: true,
    items: [
      { label: "Active Scans", href: "/scans?view=active", badge: "4" },
      { label: "Scheduled Scans", href: "/scans?view=scheduled", badge: "18" },
      { label: "Scan Templates", href: "/scans?view=templates", badge: "27" },
      { label: "Scanner Fleet", href: "/scans?view=fleet", badge: "14" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/scans?view=asset-vuln" },
      { label: "Scan Down Reports", href: "/scans?view=scan-down" },
      { label: "Alert Logs Summary", href: "/scans?view=alert-summary" },
      { label: "Top Risk Reports", href: "/scans?view=top-risks" },
      { label: "Security Improvement Analysis", href: "/scans?view=improvement" },
    ],
  },
];

function PoolKpi({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="rounded-lg border px-3 py-2" style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
      <p className="text-[10.5px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
      <p className="mt-1 text-[18px] font-semibold" style={{ color: "var(--panel-text)" }}>{value}</p>
      <p className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
    </div>
  );
}
function FailReason({ reason, count }: { reason: string; count: number }) {
  return (
    <div className="flex items-center gap-2 text-[11.5px]">
      <span className="font-mono w-6 text-right" style={{ color: "#d46a5e" }}>{count}</span>
      <span style={{ color: "var(--panel-text-muted)" }}>×</span>
      <span style={{ color: "var(--panel-text)" }}>{reason}</span>
    </div>
  );
}
function CheckCat({ name, pass, fail }: { name: string; pass: number; fail: number }) {
  const total = pass + fail;
  return (
    <div>
      <div className="flex justify-between text-[11.5px] mb-0.5">
        <span style={{ color: "var(--panel-text)" }}>{name}</span>
        <span className="font-mono" style={{ color: "var(--panel-text-muted)" }}>
          <span style={{ color: "#6fd6c4" }}>{pass}</span> / <span style={{ color: "#d46a5e" }}>{fail}</span>
        </span>
      </div>
      <div className="h-1.5 flex rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.06)" }}>
        <div style={{ width: `${(pass / total) * 100}%`, background: "#6fd6c4" }} />
        <div style={{ width: `${(fail / total) * 100}%`, background: "#d46a5e" }} />
      </div>
    </div>
  );
}

export default function ScansPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "active";
  const block = localViews[view as keyof typeof localViews] ?? localViews.active;
  const [scanPanel, setScanPanel] = useState(false);

  return (
    <PageShell
      drillTitle="Scan Operations"
      sections={sections}
      drillHeader={
        <div className="flex flex-col items-center">
         
          <NewScanDial onClick={() => setScanPanel((s) => !s)} />
          <p
            className="mt-3 text-[10px] uppercase tracking-[0.2em]"
            style={{ color: scanPanel ? "var(--metric-copper)" : "var(--panel-text-muted)" }}
          >
            {scanPanel ? "Configuring…" : "Status: Ready"}
          </p>
        </div>
      }
    >
      {scanPanel && <ScanLaunchPanel onClose={() => setScanPanel(false)} />}
      <ViewBlockView block={block} />

      {/* Worker Pool & Queue (#14) */}
      <div className="skeuo-panel p-5 mt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Worker Pool & Scan Queue
          </h3>
          <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
            style={{ background: "rgba(224,160,99,0.18)", color: "#e0a063" }}>
            Enterprise tier · 32 workers
          </span>
        </div>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <PoolKpi label="Active Workers" value="24 / 32" sub="75% saturation" />
          <PoolKpi label="Queue Depth" value="142" sub="SKIP LOCKED claim" />
          <PoolKpi label="Per-subnet limit" value="6" sub="prevents flooding" />
          <PoolKpi label="ETA (1000 hosts)" value="~35 min" sub="Enterprise estimate" />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <button className="rounded-lg px-3 py-2 text-[11.5px] font-semibold text-left"
            style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
            ▶ Trigger On-Demand Scan — select by <strong>tag / subnet / asset</strong>, priority jump
          </button>
          <button className="rounded-lg px-3 py-2 text-[11.5px] font-semibold text-left"
            style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
            🔓 View lock leases (<code className="font-mono text-[10px]" style={{ color: "#e0a063" }}>lock:scan_claim:*</code>, 30min TTL)
          </button>
        </div>
      </div>

      {/* Credential Vault (#12) */}
      <div className="skeuo-panel p-5 mt-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Credential Vault
            <span className="ml-2 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase align-middle"
              style={{ background: "rgba(212,106,94,0.18)", color: "#d46a5e" }}>
              SEC-12 · HSM-backed (Enterprise)
            </span>
          </h3>
          <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
            + Add Credential Set
          </button>
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Credential ID", "Protocol", "Age", "Rotation", "Last Used"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { id: "cred_a8b1", proto: "SSH",     age: 28, last: "2m ago" },
              { id: "cred_3f2e", proto: "WinRM",   age: 64, last: "12m ago" },
              { id: "cred_77ad", proto: "SNMP v3", age: 92, last: "1d ago" },
              { id: "cred_ce0f", proto: "SSH",     age: 12, last: "8h ago" },
            ].map((c, i) => {
              const status = c.age >= 90 ? "block" : c.age >= 60 ? "warn" : "ok";
              return (
                <tr key={c.id} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3 font-mono" style={{ color: "#e0a063" }}>{c.id}</td>
                  <td className="px-3 py-3">{c.proto}</td>
                  <td className="px-3 py-3 font-mono">{c.age}d</td>
                  <td className="px-3 py-3">
                    {status === "block" && <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase" style={{ background: "rgba(212,106,94,0.18)", color: "#d46a5e" }}>BLOCKED · rotate now</span>}
                    {status === "warn"  && <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase" style={{ background: "rgba(225,192,105,0.18)", color: "#e1c069" }}>WARN · 60d+</span>}
                    {status === "ok"    && <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase" style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>OK</span>}
                  </td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{c.last}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          AES-256 at rest · master key from Setup Wizard · auto-zeroed from memory after scan window closes. Counters tracked in <code className="font-mono text-[10px]">cred_age:&#123;id&#125;</code> Valkey keys.
        </p>
      </div>

      {/* Scan Detail Drawer — Completeness & Failed Checks (#13) */}
      <div className="skeuo-panel p-5 mt-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Scan Detail · <code className="font-mono text-[13px]" style={{ color: "#e0a063" }}>SC-12</code>
          <span className="ml-2 text-[12px] font-normal" style={{ color: "var(--panel-text-muted)" }}>completeness_pct</span>
        </h3>
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-4">
            <p className="text-[11px] uppercase tracking-wider mb-2" style={{ color: "var(--panel-text-muted)" }}>Completeness</p>
            <p className="numeric-glow text-[48px] font-light leading-none" style={{ color: "#6fd6c4" }}>94%</p>
            <p className="mt-1 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>520 checks attempted · 489 passed · 31 failed</p>
            <div className="mt-3 space-y-1">
              <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>Failed checks:</p>
              <FailReason reason="30s per-check timeout" count={18} />
              <FailReason reason="Session dropped (TCP RST)" count={9} />
              <FailReason reason="Auth failure (creds rotated mid-scan)" count={4} />
            </div>
            <p className="mt-3 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
              Partial findings retained: <strong style={{ color: "var(--panel-text)" }}>12</strong> (from dropped sessions)
            </p>
          </div>
          <div className="col-span-8">
            <p className="text-[11px] uppercase tracking-wider mb-2" style={{ color: "var(--panel-text-muted)" }}>5 Check Categories (520+ total)</p>
            <div className="space-y-2">
              <CheckCat name="OS Hardening (CIS Benchmarks v8.1)" pass={142} fail={3} />
              <CheckCat name="CVE Detection (CPE-based)" pass={184} fail={11} />
              <CheckCat name="OWASP Web Exposure" pass={64} fail={8} />
              <CheckCat name="Zero-Trust Posture" pass={48} fail={6} />
              <CheckCat name="PCI DSS Scoping" pass={51} fail={3} />
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  );
}

/* ─────────── Scan Launch Panel ─────────── */

function ScanLaunchPanel({ onClose }: { onClose: () => void }) {
  const [mode, setMode] = useState<"now" | "schedule">("now");
  const [scanType, setScanType] = useState("vulnerability");
  const [target, setTarget] = useState("tag:prod");
  const [priority, setPriority] = useState<"normal" | "high">("normal");
  const [cadence, setCadence] = useState("daily");
  const [time, setTime] = useState("02:00");
  const [submitted, setSubmitted] = useState<null | { id: string; mode: "now" | "schedule" }>(null);

  const submit = () => {
    const id = "SCN-" + Math.floor(2000 + Math.random() * 200);
    setSubmitted({ id, mode });
  };

  if (submitted) {
    return (
      <div
        className="mb-5 rounded-2xl p-5"
        style={{
          background: "linear-gradient(180deg, rgba(111,214,196,0.10), rgba(0,0,0,0.15))",
          border: "1px solid rgba(111,214,196,0.35)",
          boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05), 0 0 18px rgba(111,214,196,0.18)",
        }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className="flex h-10 w-10 items-center justify-center rounded-xl"
              style={{
                background: "radial-gradient(circle at 35% 25%, rgba(111,214,196,0.4), rgba(28,79,87,0.6))",
                color: "#6fd6c4",
                boxShadow: "inset 0 1px 0 rgba(255,255,255,0.25)",
              }}
            >
              <Radar className="h-5 w-5" />
            </div>
            <div>
              <p className="text-[10.5px] font-semibold uppercase tracking-[0.25em]" style={{ color: "#6fd6c4" }}>
                Scan {submitted.mode === "now" ? "Started" : "Scheduled"}
              </p>
              <p className="text-[14px] font-semibold" style={{ color: "var(--panel-text)" }}>
                {submitted.id} · {scanType} · {target}
              </p>
              <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                {submitted.mode === "now" ? "Running now · estimated 4–9 min" : `Next run: ${cadence} at ${time} UTC`}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="rounded-md p-1.5" style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)" }}>
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      className="mb-5 rounded-2xl p-5"
      style={{
        background:
          "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
        border: "1px solid rgba(224,160,99,0.4)",
        boxShadow:
          "inset 0 1px 0 rgba(255,255,255,0.05), inset 0 -2px 6px rgba(0,0,0,0.35), 0 0 18px rgba(224,160,99,0.18)",
      }}
    >
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-xl"
            style={{
              background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 75%)",
              color: "var(--disc-text)",
              boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
            }}
          >
            <Radar className="h-5 w-5" />
          </div>
          <div>
            <p className="text-[10.5px] font-semibold uppercase tracking-[0.25em]" style={{ color: "var(--section-heading)" }}>
              Launch Scan
            </p>
            <p className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
              {mode === "now" ? "Scan Now" : "Schedule Scan"}
            </p>
          </div>
        </div>
        <button onClick={onClose} className="rounded-md p-1.5" style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)" }}>
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* mode tabs */}
      <div className="mb-4 inline-flex rounded-full p-1"
        style={{
          background: "var(--inset-base)",
          border: "1px solid var(--row-border)",
        }}>
        {([
          { k: "now",      label: "Scan Now",      icon: <Play className="h-3.5 w-3.5" /> },
          { k: "schedule", label: "Schedule Scan", icon: <CalendarClock className="h-3.5 w-3.5" /> },
        ] as const).map((m) => (
          <button
            key={m.k}
            onClick={() => setMode(m.k)}
            className="flex items-center gap-1.5 rounded-full px-3 py-1 text-[11.5px] font-semibold transition-colors"
            style={
              mode === m.k
                ? {
                    background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                    color: "var(--disc-text)",
                    boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
                  }
                : { color: "var(--panel-text-muted)" }
            }
          >
            {m.icon} {m.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* scan type */}
        <Field label="Scan Type">
          <select value={scanType} onChange={(e) => setScanType(e.target.value)} className="w-full rounded-lg px-2.5 py-1.5 text-[12.5px]"
            style={{ background: "var(--inset-base)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
            <option value="vulnerability">Vulnerability Scan (Nessus-Pro)</option>
            <option value="config">Configuration Audit (Prowler-EE)</option>
            <option value="webapp">Web App / DAST (ZAP-Cloud)</option>
            <option value="cloud">Cloud Posture (Falcon-CSP)</option>
            <option value="adhygiene">AD Hygiene (BloodHound)</option>
            <option value="container">Container Scan (Trivy)</option>
            <option value="full">Full Stack (all engines)</option>
          </select>
        </Field>

        {/* target */}
        <Field label="Target" icon={<Target className="h-3 w-3" />}>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="tag:prod / subnet / asset id"
            className="w-full rounded-lg px-2.5 py-1.5 text-[12.5px] font-mono"
            style={{ background: "var(--inset-base)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }} />
        </Field>

        {/* priority */}
        <Field label="Priority">
          <div className="flex gap-1">
            {(["normal", "high"] as const).map((p) => (
              <button key={p} onClick={() => setPriority(p)}
                className="flex-1 rounded-lg px-2.5 py-1.5 text-[11.5px] font-semibold uppercase"
                style={{
                  background: priority === p ? "rgba(224,160,99,0.18)" : "var(--inset-base)",
                  color: priority === p ? "var(--section-heading)" : "var(--panel-text-muted)",
                  border: `1px solid ${priority === p ? "rgba(224,160,99,0.4)" : "var(--row-border)"}`,
                }}>
                {p === "high" ? "↑ Priority Jump" : p}
              </button>
            ))}
          </div>
        </Field>
      </div>

      {mode === "schedule" && (
        <div className="mt-4 grid grid-cols-2 gap-4">
          <Field label="Cadence">
            <select value={cadence} onChange={(e) => setCadence(e.target.value)} className="w-full rounded-lg px-2.5 py-1.5 text-[12.5px]"
              style={{ background: "var(--inset-base)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
              <option value="hourly">Hourly</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly (Mon)</option>
              <option value="monthly">Monthly (1st)</option>
            </select>
          </Field>
          <Field label="Run Time (UTC)">
            <input type="time" value={time} onChange={(e) => setTime(e.target.value)}
              className="w-full rounded-lg px-2.5 py-1.5 text-[12.5px] font-mono"
              style={{ background: "var(--inset-base)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }} />
          </Field>
        </div>
      )}

      <div className="mt-4 flex items-center justify-between border-t pt-4" style={{ borderColor: "var(--row-border)" }}>
        <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
          {mode === "now"
            ? "Queued to the next available worker (32 workers · 75% saturation)."
            : "Persisted via systemd timer · audit-logged."}
        </p>
        <div className="flex gap-2">
          <button onClick={onClose} className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
            Cancel
          </button>
          <button onClick={submit} className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{
              background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
              color: "var(--disc-text)",
              boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5), 0 0 12px rgba(224,160,99,0.25)",
              border: "1px solid rgba(224,160,99,0.45)",
            }}>
            {mode === "now" ? <Play className="h-3.5 w-3.5" /> : <CalendarClock className="h-3.5 w-3.5" />}
            {mode === "now" ? "Launch scan" : "Save schedule"}
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children, icon }: { label: string; children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div>
      <p className="mb-1 flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>
        {icon}{label}
      </p>
      {children}
    </div>
  );
}
