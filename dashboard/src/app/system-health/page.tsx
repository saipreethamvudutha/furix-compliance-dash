"use client";

import { PageShell } from "@/components/layout/page-shell";
import { Activity, AlertCircle, CheckCircle2, Cpu, Database, HardDrive, Gauge, Server } from "lucide-react";

const sections = [
  {
    title: "Pressure Gauge",
    defaultOpen: true,
    items: [
      { label: "Pipeline Lag", href: "/system-health?g=pipeline" },
      { label: "vLLM Queue Depth", href: "/system-health?g=vllm" },
      { label: "DB Pool %", href: "/system-health?g=dbpool" },
      { label: "Disk Pressure", href: "/system-health?g=disk" },
      { label: "Memory Pressure", href: "/system-health?g=mem" },
      { label: "Scan Worker Sat.", href: "/system-health?g=workers" },
    ],
  },
  {
    title: "Grafana Boards",
    defaultOpen: true,
    items: [
      { label: "Cluster Health", href: "/system-health?d=cluster" },
      { label: "Pipeline Throughput", href: "/system-health?d=pipeline" },
      { label: "AI Behavior", href: "/system-health?d=ai" },
      { label: "Detection", href: "/system-health?d=det" },
      { label: "Storage", href: "/system-health?d=stor" },
      { label: "Security", href: "/system-health?d=sec" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "License & Appliance", href: "/license" },
      { label: "Backup & Restore", href: "/backup" },
    ],
  },
];

const containers = [
  "C1 Discovery", "C2 Vector.dev", "C3 Scan Engine", "C4 Intel Sync",
  "C5 Kafka", "C6 Normaliser", "C7 vLLM", "C8 Detection",
  "C9 PostgreSQL+AGE", "C10 ClickHouse", "C11 Dashboard", "C12 Observability",
  "C13 Valkey",
];

const lanes = [
  { name: "HOT (firewall/IDS/auth)", rate: "8,142 e/s", lag: "62 ms", target: "<100ms", ok: true },
  { name: "WARM (servers/apps)",     rate: "12,408 e/s", lag: "412 ms", target: "<2s", ok: true },
  { name: "COLD (workstations/IoT)", rate: "24,712 e/s", lag: "1.8s",  target: "<10s", ok: true },
];

const dlqs = [
  { name: "parser_failure",        depth: 184, growth: "+12/m", replay: true },
  { name: "schema_unknown",        depth: 4,   growth: "0/m",   replay: true },
  { name: "field_mismatch",        depth: 0,   growth: "0/m",   replay: false },
  { name: "tamper.detected",       depth: 2,   growth: "0/m",   replay: false },
  { name: "enrichment_failure",    depth: 41,  growth: "+2/m",  replay: false },
  { name: "ai_parse_failure",      depth: 8,   growth: "+1/m",  replay: false },
  { name: "dlq.intel_parse",       depth: 0,   growth: "0/m",   replay: false },
  { name: "dlq.discovery_unreach", depth: 12,  growth: "0/m",   replay: false },
];

export default function SystemHealthPage() {
  return (
    <PageShell drillTitle="System Health" sections={sections}>
      {/* Pressure Gauge */}
      <div className="mb-6 grid grid-cols-12 gap-4">
        <div className="col-span-5 skeuo-panel p-5">
          <div className="flex items-center gap-2 mb-2" style={{ color: "var(--section-heading)" }}>
            <Gauge className="h-4 w-4" />
            <p className="text-[12px] uppercase tracking-wider">Pressure Gauge</p>
          </div>
          <div className="flex items-baseline gap-3">
            <p className="numeric-glow text-[64px] font-light leading-none" style={{ color: "var(--metric-copper)" }}>38</p>
            <p className="text-[12px]" style={{ color: "var(--panel-text-muted)" }}>/ 100 — healthy</p>
          </div>
          <div className="mt-4 space-y-2">
            {[
              { k: "Pipeline lag",       v: 18, max: 100 },
              { k: "vLLM queue depth",   v: 42, max: 100 },
              { k: "DB pool %",          v: 31, max: 100 },
              { k: "Disk pressure",      v: 22, max: 100 },
              { k: "Memory pressure",    v: 48, max: 100 },
              { k: "Scan worker sat.",   v: 64, max: 100 },
            ].map((s) => (
              <div key={s.k}>
                <div className="flex justify-between text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                  <span>{s.k}</span><span className="font-mono">{s.v}</span>
                </div>
                <div className="h-1.5 rounded-full" style={{ background: "rgba(255,255,255,0.06)" }}>
                  <div className="h-full rounded-full"
                    style={{ width: `${(s.v / s.max) * 100}%`, background: s.v > 70 ? "#d46a5e" : s.v > 50 ? "#e1c069" : "#6fd6c4" }} />
                </div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
            When pressure &gt; 70, system slows scans, shrinks AI batches, tightens circuit breaker.
          </p>
        </div>

        {/* Containers */}
        <div className="col-span-7 skeuo-panel p-5">
          <h3 className="mb-3 text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>Appliance Supervisor — 13 Containers</h3>
          <div className="grid grid-cols-3 gap-2">
            {containers.map((c) => (
              <div key={c} className="flex items-center gap-2 rounded-lg border px-3 py-2"
                style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
                <CheckCircle2 className="h-3.5 w-3.5" style={{ color: "#6fd6c4" }} />
                <span className="text-[11.5px]" style={{ color: "var(--panel-text)" }}>{c}</span>
                <span className="ml-auto font-mono text-[10px]" style={{ color: "var(--panel-text-muted)" }}>UP</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Lanes & DLQ */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
            <Activity className="inline h-4 w-4 mr-1.5" style={{ color: "var(--section-heading)" }} />
            Pipeline Throughput per Lane
          </h3>
          <div className="space-y-2">
            {lanes.map((l) => (
              <div key={l.name} className="rounded-lg border px-3 py-2.5" style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
                <p className="text-[12.5px] font-semibold" style={{ color: "var(--panel-text)" }}>{l.name}</p>
                <div className="mt-1 flex justify-between text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                  <span>Rate <span className="font-mono" style={{ color: "var(--panel-text)" }}>{l.rate}</span></span>
                  <span>Lag <span className="font-mono" style={{ color: "#6fd6c4" }}>{l.lag}</span> <em>(target {l.target})</em></span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
            <AlertCircle className="inline h-4 w-4 mr-1.5" style={{ color: "#e0a063" }} />
            DLQ Depths (8 queues)
          </h3>
          <div className="space-y-1.5">
            {dlqs.map((d) => (
              <div key={d.name} className="flex items-center gap-2 text-[11.5px]">
                <span className="flex-1 font-mono" style={{ color: "var(--panel-text-muted)" }}>{d.name}</span>
                <span className="font-mono" style={{ color: d.depth > 50 ? "#d46a5e" : "var(--panel-text)" }}>{d.depth}</span>
                <span className="font-mono w-12 text-right" style={{ color: "var(--panel-text-muted)" }}>{d.growth}</span>
                {d.replay && (
                  <button className="rounded-md px-1.5 py-0 text-[10px] font-semibold"
                    style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>
                    Replay
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Storage */}
      <div className="grid grid-cols-3 gap-4">
        <StorageCard icon={<Database />} label="ClickHouse Insert Backlog" value="412 rows" sub="0.8% of 50K threshold" />
        <StorageCard icon={<HardDrive />} label="Valkey Memory" value="2.4 GB / 8 GB" sub="30% used" />
        <StorageCard icon={<Server />} label="Kafka Consumer Lag" value="142 msgs" sub="across all topics" />
      </div>

      {/* Ops alerts banner */}
      <div className="mt-6 rounded-xl border p-4"
        style={{ borderColor: "rgba(225,192,105,0.35)", background: "rgba(225,192,105,0.08)" }}>
        <p className="text-[12.5px] font-semibold" style={{ color: "#e1c069" }}>
          Operational Alerts (Alertmanager) — separate from security alerts
        </p>
        <p className="mt-1 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          No active ops alerts. Watches: container down · disk &gt;90% · DLQ spike · SEC-19 absence detection · SEC-29 to SEC-32 host hardening.
        </p>
      </div>
    </PageShell>
  );
}

function StorageCard({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: string; sub: string }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center gap-1.5" style={{ color: "var(--panel-text-muted)" }}>
        <span className="[&_svg]:h-3.5 [&_svg]:w-3.5">{icon}</span>
        <p className="text-[11px] uppercase tracking-wider">{label}</p>
      </div>
      <p className="numeric-glow mt-2 text-[22px] font-light leading-none" style={{ color: "var(--metric-teal)" }}>{value}</p>
      <p className="mt-1 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
    </div>
  );
}
