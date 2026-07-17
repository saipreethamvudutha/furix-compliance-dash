"use client";

import { PageShell } from "@/components/layout/page-shell";
import { CheckCircle2, KeyRound, RefreshCw, Power, Archive, Download, AlertTriangle } from "lucide-react";

const sections = [
  {
    title: "License",
    defaultOpen: true,
    items: [
      { label: "Status & Tier", href: "/license" },
      { label: "Heartbeat Log", href: "/license?v=hb" },
      { label: "Certificates (TLS)", href: "/license?v=cert", badge: "SEC-35" },
      { label: "Urgent Messages", href: "/license?v=msg" },
    ],
  },
  {
    title: "Operator (furixctl)",
    defaultOpen: true,
    items: [
      { label: "Container Status", href: "/license?v=ctn" },
      { label: "Air-Gap Mode", href: "/license?v=airgap" },
      { label: "Support Bundle", href: "/license?v=bundle" },
      { label: "Kafka Replay", href: "/license?v=replay" },
    ],
  },
];

const containers = [
  { id: "C1",  name: "Discovery",         status: "UP", uptime: "12d 4h" },
  { id: "C2",  name: "Vector.dev",        status: "UP", uptime: "12d 4h" },
  { id: "C3",  name: "Scan Engine",       status: "UP", uptime: "12d 4h" },
  { id: "C4",  name: "Intel Sync",        status: "UP", uptime: "8h 22m" },
  { id: "C5",  name: "Kafka",             status: "UP", uptime: "12d 4h" },
  { id: "C6",  name: "Normaliser",        status: "UP", uptime: "12d 4h" },
  { id: "C7",  name: "vLLM",              status: "UP", uptime: "2d 1h" },
  { id: "C8",  name: "Detection",         status: "UP", uptime: "12d 4h" },
  { id: "C9",  name: "PostgreSQL+AGE",    status: "UP", uptime: "32d 11h" },
  { id: "C10", name: "ClickHouse",        status: "UP", uptime: "32d 11h" },
  { id: "C11", name: "Dashboard",         status: "UP", uptime: "4h 18m" },
  { id: "C12", name: "Observability",     status: "UP", uptime: "32d 11h" },
  { id: "C13", name: "Valkey",            status: "UP", uptime: "32d 11h" },
];

const ctlCmds = [
  { cmd: "furixctl container restart",   desc: "Restart any container by ID" },
  { cmd: "furixctl intel sync --force",  desc: "Force intel feed sync (admin)" },
  { cmd: "furixctl backup take",         desc: "Manual backup invocation" },
  { cmd: "furixctl kafka replay",        desc: "Replay topic from offset" },
  { cmd: "furixctl support-bundle",      desc: "PII-scrubbed support tar" },
  { cmd: "furixctl cert rotate",         desc: "Rotate TLS certificates (SEC-35)" },
];

export default function LicensePage() {
  return (
    <PageShell drillTitle="License & Appliance" sections={sections}>
      {/* License banner */}
      <div className="mb-6 rounded-xl border p-5"
        style={{
          borderColor: "rgba(111,214,196,0.35)",
          background: "linear-gradient(180deg, rgba(111,214,196,0.10), rgba(0,0,0,0.20))",
        }}>
        <div className="grid grid-cols-4 gap-4">
          <div>
            <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>Status</p>
            <p className="mt-1 text-[18px] font-semibold" style={{ color: "#6fd6c4" }}>
              <CheckCircle2 className="inline h-4 w-4 mr-1" /> ACTIVE
            </p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>Tier</p>
            <p className="mt-1 text-[18px] font-semibold" style={{ color: "var(--panel-text)" }}>Enterprise</p>
            <p className="text-[10px]" style={{ color: "var(--panel-text-muted)" }}>32 scan workers · HSM-backed creds</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>Last Heartbeat</p>
            <p className="mt-1 text-[14px] font-semibold font-mono" style={{ color: "var(--panel-text)" }}>2026-06-10 16:47 UTC</p>
            <p className="text-[10px]" style={{ color: "var(--panel-text-muted)" }}>42s ago — Furix Cloud /v1/heartbeat</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>TLS Cert Expiry</p>
            <p className="mt-1 text-[14px] font-semibold font-mono" style={{ color: "var(--panel-text)" }}>2026-11-22</p>
            <p className="text-[10px]" style={{ color: "#6fd6c4" }}>164d remaining</p>
          </div>
        </div>
      </div>

      {/* Tier limits */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <TierCard tier="SMB" workers="8" active={false} />
        <TierCard tier="Mid" workers="16" active={false} />
        <TierCard tier="Enterprise" workers="32" active={true} />
      </div>

      {/* Containers grid */}
      <div className="skeuo-panel p-5 mb-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Appliance Supervisor — All 13 Containers
        </h3>
        <div className="grid grid-cols-4 gap-2">
          {containers.map((c) => (
            <div key={c.id} className="flex items-center gap-2 rounded-lg border px-3 py-2"
              style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
              <CheckCircle2 className="h-3.5 w-3.5" style={{ color: "#6fd6c4" }} />
              <div className="flex-1">
                <p className="text-[12px] font-semibold" style={{ color: "var(--panel-text)" }}>{c.id} {c.name}</p>
                <p className="text-[10px] font-mono" style={{ color: "var(--panel-text-muted)" }}>uptime {c.uptime}</p>
              </div>
              <button className="text-[10px] font-semibold" style={{ color: "#e0a063" }}>Restart</button>
            </div>
          ))}
        </div>
      </div>

      {/* Operator commands */}
      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Operator Commands (furixctl — 30+ available)
        </h3>
        <div className="grid grid-cols-2 gap-3">
          {ctlCmds.map((c) => (
            <button key={c.cmd} className="flex flex-col items-start rounded-lg border px-3 py-2.5 text-left hover:bg-white/[0.04]"
              style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
              <span className="font-mono text-[12px]" style={{ color: "#6fd6c4" }}>{c.cmd}</span>
              <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{c.desc}</span>
            </button>
          ))}
        </div>
        <div className="mt-4 flex gap-2">
          <ActionBtn icon={<Power className="h-3.5 w-3.5" />} label="Toggle Air-Gap Mode" />
          <ActionBtn icon={<RefreshCw className="h-3.5 w-3.5" />} label="Rotate TLS Certs (SEC-35)" />
          <ActionBtn icon={<Archive className="h-3.5 w-3.5" />} label="Manual Backup" />
          <ActionBtn icon={<Download className="h-3.5 w-3.5" />} label="Support Bundle (PII-scrubbed)" primary />
        </div>
      </div>
    </PageShell>
  );
}

function TierCard({ tier, workers, active }: { tier: string; workers: string; active: boolean }) {
  return (
    <div className="skeuo-panel p-4" style={active ? { boxShadow: "0 0 0 1px var(--copper-bright), 0 4px 14px rgba(224,160,99,0.18)" } : undefined}>
      <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{tier}</p>
      <p className="numeric-glow mt-2 text-[28px] font-light leading-none" style={{ color: active ? "var(--metric-copper)" : "var(--panel-text-muted)" }}>{workers}</p>
      <p className="mt-1 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>scan workers {active && "· current tier"}</p>
    </div>
  );
}

function ActionBtn({ icon, label, primary }: { icon: React.ReactNode; label: string; primary?: boolean }) {
  return (
    <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
      style={primary
        ? { background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }
        : { background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
      {icon}{label}
    </button>
  );
}
