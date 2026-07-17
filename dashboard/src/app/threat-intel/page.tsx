"use client";

import { PageShell } from "@/components/layout/page-shell";
import { CheckCircle2, AlertTriangle, RefreshCw, Upload, ShieldCheck, Cloud, WifiOff } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "Intel Feeds",
    defaultOpen: true,
    items: [
      { label: "NIST NVD", href: "/threat-intel?feed=nvd", badge: "6h" },
      { label: "CISA KEV", href: "/threat-intel?feed=kev", badge: "1d" },
      { label: "FIRST EPSS", href: "/threat-intel?feed=epss", badge: "1d" },
      { label: "Nation-State Actors (RU/CN/KP/IR)", href: "/threat-intel?feed=attack", badge: "1mo" },
    ],
  },
  {
    title: "Sync",
    defaultOpen: true,
    items: [
      { label: "Sync History", href: "/threat-intel?view=history" },
      { label: "Air-Gap Bundles", href: "/threat-intel?view=airgap" },
      { label: "Signature Validation", href: "/threat-intel?view=sig" },
      { label: "Delta Fetch Log", href: "/threat-intel?view=delta" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Detection Rules", href: "/detection-rules" },
      { label: "Findings Triage", href: "/findings" },
    ],
  },
];

type Mode = "Online" | "Air-Gap";
const feeds: {
  name: string; cadence: string; lastSync: string; nextSync: string; mode: Mode;
  ok: boolean; signature: "Valid" | "Pending" | "Failed"; lastSyncId: string; size: string;
}[] = [
  { name: "NIST NVD",      cadence: "Every 6 hrs",  lastSync: "2h 14m ago", nextSync: "in 3h 46m", mode: "Online",  ok: true,  signature: "Valid",  lastSyncId: "sync_4f2a91", size: "284 MB" },
  { name: "CISA KEV",      cadence: "Daily",        lastSync: "8h 02m ago", nextSync: "in 15h 58m", mode: "Online", ok: true,  signature: "Valid",  lastSyncId: "sync_8b41c2", size: "1.2 MB" },
  { name: "FIRST EPSS",    cadence: "Daily",        lastSync: "29h 18m ago", nextSync: "overdue",   mode: "Online", ok: false, signature: "Valid",  lastSyncId: "sync_91ace4", size: "18 MB" },
  { name: "MITRE ATT&CK",  cadence: "Monthly",      lastSync: "12d ago",    nextSync: "in 18d",    mode: "Air-Gap", ok: true,  signature: "Valid",  lastSyncId: "bundle_v15.1", size: "42 MB" },
];

export default function ThreatIntelPage() {
  return (
    <PageShell drillTitle="Threat Intelligence" sections={sections}>
      {/* KPIs */}
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Kpi label="Feeds Online" value="3 / 4" sub="1 in air-gap" tone="copper" />
        <Kpi label="CVEs Tracked" value="248,184" sub="from NVD" />
        <Kpi label="KEV Catalog" value="1,142" sub="actively exploited" tone="copper" />
        <Kpi label="ATT&CK Coverage" value="86%" sub="of techniques" />
      </div>

      {/* Mode toggle */}
      <div className="mb-4 flex items-center gap-3 rounded-xl border px-4 py-3"
        style={{ borderColor: "var(--row-border)", background: "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(0,0,0,0.15))" }}>
        <Cloud className="h-4 w-4" style={{ color: "#6fd6c4" }} />
        <div className="flex-1">
          <p className="text-[12.5px] font-semibold" style={{ color: "var(--panel-text)" }}>Sync Mode: Online (3 of 4 feeds)</p>
          <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
            4-hour cycle · Ed25519 signature validation · last_sync_id checkpointing
          </p>
        </div>
        <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
          style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
          <WifiOff className="inline h-3.5 w-3.5 mr-1" /> Switch to Air-Gap
        </button>
        <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
          style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
          <Upload className="h-3.5 w-3.5" /> Import .fbundle
        </button>
      </div>

      {/* Feed status table */}
      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Feed Status</h3>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["Source", "Cadence", "Last Sync", "Next Sync", "Mode", "Sig Ed25519", "last_sync_id", "Size", "Actions"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {feeds.map((f, i) => (
                <tr key={f.name} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3 font-semibold">{f.name}</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{f.cadence}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: f.ok ? "var(--panel-text)" : "#d46a5e" }}>
                    {f.ok ? <CheckCircle2 className="inline h-3 w-3 mr-1" style={{ color: "#6fd6c4" }} /> : <AlertTriangle className="inline h-3 w-3 mr-1" style={{ color: "#d46a5e" }} />}
                    {f.lastSync}
                  </td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: f.nextSync === "overdue" ? "#d46a5e" : "var(--panel-text-muted)" }}>{f.nextSync}</td>
                  <td className="px-3 py-3 text-[11.5px]">{f.mode}</td>
                  <td className="px-3 py-3">
                    <span className="flex items-center gap-1 text-[11px]" style={{ color: "#6fd6c4" }}>
                      <ShieldCheck className="h-3 w-3" /> {f.signature}
                    </span>
                  </td>
                  <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "#e0a063" }}>{f.lastSyncId}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{f.size}</td>
                  <td className="px-3 py-3">
                    <button className="flex items-center gap-1 rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
                      style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
                      <RefreshCw className="h-3 w-3" /> Sync (admin)
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Staleness banner */}
      <div className="mt-4 flex items-center gap-2 rounded-xl border px-4 py-2.5 text-[12px]"
        style={{ borderColor: "rgba(212,106,94,0.35)", background: "rgba(212,106,94,0.10)", color: "#d46a5e" }}>
        <AlertTriangle className="h-4 w-4" />
        <strong>EPSS feed is stale</strong> — last sync 29h 18m ago (&gt;24h threshold). Coventra PHI-zone risk scoring (phi-db-01, hsm-01) may use outdated exploit probabilities.
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
