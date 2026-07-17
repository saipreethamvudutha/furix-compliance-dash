"use client";

import { PageShell } from "@/components/layout/page-shell";
import { HardDrive, Cloud, Server, ShieldCheck, RotateCcw, CheckCircle2, Plus } from "lucide-react";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "Schedules",
    defaultOpen: true,
    items: [
      { label: "Hourly Incremental", href: "/backup?s=hourly", badge: "ON" },
      { label: "Daily Full", href: "/backup?s=daily", badge: "ON" },
      { label: "Weekly Deep", href: "/backup?s=weekly", badge: "ON" },
    ],
  },
  {
    title: "Destinations",
    defaultOpen: true,
    items: [
      { label: "Local LUKS Volume", href: "/backup?d=luks" },
      { label: "On-prem MinIO/NAS", href: "/backup?d=minio" },
      { label: "Customer S3/Azure/GCS", href: "/backup?d=cloud" },
      { label: "Air-gapped Replica", href: "/backup?d=airgap" },
    ],
  },
  {
    title: "Restore",
    defaultOpen: true,
    items: [
      { label: "Backup Catalog", href: "/backup?view=catalog" },
      { label: "Point-in-Time Restore", href: "/backup?view=pitr" },
      { label: "3-2-1 Compliance", href: "/backup?view=compliance" },
    ],
  },
];

const dests = [
  { name: "Local LUKS Volume",     icon: HardDrive, role: "Fast restore",          on: true,  size: "1.2 TB / 4 TB", lastOk: "12m ago", encryption: "DEK + LUKS" },
  { name: "On-prem MinIO/NAS",     icon: Server,    role: "Primary off-host",      on: true,  size: "4.8 TB / 20 TB", lastOk: "14m ago", encryption: "DEK + KEK customer" },
  { name: "Customer S3 (object-lock)", icon: Cloud, role: "Cloud immutable",       on: true,  size: "11.3 TB", lastOk: "18m ago", encryption: "DEK + KMS-CMK" },
  { name: "Air-gapped Replica",    icon: ShieldCheck, role: "Disaster recovery",   on: false, size: "—",       lastOk: "—",     encryption: "Configure to enable" },
];

const catalog = [
  { id: "BK-44218", time: "2026-06-10 16:00:00 UTC", kind: "Hourly Incremental", dest: "LUKS + MinIO + S3", size: "4.8 GB", services: "PG WAL · CH parts · Valkey AOF · Kafka meta", verified: true },
  { id: "BK-44209", time: "2026-06-10 15:00:00 UTC", kind: "Hourly Incremental", dest: "LUKS + MinIO + S3", size: "5.1 GB", services: "PG WAL · CH parts · Valkey AOF · Kafka meta", verified: true },
  { id: "BK-44200", time: "2026-06-10 14:00:00 UTC", kind: "Hourly Incremental", dest: "LUKS + MinIO + S3", size: "4.4 GB", services: "PG WAL · CH parts · Valkey AOF · Kafka meta", verified: true },
  { id: "BK-44102", time: "2026-06-10 00:00:00 UTC", kind: "Daily Full",         dest: "LUKS + MinIO + S3", size: "188 GB", services: "Full snapshot, consistency-coordinated", verified: true },
  { id: "BK-43800", time: "2026-06-08 00:00:00 UTC", kind: "Weekly Deep",        dest: "MinIO + S3 (immutable)", size: "412 GB", services: "Full + binary logs + integrity manifest", verified: true },
];

export default function BackupPage() {
  return (
    <PageShell drillTitle="Backup & Restore" sections={sections}>
      <div className="mb-6 grid grid-cols-4 gap-4">
        <Kpi label="Last Backup" value="12m ago" sub="hourly incremental" tone="copper" />
        <Kpi label="Restore Points" value="284" sub="trailing 14 days" />
        <Kpi label="3-2-1 Rule" value="✓ OK" sub="3 copies · 2 media · 1 off-site" tone="copper" />
        <Kpi label="Avg Restore" value="6m 42s" sub="hourly PITR" />
      </div>

      {/* Destinations */}
      <div className="skeuo-panel p-5 mb-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Destinations</h3>
        <div className="grid grid-cols-2 gap-4">
          {dests.map((d) => {
            const Icon = d.icon;
            return (
              <div key={d.name} className="rounded-xl border p-4"
                style={{ borderColor: "var(--row-border)", background: "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(0,0,0,0.15))" }}>
                <div className="flex items-center gap-3 mb-2">
                  <Icon className="h-5 w-5" style={{ color: d.on ? "#6fd6c4" : "var(--panel-text-muted)" }} />
                  <div className="flex-1">
                    <p className="text-[13px] font-semibold" style={{ color: "var(--panel-text)" }}>{d.name}</p>
                    <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{d.role}</p>
                  </div>
                  <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                    style={{ background: d.on ? "rgba(111,214,196,0.15)" : "rgba(255,255,255,0.05)", color: d.on ? "#6fd6c4" : "var(--panel-text-muted)" }}>
                    {d.on ? "Enabled" : "Disabled"}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                  <span>Size: <strong style={{ color: "var(--panel-text)" }}>{d.size}</strong></span>
                  <span>Last OK: <strong style={{ color: "var(--panel-text)" }}>{d.lastOk}</strong></span>
                  <span className="col-span-3">Encryption: <strong style={{ color: "var(--panel-text)" }}>{d.encryption}</strong></span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Catalog */}
      <div className="skeuo-panel p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>Backup Catalog</h3>
          <div className="flex gap-2">
            <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
              style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
              <Plus className="h-3.5 w-3.5" /> Manual Backup
            </button>
            <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
              style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
              <RotateCcw className="h-3.5 w-3.5" /> Restore Wizard
            </button>
          </div>
        </div>
        <div className="overflow-x-auto rounded-xl">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["ID", "Time (UTC)", "Kind", "Destinations", "Size", "Services", "Verified", "Action"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {catalog.map((b, i) => (
                <tr key={b.id} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{b.id}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{b.time}</td>
                  <td className="px-3 py-3 font-semibold">{b.kind}</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{b.dest}</td>
                  <td className="px-3 py-3 font-mono">{b.size}</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{b.services}</td>
                  <td className="px-3 py-3">
                    {b.verified && <CheckCircle2 className="h-4 w-4" style={{ color: "#6fd6c4" }} />}
                  </td>
                  <td className="px-3 py-3">
                    <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold"
                      style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
                      Restore
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Envelope encryption — DEK per backup, KEK customer-managed (TPM-sealed). Catalog tracked in <code>backup_audit</code> table.
        </p>
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
