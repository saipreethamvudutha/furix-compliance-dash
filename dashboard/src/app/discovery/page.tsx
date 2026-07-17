"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import {
  Radar, Plus, Upload, Play, Pause, Trash2, CheckCircle2, AlertTriangle,
  Server, Globe, ShieldCheck, Activity, FileText, Settings as Cog,
} from "lucide-react";
import { useCoventraStats } from "@/lib/data/use-coventra-stats";
import { KpiBgIcon } from "@/lib/kpi-icon";

const sections = [
  {
    title: "Asset Configuration",
    defaultOpen: true,
    items: [
      { label: "Manual Configuration", href: "/discovery?mode=manual" },
      { label: "Automatic Discovery", href: "/discovery?mode=auto", badge: "nmap" },
    ],
  },
  {
    title: "Auto Discovery",
    defaultOpen: true,
    items: [
      { label: "Active Scans", href: "/discovery?mode=auto&view=active", badge: "2" },
      { label: "Discovery Schedules", href: "/discovery?mode=auto&view=sched" },
      { label: "Discovered Hosts", href: "/discovery?mode=auto&view=hosts", badge: "284" },
      { label: "Subnets & Ranges", href: "/discovery?mode=auto&view=subnets" },
    ],
  },
  {
    title: "Manual",
    defaultOpen: true,
    items: [
      { label: "Single Asset", href: "/discovery?mode=manual&view=single" },
      { label: "Bulk Import (CSV)", href: "/discovery?mode=manual&view=csv" },
      { label: "API / Token", href: "/discovery?mode=manual&view=api" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Asset Inventory", href: "/assets" },
      { label: "Scan Operations", href: "/scans" },
    ],
  },
];

export default function DiscoveryPage() {
  const sp = useSearchParams();
  const mode = sp.get("mode") ?? "manual";
  const view = sp.get("view") ?? "";

  return (
    <PageShell drillTitle="Discovery" sections={sections}>
      <Header />

      {/* Mode tab pill */}
      <ModeTabs mode={mode} />

      {mode === "auto" ? <AutomaticConfig view={view} /> : <ManualConfig view={view} />}
    </PageShell>
  );
}

/* ─────────── header + summary KPIs ─────────── */
function Header() {
  const s = useCoventraStats();
  const total = s?.total ?? 0;
  const auto = Math.round(total * 0.87);
  const manual = total - auto;
  const unreach = s ? s.byStatus.critical : 0;
  return (
    <>
      <div className="mb-5 flex items-baseline gap-3">
        <h1 className="text-[22px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Asset Configuration Dashboard
        </h1>
        <span className="rounded-full px-2 py-0.5 text-[10px] font-mono uppercase"
          style={{ background: "rgba(224,160,99,0.18)", color: "#e0a063" }}>
          C1 Discovery
        </span>
      </div>
      <div className="grid grid-cols-4 gap-4 mb-6">
        <K label="Total Assets" value={total ? total.toLocaleString() : "—"} sub="+24 last 7d" tone="copper" />
        <K label="Discovered (auto)" value={auto ? auto.toLocaleString() : "—"} sub="87% of fleet" />
        <K label="Configured (manual)" value={manual ? manual.toLocaleString() : "—"} sub="13% of fleet" tone="copper" />
        <K label="Unreachable" value={String(unreach)} sub="dlq.discovery_unreach" />
      </div>
    </>
  );
}

function ModeTabs({ mode }: { mode: string }) {
  return (
    <div className="mb-6 inline-flex rounded-full p-1"
      style={{
        background: "linear-gradient(180deg, var(--pill-track-grad-top), var(--pill-track-grad-bot))",
        boxShadow: "inset 0 2px 4px var(--pill-shadow-inset)",
      }}>
      <a href="/discovery?mode=manual"
        className="rounded-full px-4 py-1.5 text-[12px] font-semibold transition-colors"
        style={mode === "manual"
          ? { background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }
          : { color: "var(--panel-text-muted)" }}>
        <Cog className="inline h-3.5 w-3.5 mr-1" /> Manual Configuration
      </a>
      <a href="/discovery?mode=auto"
        className="rounded-full px-4 py-1.5 text-[12px] font-semibold transition-colors"
        style={mode === "auto"
          ? { background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }
          : { color: "var(--panel-text-muted)" }}>
        <Radar className="inline h-3.5 w-3.5 mr-1" /> Automatic Discovery (nmap)
      </a>
    </div>
  );
}

/* ─────────── MANUAL CONFIG ─────────── */
function ManualConfig({ view }: { view: string }) {
  if (view === "csv") return <BulkCsvSection />;
  if (view === "api") return <ApiTokenSection />;
  // "single" or default → full form + table
  return <ManualConfigFull />;
}

function ManualConfigFull() {
  const [hostname, setHostname] = useState("");
  const [ip, setIp] = useState("");
  const [type, setType] = useState("server");

  return (
    <>
      <SubHeader label="Single Asset" desc="Add an asset by entering its hostname, IP, type, and metadata." />

      {/* Add single asset */}
      <div className="skeuo-panel p-5 mb-6">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          <Plus className="inline h-4 w-4 mr-1.5" style={{ color: "var(--section-heading)" }} />
          Add Asset Manually
        </h3>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Hostname" value={hostname} onChange={setHostname} placeholder="phi-db-01" />
          <Field label="IP Address" value={ip} onChange={setIp} placeholder="10.30.1.10" mono />
          <SelectField label="Asset Type" value={type} onChange={setType}
            options={["server", "endpoint", "database", "network device", "cloud instance", "iot"]} />
        </div>
        <div className="grid grid-cols-3 gap-3 mt-3">
          <SelectField label="OS" value="auto" onChange={() => {}} options={["auto-detect", "Ubuntu 24.04", "Windows Server 2022", "RHEL 9", "Other"]} />
          <SelectField label="Environment" value="prod" onChange={() => {}} options={["prod", "staging", "dev", "test"]} />
          <SelectField label="Criticality" value="high" onChange={() => {}} options={["critical", "high", "medium", "low"]} />
        </div>
        <div className="grid grid-cols-3 gap-3 mt-3">
          <Field label="Tags (comma-sep)" value="" onChange={() => {}} placeholder="hipaa, phi, prod" />
          <Field label="Owner Team" value="" onChange={() => {}} placeholder="DBA · Oracle" />
          <SelectField label="Credential Set" value="cred_a8b1" onChange={() => {}}
            options={["cred_a8b1 (SSH)", "cred_3f2e (WinRM)", "cred_77ad (SNMP v3)", "— none —"]} />
        </div>
        <div className="mt-4 flex gap-2">
          <PrimaryBtn label="Add Asset" icon={<Plus className="h-3.5 w-3.5" />} />
          <GhostBtn label="Add & Run Initial Scan" />
        </div>
      </div>

      {/* Bulk CSV + API */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
            <Upload className="inline h-4 w-4 mr-1.5" style={{ color: "var(--section-heading)" }} />
            Bulk Import (CSV)
          </h3>
          <div className="rounded-xl border border-dashed p-6 text-center"
            style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
            <FileText className="h-8 w-8 mx-auto mb-2 opacity-60" style={{ color: "var(--section-heading)" }} />
            <p className="text-[12.5px]" style={{ color: "var(--panel-text)" }}>Drop <code className="font-mono text-[11px]" style={{ color: "#e0a063" }}>assets.csv</code> here or click to browse</p>
            <p className="text-[10.5px] mt-1" style={{ color: "var(--panel-text-muted)" }}>
              Schema: hostname, ip, type, os, env, criticality, tags
            </p>
            <button className="mt-3 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold" style={btn}>
              Download template
            </button>
          </div>
        </div>

        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
            API / Token Onboarding
          </h3>
          <p className="text-[11.5px] mb-3" style={{ color: "var(--panel-text-muted)" }}>
            For agents and CI pipelines registering assets programmatically.
          </p>
          <div className="rounded-lg p-3 font-mono text-[11px]"
            style={{ background: "#0d1117", color: "#6fd6c4", border: "1px solid #1f2933" }}>
{`POST /v1/assets
Authorization: Bearer fxc_•••••••
Content-Type: application/json

{ "hostname": "...", "ip": "...", "type": "..." }`}
          </div>
          <div className="mt-3 flex items-center justify-between text-[11.5px]">
            <span style={{ color: "var(--panel-text-muted)" }}>Token: <code className="font-mono" style={{ color: "#e0a063" }}>fxc_a8b1c2d3…</code></span>
            <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>Rotate</button>
          </div>
        </div>
      </div>

      {/* Manually-configured assets */}
      <div className="skeuo-panel p-5">
        <h3 className="mb-4 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Manually-Configured Assets
        </h3>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Hostname", "IP", "Type", "Env", "Owner", "Added", "Credential", "Actions"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { h: "phi-db-01",        ip: "10.30.1.10",  t: "Database", e: "prod", o: "DBA Oracle",   a: "12d ago", c: "cred_a8b1" },
              { h: "member-portal-01", ip: "172.16.1.10", t: "Server",   e: "prod", o: "Web Ops",      a: "8d ago",  c: "cred_a8b1" },
              { h: "claims-proc-01",   ip: "10.20.1.10",  t: "Server",   e: "prod", o: "Claims Plt",   a: "30d ago", c: "cred_a8b1" },
              { h: "ad-dc-01",         ip: "10.10.5.10",  t: "Server",   e: "prod", o: "IT Ops",       a: "60d ago", c: "cred_a8b1" },
            ].map((r, i) => (
              <tr key={r.h} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-semibold">{r.h}</td>
                <td className="px-3 py-3 font-mono">{r.ip}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.t}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.e}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.o}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.a}</td>
                <td className="px-3 py-3 font-mono text-[11px]" style={{ color: "#e0a063" }}>{r.c}</td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold mr-1" style={btn}>Edit</button>
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={{ background: "rgba(212,106,94,0.15)", color: "#d46a5e", border: "1px solid rgba(212,106,94,0.35)" }}>
                    <Trash2 className="inline h-3 w-3" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ─────────── MANUAL: standalone sections ─────────── */
function BulkCsvSection() {
  return (
    <>
      <SubHeader label="Bulk Import (CSV)" desc="Upload many assets at once with a CSV file." />
      <div className="skeuo-panel p-5">
        <div className="rounded-xl border border-dashed p-8 text-center"
          style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
          <FileText className="h-10 w-10 mx-auto mb-2 opacity-60" style={{ color: "var(--section-heading)" }} />
          <p className="text-[13px]" style={{ color: "var(--panel-text)" }}>Drop <code className="font-mono text-[12px]" style={{ color: "#e0a063" }}>assets.csv</code> here or click to browse</p>
          <p className="text-[11px] mt-1" style={{ color: "var(--panel-text-muted)" }}>
            Schema: hostname, ip, type, os, env, criticality, tags
          </p>
          <div className="mt-4 flex gap-2 justify-center">
            <PrimaryBtn label="Choose File" icon={<Upload className="h-3.5 w-3.5" />} />
            <GhostBtn label="Download template" />
          </div>
        </div>
        <div className="mt-5">
          <h4 className="text-[13px] font-semibold mb-2" style={{ color: "var(--panel-text)" }}>Recent imports</h4>
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["File", "Rows", "Added", "Skipped", "When", "Operator"].map((h) => (
                  <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                { f: "coventra-fleet-2026-06.csv", rows: 412, add: 388, skip: 24, when: "2d ago", op: "sysadmin_ops@coventra.com" },
                { f: "coventra-dmz-batch.csv",     rows: 84,  add: 84,  skip: 0,  when: "8d ago", op: "netadmin_01@coventra.com" },
              ].map((r, i) => (
                <tr key={r.f} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#e0a063" }}>{r.f}</td>
                  <td className="px-3 py-3 font-mono">{r.rows}</td>
                  <td className="px-3 py-3 font-mono" style={{ color: "#6fd6c4" }}>+{r.add}</td>
                  <td className="px-3 py-3 font-mono" style={{ color: "#e1c069" }}>{r.skip}</td>
                  <td className="px-3 py-3 font-mono text-[11.5px]">{r.when}</td>
                  <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.op}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

function ApiTokenSection() {
  return (
    <>
      <SubHeader label="API / Token Onboarding" desc="For agents and CI pipelines that register assets programmatically." />
      <div className="grid grid-cols-2 gap-4">
        <div className="skeuo-panel p-5">
          <h4 className="text-[14px] font-semibold mb-2" style={{ color: "var(--panel-text)" }}>Register endpoint</h4>
          <div className="rounded-lg p-3 font-mono text-[11.5px]"
            style={{ background: "#0d1117", color: "#6fd6c4", border: "1px solid #1f2933" }}>
{`POST /v1/assets
Authorization: Bearer fxc_•••••••
Content-Type: application/json

{
  "hostname": "phi-db-01",
  "ip": "10.30.1.10",
  "type": "database",
  "os": "Oracle Linux 8",
  "env": "prod",
  "criticality": "critical",
  "tags": ["hipaa", "phi"]
}`}
          </div>
        </div>
        <div className="skeuo-panel p-5">
          <h4 className="text-[14px] font-semibold mb-2" style={{ color: "var(--panel-text)" }}>Active tokens</h4>
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
                {["Token ID", "Scope", "Created", "Last Used", "Actions"].map((h) => (
                  <th key={h} className="px-3 py-2 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                { id: "fxc_a8b1c2…", scope: "assets:write", created: "32d ago", last: "2m ago" },
                { id: "fxc_3f2e91…", scope: "assets:read",  created: "60d ago", last: "1h ago" },
              ].map((t, i) => (
                <tr key={t.id} style={{
                  background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                  color: "var(--panel-text)",
                  borderTop: "1px solid var(--row-border)",
                }}>
                  <td className="px-3 py-2 font-mono text-[11px]" style={{ color: "#e0a063" }}>{t.id}</td>
                  <td className="px-3 py-2 text-[11.5px]">{t.scope}</td>
                  <td className="px-3 py-2 font-mono text-[11px]" style={{ color: "var(--panel-text-muted)" }}>{t.created}</td>
                  <td className="px-3 py-2 font-mono text-[11px]">{t.last}</td>
                  <td className="px-3 py-2">
                    <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>Rotate</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button className="mt-3 w-full rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
            + Issue new token
          </button>
        </div>
      </div>
    </>
  );
}

/* ─────────── AUTOMATIC CONFIG (nmap-style) ─────────── */
function AutomaticConfig({ view }: { view: string }) {
  if (view === "active")  return <ActiveScansSection />;
  if (view === "sched")   return <SchedulesSection />;
  if (view === "hosts")   return <DiscoveredHostsSection />;
  if (view === "subnets") return <SubnetsSection />;
  return <AutoConfigFull />;
}

function AutoConfigFull() {
  const [range, setRange] = useState("10.30.0.0/16");
  const [running, setRunning] = useState(false);

  return (
    <>
      {/* New scan form */}
      <div className="skeuo-panel p-5 mb-6">
        <h3 className="mb-1 text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
          <Radar className="inline h-4 w-4 mr-1.5" style={{ color: "var(--section-heading)" }} />
          Run Discovery Scan
        </h3>
        <p className="mb-4 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          nmap-based discovery — TCP SYN sweep · OS fingerprinting · service version detection. Discovered hosts auto-populate the asset registry.
        </p>

        <div className="grid grid-cols-2 gap-3 mb-3">
          <Field label="Subnet / CIDR / Range" value={range} onChange={setRange} placeholder="10.30.0.0/16 or 10.10.5.1-254" mono />
          <SelectField label="Scan Profile" value="balanced" onChange={() => {}}
            options={["balanced (-T3 default)", "stealth (-T1 -sS)", "fast (-T4 -F)", "aggressive (-A -T4)", "discovery-only (-sn)"]} />
        </div>
        <div className="grid grid-cols-4 gap-3 mb-3">
          <SelectField label="Port Range" value="top-1000" onChange={() => {}}
            options={["top-100", "top-1000", "1-65535 (all)", "custom"]} />
          <SelectField label="Probe Type" value="syn" onChange={() => {}}
            options={["TCP SYN (-sS)", "TCP Connect (-sT)", "UDP (-sU)", "ICMP ping"]} />
          <Checkbox label="OS Fingerprint (-O)" defaultChecked />
          <Checkbox label="Service Version (-sV)" defaultChecked />
        </div>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <Checkbox label="Auto-add to inventory" defaultChecked />
          <Checkbox label="Run baseline scan after discovery" />
          <Checkbox label="Resolve DNS (-R)" defaultChecked />
          <Checkbox label="Skip excluded subnets" defaultChecked />
        </div>

        <div className="flex items-center gap-2">
          <button onClick={() => setRunning((r) => !r)}
            className="flex items-center gap-1.5 rounded-lg px-4 py-2 text-[12px] font-semibold"
            style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
            {running ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            {running ? "Stop Discovery" : "Start Discovery Scan"}
          </button>
          <GhostBtn label="Save as Schedule" />
          <span className="ml-auto text-[11px] font-mono" style={{ color: "var(--panel-text-muted)" }}>
            est. {range.includes("/16") ? "12-18 min" : "30 sec"} · 65,534 hosts
          </span>
        </div>
      </div>

      {/* Active scan progress */}
      {(running || true) && (
        <div className="skeuo-panel p-5 mb-6">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
              <Activity className="inline h-4 w-4 mr-1.5 animate-pulse" style={{ color: "#6fd6c4" }} />
              Active Discovery — <code className="font-mono text-[13px]" style={{ color: "#e0a063" }}>DSC-3142</code>
            </h3>
            <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
              style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>RUNNING</span>
          </div>
          <div className="grid grid-cols-4 gap-3 mb-3">
            <Tiny label="Hosts swept" value="42,184 / 65,534" />
            <Tiny label="Up / Responsive" value="284" />
            <Tiny label="New assets" value="42" color="#6fd6c4" />
            <Tiny label="ETA" value="7m 12s" />
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.06)" }}>
            <div className="h-full" style={{ width: "64%", background: "linear-gradient(90deg, #6fd6c4, #e0a063)" }} />
          </div>
          <p className="mt-2 text-[10.5px] font-mono" style={{ color: "var(--panel-text-muted)" }}>
            Scanning 172.16.1.0/24 · current host 172.16.1.11 (member-portal-02) · TCP/443 open · nginx/1.27.2
          </p>
        </div>
      )}

      {/* Live discovered hosts */}
      <div className="skeuo-panel p-5 mb-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Discovered Hosts (live)
          </h3>
          <div className="flex gap-2 text-[10.5px]">
            <Legend dot="#6fd6c4" label="New" />
            <Legend dot="#e1c069" label="Updated" />
            <Legend dot="#7eaeae" label="Already known" />
            <Legend dot="#d46a5e" label="Unreachable" />
          </div>
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["IP", "Hostname (rDNS)", "OS Fingerprint", "Open Ports", "Services Detected", "Status", "Action"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { ip: "172.16.1.11", host: "member-portal-02.coventra.com", os: "Linux 6.5 (Ubuntu 24.04)", ports: "22, 80, 443",     svc: "OpenSSH 9.7 · nginx 1.27.2",       state: "new" },
              { ip: "10.10.5.11",  host: "ad-dc-02.coventra.local",       os: "Windows Server 2022",      ports: "445, 3389, 5985", svc: "SMB · RDP · WinRM",                state: "new" },
              { ip: "10.0.1.2",    host: "fw-perimeter-02.coventra.local", os: "PAN-OS 11.1 (Palo Alto)", ports: "22, 443, 4433",   svc: "SSH · admin UI · GlobalProtect",   state: "updated" },
              { ip: "10.60.1.45",  host: "iot-badge-12.coventra.local",   os: "Embedded Linux 4.x",       ports: "80, 554, 8080",   svc: "HTTP · RTSP · HTTP-alt",           state: "known" },
              { ip: "10.30.1.99",  host: "—",                              os: "no fingerprint",          ports: "—",               svc: "—",                                state: "unreach" },
              { ip: "10.20.3.11",  host: "splunk-idx-02.coventra.local",  os: "Linux 6.5 (RHEL 9)",       ports: "22, 8000, 9997",  svc: "OpenSSH · Splunk Web · Splunk-S2S", state: "new" },
            ].map((r, i) => (
              <tr key={r.ip} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono">{r.ip}</td>
                <td className="px-3 py-3 font-semibold">{r.host}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.os}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]">{r.ports}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.svc}</td>
                <td className="px-3 py-3">
                  {r.state === "new"     && <Pill bg="rgba(111,214,196,0.15)" fg="#6fd6c4" label="NEW" />}
                  {r.state === "updated" && <Pill bg="rgba(225,192,105,0.18)" fg="#e1c069" label="UPDATED" />}
                  {r.state === "known"   && <Pill bg="rgba(126,174,174,0.15)" fg="#7eaeae" label="KNOWN" />}
                  {r.state === "unreach" && <Pill bg="rgba(212,106,94,0.18)"  fg="#d46a5e" label="UNREACHABLE" />}
                </td>
                <td className="px-3 py-3">
                  {r.state === "new"
                    ? <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>Add to inventory</button>
                    : <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>View</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
          Failures routed to <code className="font-mono text-[10px]">dlq.discovery_unreachable</code>. New hosts emit <code className="font-mono text-[10px]" style={{ color: "#6fd6c4" }}>asset.discovered</code> on Valkey pub/sub.
        </p>
      </div>

      {/* Subnets + schedules */}
      <div className="grid grid-cols-2 gap-4">
        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
            <Globe className="inline h-4 w-4 mr-1.5" style={{ color: "var(--section-heading)" }} />
            Subnets & Ranges
          </h3>
          <ul className="space-y-1.5 text-[11.5px]">
            {[
              { r: "10.30.0.0/16",  note: "Secure Data Zone · scanned", excl: false },
              { r: "10.20.0.0/16",  note: "Server VLAN · scanned",      excl: false },
              { r: "10.10.0.0/16",  note: "User LAN · workstations",    excl: false },
              { r: "10.60.0.0/16",  note: "Physical/IoT · EXCLUDED",    excl: true },
            ].map((s) => (
              <li key={s.r} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5"
                style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
                <Server className="h-3.5 w-3.5" style={{ color: s.excl ? "#d46a5e" : "#6fd6c4" }} />
                <code className="font-mono" style={{ color: "var(--panel-text)" }}>{s.r}</code>
                <span style={{ color: "var(--panel-text-muted)" }}>· {s.note}</span>
                <button className="ml-auto text-[10px]" style={{ color: "#e0a063" }}>
                  {s.excl ? "Re-include" : "Exclude"}
                </button>
              </li>
            ))}
            <li>
              <button className="w-full rounded-md border border-dashed px-2.5 py-1.5 text-[11.5px]"
                style={{ borderColor: "var(--row-border)", color: "var(--panel-text-muted)" }}>
                + Add subnet
              </button>
            </li>
          </ul>
        </div>

        <div className="skeuo-panel p-5">
          <h3 className="mb-3 text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Discovery Schedules
          </h3>
          <ul className="space-y-2 text-[11.5px]">
            {[
              { name: "Hourly · auth subnet sweep",  cron: "0 * * * *",       last: "12m ago",  next: "in 48m",  on: true },
              { name: "Daily · full /16 sweep",       cron: "0 2 * * *",       last: "14h ago",  next: "in 10h",  on: true },
              { name: "Weekly · deep aggressive",     cron: "0 3 * * 6",       last: "6d ago",   next: "in 1d",   on: false },
            ].map((s) => (
              <li key={s.name} className="rounded-md border px-3 py-2"
                style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
                <div className="flex items-center justify-between">
                  <span style={{ color: "var(--panel-text)" }} className="font-semibold">{s.name}</span>
                  <span className="text-[10px] font-semibold uppercase"
                    style={{ color: s.on ? "#6fd6c4" : "var(--panel-text-muted)" }}>
                    {s.on ? "ENABLED" : "PAUSED"}
                  </span>
                </div>
                <div className="mt-1 flex gap-3 text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>
                  <span>cron <code className="font-mono" style={{ color: "#e0a063" }}>{s.cron}</code></span>
                  <span>last {s.last}</span>
                  <span>next {s.next}</span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </>
  );
}

/* ─────────── AUTO: standalone sections ─────────── */
function ActiveScansSection() {
  return (
    <>
      <SubHeader label="Active Discovery Scans" desc="Currently running nmap sweeps and their live progress." />
      {[
        { id: "DSC-3142", range: "10.2.0.0/16", swept: "42,184 / 65,534", pct: 64, eta: "7m 12s", new: 42 },
        { id: "DSC-3141", range: "10.0.1.0/24", swept: "118 / 254",      pct: 46, eta: "1m 8s",  new: 4  },
      ].map((s) => (
        <div key={s.id} className="skeuo-panel p-5 mb-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
              <Activity className="inline h-4 w-4 mr-1.5 animate-pulse" style={{ color: "#6fd6c4" }} />
              <code className="font-mono text-[13px]" style={{ color: "#e0a063" }}>{s.id}</code>
              <span className="ml-2 text-[12px] font-normal" style={{ color: "var(--panel-text-muted)" }}>{s.range}</span>
            </h3>
            <div className="flex gap-2">
              <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
                style={{ background: "rgba(111,214,196,0.15)", color: "#6fd6c4" }}>RUNNING</span>
              <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>
                <Pause className="inline h-3 w-3" /> Stop
              </button>
            </div>
          </div>
          <div className="grid grid-cols-4 gap-3 mb-3">
            <Tiny label="Hosts swept" value={s.swept} />
            <Tiny label="New assets" value={String(s.new)} color="#6fd6c4" />
            <Tiny label="Progress" value={`${s.pct}%`} />
            <Tiny label="ETA" value={s.eta} />
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.06)" }}>
            <div className="h-full" style={{ width: `${s.pct}%`, background: "linear-gradient(90deg, #6fd6c4, #e0a063)" }} />
          </div>
        </div>
      ))}
    </>
  );
}

function SchedulesSection() {
  return (
    <>
      <SubHeader label="Discovery Schedules" desc="Recurring nmap sweeps that run on a cron timer." />
      <div className="skeuo-panel p-5">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Name", "Cron", "Subnet/Range", "Profile", "Last Run", "Next Run", "State", "Actions"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { name: "Hourly auth sweep",  cron: "0 * * * *",     range: "10.0.1.0/24",  prof: "fast",       last: "12m ago", next: "in 48m",  on: true  },
              { name: "Daily /16 sweep",    cron: "0 2 * * *",     range: "10.2.0.0/16",  prof: "balanced",   last: "14h ago", next: "in 10h",  on: true  },
              { name: "Daily platform",     cron: "0 3 * * *",     range: "10.4.0.0/16",  prof: "balanced",   last: "13h ago", next: "in 11h",  on: true  },
              { name: "Weekly deep aggro",  cron: "0 3 * * 6",     range: "all subnets",  prof: "aggressive", last: "6d ago",  next: "in 1d",   on: false },
            ].map((r, i) => (
              <tr key={r.name} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-semibold">{r.name}</td>
                <td className="px-3 py-3 font-mono" style={{ color: "#e0a063" }}>{r.cron}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]">{r.range}</td>
                <td className="px-3 py-3 text-[11.5px]">{r.prof}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.last}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "#6fd6c4" }}>{r.next}</td>
                <td className="px-3 py-3 text-[11px] font-semibold" style={{ color: r.on ? "#6fd6c4" : "var(--panel-text-muted)" }}>
                  {r.on ? "ENABLED" : "PAUSED"}
                </td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold mr-1" style={btn}>Edit</button>
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>Run now</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <button className="mt-4 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
          style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
          + New Schedule
        </button>
      </div>
    </>
  );
}

function DiscoveredHostsSection() {
  return (
    <>
      <SubHeader label="Discovered Hosts" desc="All hosts found by recent discovery sweeps across every subnet." />
      <div className="skeuo-panel p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex gap-2 text-[10.5px]">
            <Legend dot="#6fd6c4" label="New" />
            <Legend dot="#e1c069" label="Updated" />
            <Legend dot="#7eaeae" label="Already known" />
            <Legend dot="#d46a5e" label="Unreachable" />
          </div>
          <span className="text-[11px] font-mono" style={{ color: "var(--panel-text-muted)" }}>284 total · 42 NEW</span>
        </div>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["IP", "Hostname (rDNS)", "OS Fingerprint", "Open Ports", "Services Detected", "Status", "Action"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { ip: "172.16.1.11", host: "member-portal-02.coventra.com",  os: "Linux 6.5 (Ubuntu 24.04)", ports: "22, 80, 443",     svc: "OpenSSH 9.7 · nginx 1.27.2",     state: "new" },
              { ip: "10.10.5.11",  host: "ad-dc-02.coventra.local",         os: "Windows Server 2022",      ports: "445, 3389, 5985", svc: "SMB · RDP · WinRM",              state: "new" },
              { ip: "10.0.1.2",    host: "fw-perimeter-02.coventra.local",  os: "PAN-OS 11.1 (Palo Alto)",  ports: "22, 443, 4433",   svc: "SSH · admin UI · GlobalProtect", state: "updated" },
              { ip: "10.60.1.45",  host: "iot-badge-12.coventra.local",     os: "Embedded Linux 4.x",       ports: "80, 554, 8080",   svc: "HTTP · RTSP · HTTP-alt",         state: "known" },
              { ip: "10.30.1.99",  host: "—",                               os: "no fingerprint",           ports: "—",               svc: "—",                              state: "unreach" },
              { ip: "10.20.3.11",  host: "splunk-idx-02.coventra.local",    os: "Linux 6.5 (RHEL 9)",       ports: "22, 8000, 9997",  svc: "OpenSSH · Splunk Web · Splunk-S2S", state: "new" },
              { ip: "10.20.1.10",  host: "claims-proc-01.coventra.local",   os: "Linux 6.5 (RHEL 9)",       ports: "22, 443, 8443",   svc: "OpenSSH · Claims API · Mgmt UI", state: "known" },
              { ip: "10.40.1.10",  host: "edi-srv-01.coventra.local",       os: "Windows Server 2022",      ports: "445, 3389, 5985", svc: "SMB · RDP · WinRM",              state: "updated" },
            ].map((r, i) => (
              <tr key={r.ip} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono">{r.ip}</td>
                <td className="px-3 py-3 font-semibold">{r.host}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.os}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]">{r.ports}</td>
                <td className="px-3 py-3 text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{r.svc}</td>
                <td className="px-3 py-3">
                  {r.state === "new"     && <Pill bg="rgba(111,214,196,0.15)" fg="#6fd6c4" label="NEW" />}
                  {r.state === "updated" && <Pill bg="rgba(225,192,105,0.18)" fg="#e1c069" label="UPDATED" />}
                  {r.state === "known"   && <Pill bg="rgba(126,174,174,0.15)" fg="#7eaeae" label="KNOWN" />}
                  {r.state === "unreach" && <Pill bg="rgba(212,106,94,0.18)"  fg="#d46a5e" label="UNREACHABLE" />}
                </td>
                <td className="px-3 py-3">
                  {r.state === "new"
                    ? <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>Add to inventory</button>
                    : <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={btn}>View</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function SubnetsSection() {
  return (
    <>
      <SubHeader label="Subnets & Ranges" desc="The address space the discovery scanner is allowed to sweep, and what to skip." />
      <div className="skeuo-panel p-5">
        <table className="w-full text-[12.5px]">
          <thead>
            <tr style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.05), var(--pill-track-grad-top))", color: "var(--section-heading)" }}>
              {["Subnet / Range", "Label", "Last Swept", "Hosts Up", "State", "Actions"].map((h) => (
                <th key={h} className="px-3 py-2.5 text-left text-[10.5px] uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { r: "10.2.0.0/16",  label: "Production",  last: "14h ago", up: 612, excl: false },
              { r: "10.4.0.0/16",  label: "Platform",    last: "13h ago", up: 248, excl: false },
              { r: "10.0.1.0/24",  label: "Management",  last: "12m ago", up: 22,  excl: false },
              { r: "10.99.0.0/24", label: "Honeypot",    last: "—",       up: 0,   excl: true },
            ].map((s, i) => (
              <tr key={s.r} style={{
                background: i % 2 ? "rgba(255,255,255,0.04)" : "transparent",
                color: "var(--panel-text)",
                borderTop: "1px solid var(--row-border)",
              }}>
                <td className="px-3 py-3 font-mono">{s.r}</td>
                <td className="px-3 py-3">{s.label}</td>
                <td className="px-3 py-3 font-mono text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>{s.last}</td>
                <td className="px-3 py-3 font-mono">{s.up}</td>
                <td className="px-3 py-3 text-[11px] font-semibold"
                  style={{ color: s.excl ? "#d46a5e" : "#6fd6c4" }}>
                  {s.excl ? "EXCLUDED" : "INCLUDED"}
                </td>
                <td className="px-3 py-3">
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold mr-1" style={btn}>Edit</button>
                  <button className="rounded-md px-2 py-0.5 text-[10.5px] font-semibold" style={{ background: "rgba(255,255,255,0.06)", color: "#e0a063", border: "1px solid var(--row-border)" }}>
                    {s.excl ? "Re-include" : "Exclude"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <button className="mt-4 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
          style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
          + Add Subnet
        </button>
      </div>
    </>
  );
}

/* ─────────── shared bits ─────────── */
const btn: React.CSSProperties = { background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" };

function SubHeader({ label, desc }: { label: string; desc: string }) {
  return (
    <div className="mb-4">
      <h2 className="text-[18px] font-semibold" style={{ color: "var(--panel-text)" }}>{label}</h2>
      <p className="text-[12px] mt-0.5" style={{ color: "var(--panel-text-muted)" }}>{desc}</p>
    </div>
  );
}

function K({ label, value, sub, tone = "teal" }: { label: string; value: string; sub?: string; tone?: "teal" | "copper" }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[28px] font-light leading-none" style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}>{value}</p>
          {sub && <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>}
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}

function Field({ label, value, onChange, placeholder, mono }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean }) {
  return (
    <label className="block">
      <span className="block text-[11px] uppercase tracking-wider mb-1" style={{ color: "var(--panel-text-muted)" }}>{label}</span>
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className={`w-full rounded-lg px-3 py-2 text-[12.5px] outline-none ${mono ? "font-mono" : ""}`}
        style={{ background: "rgba(0,0,0,0.25)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }} />
    </label>
  );
}

function SelectField({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <label className="block">
      <span className="block text-[11px] uppercase tracking-wider mb-1" style={{ color: "var(--panel-text-muted)" }}>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg px-3 py-2 text-[12.5px] outline-none"
        style={{ background: "rgba(0,0,0,0.25)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );
}

function Checkbox({ label, defaultChecked }: { label: string; defaultChecked?: boolean }) {
  return (
    <label className="flex items-center gap-2 rounded-lg border px-3 py-2 text-[12px]"
      style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)", color: "var(--panel-text)" }}>
      <input type="checkbox" defaultChecked={defaultChecked} className="h-3.5 w-3.5 accent-current" />
      {label}
    </label>
  );
}

function PrimaryBtn({ label, icon }: { label: string; icon?: React.ReactNode }) {
  return (
    <button className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
      style={{ background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)", color: "var(--disc-text)", boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)" }}>
      {icon}{label}
    </button>
  );
}

function GhostBtn({ label }: { label: string }) {
  return (
    <button className="rounded-lg px-3 py-1.5 text-[11.5px] font-semibold" style={btn}>
      {label}
    </button>
  );
}

function Tiny({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="rounded-lg border px-3 py-2"
      style={{ borderColor: "var(--row-border)", background: "rgba(0,0,0,0.15)" }}>
      <p className="text-[10px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
      <p className="mt-0.5 text-[15px] font-mono font-semibold" style={{ color: color ?? "var(--panel-text)" }}>{value}</p>
    </div>
  );
}

function Pill({ bg, fg, label }: { bg: string; fg: string; label: string }) {
  return <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase" style={{ background: bg, color: fg }}>{label}</span>;
}

function Legend({ dot, label }: { dot: string; label: string }) {
  return (
    <span className="flex items-center gap-1" style={{ color: "var(--panel-text-muted)" }}>
      <span className="h-2 w-2 rounded-full" style={{ background: dot }} /> {label}
    </span>
  );
}

