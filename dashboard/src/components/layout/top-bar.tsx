"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import {
  Bell,
  Search,
  ChevronDown,
  Shield,
  ScanLine,
  Server,
  FileText,
  Bot,
  Activity,
  Bug,
  CheckSquare,
  Gauge,
  CreditCard,
  Settings as SettingsIcon,
  HelpCircle,
  AlertTriangle,
  Command,
} from "lucide-react";
import { ThemeToggle } from "./theme-toggle";
import { RoleSwitcher } from "./role-switcher";
import { getAssets } from "@/lib/data/assets";
import type { Asset } from "@/lib/data/types";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { User, LogOut } from "lucide-react";

const pageTitles: Record<string, string> = {
  "/": "Global Command Cluster",
  "/scans": "Scan Operations Cluster",
  "/assets": "Asset Registry Cluster",
  "/risk-scoring": "Risk Posture Cluster",
  "/reports": "Archives Cluster",
  "/ai-actions": "AI Operations Cluster",
  "/siem": "Data Streams Cluster",
  "/vulnerabilities": "Vulnerability Cluster",
  "/compliance": "Compliance Cluster",
  "/security-score": "Security Score Cluster",
  "/billing": "Billing Cluster",
  "/settings": "Settings Cluster",
  "/help": "Help Cluster",
};

type CmdItem = {
  label: string;
  href: string;
  group: string;
  icon: React.ReactNode;
  hint?: string;
};

const commands: CmdItem[] = [
  { group: "Navigate", label: "Global Command Cluster", href: "/", icon: <Shield className="h-4 w-4" /> },
  { group: "Navigate", label: "Scan Operations", href: "/scans", icon: <ScanLine className="h-4 w-4" /> },
  { group: "Navigate", label: "Asset Registry", href: "/assets", icon: <Server className="h-4 w-4" /> },
  { group: "Navigate", label: "Vulnerabilities", href: "/vulnerabilities", icon: <Bug className="h-4 w-4" /> },
  { group: "Navigate", label: "Risk Scoring", href: "/risk-scoring", icon: <Gauge className="h-4 w-4" /> },
  { group: "Navigate", label: "Compliance", href: "/compliance", icon: <CheckSquare className="h-4 w-4" /> },
  { group: "Navigate", label: "AI Actions", href: "/ai-actions", icon: <Bot className="h-4 w-4" /> },
  { group: "Navigate", label: "SIEM Streams", href: "/siem", icon: <Activity className="h-4 w-4" /> },
  { group: "Navigate", label: "Reports", href: "/reports", icon: <FileText className="h-4 w-4" /> },
  { group: "Navigate", label: "Security Score", href: "/security-score", icon: <Shield className="h-4 w-4" /> },
  { group: "Navigate", label: "Billing", href: "/billing", icon: <CreditCard className="h-4 w-4" /> },
  { group: "Navigate", label: "Settings", href: "/settings", icon: <SettingsIcon className="h-4 w-4" /> },
  { group: "Navigate", label: "Help & Docs", href: "/help", icon: <HelpCircle className="h-4 w-4" /> },
  { group: "Quick Actions", label: "Live Threat Feed", href: "/live-threat-feed", icon: <Activity className="h-4 w-4" />, hint: "Live" },
  { group: "Quick Actions", label: "Top Risks", href: "/risk-scoring/top-risks", icon: <AlertTriangle className="h-4 w-4" /> },
  { group: "Quick Actions", label: "Triage Queue", href: "/ai-actions/triage-queue", icon: <Bot className="h-4 w-4" /> },
  { group: "Quick Actions", label: "Zero Trust Posture", href: "/risk-scoring?view=zero-trust", icon: <Shield className="h-4 w-4" /> },
  { group: "Quick Actions", label: "Remediation Steps", href: "/ai-actions?view=remediation", icon: <Bot className="h-4 w-4" /> },
  { group: "Quick Actions", label: "Roles & Permissions", href: "/settings?view=permissions", icon: <SettingsIcon className="h-4 w-4" /> },
];

const STATIC_FINDINGS: CmdItem[] = [
  { group: "Findings", label: "F-90412 · CVE-2024-21287 · phi-db-01",      href: "/ai-actions?view=remediation", icon: <Bug className="h-4 w-4" />, hint: "Critical" },
  { group: "Findings", label: "F-90408 · CVE-2024-3094 · web-edge-2",       href: "/ai-actions?view=remediation", icon: <Bug className="h-4 w-4" />, hint: "High" },
  { group: "Findings", label: "F-90401 · CVE-2025-0871 · k8s-node-7",       href: "/ai-actions?view=remediation", icon: <Bug className="h-4 w-4" />, hint: "High" },
  { group: "Findings", label: "F-90395 · CVE-2025-2104 · wks-1042",         href: "/ai-actions?view=remediation", icon: <Bug className="h-4 w-4" />, hint: "Medium" },
  { group: "Findings", label: "F-90388 · CVE-2024-9821 · srv-app-3",        href: "/ai-actions?view=remediation", icon: <Bug className="h-4 w-4" />, hint: "Medium" },
];

const STATIC_CVES: CmdItem[] = [
  { group: "CVEs",    label: "CVE-2024-21287 — Oracle DB authenticated RCE", href: "/vulnerabilities", icon: <AlertTriangle className="h-4 w-4" />, hint: "KEV" },
  { group: "CVEs",    label: "CVE-2024-3094 — xz-utils liblzma backdoor",    href: "/vulnerabilities", icon: <AlertTriangle className="h-4 w-4" />, hint: "KEV" },
  { group: "CVEs",    label: "CVE-2025-1042 — PostgreSQL RCE",               href: "/vulnerabilities", icon: <AlertTriangle className="h-4 w-4" />, hint: "KEV" },
  { group: "CVEs",    label: "CVE-2025-0871 — containerd privesc",           href: "/vulnerabilities", icon: <AlertTriangle className="h-4 w-4" />, hint: "KEV" },
];

const STATIC_USERS: CmdItem[] = [
  { group: "Users",   label: "ciso_patel@coventra.com — CISO",                     href: "/users", icon: <User className="h-4 w-4" /> },
  { group: "Users",   label: "hipaa_officer@coventra.com — Compliance",            href: "/users", icon: <User className="h-4 w-4" /> },
  { group: "Users",   label: "soc_analyst_01@coventra.com — SOC Tier 1",           href: "/users", icon: <User className="h-4 w-4" /> },
  { group: "Users",   label: "risk_analyst_01@coventra.com — Risk",                href: "/users", icon: <User className="h-4 w-4" /> },
  { group: "Users",   label: "audit_mgr_01@coventra.com — Audit",                  href: "/users", icon: <User className="h-4 w-4" /> },
];

const STATIC_MITRE: CmdItem[] = [
  { group: "MITRE ATT&CK", label: "T1003.001 — LSASS memory dump",                href: "/knowledge-graph?n=attack", icon: <Shield className="h-4 w-4" /> },
  { group: "MITRE ATT&CK", label: "T1068 — Exploitation for privilege escalation", href: "/knowledge-graph?n=attack", icon: <Shield className="h-4 w-4" /> },
  { group: "MITRE ATT&CK", label: "T1190 — Exploit public-facing application",     href: "/knowledge-graph?n=attack", icon: <Shield className="h-4 w-4" /> },
];

const EXTRA_COMMANDS: CmdItem[] = [...STATIC_FINDINGS, ...STATIC_CVES, ...STATIC_USERS, ...STATIC_MITRE];

const tileStyle: React.CSSProperties = {
  background:
    "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
  boxShadow:
    "inset 0 1px 0 rgba(255,255,255,0.08), inset 0 -2px 4px rgba(0,0,0,0.35)",
  color: "var(--tile-text)",
  border: "1px solid var(--tile-border)",
};

export function TopBar() {
  const pathname = usePathname();
  const router = useRouter();
  const title = pageTitles[pathname] || "Global Command Cluster";

  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);
  const [userEmail, setUserEmail] = useState("admin@byoc.local");
  const [userRole, setUserRole] = useState("BYOC Admin");
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    getAssets().then(setAssets);
  }, []);

  useEffect(() => {
    try {
      const e = localStorage.getItem("byoc-user-email");
      const r = localStorage.getItem("byoc-user-role");
      if (e) setUserEmail(e);
      if (r) setUserRole(r);
    } catch {}
  }, []);

  const initials = userRole
    .split(/\s+/)
    .map((p) => p[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase();

  const signOut = () => {
    try {
      localStorage.removeItem("byoc-auth");
      localStorage.removeItem("byoc-user-email");
      localStorage.removeItem("byoc-user-role");
      localStorage.removeItem("byoc-rbac-role");
    } catch {}
    router.replace("/login");
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const base = [...commands, ...EXTRA_COMMANDS];
    if (!q) return base;

    const assetMatches: CmdItem[] = assets
      .filter((a) =>
        a.name.toLowerCase().includes(q) ||
        a.businessLabel.toLowerCase().includes(q) ||
        a.businessRole.toLowerCase().includes(q) ||
        a.ip.toLowerCase().includes(q) ||
        a.os.toLowerCase().includes(q)
      )
      .slice(0, 12)
      .map((a) => ({
        group: "Assets",
        label: `${a.name} — ${a.businessRole} · ${a.ip}`,
        href: `/assets?view=all`,
        icon: <Server className="h-4 w-4" />,
        hint:
          a.status === "critical" ? "Critical" :
          a.status === "warning"  ? "Warning"  : undefined,
      }));

    const cmdMatches = base.filter((c) => c.label.toLowerCase().includes(q));
    return [...assetMatches, ...cmdMatches];
  }, [query, assets]);

  const grouped = useMemo(() => {
    const g: Record<string, CmdItem[]> = {};
    results.forEach((r) => {
      (g[r.group] ||= []).push(r);
    });
    return g;
  }, [results]);

  useEffect(() => setActiveIdx(0), [query]);

  const go = (href: string) => {
    setOpen(false);
    setQuery("");
    router.push(href);
  };

  const onKeyNav = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = results[activeIdx];
      if (item) go(item.href);
    }
  };

  return (
    <>
      <header className="engraved-bar sticky top-0 z-30 flex h-[68px] items-center justify-between px-6">
        <h1
          className="text-[20px] font-semibold tracking-wide"
          style={{
            color: "var(--topbar-text)",
            letterSpacing: "0.02em",
          }}
        >
          {title}
        </h1>

        <div className="flex items-center gap-3">
          <RoleSwitcher />
          <ThemeToggle />

          {/* Search — opens command palette */}
          <button
            onClick={() => setOpen(true)}
            className="relative flex h-10 w-80 items-center rounded-xl px-3 transition-colors hover:brightness-110"
            style={{
              background:
                "linear-gradient(180deg, var(--search-bg-top), var(--search-bg-bot))",
              border: "1px solid var(--search-border)",
              boxShadow:
                "inset 0 2px 4px var(--pill-shadow-inset), inset 0 -1px 0 rgba(255,255,255,0.04)",
            }}
            aria-label="Open command palette"
          >
            <Search className="h-4 w-4" style={{ color: "var(--panel-text-muted)" }} />
            <span
              className="ml-2 flex-1 text-left text-sm"
              style={{ color: "var(--panel-text-muted)" }}
            >
              Search 
            </span>
            <kbd
              className="ml-2 flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] font-semibold"
              style={{
                background: "rgba(0,0,0,0.35)",
                color: "var(--panel-text-muted)",
                border: "1px solid var(--search-border)",
              }}
            >
              <Command className="h-3 w-3" /> K
            </kbd>
          </button>

          {/* Single notification bell */}
          <button
            className="relative flex h-9 w-9 items-center justify-center rounded-lg"
            style={tileStyle}
            aria-label="Notifications"
          >
            <Bell className="h-[18px] w-[18px]" strokeWidth={1.8} />
            <span
              className="absolute -right-1 -top-1 flex h-4 min-w-[16px] items-center justify-center rounded-full px-1 text-[9px] font-bold"
              style={{
                background: "var(--crit-red)",
                color: "#1a1612",
                boxShadow: "0 0 8px rgba(212,106,94,0.7)",
              }}
            >
              3
            </span>
          </button>

          {/* User profile dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                className="flex items-center gap-2 rounded-xl py-1.5 pl-1.5 pr-3 outline-none"
                style={{
                  background:
                    "linear-gradient(180deg, rgba(224,160,99,0.18), rgba(120,80,40,0.10))",
                  border: "1px solid rgba(184,122,63,0.45)",
                  boxShadow:
                    "inset 0 1px 0 rgba(255,224,180,0.25), 0 4px 10px rgba(120,90,40,0.18)",
                }}
              >
                <div
                  className="flex h-7 w-7 items-center justify-center rounded-lg text-[11px] font-bold"
                  style={{
                    background:
                      "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 75%)",
                    color: "var(--disc-text)",
                    boxShadow:
                      "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.55)",
                  }}
                >
                  {initials}
                </div>
                <span className="text-sm font-medium" style={{ color: "var(--topbar-text)" }}>
                  {userRole}
                </span>
                <ChevronDown className="h-3.5 w-3.5" style={{ color: "var(--section-heading)" }} />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="w-64 p-1"
              style={{
                background: "linear-gradient(180deg, var(--card), var(--background))",
                border: "1px solid var(--border)",
                color: "var(--panel-text)",
              }}
            >
              <DropdownMenuLabel className="px-2 py-2">
                <div className="flex flex-col">
                  <span className="text-[13px] font-semibold" style={{ color: "var(--panel-text)" }}>
                    {userRole}
                  </span>
                  <span className="text-[11px] font-normal" style={{ color: "var(--panel-text-muted)" }}>
                    {userEmail}
                  </span>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator style={{ background: "var(--divider)" }} />
              <DropdownMenuItem onClick={() => router.push("/profile")} className="gap-2">
                <User className="h-4 w-4" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => router.push("/settings")} className="gap-2">
                <SettingsIcon className="h-4 w-4" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => router.push("/help")} className="gap-2">
                <HelpCircle className="h-4 w-4" />
                Help & Docs
              </DropdownMenuItem>
              <DropdownMenuSeparator style={{ background: "var(--divider)" }} />
              <DropdownMenuItem
                onClick={signOut}
                className="gap-2"
                style={{ color: "var(--crit-red)" }}
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent
          showCloseButton={false}
          className="top-[20%] max-w-2xl translate-y-0 gap-0 overflow-hidden p-0"
          style={{
            background: "linear-gradient(180deg, var(--card), var(--background))",
            border: "1px solid var(--border)",
            color: "var(--panel-text)",
            boxShadow: "0 30px 80px rgba(0,0,0,0.6)",
          }}
        >
          <DialogTitle className="sr-only">Command Palette</DialogTitle>
          <DialogDescription className="sr-only">
            Search assets, CVEs, and navigate pages.
          </DialogDescription>

          <div
            className="flex items-center gap-2 border-b px-4 py-3"
            style={{ borderColor: "var(--divider)" }}
          >
            <Search className="h-4 w-4" style={{ color: "var(--panel-text-muted)" }} />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={onKeyNav}
              placeholder="Type a command, asset, or CVE…"
              className="flex-1 bg-transparent text-sm outline-none"
              style={{ color: "var(--panel-text)" }}
            />
            <kbd
              className="rounded-md px-1.5 py-0.5 text-[10px] font-semibold"
              style={{
                background: "var(--inset-base)",
                color: "var(--panel-text-muted)",
                border: "1px solid var(--divider)",
              }}
            >
              ESC
            </kbd>
          </div>

          <div className="cmdk-scroll max-h-[420px] overflow-y-auto p-2">
            {results.length === 0 ? (
              <div
                className="px-4 py-10 text-center text-sm"
                style={{ color: "var(--panel-text-muted)" }}
              >
                No matches for &ldquo;{query}&rdquo;
              </div>
            ) : (
              Object.entries(grouped).map(([group, items]) => (
                <div key={group} className="mb-2">
                  <div
                    className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider"
                    style={{ color: "var(--section-heading)" }}
                  >
                    {group}
                  </div>
                  {items.map((item) => {
                    const idx = results.indexOf(item);
                    const active = idx === activeIdx;
                    return (
                      <button
                        key={item.href + item.label}
                        onMouseEnter={() => setActiveIdx(idx)}
                        onClick={() => go(item.href)}
                        className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors"
                        style={{
                          background: active ? "var(--accent)" : "transparent",
                          color: "var(--panel-text)",
                          border: active
                            ? "1px solid var(--border)"
                            : "1px solid transparent",
                        }}
                      >
                        <span style={{ color: "var(--section-heading)" }}>{item.icon}</span>
                        <span className="flex-1">{item.label}</span>
                        {item.hint && (
                          <span
                            className="rounded-full px-2 py-0.5 text-[10px] font-semibold"
                            style={{
                              background: "rgba(212,106,94,0.18)",
                              color: "var(--crit-red)",
                            }}
                          >
                            {item.hint}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </div>

          <div
            className="flex items-center justify-between border-t px-4 py-2 text-[11px]"
            style={{ borderColor: "var(--divider)", color: "var(--panel-text-muted)" }}
          >
            <div className="flex items-center gap-3">
              <span>↑↓ navigate</span>
              <span>↵ open</span>
            </div>
            <span>Powered by Command Palette</span>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
