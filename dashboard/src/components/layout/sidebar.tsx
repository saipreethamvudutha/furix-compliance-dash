"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import {
  LayoutGrid,
  Radar,
  Database,
  Gauge,
  Layers,
  CircuitBoard,
  Waves,
  Settings,
  HelpCircle,
  AlertTriangle,
  Network,
  Activity,
  Compass,
  ShieldCheck,
  FileInput,
  Plug,
  FileCheck2,
  ScrollText,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useRole } from "@/lib/rbac/context";
import type { RoleId } from "@/lib/rbac/permissions";

type NavItem = { label: string; href: string; icon: typeof LayoutGrid };

const NAV: Record<string, NavItem> = {
  overview:  { label: "Overview",     href: "/",                icon: LayoutGrid },
  discovery: { label: "Discovery",    href: "/discovery",       icon: Compass },
  scans:     { label: "Scans",        href: "/scans",           icon: Radar },
  ingest:    { label: "Ingest",       href: "/ingest",          icon: FileInput },
  connectors:{ label: "Connectors",   href: "/connectors",      icon: Plug },
  compliance:{ label: "Compliance",   href: "/compliance", icon: ShieldCheck },
  audit:     { label: "Audit",        href: "/audit",           icon: FileCheck2 },
  evidenceAccess: { label: "Evidence Log", href: "/evidence-access", icon: ScrollText },
  alerts:    { label: "Alerts",       href: "/alerts",          icon: AlertTriangle },
  assets:    { label: "Assets",       href: "/assets",          icon: Database },
  risks:     { label: "Risks",        href: "/risk-scoring",    icon: Gauge },
  graph:     { label: "Graph",        href: "/knowledge-graph", icon: Network },
  reports:   { label: "Reports",      href: "/reports",         icon: Layers },
  ai:        { label: "AI Operations",href: "/ai-actions",      icon: CircuitBoard },
  siem:      { label: "SIEM",         href: "/siem",            icon: Waves },
  health:    { label: "Health",       href: "/system-health",   icon: Activity },
  settings:  { label: "Settings",     href: "/settings",        icon: Settings },
};

const ROLE_NAV: Record<RoleId, string[]> = {
  // Flow: Overview → Discovery → Scans → Ingest → Compliance → Assets → then
  // Risks / Alerts / SIEM / AI / Graph / Reports / Health / Settings
  admin:   ["overview", "discovery", "scans", "ingest", "connectors", "compliance", "audit", "evidenceAccess", "assets", "risks", "alerts", "siem", "ai", "graph", "reports", "health", "settings"],
  analyst: ["overview",              "scans", "ingest", "connectors", "compliance",          "assets", "risks", "alerts", "siem", "ai", "graph",            "health"],
  auditor: ["overview",                       "ingest", "connectors", "compliance", "audit", "evidenceAccess", "assets", "risks",                                  "reports"],
  mssp:    ["overview", "discovery", "scans", "ingest", "connectors", "compliance", "audit", "assets", "risks", "alerts", "siem",               "reports", "health", "settings"],
};

/**
 * The drill-down panel uses the same teal gradient as the active tab,
 * and the active tab extends 14px to the right (over the seam) so they
 * read as one continuous molded folder-tab shape.
 */
export const ACTIVE_TAB_BG =
  "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)";

export function Sidebar() {
  const pathname = usePathname();
  const { activeRole } = useRole();
  const mainNav = ROLE_NAV[activeRole].map((k) => NAV[k]);

  return (
    <aside
      className="fixed left-0 top-0 z-40 flex h-screen w-[92px] flex-col items-center py-4"
      style={{
        background:
          "linear-gradient(180deg, var(--sidebar-grad-top) 0%, var(--sidebar-grad-bot) 100%)",
        boxShadow:
          "inset -1px 0 0 rgba(255,255,255,0.04), 4px 0 18px var(--sidebar-shadow-r)",
      }}
    >
      {/* Platform emblem — Furix logo */}
      {/* Platform emblem — Furix logo */}
<Link
  href="/"
  aria-label="Furix Home"
  className="mb-1 flex h-16 w-16 items-center justify-center self-center"
>
  <Image
    src="/furix-logo-new.png"
    alt="Furix"
    width={80}
    height={80}
    priority
    className="furix-logo object-contain"
    style={{ filter: "hue-rotate(25deg) saturate(0.7) brightness(0.95) sepia(0.3)" }}
  />
</Link>

      <nav
        className="flex flex-1 flex-col items-stretch gap-1.5 self-stretch overflow-y-auto px-2 [&::-webkit-scrollbar]:hidden"
        style={{ scrollbarWidth: "none", msOverflowStyle: "none" }}
      >
        {mainNav.map((item) => {
          const isActive =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className="group relative flex flex-col items-center gap-1 py-2"
              style={
                isActive
                  ? {
                      /* same footprint as the non-active tabs â€” stays
                         inside the sidebar, just differentiated by the
                         copper icon and a brighter outline. */
                      borderRadius: 14,
                      background: ACTIVE_TAB_BG,
                      border: "1px solid rgba(224,160,99,0.35)",
                      boxShadow:
                        "inset 0 1px 0 rgba(255,224,180,0.15), inset 0 -2px 4px rgba(0,0,0,0.35), 0 4px 10px rgba(0,0,0,0.25)",
                    }
                  : {
                      /* non-active: small recessed pill with subtle outline */
                      borderRadius: 14,
                      background:
                        "linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.15))",
                      border: "1px solid rgba(255,255,255,0.04)",
                      boxShadow:
                        "inset 0 1px 0 rgba(255,255,255,0.04), inset 0 -1px 0 rgba(0,0,0,0.25)",
                    }
              }
            >
              <span
                className="flex h-9 w-9 items-center justify-center rounded-xl"
                style={
                  isActive
                    ? {
                        background:
                          "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 75%)",
                        boxShadow:
                          "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.55), 0 0 12px rgba(224,160,99,0.25)",
                        color: "var(--disc-text)",
                      }
                    : {
                        background:
                          "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
                        boxShadow:
                          "inset 0 1px 0 rgba(255,255,255,0.07), inset 0 -2px 4px rgba(0,0,0,0.35)",
                        color: "var(--tile-text)",
                        border: "1px solid rgba(255,255,255,0.05)",
                      }
                }
              >
                <Icon className="h-[18px] w-[18px]" strokeWidth={1.7} />
              </span>
              <span
                className="text-[10px] tracking-wide"
                style={{
                  color: isActive
                    ? "var(--section-heading)"
                    : "var(--tile-text-accent)",
                }}
              >
                {item.label.toLowerCase()}
              </span>
            </Link>
          );
        })}
      </nav>

      <Link
        href="/help"
        className="mt-4 flex h-10 w-10 items-center justify-center rounded-full"
        style={{
          background: "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.07), inset 0 -2px 4px rgba(0,0,0,0.35)",
          color: "var(--tile-text)",
          border: "1px solid var(--tile-border)",
        }}
        aria-label="Help"
      >
        <HelpCircle className="h-5 w-5" strokeWidth={1.7} />
      </Link>
    </aside>
  );
}
