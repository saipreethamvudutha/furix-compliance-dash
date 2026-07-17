"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { ChevronDown, ChevronsLeft, ChevronsRight } from "lucide-react";
import { cn } from "@/lib/utils";

export type DrillItem = string | { label: string; href?: string; badge?: string };

export type DrillSection = {
  title: string;
  items: DrillItem[];
  defaultOpen?: boolean;
};

function normalizeItem(item: DrillItem): { label: string; href?: string; badge?: string } {
  return typeof item === "string" ? { label: item } : item;
}

export function DrillDown({
  title,
  sections,
  footerSlot,
  headerSlot,
}: {
  title: string;
  sections: DrillSection[];
  footerSlot?: React.ReactNode;
  headerSlot?: React.ReactNode;
}) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const currentUrl = searchParams.toString()
    ? `${pathname}?${searchParams.toString()}`
    : pathname;
  const [collapsed, setCollapsed] = useState(false);
  const [open, setOpen] = useState<Record<string, boolean>>(
    Object.fromEntries(sections.map((s) => [s.title, s.defaultOpen ?? true]))
  );

  return (
    <aside
      className="sticky z-20 shrink-0 self-start transition-[width] duration-200 ease-in-out"
      style={{
        top: 68,
        width: collapsed ? 28 : 240,
        height: "calc(100vh - 68px)",
      }}
    >
      <div
        className="relative h-full w-full"
        style={{
          background:
            "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.05), inset 0 -2px 6px rgba(0,0,0,0.4)",
        }}
      >
        {/* Collapse / expand handle — sits half-overlapping the right edge.
            Only shown when expanded; when collapsed, the entire rail is the toggle. */}
        {!collapsed && (
          <button
            type="button"
            aria-label="Collapse inner sidebar"
            onClick={() => setCollapsed(true)}
            className="absolute top-5 z-20 flex h-7 w-7 items-center justify-center rounded-full transition-all duration-200 hover:scale-110"
            style={{
              right: -14,
              background:
                "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
              color: "var(--disc-text)",
              boxShadow:
                "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5), 0 4px 10px rgba(0,0,0,0.35)",
              border: "1px solid rgba(224,160,99,0.4)",
            }}
          >
            <ChevronsLeft className="h-4 w-4" strokeWidth={2.2} />
          </button>
        )}

        {collapsed ? (
          <button
            type="button"
            aria-label="Expand inner sidebar"
            onClick={() => setCollapsed(false)}
            className="group flex h-full w-full cursor-pointer items-center justify-center transition-colors hover:bg-white/[0.04]"
          >
            <span
              className="origin-center -rotate-90 whitespace-nowrap text-[11px] font-semibold uppercase tracking-[0.25em] transition-colors group-hover:text-copper"
              style={{ color: "var(--section-heading)" }}
            >
              {title}
            </span>
            <ChevronsRight
              className="absolute top-5 h-4 w-4 opacity-60 transition-opacity group-hover:opacity-100"
              strokeWidth={2.2}
              style={{ color: "var(--section-heading)" }}
            />
          </button>
        ) : (
          <div
            className="h-full overflow-y-auto overflow-x-hidden px-5 py-6 [&::-webkit-scrollbar]:hidden"
            style={{ scrollbarWidth: "none", msOverflowStyle: "none" }}
          >
          <h2
            className="mb-5 text-[18px] font-semibold tracking-wide"
            style={{
              color: "var(--panel-text)",
              textShadow: "0 1px 0 rgba(255,224,180,0.15)",
            }}
          >
            {title}
          </h2>

          {headerSlot && (
            <div
              className="mb-5 pb-5 border-b"
              style={{ borderColor: "rgba(224,160,99,0.18)" }}
            >
              {headerSlot}
            </div>
          )}

          <div className="space-y-4">
            {sections.map((section) => (
              <div key={section.title}>
                <button
                  onClick={() =>
                    setOpen((o) => ({ ...o, [section.title]: !o[section.title] }))
                  }
                  className="flex w-full items-center gap-2 rounded-md py-1.5 transition-colors hover:bg-white/[0.03]"
                  style={{ color: "var(--section-heading)" }}
                >
                  <ChevronDown
                    className={cn(
                      "h-4 w-4 transition-transform duration-200",
                      !open[section.title] && "-rotate-90"
                    )}
                    strokeWidth={2}
                    style={{ color: "var(--section-subtext)" }}
                  />
                  <span
                    className="text-[15px] font-medium"
                    style={{ color: "var(--section-heading)" }}
                  >
                    {section.title}
                  </span>
                  <span
                    className="ml-auto rounded-full px-1.5 text-[10px] font-semibold"
                    style={{
                      background: "rgba(224,160,99,0.12)",
                      color: "var(--section-heading)",
                    }}
                  >
                    {section.items.length}
                  </span>
                </button>

                <div
                  className="overflow-hidden transition-[max-height,opacity] duration-200 ease-in-out"
                  style={{
                    maxHeight: open[section.title] ? section.items.length * 36 + 8 : 0,
                    opacity: open[section.title] ? 1 : 0,
                  }}
                >
                  <ul className="relative ml-2 mt-1 pl-4">
                    {section.items.map((raw, idx) => {
                      const it = normalizeItem(raw);
                      const isLast = idx === section.items.length - 1;
                      const isActive = it.href ? currentUrl === it.href : false;

                      const content = (
                        <span className="flex items-center justify-between gap-2">
                          <span className="truncate">{it.label}</span>
                          {it.badge && (
                            <span
                              className="rounded-full px-1.5 py-0.5 text-[9px] font-bold uppercase"
                              style={{
                                background: "var(--badge-wait-bg)",
                                color: "var(--badge-wait-fg)",
                              }}
                            >
                              {it.badge}
                            </span>
                          )}
                        </span>
                      );

                      const baseStyle: React.CSSProperties = {
                        color: isActive ? "var(--section-heading)" : "var(--section-subtext)",
                        background: isActive
                          ? "linear-gradient(270deg, rgba(224,160,99,0.28) 0%, rgba(224,160,99,0.08) 40%, rgba(224,160,99,0) 70%)"
                          : "transparent",
                        borderRight: isActive
                          ? "2px solid var(--copper-bright)"
                          : "2px solid transparent",
                        borderLeft: "2px solid transparent",
                        boxShadow: isActive
                          ? "inset -8px 0 12px -8px rgba(224,160,99,0.35)"
                          : "none",
                        fontWeight: isActive ? 600 : 500,
                      };

                      return (
                        <li
                          key={`${it.label}-${idx}`}
                          className="relative my-0.5 cursor-pointer rounded-md px-2 py-1.5 text-[13px] leading-snug transition-colors hover:bg-white/[0.04] hover:text-copper"
                          style={baseStyle}
                        >
                          {/* L-bracket connector */}
                          <span
                            aria-hidden
                            className="pointer-events-none absolute"
                            style={{
                              left: -8,
                              top: 0,
                              width: 12,
                              height: "50%",
                              borderLeft: "1px solid var(--tree-line)",
                              borderBottom: "1px solid var(--tree-line)",
                              borderBottomLeftRadius: 8,
                              filter: "drop-shadow(0 0 2px rgba(111,214,196,0.35))",
                            }}
                          />
                          {!isLast && (
                            <span
                              aria-hidden
                              className="pointer-events-none absolute"
                              style={{
                                left: -8,
                                top: "50%",
                                width: 1,
                                bottom: -6,
                                background: "var(--tree-line)",
                                filter: "drop-shadow(0 0 2px rgba(111,214,196,0.3))",
                              }}
                            />
                          )}
                          {it.href ? (
                            <Link href={it.href} className="block">
                              {content}
                            </Link>
                          ) : (
                            content
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              </div>
            ))}
          </div>
          {footerSlot && (
            <div
              className="mt-6 border-t pt-4"
              style={{ borderColor: "rgba(224,160,99,0.18)" }}
            >
              {footerSlot}
            </div>
          )}
        </div>
      )}
      </div>
    </aside>
  );
}
