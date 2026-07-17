"use client";

import { PageShell } from "@/components/layout/page-shell";

export default function HelpPage() {
  const topics = [
    "Getting Started",
    "Running your first scan",
    "Understanding CVSS scores",
    "Configuring SSO",
    "Connecting cloud accounts",
    "Approving AI remediation",
    "Exporting reports",
    "API tokens & rate limits",
  ];
  return (
    <PageShell
      drillTitle="Help Cluster"
      sections={[
        {
          title: "Guides",
          defaultOpen: true,
          items: topics.slice(0, 4).map((t) => ({ label: t, href: "/help" })),
        },
        {
          title: "References",
          defaultOpen: true,
          items: topics.slice(4).map((t) => ({ label: t, href: "/help" })),
        },
        {
          title: "Other Modules",
          defaultOpen: false,
          items: [
            { label: "Settings", href: "/settings" },
            { label: "Billing", href: "/billing" },
            { label: "Compliance", href: "/compliance" },
          ],
        },
      ]}
    >
      <div className="skeuo-panel p-6">
        <h3 className="mb-3 text-[18px] font-semibold" style={{ color: "var(--panel-text)" }}>
          Help & Documentation
        </h3>
        <p className="mb-5 text-[13px]" style={{ color: "var(--panel-text-muted)" }}>
          Browse guides, references, and API documentation for the BYOC platform.
        </p>
        <div className="grid grid-cols-2 gap-3">
          {topics.map((t) => (
            <div
              key={t}
              className="skeuo-inset px-4 py-3 text-[13px] cursor-pointer"
              style={{ color: "var(--panel-text)" }}
            >
              {t}
            </div>
          ))}
        </div>
      </div>
    </PageShell>
  );
}
