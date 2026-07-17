"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { vulnViews, commonViews } from "@/lib/mock/views";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...vulnViews,
  "asset-vuln": commonViews["asset-vuln"],
  "top-risks": commonViews["top-risks"],
  "patches": commonViews["ai-remediation"],
  "alerts": commonViews["alert-summary"],
  "compliance-map": commonViews["compliance-map"],
  "reports": commonViews["reports-summary"],
  "improvement": commonViews.improvement,
};

const sections = [
  {
    title: "Vulnerabilities",
    defaultOpen: true,
    items: [
      { label: "Critical", href: "/vulnerabilities?view=critical", badge: "7" },
      { label: "High", href: "/vulnerabilities?view=high", badge: "23" },
      { label: "Medium", href: "/vulnerabilities?view=medium", badge: "41" },
      { label: "Low", href: "/vulnerabilities?view=low", badge: "88" },
      { label: "Fixed", href: "/vulnerabilities?view=fixed" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Asset Vulnerability Drill-down", href: "/vulnerabilities?view=asset-vuln" },
      { label: "Top Risk Reports", href: "/vulnerabilities?view=top-risks" },
      { label: "Patch Proposals", href: "/vulnerabilities?view=patches", badge: "AI" },
      { label: "Alert Stream", href: "/vulnerabilities?view=alerts" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Compliance Gaps", href: "/vulnerabilities?view=compliance-map" },
      { label: "Reports", href: "/vulnerabilities?view=reports" },
      { label: "Security Improvement", href: "/vulnerabilities?view=improvement" },
    ],
  },
];

export default function VulnerabilitiesPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "critical";
  const block = localViews[view as keyof typeof localViews] ?? localViews.critical;

  return (
    <PageShell drillTitle="Vulnerability Cluster" sections={sections}>
      <ViewBlockView block={block} />
    </PageShell>
  );
}
