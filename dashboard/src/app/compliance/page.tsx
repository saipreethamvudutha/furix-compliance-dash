"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { complianceViews, commonViews } from "@/lib/mock/views";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...complianceViews,
  "asset-vuln": commonViews["asset-vuln"],
  "top-risks": commonViews["top-risks"],
  "compliance-map": commonViews["compliance-map"],
  "evidence": commonViews["reports-summary"],
  "improvement": commonViews.improvement,
  "ai-remediation": commonViews["ai-remediation"],
  "alerts": commonViews["alert-summary"],
};

const sections = [
  {
    title: "Frameworks",
    defaultOpen: true,
    items: [
      { label: "HIPAA", href: "/compliance?view=hipaa", badge: "94%" },
      { label: "SOC 2", href: "/compliance?view=soc2", badge: "88%" },
      { label: "ISO 27001", href: "/compliance?view=iso27001", badge: "91%" },
      { label: "PCI-DSS", href: "/compliance?view=pci", badge: "82%" },
      { label: "NIST CSF", href: "/compliance?view=nist", badge: "76%" },
      { label: "GDPR", href: "/compliance?view=gdpr", badge: "89%" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Control Coverage Map", href: "/compliance?view=compliance-map" },
      { label: "Evidence Drill-down", href: "/compliance?view=evidence" },
      { label: "Top Risk Reports", href: "/compliance?view=top-risks" },
      { label: "Security Improvement Analysis", href: "/compliance?view=improvement" },
    ],
  },
  {
    title: "Related",
    defaultOpen: false,
    items: [
      { label: "Asset Vulnerabilities", href: "/compliance?view=asset-vuln" },
      { label: "AI Remediation", href: "/compliance?view=ai-remediation" },
      { label: "Alert Summary", href: "/compliance?view=alerts" },
    ],
  },
];

export default function CompliancePage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "hipaa";
  const block = localViews[view as keyof typeof localViews] ?? localViews.hipaa;

  return (
    <PageShell drillTitle="Compliance Cluster" sections={sections}>
      <ViewBlockView block={block} />
    </PageShell>
  );
}
