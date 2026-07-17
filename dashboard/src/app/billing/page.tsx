"use client";

import { useSearchParams } from "next/navigation";
import { PageShell } from "@/components/layout/page-shell";
import { ViewBlockView } from "@/components/layout/view-block";
import { billingViews, commonViews } from "@/lib/mock/views";

const localViews: Record<string, import("@/lib/mock/views").ViewBlock> = {
  ...billingViews,
  "help": commonViews.help,
  "improvement": commonViews.improvement,
};

const sections = [
  {
    title: "Account",
    defaultOpen: true,
    items: [
      { label: "Plan", href: "/billing?view=plan", badge: "Pro" },
      { label: "Invoices", href: "/billing?view=invoices" },
      { label: "Payment Methods", href: "/billing?view=methods" },
      { label: "Usage", href: "/billing?view=usage" },
    ],
  },
  {
    title: "Drill-down",
    defaultOpen: true,
    items: [
      { label: "Security Improvement Analysis", href: "/billing?view=improvement" },
      { label: "Help & Docs", href: "/billing?view=help" },
    ],
  },
];

export default function BillingPage() {
  const sp = useSearchParams();
  const view = sp.get("view") ?? "plan";
  const block = localViews[view as keyof typeof localViews] ?? localViews.plan;

  return (
    <PageShell drillTitle="Billing Cluster" sections={sections}>
      <ViewBlockView block={block} />
    </PageShell>
  );
}
