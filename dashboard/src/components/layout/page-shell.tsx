"use client";

import { Suspense } from "react";
import { DrillDown, type DrillSection } from "./drill-down";

export function PageShell({
  drillTitle,
  sections,
  children,
  drillFooter,
  drillHeader,
}: {
  drillTitle: string;
  sections: DrillSection[];
  children: React.ReactNode;
  drillFooter?: React.ReactNode;
  drillHeader?: React.ReactNode;
}) {
  return (
    <div className="flex">
      <Suspense fallback={null}>
        <DrillDown title={drillTitle} sections={sections} footerSlot={drillFooter} headerSlot={drillHeader} />
      </Suspense>
      <main className="flex-1 px-6 py-6">
        <Suspense fallback={null}>{children}</Suspense>
      </main>
    </div>
  );
}
