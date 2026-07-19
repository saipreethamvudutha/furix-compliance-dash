"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// The live and mock compliance views were unified into one domain (FUR-UX-001).
// This route now redirects to /compliance, which shows LIVE / DEGRADED / DEMO
// data with an explicit mode badge — no more separate "live" URL to confuse
// with the seed view.
export default function LiveComplianceRedirect() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/compliance");
  }, [router]);
  return null;
}
