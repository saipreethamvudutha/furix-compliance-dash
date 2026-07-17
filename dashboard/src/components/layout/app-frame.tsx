"use client";

import { usePathname, useRouter } from "next/navigation";
import { Suspense, useEffect } from "react";
import { Sidebar } from "@/components/layout/sidebar";
import { TopBar } from "@/components/layout/top-bar";
import { RoleProvider } from "@/lib/rbac/context";

const PUBLIC_PATHS = ["/login"];

export function AppFrame({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isPublic = PUBLIC_PATHS.includes(pathname);

  useEffect(() => {
    if (isPublic) return;
    try {
      const ok = localStorage.getItem("byoc-auth") === "1";
      if (!ok) router.replace("/login");
    } catch {}
  }, [isPublic, pathname, router]);

  if (isPublic) {
    return <Suspense fallback={null}>{children}</Suspense>;
  }

  return (
    <RoleProvider>
      <Sidebar />
      <div className="ml-[92px] min-h-screen">
        <TopBar />
        <Suspense fallback={null}>{children}</Suspense>
      </div>
    </RoleProvider>
  );
}
