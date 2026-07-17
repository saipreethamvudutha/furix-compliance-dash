"use client";

import { useEffect, useState } from "react";
import { getCoventraStats, _peekCached, type CoventraStats } from "./coventra-stats";

export function useCoventraStats() {
  const [stats, setStats] = useState<CoventraStats | null>(_peekCached());
  useEffect(() => {
    const cached = _peekCached();
    if (cached) {
      setStats(cached);
      return;
    }
    getCoventraStats().then(setStats);
  }, []);
  return stats;
}
