"use client";

import { useEffect, useState } from "react";
import { getCoventraStats, _peekCached, type CoventraStats } from "./coventra-stats";

export function useCoventraStats() {
  const [stats, setStats] = useState<CoventraStats | null>(_peekCached());
  useEffect(() => {
    const cached = _peekCached();
    if (cached) {
      // client-only cache hydration on mount
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setStats(cached);
      return;
    }
    getCoventraStats().then(setStats);
  }, []);
  return stats;
}
