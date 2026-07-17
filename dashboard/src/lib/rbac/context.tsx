"use client";

import { createContext, useContext, useEffect, useMemo, useState, useCallback } from "react";
import {
  DEFAULT_MATRIX,
  ROLES,
  DEFAULT_SCOPE,
  DEFAULT_TIER,
  evaluatePermission,
  type PermissionMatrix,
  type RoleId,
  type ResourceScope,
  type RoleTierConfig,
  type EffectiveContext,
  type EffectiveResult,
} from "./permissions";

type RoleContextValue = {
  activeRole: RoleId;
  setActiveRole: (r: RoleId) => void;
  matrix: PermissionMatrix;
  setMatrix: (m: PermissionMatrix) => void;
  togglePermission: (role: RoleId, capId: string) => void;
  resetRole: (role: RoleId) => void;
  applyToRole: (role: RoleId, perms: Record<string, boolean>) => void;
  can: (capId: string, role?: RoleId) => boolean;

  // 3-tier model
  scopes: Record<RoleId, ResourceScope>;
  tiers: Record<RoleId, RoleTierConfig>;
  setScope: (role: RoleId, scope: ResourceScope) => void;
  setTierConfig: (role: RoleId, cfg: RoleTierConfig) => void;
  jitActive: boolean;
  jitExpiresAt: number | null;
  elevate: () => void;       // start JIT window
  revoke: () => void;        // end JIT early
  evaluate: (capId: string, ctx?: EffectiveContext, role?: RoleId) => EffectiveResult;
};

const RoleContext = createContext<RoleContextValue | null>(null);

const LS_ROLE = "byoc-rbac-role";
const LS_MATRIX = "byoc-rbac-matrix";
const LS_SCOPES = "byoc-rbac-scopes";
const LS_TIERS = "byoc-rbac-tiers";

export function RoleProvider({ children }: { children: React.ReactNode }) {
  const [activeRole, setActiveRoleState] = useState<RoleId>("admin");
  const [matrix, setMatrixState] = useState<PermissionMatrix>(DEFAULT_MATRIX);
  const [scopes, setScopesState] = useState<Record<RoleId, ResourceScope>>(DEFAULT_SCOPE);
  const [tiers, setTiersState] = useState<Record<RoleId, RoleTierConfig>>(DEFAULT_TIER);
  const [jitExpiresAt, setJitExpiresAt] = useState<number | null>(null);
  const [, tick] = useState(0);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    try {
      const r = localStorage.getItem(LS_ROLE) as RoleId | null;
      if (r && ROLES[r]) setActiveRoleState(r);
      const m = localStorage.getItem(LS_MATRIX);
      if (m) setMatrixState({ ...DEFAULT_MATRIX, ...JSON.parse(m) });
      const s = localStorage.getItem(LS_SCOPES);
      if (s) setScopesState({ ...DEFAULT_SCOPE, ...JSON.parse(s) });
      const t = localStorage.getItem(LS_TIERS);
      if (t) setTiersState({ ...DEFAULT_TIER, ...JSON.parse(t) });
    } catch {}
    setHydrated(true);
  }, []);

  // JIT countdown — re-render every 1s while active so UI shows time left
  useEffect(() => {
    if (!jitExpiresAt) return;
    const i = setInterval(() => {
      if (Date.now() >= jitExpiresAt) {
        setJitExpiresAt(null);
      } else {
        tick((n) => n + 1);
      }
    }, 1000);
    return () => clearInterval(i);
  }, [jitExpiresAt]);

  const setActiveRole = useCallback((r: RoleId) => {
    setActiveRoleState(r);
    try { localStorage.setItem(LS_ROLE, r); } catch {}
  }, []);

  const setMatrix = useCallback((m: PermissionMatrix) => {
    setMatrixState(m);
    try { localStorage.setItem(LS_MATRIX, JSON.stringify(m)); } catch {}
  }, []);

  const togglePermission = useCallback((role: RoleId, capId: string) => {
    setMatrixState((prev) => {
      const next = { ...prev, [role]: { ...prev[role], [capId]: !prev[role]?.[capId] } };
      try { localStorage.setItem(LS_MATRIX, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  const resetRole = useCallback((role: RoleId) => {
    setMatrixState((prev) => {
      const next = { ...prev, [role]: { ...DEFAULT_MATRIX[role] } };
      try { localStorage.setItem(LS_MATRIX, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  const applyToRole = useCallback((role: RoleId, perms: Record<string, boolean>) => {
    setMatrixState((prev) => {
      const next = { ...prev, [role]: perms };
      try { localStorage.setItem(LS_MATRIX, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  const jitActive = jitExpiresAt !== null && Date.now() < jitExpiresAt;

  const can = useCallback(
    (capId: string, role?: RoleId) => {
      const r = role ?? activeRole;
      return !!matrix[r]?.[capId];
    },
    [activeRole, matrix]
  );

  const setScope = useCallback((role: RoleId, sc: ResourceScope) => {
    setScopesState((prev) => {
      const next = { ...prev, [role]: sc };
      try { localStorage.setItem(LS_SCOPES, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  const setTierConfig = useCallback((role: RoleId, cfg: RoleTierConfig) => {
    setTiersState((prev) => {
      const next = { ...prev, [role]: cfg };
      try { localStorage.setItem(LS_TIERS, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  const elevate = useCallback(() => {
    const mins = tiers[activeRole]?.jitMinutes ?? 0;
    if (mins <= 0) return;
    setJitExpiresAt(Date.now() + mins * 60_000);
  }, [tiers, activeRole]);

  const revoke = useCallback(() => setJitExpiresAt(null), []);

  const evaluate = useCallback(
    (capId: string, ctx: EffectiveContext = {}, role?: RoleId): EffectiveResult => {
      const r = role ?? activeRole;
      return evaluatePermission(r, capId, matrix, scopes[r], tiers[r], {
        jitActive,
        ...ctx,
      });
    },
    [activeRole, matrix, scopes, tiers, jitActive]
  );

  const value = useMemo<RoleContextValue>(
    () => ({
      activeRole, setActiveRole, matrix, setMatrix, togglePermission, resetRole, applyToRole, can,
      scopes, tiers, setScope, setTierConfig,
      jitActive, jitExpiresAt, elevate, revoke, evaluate,
    }),
    [
      activeRole, setActiveRole, matrix, setMatrix, togglePermission, resetRole, applyToRole, can,
      scopes, tiers, setScope, setTierConfig, jitActive, jitExpiresAt, elevate, revoke, evaluate,
    ]
  );

  return (
    <RoleContext.Provider value={value}>
      {hydrated ? children : <div style={{ visibility: "hidden" }}>{children}</div>}
    </RoleContext.Provider>
  );
}

export function useRole() {
  const ctx = useContext(RoleContext);
  if (!ctx) throw new Error("useRole must be used within RoleProvider");
  return ctx;
}

export function useCan(capId: string, role?: RoleId) {
  return useRole().can(capId, role);
}
