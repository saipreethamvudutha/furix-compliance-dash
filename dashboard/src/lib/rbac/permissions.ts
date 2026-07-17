export type RoleId = "admin" | "analyst" | "auditor" | "mssp";

/* ────────────────────────────────────────────────────────────
 * 3-TIER RBAC MODEL (production-grade)
 *   Tier 1 — Identity:    WHO  (Role)
 *   Tier 2 — Capability:  WHAT (read / write / destructive action)
 *   Tier 3 — Resource:    WHERE (data sensitivity, deployment, framework, tenant)
 *
 * A permission check is granted only if all three tiers allow it:
 *   role grants capability  AND  scope includes resource  AND
 *   tier ≥ required tier  (destructive needs JIT-elevation)
 * ──────────────────────────────────────────────────────────── */

export type Tier = "read" | "write" | "admin";

export type DataSensitivity = "public" | "internal" | "confidential" | "restricted";
export type Deployment = "on-prem" | "cloud" | "hybrid";
export type Framework = "HIPAA" | "SOC2" | "PCI-DSS" | "ISO27001" | "NIST" | "CIS";

export type ResourceScope = {
  sensitivities: DataSensitivity[];   // which classes the role can touch
  deployments: Deployment[];           // on-prem / cloud / both
  frameworks: Framework[];             // which compliance scopes
  tenants: string[];                   // "*" = all, else specific tenant ids
};

export type RoleTierConfig = {
  baseTier: Tier;                      // default tier the role operates at
  maxTier: Tier;                       // ceiling — JIT elevation cannot exceed
  jitMinutes: number;                  // how long destructive elevation lasts
  requireDualApproval: boolean;        // 2-person rule for destructive actions
  ipBindings: string[];                // CIDR subnets the role may sign in from
};

export const DEFAULT_SCOPE: Record<RoleId, ResourceScope> = {
  admin: {
    sensitivities: ["public", "internal", "confidential", "restricted"],
    deployments: ["on-prem", "cloud", "hybrid"],
    frameworks: ["HIPAA", "SOC2", "PCI-DSS", "ISO27001", "NIST", "CIS"],
    tenants: ["*"],
  },
  analyst: {
    sensitivities: ["public", "internal", "confidential"],
    deployments: ["on-prem", "cloud", "hybrid"],
    frameworks: ["HIPAA", "SOC2"],
    tenants: ["coventra"],
  },
  auditor: {
    sensitivities: ["public", "internal", "confidential", "restricted"],
    deployments: ["on-prem", "cloud", "hybrid"],
    frameworks: ["HIPAA", "SOC2", "PCI-DSS", "ISO27001", "NIST", "CIS"],
    tenants: ["coventra"],
  },
  mssp: {
    sensitivities: ["public", "internal", "confidential"],
    deployments: ["on-prem", "cloud", "hybrid"],
    frameworks: ["HIPAA", "SOC2"],
    tenants: ["*"],
  },
};

export const DEFAULT_TIER: Record<RoleId, RoleTierConfig> = {
  admin:   { baseTier: "admin", maxTier: "admin", jitMinutes: 30, requireDualApproval: true,  ipBindings: ["10.10.5.0/24"] },
  analyst: { baseTier: "write", maxTier: "write", jitMinutes: 15, requireDualApproval: false, ipBindings: ["10.10.5.0/24", "10.10.4.0/24"] },
  auditor: { baseTier: "read",  maxTier: "read",  jitMinutes: 0,  requireDualApproval: false, ipBindings: ["10.10.6.0/24"] },
  mssp:    { baseTier: "write", maxTier: "admin", jitMinutes: 20, requireDualApproval: true,  ipBindings: [] },
};

const TIER_RANK: Record<Tier, number> = { read: 1, write: 2, admin: 3 };
const KIND_TO_TIER: Record<"read" | "write" | "destructive", Tier> = {
  read: "read", write: "write", destructive: "admin",
};

export type EffectiveContext = {
  sensitivity?: DataSensitivity;
  deployment?: Deployment;
  framework?: Framework;
  tenant?: string;
  jitActive?: boolean;
};

export type EffectiveResult = {
  allowed: boolean;
  reason: string;
  failedTier?: 1 | 2 | 3;
};

export function evaluatePermission(
  role: RoleId,
  capId: string,
  matrix: Record<RoleId, Record<string, boolean>>,
  scope: ResourceScope,
  tierCfg: RoleTierConfig,
  ctx: EffectiveContext = {}
): EffectiveResult {
  // Tier 1 — Identity / Capability grant
  if (!matrix[role]?.[capId]) {
    return { allowed: false, reason: `Role does not have capability '${capId}'`, failedTier: 1 };
  }

  const cap = findCap(capId)?.cap;
  if (!cap) return { allowed: false, reason: "Capability not found", failedTier: 1 };

  // Tier 2 — Capability tier vs. role tier ceiling
  const requiredTier = KIND_TO_TIER[cap.kind];
  const effectiveCeiling = ctx.jitActive ? tierCfg.maxTier : tierCfg.baseTier;
  if (TIER_RANK[requiredTier] > TIER_RANK[effectiveCeiling]) {
    return {
      allowed: false,
      reason: `Capability requires tier '${requiredTier}' but role is at '${effectiveCeiling}' — JIT elevation needed`,
      failedTier: 2,
    };
  }

  // Tier 3 — Resource scope
  if (ctx.sensitivity && !scope.sensitivities.includes(ctx.sensitivity)) {
    return { allowed: false, reason: `Sensitivity '${ctx.sensitivity}' is outside role scope`, failedTier: 3 };
  }
  if (ctx.deployment && !scope.deployments.includes(ctx.deployment)) {
    return { allowed: false, reason: `Deployment '${ctx.deployment}' is outside role scope`, failedTier: 3 };
  }
  if (ctx.framework && !scope.frameworks.includes(ctx.framework)) {
    return { allowed: false, reason: `Framework '${ctx.framework}' is outside role scope`, failedTier: 3 };
  }
  if (ctx.tenant && !scope.tenants.includes("*") && !scope.tenants.includes(ctx.tenant)) {
    return { allowed: false, reason: `Tenant '${ctx.tenant}' is outside role scope`, failedTier: 3 };
  }

  return { allowed: true, reason: "All 3 tiers passed" };
}

export type Role = {
  id: RoleId;
  label: string;
  blurb: string;
  scope: string;
  members: number;
  accent: "copper" | "teal" | "amber" | "violet";
};

export const ROLES: Record<RoleId, Role> = {
  admin: {
    id: "admin",
    label: "Administrator",
    blurb: "Owns the appliance — full platform control",
    scope: "Global",
    members: 4,
    accent: "copper",
  },
  analyst: {
    id: "analyst",
    label: "Security Analyst",
    blurb: "Triage alerts, run scans, drive response",
    scope: "Operations",
    members: 18,
    accent: "teal",
  },
  auditor: {
    id: "auditor",
    label: "Compliance Auditor",
    blurb: "Read-only — evidence, chain-of-custody, reports",
    scope: "Read-only",
    members: 6,
    accent: "amber",
  },
  mssp: {
    id: "mssp",
    label: "MSSP Operator",
    blurb: "Cross-tenant fleet ops — manage client estates",
    scope: "Multi-tenant",
    members: 11,
    accent: "violet",
  },
};

export type CapabilityKind = "read" | "write" | "destructive";

export type Capability = {
  id: string;
  label: string;
  kind: CapabilityKind;
  hint?: string;
};

export type Domain = {
  id: string;
  label: string;
  tag: string;
  caps: Capability[];
};

export const DOMAINS: Domain[] = [
  {
    id: "detection",
    label: "Detection",
    tag: "DET",
    caps: [
      { id: "detection.alerts.view",   label: "View Alerts",        kind: "read" },
      { id: "detection.alerts.triage", label: "Triage & Assign",    kind: "write" },
      { id: "detection.rules.edit",    label: "Edit Detection Rules", kind: "write" },
      { id: "detection.rules.publish", label: "Publish Rules",      kind: "destructive", hint: "Pushes to live SIEM" },
    ],
  },
  {
    id: "response",
    label: "Response",
    tag: "RSP",
    caps: [
      { id: "response.scans.run",      label: "Run Scans",          kind: "write" },
      { id: "response.scans.cancel",   label: "Cancel Scans",       kind: "write" },
      { id: "response.ai.execute",     label: "Execute AI Actions", kind: "destructive", hint: "Auto-remediation" },
      { id: "response.isolate.host",   label: "Isolate Host",       kind: "destructive", hint: "Network quarantine" },
    ],
  },
  {
    id: "data",
    label: "Data Plane",
    tag: "DAT",
    caps: [
      { id: "data.assets.view",        label: "View Assets",        kind: "read" },
      { id: "data.assets.edit",        label: "Edit Assets",        kind: "write" },
      { id: "data.assets.delete",      label: "Delete Assets",      kind: "destructive" },
      { id: "data.siem.query",         label: "Query Streams",      kind: "read" },
      { id: "data.siem.export",        label: "Export Raw Logs",    kind: "write" },
    ],
  },
  {
    id: "compliance",
    label: "Compliance",
    tag: "CMP",
    caps: [
      { id: "compliance.reports.view",   label: "View Reports",       kind: "read" },
      { id: "compliance.reports.export", label: "Export Evidence",    kind: "write" },
      { id: "compliance.audit.chain",    label: "Audit Hash Chain",   kind: "read" },
      { id: "compliance.attest",         label: "Sign Attestations",  kind: "destructive", hint: "Legally binding" },
    ],
  },
  {
    id: "admin",
    label: "Administration",
    tag: "ADM",
    caps: [
      { id: "admin.users.manage",      label: "Manage Users",       kind: "write" },
      { id: "admin.roles.edit",        label: "Edit Roles",         kind: "destructive", hint: "Changes RBAC matrix" },
      { id: "admin.license",           label: "License & Appliance", kind: "write" },
      { id: "admin.backup",            label: "Backup & Restore",   kind: "destructive" },
      { id: "admin.integrations",      label: "Integrations",       kind: "write" },
    ],
  },
  {
    id: "mssp",
    label: "MSSP Fleet",
    tag: "MSP",
    caps: [
      { id: "mssp.tenants.view",       label: "View Tenants",       kind: "read" },
      { id: "mssp.tenants.switch",     label: "Cross-Tenant Switch", kind: "write" },
      { id: "mssp.billing",            label: "Billing Rollup",     kind: "write" },
      { id: "mssp.tenants.provision",  label: "Provision Tenant",   kind: "destructive" },
    ],
  },
];

export const ALL_CAP_IDS = DOMAINS.flatMap((d) => d.caps.map((c) => c.id));

export type PermissionMatrix = Record<RoleId, Record<string, boolean>>;

function grant(ids: string[]): Record<string, boolean> {
  return Object.fromEntries(ALL_CAP_IDS.map((id) => [id, ids.includes(id)]));
}

const READ_ONLY_IDS = DOMAINS.flatMap((d) =>
  d.caps.filter((c) => c.kind === "read").map((c) => c.id)
);

export const DEFAULT_MATRIX: PermissionMatrix = {
  admin: Object.fromEntries(ALL_CAP_IDS.map((id) => [id, true])),
  analyst: grant([
    "detection.alerts.view",
    "detection.alerts.triage",
    "detection.rules.edit",
    "response.scans.run",
    "response.scans.cancel",
    "response.ai.execute",
    "data.assets.view",
    "data.assets.edit",
    "data.siem.query",
    "data.siem.export",
    "compliance.reports.view",
  ]),
  auditor: grant([
    ...READ_ONLY_IDS,
    "compliance.reports.export",
    "compliance.attest",
  ]),
  mssp: grant([
    "detection.alerts.view",
    "detection.alerts.triage",
    "response.scans.run",
    "data.assets.view",
    "data.siem.query",
    "compliance.reports.view",
    "mssp.tenants.view",
    "mssp.tenants.switch",
    "mssp.billing",
    "mssp.tenants.provision",
  ]),
};

export const PRESETS: Record<string, (role: RoleId) => Record<string, boolean>> = {
  "Least Privilege": () => grant([]),
  "Read Only":      () => grant(READ_ONLY_IDS),
  "Standard":       (r) => ({ ...DEFAULT_MATRIX[r] }),
  "Power User":     () => Object.fromEntries(ALL_CAP_IDS.map((id) => [id, true])),
};

export function findCap(id: string): { domain: Domain; cap: Capability } | null {
  for (const d of DOMAINS) {
    const c = d.caps.find((x) => x.id === id);
    if (c) return { domain: d, cap: c };
  }
  return null;
}
