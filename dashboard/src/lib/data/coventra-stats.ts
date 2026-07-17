// ============================================================
// Aggregate statistics derived from the Coventra Health Insurance
// asset fleet — used across all BYOC modules so the platform
// reflects one consistent dataset.
// ============================================================

import { getAssets } from "./assets";
import type { Asset } from "./types";

export type CoventraStats = {
  total: number;
  byStatus: { healthy: number; warning: number; critical: number };
  byType: Record<Asset["type"], number>;
  byDeployment: { onPrem: number; cloud: number };
  byZone: { userLan: number; serverVlan: number; dmz: number; vendor: number; cloud: number; network: number };
  vulns: { critical: number; high: number; medium: number; low: number; total: number };
  riskScore: number;            // 0–100, lower = riskier
  complianceScore: number;      // 0–100
  patchCurrency: number;        // 0–100
  topRiskAssets: Asset[];
  criticalAssets: number;
  activeScans: number;
  scheduledScans: number;
  openAlerts: number;
  evidenceItems: number;
};

let _cached: CoventraStats | null = null;
export function _peekCached() { return _cached; }

export async function getCoventraStats(): Promise<CoventraStats> {
  if (_cached) return _cached;
  const assets = await getAssets();

  const byStatus = { healthy: 0, warning: 0, critical: 0 };
  const byType: Record<Asset["type"], number> = {
    server: 0, workstation: 0, network: 0, iot: 0, cloud: 0, unknown: 0,
  };
  const byDeployment = { onPrem: 0, cloud: 0 };
  const byZone = { userLan: 0, serverVlan: 0, dmz: 0, vendor: 0, cloud: 0, network: 0 };
  const vulns = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };

  for (const a of assets) {
    if (a.status === "healthy" || a.status === "warning" || a.status === "critical") {
      byStatus[a.status]++;
    }
    byType[a.type]++;
    if (a.deployment === "cloud") byDeployment.cloud++; else byDeployment.onPrem++;

    if (a.name.startsWith("wks-")) byZone.userLan++;
    else if (a.name.startsWith("db-")) byZone.serverVlan++;
    else if (a.name.startsWith("srv-")) byZone.serverVlan++;
    else if (a.name.startsWith("dmz-")) byZone.dmz++;
    else if (a.name.startsWith("ven-")) byZone.vendor++;
    else if (a.name.startsWith("aws-") || a.name.startsWith("az-")) byZone.cloud++;
    else if (a.name.startsWith("net-")) byZone.network++;

    vulns.critical += a.vulnerabilities.critical;
    vulns.high     += a.vulnerabilities.high;
    vulns.medium   += a.vulnerabilities.medium;
    vulns.low      += a.vulnerabilities.low;
  }
  vulns.total = vulns.critical + vulns.high + vulns.medium + vulns.low;

  const avgHealth = assets.reduce((s, a) => s + a.healthScore, 0) / Math.max(1, assets.length);
  const riskScore = Math.round(avgHealth);

  // Higher = better; compliance computed from healthy share + frameworks coverage
  const frameworksTracked = new Set<string>();
  assets.forEach((a) => a.complianceFrameworks.forEach((f) => frameworksTracked.add(f)));
  const complianceScore = Math.min(100, Math.round((byStatus.healthy / assets.length) * 80 + frameworksTracked.size * 4));

  const patchCurrency = Math.round(100 - (vulns.critical * 2 + vulns.high) / Math.max(1, assets.length) * 12);

  const topRiskAssets = [...assets]
    .sort((a, b) => {
      const sa = a.vulnerabilities.critical * 100 + a.vulnerabilities.high * 30 + a.vulnerabilities.medium * 5;
      const sb = b.vulnerabilities.critical * 100 + b.vulnerabilities.high * 30 + b.vulnerabilities.medium * 5;
      if (sb !== sa) return sb - sa;
      return a.healthScore - b.healthScore;
    })
    .slice(0, 10);

  // Activity-style metrics scaled to fleet size
  const activeScans = Math.round(assets.length / 200);
  const scheduledScans = Math.round(assets.length / 30);
  const openAlerts = Math.round(vulns.critical * 0.8 + vulns.high * 0.3);
  const evidenceItems = Math.round(assets.length * 15);

  _cached = {
    total: assets.length,
    byStatus,
    byType,
    byDeployment,
    byZone,
    vulns,
    riskScore: Math.max(0, Math.min(100, riskScore)),
    complianceScore,
    patchCurrency: Math.max(0, Math.min(100, patchCurrency)),
    topRiskAssets,
    criticalAssets: byStatus.critical,
    activeScans,
    scheduledScans,
    openAlerts,
    evidenceItems,
  };
  return _cached;
}
