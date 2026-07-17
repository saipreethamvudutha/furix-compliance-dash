"use client";

import { useRef, useState } from "react";
import {
  Shield,
  Search,
  FileCheck2,
  Network,
  Sparkles,
  RotateCcw,
  Save,
  AlertTriangle,
  Lock,
  Unlock,
  Cpu,
  Radar,
  Database,
  ClipboardCheck,
  ShieldCheck,
  Building2,
  Upload,
  CheckCircle2,
  XCircle,
  FileJson,
  FileUp,
  X,
  Download,
  Info,
} from "lucide-react";
import { useRole } from "@/lib/rbac/context";
import { TierPanel } from "./tier-panel";
import {
  DOMAINS,
  ROLES,
  PRESETS,
  DEFAULT_MATRIX,
  ALL_CAP_IDS,
  findCap,
  type RoleId,
  type CapabilityKind,
} from "@/lib/rbac/permissions";

const ROLE_ICONS: Record<RoleId, React.ReactNode> = {
  admin: <Shield className="h-4 w-4" />,
  analyst: <Search className="h-4 w-4" />,
  auditor: <FileCheck2 className="h-4 w-4" />,
  mssp: <Network className="h-4 w-4" />,
};

const DOMAIN_ICONS: Record<string, React.ReactNode> = {
  detection: <Radar className="h-4 w-4" />,
  response: <Cpu className="h-4 w-4" />,
  data: <Database className="h-4 w-4" />,
  compliance: <ClipboardCheck className="h-4 w-4" />,
  admin: <ShieldCheck className="h-4 w-4" />,
  mssp: <Building2 className="h-4 w-4" />,
};

const KIND_COLORS: Record<CapabilityKind, { lit: string; dim: string; label: string }> = {
  read:        { lit: "var(--metric-teal)",   dim: "rgba(111,214,196,0.18)", label: "READ" },
  write:       { lit: "var(--metric-copper)", dim: "rgba(224,160,99,0.18)",  label: "WRITE" },
  destructive: { lit: "var(--crit-red)",      dim: "rgba(212,106,94,0.18)",  label: "CRIT" },
};

export function PermissionsConsole() {
  const { matrix, togglePermission, resetRole, applyToRole } = useRole();
  const [selectedRole, setSelectedRole] = useState<RoleId>("admin");
  const [tab, setTab] = useState<"permissions" | "scope">("permissions");
  const [pendingDestructive, setPendingDestructive] = useState<string | null>(null);

  // ── Upload modal state ─────────────────────────────────────
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  type Preview = {
    file: string;
    sizeBytes: number;
    perRole: Record<RoleId, { grant: number; revoke: number; total: number; perms: Record<string, boolean> }>;
    unknownIds: string[];
    unknownRoles: string[];
  };
  const [preview, setPreview] = useState<Preview | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [expandedRole, setExpandedRole] = useState<RoleId | null>(null);
  const [lastApplied, setLastApplied] = useState<{ file: string; roles: RoleId[]; applied: number } | null>(null);

  const openUpload = () => {
    setPreview(null);
    setParseError(null);
    setExpandedRole(null);
    setUploadOpen(true);
  };
  const closeUpload = () => {
    setUploadOpen(false);
    setIsDragging(false);
  };

  const parseFile = async (file: File) => {
    setParseError(null);
    setPreview(null);
    try {
      const text = await file.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error("File is not valid JSON.");
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Top-level must be an object keyed by role id.");
      }
      const obj = parsed as Record<string, unknown>;
      const validRoles = Object.keys(ROLES) as RoleId[];
      const capIds = new Set(ALL_CAP_IDS);

      const perRole = {} as Preview["perRole"];
      const unknownIds = new Set<string>();
      const unknownRoles: string[] = [];

      for (const key of Object.keys(obj)) {
        if (!(validRoles as string[]).includes(key)) {
          unknownRoles.push(key);
          continue;
        }
        const role = key as RoleId;
        const entry = obj[role];
        const perms: Record<string, boolean> = {};
        let grant = 0;
        let revoke = 0;

        if (Array.isArray(entry)) {
          for (const id of entry) {
            if (typeof id === "string" && capIds.has(id)) {
              perms[id] = true;
              grant++;
            } else if (typeof id === "string") unknownIds.add(id);
          }
        } else if (entry && typeof entry === "object") {
          for (const [id, v] of Object.entries(entry as Record<string, unknown>)) {
            if (capIds.has(id) && typeof v === "boolean") {
              perms[id] = v;
              if (v) grant++; else revoke++;
            } else if (!capIds.has(id)) unknownIds.add(id);
          }
        } else {
          continue;
        }
        perRole[role] = { grant, revoke, total: grant + revoke, perms };
      }

      if (Object.keys(perRole).length === 0) {
        throw new Error("No recognized role keys (admin, analyst, auditor, mssp) found in file.");
      }

      setPreview({
        file: file.name,
        sizeBytes: file.size,
        perRole,
        unknownIds: [...unknownIds],
        unknownRoles,
      });
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "Failed to read file.");
    }
  };

  const onPickFile = (f: File | undefined) => {
    if (!f) return;
    parseFile(f);
  };

  const applyPreview = () => {
    if (!preview) return;
    const roles: RoleId[] = [];
    let total = 0;
    for (const role of Object.keys(preview.perRole) as RoleId[]) {
      applyToRole(role, preview.perRole[role].perms);
      roles.push(role);
      total += preview.perRole[role].total;
    }
    setLastApplied({ file: preview.file, roles, applied: total });
    closeUpload();
  };

  const downloadSample = () => {
    const sample = {
      admin: Object.fromEntries(ALL_CAP_IDS.slice(0, 6).map((id) => [id, true])),
      analyst: ALL_CAP_IDS.slice(0, 4),
      auditor: { [ALL_CAP_IDS[0]]: true, [ALL_CAP_IDS[1]]: false },
    };
    const blob = new Blob([JSON.stringify(sample, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "rbac-sample.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const SAMPLE_SNIPPET = `{
  "admin":   { "${ALL_CAP_IDS[0] ?? "detect.read"}": true,  "${ALL_CAP_IDS[1] ?? "detect.write"}": false },
  "analyst": ["${ALL_CAP_IDS[0] ?? "detect.read"}", "${ALL_CAP_IDS[2] ?? "data.read"}"],
  "auditor": { "${ALL_CAP_IDS[0] ?? "detect.read"}": true },
  "mssp":    []
}`;

  const rolePerms = matrix[selectedRole] ?? {};
  const totalCount = ALL_CAP_IDS.length;
  const dirty = JSON.stringify(rolePerms) !== JSON.stringify(DEFAULT_MATRIX[selectedRole]);

  const doToggle = (capId: string) => {
    const cap = findCap(capId)?.cap;
    if (!cap) return;
    const willGrant = !rolePerms[capId];
    if (cap.kind === "destructive" && willGrant) {
      setPendingDestructive(capId);
      return;
    }
    togglePermission(selectedRole, capId);
  };

  const confirmDestructive = () => {
    if (!pendingDestructive) return;
    togglePermission(selectedRole, pendingDestructive);
    setPendingDestructive(null);
  };

  return (
    <div className="space-y-4">
      {/* ─────── LAST APPLY BANNER ─────── */}
      {lastApplied && (
        <div
          className="flex items-center gap-3 rounded-xl px-3 py-2"
          style={{
            background: "linear-gradient(180deg, rgba(111,214,196,0.14), rgba(111,214,196,0.05))",
            border: "1px solid rgba(111,214,196,0.4)",
            boxShadow: "0 0 14px rgba(111,214,196,0.15)",
          }}
        >
          <CheckCircle2 className="h-4 w-4 shrink-0" style={{ color: "var(--metric-teal)" }} />
          <p className="flex-1 text-[12px]" style={{ color: "var(--panel-text)" }}>
            <strong>{lastApplied.file}</strong> applied · {lastApplied.applied} capability changes across{" "}
            {lastApplied.roles.map((r) => ROLES[r].label).join(", ")}
          </p>
          <button
            onClick={() => setLastApplied(null)}
            className="text-[11px] font-semibold"
            style={{ color: "var(--panel-text-muted)" }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* ─────── ROLE TABS + MATRIX (CONNECTED FOLDER) ─────── */}
      <div
        className="relative rounded-2xl p-3"
        style={{
          background:
            "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
          border: "1px solid rgba(224,160,99,0.45)",
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.04), inset 0 -2px 6px rgba(0,0,0,0.35), 0 0 24px rgba(224,160,99,0.15)",
        }}
      >
        {/* role tabs */}
        <div className="relative z-10 grid grid-cols-4 gap-3">
          {(Object.keys(ROLES) as RoleId[]).map((id) => {
            const r = ROLES[id];
            const active = id === selectedRole;
            const granted = Object.values(matrix[id] ?? {}).filter(Boolean).length;
            const pct = Math.round((granted / totalCount) * 100);
            return (
              <button
                key={id}
                onClick={() => setSelectedRole(id)}
                className="relative flex items-center gap-3 rounded-xl p-3 text-left transition-all"
                style={{
                  background: active
                    ? "linear-gradient(180deg, rgba(224,160,99,0.22), rgba(120,80,40,0.12))"
                    : "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
                  border: active
                    ? "1px solid rgba(224,160,99,0.7)"
                    : "1px solid var(--tile-border)",
                  boxShadow: active
                    ? "inset 0 1px 0 rgba(255,224,180,0.25), inset 0 -2px 4px rgba(0,0,0,0.35), 0 0 18px rgba(224,160,99,0.35)"
                    : "inset 0 1px 0 rgba(255,255,255,0.06), inset 0 -2px 4px rgba(0,0,0,0.3)",
                }}
              >
                <div
                  className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl"
                  style={{
                    background: active
                      ? "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 75%)"
                      : "linear-gradient(180deg, rgba(255,255,255,0.05), rgba(0,0,0,0.2))",
                    color: active ? "var(--disc-text)" : "var(--section-heading)",
                    boxShadow: active
                      ? "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)"
                      : "inset 0 1px 0 rgba(255,255,255,0.05)",
                  }}
                >
                  {ROLE_ICONS[id]}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-[13px] font-semibold truncate" style={{ color: "var(--panel-text)" }}>
                      {r.label}
                    </p>
                    <span className="font-mono text-[10.5px]" style={{ color: "var(--section-heading)" }}>
                      {pct}%
                    </span>
                  </div>
                  <p className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>
                    {r.scope} · {r.members} members · {granted}/{totalCount} caps
                  </p>
                  <div className="mt-1.5 h-1 rounded-full" style={{ background: "rgba(0,0,0,0.4)" }}>
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${pct}%`,
                        background: "linear-gradient(90deg, var(--metric-teal), var(--metric-copper))",
                        boxShadow: active ? "0 0 8px rgba(224,160,99,0.5)" : "none",
                      }}
                    />
                  </div>
                </div>

                {/* active tab → matrix connector */}
                {active && (
                  <>
                    <span
                      aria-hidden
                      className="absolute left-1/2 -translate-x-1/2"
                      style={{
                        bottom: -10,
                        width: 2,
                        height: 10,
                        background:
                          "linear-gradient(180deg, rgba(224,160,99,0.9), rgba(224,160,99,0.2))",
                        boxShadow: "0 0 6px rgba(224,160,99,0.6)",
                      }}
                    />
                    <span
                      aria-hidden
                      className="absolute left-1/2 -translate-x-1/2"
                      style={{
                        bottom: -14,
                        width: 10,
                        height: 10,
                        borderRadius: 999,
                        background:
                          "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                        boxShadow:
                          "inset 0 1px 0 rgba(255,224,180,0.5), 0 0 10px rgba(224,160,99,0.7)",
                      }}
                    />
                  </>
                )}
              </button>
            );
          })}
        </div>

        {/* tab switcher + preset/save controls */}
        <div className="relative mt-4 mb-3 flex items-center gap-3">
          <div className="inline-flex shrink-0 rounded-full p-1"
            style={{ background: "var(--inset-base)", border: "1px solid var(--row-border)" }}>
            {(["permissions", "scope"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className="rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-wide transition-colors"
                style={
                  tab === t
                    ? {
                        background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                        color: "var(--disc-text)",
                        boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
                      }
                    : { color: "var(--panel-text-muted)" }
                }
              >
                {t === "permissions" ? "Permissions" : "Access Scope"}
              </button>
            ))}
          </div>
          <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
            for <strong style={{ color: "var(--panel-text)" }}>{ROLES[selectedRole].label}</strong>
          </span>
          <div className="h-px flex-1" style={{ background: "linear-gradient(90deg, transparent, rgba(224,160,99,0.4), transparent)" }} />
          <div className="flex shrink-0 items-center gap-2">
            <span className="text-[10.5px] font-semibold uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>
              Preset
            </span>
            {Object.keys(PRESETS).map((p) => (
              <button
                key={p}
                onClick={() => applyToRole(selectedRole, PRESETS[p](selectedRole))}
                className="rounded-lg px-2.5 py-1 text-[11px] font-semibold transition-all hover:brightness-125"
                style={{
                  background: "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
                  color: "var(--tile-text)",
                  border: "1px solid var(--tile-border)",
                }}
              >
                {p}
              </button>
            ))}
            <div className="mx-1 h-5 w-px" style={{ background: "var(--divider)" }} />
            <button
              onClick={openUpload}
              title="Bulk upload role / permission file"
              className="flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-semibold transition-all hover:brightness-125"
              style={{
                background:
                  "linear-gradient(180deg, rgba(111,214,196,0.22), rgba(60,120,110,0.12))",
                color: "var(--panel-text)",
                border: "1px solid rgba(111,214,196,0.45)",
                boxShadow: "0 0 10px rgba(111,214,196,0.18)",
              }}
            >
              <FileUp className="h-3.5 w-3.5" /> Bulk Upload
            </button>
            <button
              onClick={() => resetRole(selectedRole)}
              disabled={!dirty}
              className="flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-semibold disabled:opacity-40"
              style={{
                background: "rgba(255,255,255,0.06)",
                color: "var(--panel-text)",
                border: "1px solid var(--row-border)",
              }}
            >
              <RotateCcw className="h-3.5 w-3.5" /> Reset
            </button>
            <button
              className="flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-semibold"
              style={{
                background: dirty
                  ? "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)"
                  : "rgba(255,255,255,0.06)",
                color: dirty ? "var(--disc-text)" : "var(--panel-text-muted)",
                border: dirty ? "1px solid rgba(224,160,99,0.45)" : "1px solid var(--row-border)",
                boxShadow: dirty ? "0 0 14px rgba(224,160,99,0.35)" : "none",
              }}
            >
              <Save className="h-3.5 w-3.5" /> {dirty ? "Save (auto)" : "Saved"}
            </button>
          </div>
        </div>

        {/* CAPABILITY MATRIX — flat list, grouped by domain */}
        {tab === "permissions" && (
        <div className="space-y-4">
        {DOMAINS.map((d) => {
          const granted = d.caps.filter((c) => rolePerms[c.id]).length;
          const lit = granted > 0;
          return (
            <div key={d.id}>
              <div className="mb-2 flex items-center gap-3">
                <div
                  className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg"
                  style={{
                    background: lit
                      ? "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)"
                      : "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(0,0,0,0.2))",
                    color: lit ? "var(--disc-text)" : "var(--section-heading)",
                    boxShadow: lit
                      ? "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)"
                      : "inset 0 1px 0 rgba(255,255,255,0.05)",
                  }}
                >
                  {DOMAIN_ICONS[d.id]}
                </div>
                <div className="flex items-baseline gap-2">
                  <p className="text-[13px] font-semibold uppercase tracking-wider" style={{ color: "var(--panel-text)" }}>
                    {d.label}
                  </p>
                  <p className="text-[10px] font-mono uppercase tracking-wider" style={{ color: "var(--section-heading)" }}>
                    {d.tag}
                  </p>
                </div>
                <div className="h-px flex-1" style={{ background: "linear-gradient(90deg, rgba(224,160,99,0.25), transparent)" }} />
                <div className="flex items-center gap-2">
                  <div className="flex gap-1">
                    {d.caps.map((c) => {
                      const on = !!rolePerms[c.id];
                      return (
                        <span
                          key={c.id}
                          className="h-1.5 w-1.5 rounded-full transition-all"
                          style={{
                            background: on ? KIND_COLORS[c.kind].lit : "rgba(255,255,255,0.1)",
                            boxShadow: on ? `0 0 6px ${KIND_COLORS[c.kind].lit}` : "none",
                          }}
                        />
                      );
                    })}
                  </div>
                  <span className="text-[10.5px] font-mono" style={{ color: "var(--panel-text-muted)" }}>
                    {granted}/{d.caps.length}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-4 gap-1.5">
                {d.caps.map((c) => {
                  const on = !!rolePerms[c.id];
                  const colors = KIND_COLORS[c.kind];
                  return (
                    <button
                      key={c.id}
                      onClick={() => doToggle(c.id)}
                      className="group flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left transition-colors"
                      style={{
                        background: on ? colors.dim : "var(--inset-base)",
                        border: `1px solid ${on ? colors.lit + "55" : "var(--row-border)"}`,
                      }}
                    >
                      <div
                        className="relative flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition-colors"
                        style={{
                          background: on ? colors.lit : "rgba(0,0,0,0.25)",
                          border: `1px solid ${on ? colors.lit : "var(--row-border)"}`,
                        }}
                      >
                        <div
                          className="h-4 w-4 rounded-full bg-white transition-transform"
                          style={{
                            transform: on ? "translateX(16px)" : "translateX(0)",
                            boxShadow: "0 1px 2px rgba(0,0,0,0.35)",
                          }}
                        />
                      </div>

                      <p
                        className="flex-1 min-w-0 truncate text-[12.5px] font-semibold"
                        style={{ color: "var(--panel-text)" }}
                      >
                        {c.label}
                      </p>

                      {c.kind === "destructive" && (
                        <Lock className="h-3 w-3 shrink-0" style={{ color: colors.lit }} />
                      )}
                      <span
                        className="shrink-0 rounded-sm px-1.5 py-px text-[9px] font-bold tracking-wider"
                        style={{ background: colors.dim, color: colors.lit, border: `1px solid ${colors.lit}33` }}
                      >
                        {colors.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
        </div>
        )}

        {tab === "scope" && <TierPanel role={selectedRole} />}
      </div>

      {/* ─────── BULK UPLOAD MODAL ─────── */}
      {uploadOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)" }}
          onClick={closeUpload}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="flex w-full max-w-3xl flex-col rounded-2xl overflow-hidden"
            style={{
              maxHeight: "90vh",
              background:
                "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
              border: "1px solid rgba(224,160,99,0.45)",
              boxShadow:
                "0 24px 60px rgba(0,0,0,0.65), 0 0 28px rgba(224,160,99,0.18), inset 0 1px 0 rgba(255,255,255,0.04)",
            }}
          >
            {/* HEADER */}
            <div
              className="flex shrink-0 items-center gap-3 px-5 py-4"
              style={{ borderBottom: "1px solid var(--row-border)" }}
            >
              <div
                className="flex h-10 w-10 items-center justify-center rounded-xl"
                style={{
                  background:
                    "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                  color: "var(--disc-text)",
                  boxShadow:
                    "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
                }}
              >
                <FileUp className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <p
                  className="text-[10.5px] font-semibold uppercase tracking-[0.25em]"
                  style={{ color: "var(--section-heading)" }}
                >
                  Bulk Upload
                </p>
                <p className="text-[15px] font-semibold" style={{ color: "var(--panel-text)" }}>
                  Import Role &amp; Permission Policy
                </p>
              </div>
              <button
                onClick={closeUpload}
                className="rounded-lg p-1.5"
                style={{
                  background: "rgba(255,255,255,0.05)",
                  border: "1px solid var(--row-border)",
                  color: "var(--panel-text-muted)",
                }}
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex-1 min-h-0 overflow-y-auto">
            <div className="grid grid-cols-1 gap-4 p-5 md:grid-cols-2">
              {/* LEFT — Drop zone */}
              <div className="space-y-3">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,application/json"
                  className="hidden"
                  onChange={(e) => {
                    onPickFile(e.target.files?.[0]);
                    e.target.value = "";
                  }}
                />
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDragging(true);
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setIsDragging(false);
                    onPickFile(e.dataTransfer.files?.[0]);
                  }}
                  onClick={() => fileInputRef.current?.click()}
                  className="flex cursor-pointer flex-col items-center justify-center rounded-xl px-5 py-8 text-center transition-all"
                  style={{
                    background: isDragging
                      ? "linear-gradient(180deg, rgba(224,160,99,0.22), rgba(120,80,40,0.12))"
                      : "var(--inset-base)",
                    border: isDragging
                      ? "2px dashed rgba(224,160,99,0.8)"
                      : "2px dashed var(--row-border)",
                    minHeight: 220,
                  }}
                >
                  <div
                    className="flex h-14 w-14 items-center justify-center rounded-2xl"
                    style={{
                      background: isDragging
                        ? "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)"
                        : "linear-gradient(180deg, rgba(255,255,255,0.06), rgba(0,0,0,0.25))",
                      color: isDragging ? "var(--disc-text)" : "var(--section-heading)",
                      boxShadow:
                        "inset 0 1px 0 rgba(255,255,255,0.08), inset 0 -2px 4px rgba(0,0,0,0.35)",
                    }}
                  >
                    <Upload className="h-6 w-6" />
                  </div>
                  <p
                    className="mt-3 text-[13px] font-semibold"
                    style={{ color: "var(--panel-text)" }}
                  >
                    Drop your <span style={{ color: "var(--metric-copper)" }}>.json</span> file here
                  </p>
                  <p className="text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
                    or click to browse
                  </p>
                  <div
                    className="mt-3 flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] font-mono uppercase tracking-wider"
                    style={{
                      background: "rgba(0,0,0,0.35)",
                      border: "1px solid var(--row-border)",
                      color: "var(--section-heading)",
                    }}
                  >
                    <FileJson className="h-3 w-3" /> JSON · max 1 MB
                  </div>
                </div>

                <button
                  onClick={downloadSample}
                  className="flex w-full items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px] font-semibold"
                  style={{
                    background:
                      "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
                    color: "var(--tile-text)",
                    border: "1px solid var(--tile-border)",
                  }}
                >
                  <Download className="h-3.5 w-3.5" /> Download sample file
                </button>
              </div>

              {/* RIGHT — Spec + example */}
              <div className="space-y-3">
                <div
                  className="rounded-xl p-3"
                  style={{
                    background: "var(--inset-base)",
                    border: "1px solid var(--row-border)",
                  }}
                >
                  <div className="mb-2 flex items-center gap-2">
                    <Info className="h-3.5 w-3.5" style={{ color: "var(--metric-teal)" }} />
                    <p
                      className="text-[11px] font-semibold uppercase tracking-wider"
                      style={{ color: "var(--panel-text)" }}
                    >
                      Expected format
                    </p>
                  </div>
                  <ul
                    className="space-y-1 text-[11.5px]"
                    style={{ color: "var(--panel-text-muted)" }}
                  >
                    <li>
                      • Top-level keys must be role ids:{" "}
                      <code style={{ color: "var(--metric-copper)" }}>
                        admin · analyst · auditor · mssp
                      </code>
                    </li>
                    <li>
                      • Value can be an{" "}
                      <strong style={{ color: "var(--panel-text)" }}>object</strong>{" "}
                      <code>{`{ capId: true|false }`}</code> or an{" "}
                      <strong style={{ color: "var(--panel-text)" }}>array</strong>{" "}
                      <code>{`["capId", ...]`}</code> of grants.
                    </li>
                    <li>• Unknown capability ids are skipped with a warning.</li>
                  </ul>
                </div>

                <pre
                  className="overflow-auto rounded-xl p-3 text-[11px] font-mono leading-relaxed"
                  style={{
                    background: "rgba(0,0,0,0.4)",
                    border: "1px solid var(--row-border)",
                    color: "var(--panel-text)",
                    maxHeight: 180,
                  }}
                >
{SAMPLE_SNIPPET}
                </pre>
              </div>
            </div>

            {/* PREVIEW / ERROR */}
            <div className="px-5 pb-2">
              {parseError && (
                <div
                  className="flex items-start gap-2 rounded-xl px-3 py-2.5"
                  style={{
                    background:
                      "linear-gradient(180deg, rgba(212,106,94,0.18), rgba(212,106,94,0.06))",
                    border: "1px solid rgba(212,106,94,0.5)",
                  }}
                >
                  <XCircle
                    className="mt-0.5 h-4 w-4 shrink-0"
                    style={{ color: "var(--crit-red)" }}
                  />
                  <div className="flex-1">
                    <p
                      className="text-[12px] font-semibold"
                      style={{ color: "var(--panel-text)" }}
                    >
                      Cannot import this file
                    </p>
                    <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                      {parseError}
                    </p>
                  </div>
                </div>
              )}

              {preview && (
                <div
                  className="rounded-xl p-3"
                  style={{
                    background:
                      "linear-gradient(180deg, rgba(111,214,196,0.10), rgba(111,214,196,0.03))",
                    border: "1px solid rgba(111,214,196,0.4)",
                  }}
                >
                  <div className="mb-2 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CheckCircle2
                        className="h-4 w-4"
                        style={{ color: "var(--metric-teal)" }}
                      />
                      <p
                        className="text-[12px] font-semibold"
                        style={{ color: "var(--panel-text)" }}
                      >
                        {preview.file}
                      </p>
                      <span
                        className="rounded px-1.5 py-px text-[10px] font-mono"
                        style={{
                          background: "rgba(0,0,0,0.35)",
                          color: "var(--section-heading)",
                          border: "1px solid var(--row-border)",
                        }}
                      >
                        {(preview.sizeBytes / 1024).toFixed(1)} KB
                      </span>
                    </div>
                    <p className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
                      Review changes before applying
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
                    {(Object.keys(ROLES) as RoleId[]).map((r) => {
                      const row = preview.perRole[r];
                      const touched = !!row;
                      const active = expandedRole === r;
                      return (
                        <button
                          key={r}
                          type="button"
                          disabled={!touched}
                          onClick={() => setExpandedRole(active ? null : r)}
                          className="rounded-lg p-2.5 text-left transition-all disabled:cursor-not-allowed"
                          style={{
                            background: !touched
                              ? "rgba(255,255,255,0.03)"
                              : active
                                ? "linear-gradient(180deg, rgba(224,160,99,0.22), rgba(120,80,40,0.12))"
                                : "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
                            border: !touched
                              ? "1px dashed var(--row-border)"
                              : active
                                ? "1px solid rgba(224,160,99,0.8)"
                                : "1px solid rgba(224,160,99,0.5)",
                            opacity: touched ? 1 : 0.55,
                            boxShadow: active
                              ? "0 0 14px rgba(224,160,99,0.35), inset 0 1px 0 rgba(255,224,180,0.2)"
                              : "none",
                          }}
                        >
                          <div className="flex items-center justify-between gap-1.5">
                            <div className="flex items-center gap-1.5 min-w-0">
                              <span style={{ color: "var(--panel-text)" }}>{ROLE_ICONS[r]}</span>
                              <p
                                className="truncate text-[11.5px] font-semibold"
                                style={{ color: "var(--panel-text)" }}
                              >
                                {ROLES[r].label}
                              </p>
                            </div>
                            {touched && (
                              <span
                                className="text-[10px] font-mono"
                                style={{ color: active ? "var(--metric-copper)" : "var(--panel-text-muted)" }}
                              >
                                {active ? "hide" : "view"}
                              </span>
                            )}
                          </div>
                          {touched ? (
                            <div className="mt-1.5 flex items-center gap-2 text-[10.5px]">
                              <span style={{ color: "var(--metric-teal)" }}>
                                +{row.grant} grant
                              </span>
                              <span style={{ color: "var(--panel-text-muted)" }}>·</span>
                              <span style={{ color: "var(--crit-red)" }}>
                                −{row.revoke} revoke
                              </span>
                            </div>
                          ) : (
                            <p
                              className="mt-1.5 text-[10.5px]"
                              style={{ color: "var(--panel-text-muted)" }}
                            >
                              unchanged
                            </p>
                          )}
                        </button>
                      );
                    })}
                  </div>

                  {/* Expanded permission list */}
                  {expandedRole && preview.perRole[expandedRole] && (() => {
                    const row = preview.perRole[expandedRole];
                    const entries = Object.entries(row.perms);
                    const grants = entries.filter(([, v]) => v).map(([id]) => id);
                    const revokes = entries.filter(([, v]) => !v).map(([id]) => id);
                    const renderRow = (id: string, granted: boolean) => {
                      const cap = findCap(id)?.cap;
                      const accent = granted ? "var(--metric-teal)" : "var(--crit-red)";
                      return (
                        <div
                          key={id}
                          className="flex items-center gap-1.5 py-0.5"
                          title={id}
                        >
                          <span
                            className="h-1.5 w-1.5 shrink-0 rounded-full"
                            style={{
                              background: accent,
                              boxShadow: `0 0 4px ${accent}`,
                            }}
                          />
                          <span
                            className="flex-1 min-w-0 truncate text-[11.5px]"
                            style={{ color: "var(--panel-text)" }}
                          >
                            {cap?.label ?? id}
                          </span>
                        </div>
                      );
                    };
                    return (
                      <div
                        className="mt-2 rounded-lg px-3 py-2"
                        style={{
                          background: "var(--inset-base)",
                          border: "1px solid var(--row-border)",
                        }}
                      >
                        <div className="mb-1.5 flex items-center justify-between">
                          <p
                            className="text-[10.5px] font-semibold uppercase tracking-wider"
                            style={{ color: "var(--panel-text)" }}
                          >
                            {ROLES[expandedRole].label}
                          </p>
                          <div className="flex items-center gap-2 text-[10px] font-mono">
                            {grants.length > 0 && (
                              <span style={{ color: "var(--metric-teal)" }}>
                                +{grants.length}
                              </span>
                            )}
                            {revokes.length > 0 && (
                              <span style={{ color: "var(--crit-red)" }}>
                                −{revokes.length}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 md:grid-cols-3">
                          {grants.map((id) => renderRow(id, true))}
                          {revokes.map((id) => renderRow(id, false))}
                        </div>
                      </div>
                    );
                  })()}

                  {(preview.unknownIds.length > 0 || preview.unknownRoles.length > 0) && (
                    <div
                      className="mt-3 flex items-start gap-2 rounded-lg px-2.5 py-2 text-[10.5px]"
                      style={{
                        background: "rgba(224,160,99,0.10)",
                        border: "1px solid rgba(224,160,99,0.35)",
                        color: "var(--panel-text-muted)",
                      }}
                    >
                      <AlertTriangle
                        className="mt-0.5 h-3.5 w-3.5 shrink-0"
                        style={{ color: "var(--metric-copper)" }}
                      />
                      <div>
                        {preview.unknownRoles.length > 0 && (
                          <p>
                            <strong style={{ color: "var(--panel-text)" }}>
                              Unknown roles ignored:
                            </strong>{" "}
                            {preview.unknownRoles.join(", ")}
                          </p>
                        )}
                        {preview.unknownIds.length > 0 && (
                          <p>
                            <strong style={{ color: "var(--panel-text)" }}>
                              Unknown capabilities skipped ({preview.unknownIds.length}):
                            </strong>{" "}
                            {preview.unknownIds.slice(0, 6).join(", ")}
                            {preview.unknownIds.length > 6 ? " …" : ""}
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            </div>

            {/* FOOTER ACTIONS */}
            <div
              className="flex shrink-0 items-center justify-end gap-2 px-5 py-3"
              style={{ borderTop: "1px solid var(--row-border)" }}
            >
              <button
                onClick={closeUpload}
                className="rounded-lg px-4 py-1.5 text-[12px] font-semibold"
                style={{
                  background: "rgba(255,255,255,0.06)",
                  color: "var(--panel-text)",
                  border: "1px solid var(--row-border)",
                }}
              >
                Cancel
              </button>
              <button
                onClick={applyPreview}
                disabled={!preview}
                className="flex items-center gap-1.5 rounded-lg px-4 py-1.5 text-[12px] font-semibold disabled:opacity-40"
                style={{
                  background: preview
                    ? "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)"
                    : "rgba(255,255,255,0.06)",
                  color: preview ? "var(--disc-text)" : "var(--panel-text-muted)",
                  border: preview
                    ? "1px solid rgba(224,160,99,0.6)"
                    : "1px solid var(--row-border)",
                  boxShadow: preview ? "0 0 14px rgba(224,160,99,0.35)" : "none",
                }}
              >
                <CheckCircle2 className="h-3.5 w-3.5" /> Apply Policy
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─────── DESTRUCTIVE CONFIRM ─────── */}
      {pendingDestructive && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)" }}
          onClick={() => setPendingDestructive(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="max-w-md rounded-2xl p-6"
            style={{
              background:
                "linear-gradient(180deg, var(--drilldown-grad-top) 0%, var(--drilldown-grad-bot) 100%)",
              border: "1px solid rgba(212,106,94,0.5)",
              boxShadow: "0 20px 60px rgba(0,0,0,0.6), 0 0 30px rgba(212,106,94,0.2)",
            }}
          >
            <div className="mb-3 flex items-center gap-3">
              <div
                className="flex h-12 w-12 items-center justify-center rounded-xl"
                style={{
                  background: "radial-gradient(circle at 35% 25%, rgba(212,106,94,0.4), rgba(80,30,25,0.6))",
                  color: "var(--crit-red)",
                  boxShadow: "inset 0 1px 0 rgba(255,180,170,0.3), inset 0 -2px 4px rgba(0,0,0,0.5)",
                }}
              >
                <AlertTriangle className="h-6 w-6" />
              </div>
              <div>
                <p className="text-[10.5px] font-semibold uppercase tracking-[0.25em]" style={{ color: "var(--crit-red)" }}>
                  Destructive Capability
                </p>
                <p className="text-[16px] font-semibold" style={{ color: "var(--panel-text)" }}>
                  {findCap(pendingDestructive)?.cap.label}
                </p>
              </div>
            </div>
            <p className="mb-4 text-[12.5px]" style={{ color: "var(--panel-text-muted)" }}>
              Granting this to <strong style={{ color: "var(--panel-text)" }}>{ROLES[selectedRole].label}</strong> allows{" "}
              {findCap(pendingDestructive)?.cap.hint ?? "irreversible production-impacting actions"}. Audit logged.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setPendingDestructive(null)}
                className="flex-1 rounded-lg px-4 py-2 text-[12px] font-semibold"
                style={{
                  background: "rgba(255,255,255,0.06)",
                  color: "var(--panel-text)",
                  border: "1px solid var(--row-border)",
                }}
              >
                Cancel
              </button>
              <button
                onClick={confirmDestructive}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2 text-[12px] font-semibold"
                style={{
                  background: "linear-gradient(180deg, rgba(212,106,94,0.4), rgba(150,50,40,0.6))",
                  color: "#fff",
                  border: "1px solid rgba(212,106,94,0.6)",
                  boxShadow: "inset 0 1px 0 rgba(255,180,170,0.3), 0 0 14px rgba(212,106,94,0.4)",
                }}
              >
                <Unlock className="h-3.5 w-3.5" /> Grant Capability
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
