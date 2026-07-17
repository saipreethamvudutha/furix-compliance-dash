"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, Lock, Unlock, Timer } from "lucide-react";
import { useRole } from "@/lib/rbac/context";
import {
  ROLES, DOMAINS,
  type RoleId,
  type DataSensitivity,
} from "@/lib/rbac/permissions";
import { SENSITIVITY_META, SENSITIVITY_RANK } from "@/lib/rbac/sensitivity";

const SENSITIVITIES: DataSensitivity[] = ["public", "internal", "confidential", "restricted"];

const SENS_DESCRIPTION: Record<DataSensitivity, string> = {
  public: "Asset counts, public dashboards, non-sensitive metrics",
  internal: "Hostnames, scan histories, summary reports",
  confidential: "IP addresses, asset configurations, vulnerability details",
  restricted: "Passwords, secrets, audit logs, security operations data",
};

const KIND_TONE: Record<"read" | "write" | "destructive", { lit: string; bg: string; label: string }> = {
  read:        { lit: "var(--metric-teal)",   bg: "rgba(111,214,196,0.15)", label: "READ"  },
  write:       { lit: "var(--metric-copper)", bg: "rgba(224,160,99,0.18)",  label: "WRITE" },
  destructive: { lit: "var(--crit-red)",      bg: "rgba(212,106,94,0.18)",  label: "CRIT"  },
};

function fmtMMSS(ms: number) {
  const t = Math.max(0, Math.floor(ms / 1000));
  return `${String(Math.floor(t / 60)).padStart(2, "0")}:${String(t % 60).padStart(2, "0")}`;
}

export function TierPanel({ role }: { role: RoleId }) {
  const { scopes, matrix, setScope, evaluate, jitActive, jitExpiresAt, elevate, revoke, tiers, setTierConfig } = useRole();
  const sc = scopes[role];
  const tc = tiers[role];
  const r = ROLES[role];
  const remaining = jitExpiresAt ? jitExpiresAt - Date.now() : 0;

  const ALL_CAPS = DOMAINS.flatMap((d) => d.caps.map((c) => ({ ...c, domain: d.label })));
  const granted = ALL_CAPS.filter((c) => matrix[role]?.[c.id]);

  const [simCapId, setSimCapId] = useState(granted[0]?.id ?? ALL_CAPS[0].id);
  const [simSens, setSimSens] = useState<DataSensitivity | "">("");

  useEffect(() => {
    const first = granted[0]?.id;
    if (first) setSimCapId(first);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [role]);

  const result = evaluate(simCapId, {
    sensitivity: simSens || undefined,
  }, role);

  return (
    <div className="grid grid-cols-2 items-start gap-4">
      {/* LEFT — What the role can do */}
      <Card title="What this role can do" sub={`${granted.length} permissions`}>
        {granted.length === 0 ? (
          <p className="text-[11.5px]" style={{ color: "var(--panel-text-muted)" }}>
            No permissions granted yet — switch to the <strong>Permissions</strong> tab to turn some on.
          </p>
        ) : (
          <div
            className="max-h-[260px] overflow-y-auto pr-1 [&::-webkit-scrollbar]:hidden"
            style={{ scrollbarWidth: "none" }}
          >
            <div className="grid gap-1.5" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))" }}>
            {granted.map((c) => {
              const t = KIND_TONE[c.kind];
              return (
                <div
                  key={c.id}
                  className="flex items-center gap-1.5 rounded-md px-2 py-1.5"
                  style={{ background: "var(--inset-base)", border: "1px solid var(--row-border)" }}
                >
                  <span
                    className="min-w-0 flex-1 truncate text-[12px]"
                    style={{ color: "var(--panel-text)" }}
                    title={c.label}
                  >
                    {c.label}
                  </span>
                  <span
                    className="shrink-0 rounded-sm px-1.5 py-px text-[9px] font-bold tracking-wider"
                    style={{ background: t.bg, color: t.lit, border: `1px solid ${t.lit}33` }}
                  >
                    {t.label}
                  </span>
                </div>
              );
            })}
            </div>
          </div>
        )}
      </Card>

      {/* RIGHT — Data sensitivity the role can see */}
      <Card title="Data this role can see" sub="Pick the highest sensitivity level — everything below is included automatically">
        <SensitivityLadder
          selected={sc.sensitivities}
          onChange={(next) => setScope(role, { ...sc, sensitivities: next })}
        />
      </Card>

      {/* BOTTOM LEFT — Temporary Admin Mode */}
      <div className="rounded-xl p-3"
        style={{
          background: jitActive ? "rgba(212,106,94,0.10)" : "linear-gradient(180deg, var(--drilldown-grad-top), var(--drilldown-grad-bot))",
          border: `1px solid ${jitActive ? "rgba(212,106,94,0.45)" : "var(--row-border)"}`,
        }}>
        <div className="mb-1.5 flex items-center gap-2">
          <Timer className="h-3.5 w-3.5" style={{ color: jitActive ? "var(--crit-red)" : "var(--section-heading)" }} />
          <p className="text-[12px] font-semibold" style={{ color: "var(--panel-text)" }}>
            Temporary Admin Mode
          </p>
          {jitActive && (
            <span className="ml-auto font-mono text-[12px] font-semibold" style={{ color: "var(--crit-red)" }}>
              {fmtMMSS(remaining)} left
            </span>
          )}
        </div>

        <p className="mb-2.5 text-[11px] leading-snug" style={{ color: "var(--panel-text-muted)" }}>
          {jitActive
            ? <>This role can <strong style={{ color: "var(--crit-red)" }}>delete, isolate and publish</strong> right now. It will automatically turn off when the timer hits zero.</>
            : <>By default this role <strong style={{ color: "var(--panel-text)" }}>cannot</strong> delete assets, isolate hosts or publish rules. Turn on when needed.</>}
        </p>

        {!jitActive ? (
          <div className="flex items-center gap-2">
            <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>Turn on for</span>
            <input
              type="number" min={1} max={120}
              value={tc.jitMinutes}
              onChange={(e) => {
                const n = Math.max(1, Math.min(120, parseInt(e.target.value || "0") || 0));
                setTierConfig(role, { ...tc, jitMinutes: n });
              }}
              className="w-14 rounded-md px-2 py-1 text-center text-[12px] font-mono"
              style={{ background: "var(--background)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}
            />
            <span className="text-[11px]" style={{ color: "var(--panel-text-muted)" }}>minutes</span>
            <button
              onClick={elevate}
              disabled={tc.jitMinutes < 1}
              className="ml-auto rounded-md px-3 py-1 text-[11.5px] font-semibold disabled:opacity-50"
              style={{
                background: "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
                color: "var(--disc-text)",
                boxShadow: "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.5)",
              }}
            >
              <Unlock className="mr-1 inline h-3.5 w-3.5" /> Turn on
            </button>
          </div>
        ) : (
          <button
            onClick={revoke}
            className="w-full rounded-md px-3 py-1.5 text-[11.5px] font-semibold"
            style={{ background: "rgba(255,255,255,0.06)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}
          >
            <Lock className="mr-1 inline h-3.5 w-3.5" /> Turn off now
          </button>
        )}
      </div>

      {/* BOTTOM RIGHT — Quick check tester */}
      <div className="rounded-xl p-3"
        style={{
          background: "linear-gradient(180deg, var(--drilldown-grad-top), var(--drilldown-grad-bot))",
          border: `1px solid ${result.allowed ? "rgba(111,214,196,0.4)" : "rgba(212,106,94,0.4)"}`,
        }}>
        <div className="mb-1.5 flex items-center gap-2">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--section-heading)" }}>
            Quick check
          </p>
          <span className="ml-auto flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase"
            style={{
              background: result.allowed ? "rgba(111,214,196,0.18)" : "rgba(212,106,94,0.18)",
              color: result.allowed ? "var(--metric-teal)" : "var(--crit-red)",
              border: `1px solid ${result.allowed ? "rgba(111,214,196,0.4)" : "rgba(212,106,94,0.4)"}`,
            }}>
            {result.allowed
              ? <CheckCircle2 className="h-3 w-3" />
              : <XCircle className="h-3 w-3" />}
            {result.allowed ? "Allowed" : "Denied"}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-[12px]" style={{ color: "var(--panel-text)" }}>
          <span style={{ color: "var(--panel-text-muted)" }}><strong style={{ color: "var(--panel-text)" }}>{r.label}</strong> →</span>
          <select value={simCapId} onChange={(e) => setSimCapId(e.target.value)}
            className="min-w-0 flex-1 rounded-md px-2 py-1 text-[12px]"
            style={{ background: "var(--inset-base)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
            {ALL_CAPS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
          </select>
          <span style={{ color: "var(--panel-text-muted)" }}>on</span>
          <select value={simSens} onChange={(e) => setSimSens(e.target.value as DataSensitivity | "")}
            className="rounded-md px-2 py-1 text-[12px]"
            style={{ background: "var(--inset-base)", color: "var(--panel-text)", border: "1px solid var(--row-border)" }}>
            <option value="">any</option>
            {SENSITIVITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <span style={{ color: "var(--panel-text-muted)" }}>data</span>
        </div>
        <p className="mt-1.5 text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>
          {result.reason}
        </p>
      </div>
    </div>
  );
}

/* ─────────── helpers ─────────── */

function Card({ title, sub, children }: { title: string; sub: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl p-4"
      style={{
        background: "linear-gradient(180deg, var(--drilldown-grad-top), var(--drilldown-grad-bot))",
        border: "1px solid var(--row-border)",
      }}>
      <div className="mb-3">
        <p className="text-[12.5px] font-semibold" style={{ color: "var(--panel-text)" }}>{title}</p>
        <p className="text-[10.5px]" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
      </div>
      {children}
    </div>
  );
}

function SensitivityLadder({
  selected,
  onChange,
}: {
  selected: DataSensitivity[];
  onChange: (next: DataSensitivity[]) => void;
}) {
  const maxRank = selected.reduce(
    (m, s) => Math.max(m, SENSITIVITY_RANK[s]),
    -1
  );
  const currentMax =
    SENSITIVITIES.find((s) => SENSITIVITY_RANK[s] === maxRank) ?? null;

  const setMax = (level: DataSensitivity | null) => {
    if (level === null) return onChange([]);
    const r = SENSITIVITY_RANK[level];
    onChange(SENSITIVITIES.filter((s) => SENSITIVITY_RANK[s] <= r));
  };

  return (
    <div className="space-y-1.5">
      {SENSITIVITIES.map((level) => {
        const meta = SENSITIVITY_META[level];
        const on = selected.includes(level);
        const isHighest = currentMax === level;
        return (
          <button
            key={level}
            onClick={() => setMax(isHighest ? null : level)}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left transition-colors"
            style={{
              background: on ? meta.bg : "var(--inset-base)",
              border: `1px solid ${on ? meta.border : "var(--row-border)"}`,
            }}
          >
            <span
              className="flex h-4 w-4 items-center justify-center rounded-full"
              style={{
                background: on ? meta.dot : "transparent",
                border: `1.5px solid ${on ? meta.dot : "var(--row-border)"}`,
                boxShadow: on ? `0 0 6px ${meta.dot}` : "none",
              }}
            >
              {on && (
                <CheckCircle2
                  className="h-3 w-3"
                  style={{ color: "var(--background)" }}
                />
              )}
            </span>
            <div className="flex-1">
              <p
                className="text-[12px] font-semibold"
                style={{ color: on ? meta.color : "var(--panel-text)" }}
              >
                {meta.label}
                {isHighest && (
                  <span
                    className="ml-2 rounded-sm px-1.5 py-px text-[9px] font-bold uppercase tracking-wider"
                    style={{
                      background: meta.bg,
                      color: meta.color,
                      border: `1px solid ${meta.border}`,
                    }}
                  >
                    Max level
                  </span>
                )}
              </p>
              <p
                className="text-[10.5px] leading-snug"
                style={{ color: "var(--panel-text-muted)" }}
              >
                {SENS_DESCRIPTION[level]}
              </p>
            </div>
          </button>
        );
      })}

      <p
        className="mt-2 text-[10.5px] leading-snug"
        style={{ color: "var(--panel-text-muted)" }}
      >
        {currentMax ? (
          <>
            This role can access data classified up to{" "}
            <strong style={{ color: SENSITIVITY_META[currentMax].color }}>
              {SENSITIVITY_META[currentMax].label}
            </strong>
            . Anything more sensitive is hidden automatically.
          </>
        ) : (
          <>This role currently has no data access. Pick a level above.</>
        )}
      </p>
    </div>
  );
}
