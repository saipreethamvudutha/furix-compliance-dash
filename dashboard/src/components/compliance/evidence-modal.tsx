"use client";

// Evidence viewer (FUR-CMP-007/008). Resolves a furix-evidence://<sha> URI through
// the BFF to its sealed original event + provenance envelope, shows a live
// integrity verdict, the retention posture (retain-until / legal hold) and the
// store's immutability posture. Every open is recorded in the admin audit log.
//
// Styling note: this app themes via [data-theme] + CSS variables, and Tailwind's
// `dark:` variant is bound to `.dark` (globals.css) which is never set — so
// `dark:` overrides do NOT apply here. Surfaces/text therefore use the themed CSS
// variables (correct in both light and dark), and semantic accents use mid-tone
// (-500) colours with translucent fills, which read on either background.

import { useEffect, useState, type ReactNode } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  ShieldCheck, ShieldAlert, Loader2, FileText, Lock, Clock, GitBranch, Hash, Scale,
  Link as LinkIcon,
} from "lucide-react";
import {
  getEvidence, evidenceSha, placeLegalHold, releaseLegalHold, type EvidenceObject,
} from "@/lib/data/furix-api";

const INSET = {
  background: "linear-gradient(180deg, var(--inset-bg-top), var(--inset-bg-bot))",
  border: "1px solid var(--inset-border)",
};

function prettyRaw(raw: string): string {
  const t = raw.trim();
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try {
      return JSON.stringify(JSON.parse(t), null, 2);
    } catch {
      /* not JSON — show as-is */
    }
  }
  return raw;
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div
      className="mb-1 text-[11px] font-semibold uppercase tracking-wide"
      style={{ color: "var(--section-heading)" }}
    >
      {children}
    </div>
  );
}

export function EvidenceModal({
  uri,
  open,
  onClose,
}: {
  uri: string | null;
  open: boolean;
  onClose: () => void;
}) {
  const [data, setData] = useState<EvidenceObject | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [role, setRole] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    if (typeof window !== "undefined") setRole(localStorage.getItem("byoc-rbac-role"));
  }, []);

  useEffect(() => {
    if (!open || !uri) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    setData(null);
    getEvidence(uri)
      .then((d) => !cancelled && setData(d))
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [open, uri, reloadKey]);

  const sha = uri ? evidenceSha(uri) : "";
  const env = data?.envelope;
  const ret = data?.retention;
  const canPlace = role === "admin" || role === "auditor";
  const canRelease = role === "admin";

  async function doPlace() {
    if (!uri) return;
    const reason = window.prompt("Reason for placing a legal hold on this evidence:");
    if (!reason || !reason.trim()) return;
    setActionBusy(true);
    try {
      await placeLegalHold(uri, reason.trim());
      setReloadKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setActionBusy(false);
    }
  }

  async function doRelease() {
    if (!uri) return;
    const reason = window.prompt("Reason for releasing this legal hold:") ?? "";
    setActionBusy(true);
    try {
      await releaseLegalHold(uri, reason.trim());
      setReloadKey((k) => k + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2" style={{ color: "var(--panel-text)" }}>
            <FileText className="h-5 w-5" style={{ color: "var(--section-heading)" }} />
            Evidence
          </DialogTitle>
          <DialogDescription
            className="break-all font-mono text-[11px]"
            style={{ color: "var(--panel-text-muted)" }}
          >
            furix-evidence://{sha}
          </DialogDescription>
        </DialogHeader>

        <div
          className="max-h-[65vh] space-y-4 overflow-y-auto pr-2"
          style={{ color: "var(--panel-text)" }}
        >
          {loading && (
            <div className="flex items-center gap-2 text-sm" style={{ color: "var(--panel-text-muted)" }}>
              <Loader2 className="h-4 w-4 animate-spin" /> Retrieving sealed evidence…
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-500">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <div className="font-medium">Something went wrong</div>
                <div className="mt-0.5 break-all text-xs opacity-90">{error}</div>
              </div>
            </div>
          )}

          {data && env && ret && (
            <>
              {/* integrity verdict */}
              <div
                className={`flex items-center gap-2 rounded-lg border p-3 text-sm ${
                  data.integrity_verified
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-500"
                    : "border-rose-500/40 bg-rose-500/10 text-rose-500"
                }`}
              >
                {data.integrity_verified ? (
                  <ShieldCheck className="h-5 w-5 shrink-0" />
                ) : (
                  <ShieldAlert className="h-5 w-5 shrink-0" />
                )}
                <div>
                  <div className="font-medium">
                    {data.integrity_verified ? "Integrity verified" : "Integrity check FAILED"}
                  </div>
                  <div className="text-xs opacity-90">
                    {data.integrity_verified
                      ? "The stored bytes re-hash to this exact SHA-256 — untampered."
                      : "The stored bytes do not match the address — possible tampering."}
                  </div>
                </div>
              </div>

              {/* retention & legal hold */}
              <div>
                <SectionLabel>Retention &amp; legal hold</SectionLabel>
                <div
                  className={`flex items-start gap-2 rounded-lg border p-3 text-sm ${
                    ret.on_legal_hold
                      ? "border-amber-500/40 bg-amber-500/10 text-amber-500"
                      : ret.expired
                        ? "border-rose-500/40 bg-rose-500/10 text-rose-500"
                        : ""
                  }`}
                  style={
                    ret.on_legal_hold || ret.expired
                      ? undefined
                      : { border: "1px solid var(--divider)", color: "var(--panel-text)" }
                  }
                >
                  {ret.on_legal_hold ? (
                    <Scale className="mt-0.5 h-4 w-4 shrink-0" />
                  ) : (
                    <Clock className="mt-0.5 h-4 w-4 shrink-0" />
                  )}
                  <div className="min-w-0 flex-1">
                    {ret.on_legal_hold ? (
                      <>
                        <div className="font-medium">On legal hold — retention frozen</div>
                        {ret.legal_hold?.reason && (
                          <div className="text-xs opacity-90">Reason: {ret.legal_hold.reason}</div>
                        )}
                        {ret.legal_hold?.placed_by && (
                          <div className="text-xs opacity-75">
                            by {ret.legal_hold.placed_by} · {ret.legal_hold.placed_at?.slice(0, 10)}
                          </div>
                        )}
                      </>
                    ) : ret.retain_until ? (
                      <>
                        <div className="font-medium">
                          {ret.expired ? "Retention expired" : "Retained"} until{" "}
                          {ret.retain_until.slice(0, 10)}
                          <span className="ml-1 font-normal uppercase opacity-75">({ret.class})</span>
                        </div>
                        <div className="text-xs" style={ret.expired ? undefined : { color: "var(--panel-text-muted)" }}>
                          {ret.expired
                            ? "Past the mandated retention window."
                            : `${ret.days_remaining?.toLocaleString()} days remaining · ${Math.round(
                                ret.retention_days / 365,
                              )}-year policy`}
                        </div>
                      </>
                    ) : (
                      <div className="text-xs" style={{ color: "var(--panel-text-muted)" }}>
                        No collection time on record — retention window not computed.
                      </div>
                    )}

                    <div className="mt-2 flex gap-2">
                      {!ret.on_legal_hold && canPlace && (
                        <button
                          type="button"
                          disabled={actionBusy}
                          onClick={doPlace}
                          className="inline-flex items-center gap-1 rounded-md border border-amber-500/50 px-2 py-1 text-xs font-medium text-amber-500 hover:bg-amber-500/10 disabled:opacity-50"
                        >
                          {actionBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : <Lock className="h-3 w-3" />}
                          Place legal hold
                        </button>
                      )}
                      {ret.on_legal_hold && canRelease && (
                        <button
                          type="button"
                          disabled={actionBusy}
                          onClick={doRelease}
                          className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium disabled:opacity-50"
                          style={{ border: "1px solid var(--divider)", color: "var(--panel-text)" }}
                        >
                          {actionBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
                          Release hold
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* original event */}
              <div>
                <SectionLabel>Original event</SectionLabel>
                <pre
                  className="max-h-64 overflow-auto rounded-lg p-3 font-mono text-xs"
                  style={{ ...INSET, color: "var(--panel-text)" }}
                >
                  {prettyRaw(data.raw)}
                </pre>
              </div>

              {/* provenance */}
              <div>
                <SectionLabel>Provenance</SectionLabel>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <Meta icon={<FileText className="h-3.5 w-3.5" />} label="Source" value={env.source} />
                  <Meta icon={<Hash className="h-3.5 w-3.5" />} label="Size" value={`${data.size_bytes} bytes`} />
                  <Meta icon={<Clock className="h-3.5 w-3.5" />} label="Observed at (event)" value={env.observed_at ?? "—"} />
                  <Meta icon={<Clock className="h-3.5 w-3.5" />} label="Collected at (ingest)" value={env.collected_at} />
                  <Meta icon={<GitBranch className="h-3.5 w-3.5" />} label="Collector / parser" value={`${env.collector_version} / ${env.parser_version}`} />
                  <Meta icon={<Lock className="h-3.5 w-3.5" />} label="Encrypted at rest" value={env.encryption?.encrypted ? "Yes (AES-256-GCM)" : "No"} />
                  <Meta icon={<FileText className="h-3.5 w-3.5" />} label="Tenant / boundary" value={`${env.tenant} / ${env.boundary}`} />
                  <Meta icon={<FileText className="h-3.5 w-3.5" />} label="Schema" value={env.schema_version} />
                </div>
              </div>

              {/* storage posture */}
              <div
                className="flex flex-wrap items-center gap-2 rounded-lg p-2 font-mono text-[10px]"
                style={{ ...INSET, color: "var(--panel-text-muted)" }}
              >
                <span
                  className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-medium ${
                    data.storage.worm ? "bg-emerald-500/15 text-emerald-500" : ""
                  }`}
                  style={
                    data.storage.worm
                      ? undefined
                      : { background: "rgba(127,127,127,0.18)", color: "var(--panel-text)" }
                  }
                  title={
                    data.storage.worm
                      ? "S3 Object Lock — hardware-enforced write-once-read-many"
                      : "Content-addressed, no-overwrite filesystem store"
                  }
                >
                  <Lock className="h-3 w-3" />
                  {data.storage.worm ? "WORM · S3 Object Lock" : `write-once · ${data.storage.backend}`}
                </span>
                {data.storage.encrypted_at_rest && (
                  <span
                    className="inline-flex items-center gap-1 rounded px-1.5 py-0.5"
                    style={{ background: "rgba(127,127,127,0.18)", color: "var(--panel-text)" }}
                  >
                    <Lock className="h-3 w-3" /> encrypted at rest
                  </span>
                )}
                <span>· access recorded in the admin audit log</span>
              </div>
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Meta({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md p-2" style={{ border: "1px solid var(--divider)" }}>
      <div className="flex items-center gap-1.5" style={{ color: "var(--panel-text-muted)" }}>
        {icon}
        <span>{label}</span>
      </div>
      <div className="mt-0.5 break-all font-medium" style={{ color: "var(--panel-text)" }}>
        {value}
      </div>
    </div>
  );
}

/**
 * A clickable furix-evidence:// reference that opens the evidence viewer. Drop it
 * anywhere a content address appears — it manages its own modal state. Accepts a
 * full `furix-evidence://<sha>` URI or a bare sha (getEvidence normalises both).
 */
export function EvidenceLink({
  uri,
  className,
  children,
}: {
  uri: string;
  className?: string;
  children?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={
          className ??
          "inline-flex items-center gap-1 font-mono text-[10px] text-emerald-500 hover:underline"
        }
        title="View the sealed original event (integrity-verified)"
      >
        {children ?? (
          <>
            <LinkIcon className="h-3 w-3 shrink-0" />
            <span className="break-all">{uri}</span>
          </>
        )}
      </button>
      <EvidenceModal uri={open ? uri : null} open={open} onClose={() => setOpen(false)} />
    </>
  );
}
