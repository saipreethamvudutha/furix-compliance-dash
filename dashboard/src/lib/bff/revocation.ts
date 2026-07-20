// Server-side session revocation (Wave-I / Epic 3).
//
// Sealed session cookies are stateless — logout clears the browser copy, but a
// stolen cookie would otherwise stay valid until it expires. This adds a
// server-side revocation check so a session can be killed immediately:
//
//   * per-session revoke — logout revokes the exact session id (sid),
//   * per-subject revoke-all — an admin/user kills every session for a subject
//     issued before a cutoff (sign-out-everywhere / suspected compromise).
//
// Kept self-contained (only node:fs / node:os / node:path) so it runs under
// Node's type-stripping test loader. File-backed JSON: correct for a single BFF
// instance; a shared store (Redis/Postgres) is the multi-instance upgrade
// (Epic 6). Reads are cheap and re-read the file so a revocation takes effect
// across worker processes of the same instance.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

type RevocationState = {
  sids: Record<string, number>; // revoked session id → epoch seconds revoked
  subjects: Record<string, number>; // subject → revoke-all-before (epoch seconds)
};

function stateDir(): string {
  return process.env.FURIX_BFF_STATE_DIR || path.join(os.tmpdir(), "furix-bff");
}

function statePath(): string {
  return path.join(stateDir(), "revocations.json");
}

function load(): RevocationState {
  try {
    return JSON.parse(fs.readFileSync(statePath(), "utf8")) as RevocationState;
  } catch {
    return { sids: {}, subjects: {} };
  }
}

function save(state: RevocationState): void {
  const dir = stateDir();
  fs.mkdirSync(dir, { recursive: true });
  const tmp = statePath() + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, statePath()); // atomic
}

/** Revoke exactly one session (by its sid). Used on logout. */
export function revokeSession(sid: string, atEpoch: number): void {
  if (!sid) return;
  const state = load();
  state.sids[sid] = atEpoch;
  save(state);
}

/** Revoke every session for a subject issued before `beforeEpoch` (sign-out-everywhere). */
export function revokeAllForSubject(subject: string, beforeEpoch: number): void {
  if (!subject) return;
  const state = load();
  // keep the strictest (latest) cutoff
  state.subjects[subject] = Math.max(state.subjects[subject] ?? 0, beforeEpoch);
  save(state);
}

/** True if this session has been revoked (by sid, or by a subject-wide cutoff). */
export function isRevoked(session: { sid?: string; sub?: string; iat?: number }): boolean {
  const state = load();
  if (session.sid && state.sids[session.sid] !== undefined) return true;
  if (session.sub && session.iat !== undefined) {
    const cutoff = state.subjects[session.sub];
    if (cutoff !== undefined && session.iat < cutoff) return true;
  }
  return false;
}
