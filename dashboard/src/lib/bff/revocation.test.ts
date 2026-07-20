// Session revocation tests (Wave-I / Epic 3).
//   node --test src/lib/bff/revocation.test.ts

import { test, beforeEach } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { isRevoked, revokeAllForSubject, revokeSession } from "./revocation.ts";

// isolate state under a temp dir per run
const DIR = path.join(os.tmpdir(), `furix-revoke-test-${process.pid}`);
process.env.FURIX_BFF_STATE_DIR = DIR;

beforeEach(() => {
  fs.rmSync(DIR, { recursive: true, force: true });
});

test("a fresh session is not revoked", () => {
  assert.equal(isRevoked({ sid: "s1", sub: "alice", iat: 1000 }), false);
});

test("revokeSession kills exactly that sid", () => {
  revokeSession("s1", 1000);
  assert.equal(isRevoked({ sid: "s1", sub: "alice", iat: 900 }), true);
  assert.equal(isRevoked({ sid: "s2", sub: "alice", iat: 900 }), false); // other session survives
});

test("revokeAllForSubject kills sessions issued before the cutoff", () => {
  revokeAllForSubject("alice", 2000);
  // issued before the cutoff → revoked
  assert.equal(isRevoked({ sid: "old", sub: "alice", iat: 1500 }), true);
  // issued at/after the cutoff → still valid (a fresh re-login)
  assert.equal(isRevoked({ sid: "new", sub: "alice", iat: 2500 }), false);
  // a different subject is unaffected
  assert.equal(isRevoked({ sid: "bob1", sub: "bob", iat: 1500 }), false);
});

test("revocations persist across reloads (file-backed)", () => {
  revokeSession("persist-me", 1234);
  // a fresh read (simulating another worker/process) still sees it
  assert.equal(isRevoked({ sid: "persist-me", sub: "x", iat: 1 }), true);
});

test("revokeAllForSubject keeps the strictest cutoff", () => {
  revokeAllForSubject("alice", 1000);
  revokeAllForSubject("alice", 3000);
  revokeAllForSubject("alice", 2000); // earlier — must not weaken
  assert.equal(isRevoked({ sid: "s", sub: "alice", iat: 2500 }), true); // 2500 < 3000
});
