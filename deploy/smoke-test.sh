#!/usr/bin/env bash
# Full-stack smoke test (Wave-I deployment contract).
#
# Drives the running stack THROUGH THE BROWSER-FACING BFF (same-origin /bff/*),
# exactly as a real user would, and asserts the whole pipeline works end to end:
#
#   readiness → login (session cookie) → register + collect a connector →
#   run the unified posture pipeline (report) → export + schema-validate OSCAL.
#
# Usage:
#   BASE_URL=http://localhost:8088 ./smoke-test.sh
#   (defaults to the nginx port from docker-compose; for local dev pass the
#    Next dev server URL, e.g. BASE_URL=http://localhost:3010)
#
# Requires: bash, curl, python3 (stdlib only). Exits non-zero on any failure.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8088}"
EMAIL="${SMOKE_EMAIL:-admin@byoc.com}"
PASSWORD="${SMOKE_PASSWORD:-admin123}"
CONNECTOR_ID="${SMOKE_CONNECTOR_ID:-smoke-aws}"
COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; exit 1; }

jq_get() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }

echo "Furix full-stack smoke test → $BASE_URL"

# 1. health + readiness (through the same-origin BFF; open, pre-auth)
code=$(curl -fsS -o /dev/null -w '%{http_code}' "$BASE_URL/bff/api/health" || true)
[ "$code" = "200" ] || fail "health check (got $code)"
pass "health"
rz=$(curl -fsS -o /dev/null -w '%{http_code}' "$BASE_URL/bff/api/readyz" || true)
[ "$rz" = "200" ] || fail "readiness (got $rz)"
pass "readiness"

# 2. login via the BFF → sealed session + CSRF cookie
login=$(curl -fsS -c "$COOKIES" -H 'content-type: application/json' \
  -X POST "$BASE_URL/bff/auth/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "$login" | jq_get "['ok']" | grep -qi true || fail "login"
CSRF=$(awk '/furix_csrf/{print $NF}' "$COOKIES")
[ -n "$CSRF" ] || fail "no CSRF cookie after login"
pass "login (session established)"

bff() { # method path [data]
  local m="$1" p="$2" d="${3:-}"
  curl -fsS -b "$COOKIES" -H "content-type: application/json" -H "x-csrf-token: $CSRF" \
    -X "$m" "$BASE_URL/bff$p" ${d:+-d "$d"}
}

# 3. register + collect a connector (AWS data via the demo collector)
bff POST "/api/connectors" "{\"connector_id\":\"$CONNECTOR_ID\",\"kind\":\"demo-aws\",\"schedule_seconds\":86400}" >/dev/null
run=$(bff POST "/api/connectors/$CONNECTOR_ID/run")
echo "$run" | jq_get "['last_signed']" | grep -qi true || fail "connector run: manifest not signed"
echo "$run" | jq_get "['last_reconciled']" | grep -qi true || fail "connector run: not reconciled"
pass "connector collected (signed + reconciled)"

# 4. unified posture run → verified report + linked chain
pr=$(bff POST "/api/connectors/$CONNECTOR_ID/posture-run")
echo "$pr" | jq_get "['verified']" | grep -qi true || fail "posture run not verified"
REPORT_ID=$(echo "$pr" | jq_get "['report_id']")
[ -n "$REPORT_ID" ] || fail "posture run produced no report id"
echo "$pr" | jq_get "['evidence']['snapshot_sha256']" | grep -Eq '^[0-9a-f]{64}$' || fail "no snapshot evidence sha"
pass "posture run → report $REPORT_ID (verified, evidence linked)"

# 5. export OSCAL + require schema validation ran & ok
pkg=$(bff GET "/api/audit/export")
echo "$pkg" | jq_get "['oscal']['validation_ok']" | grep -qi true || fail "OSCAL export not schema-validated"
schema=$(echo "$pkg" | jq_get "['oscal']['schema']")
echo "$schema" | grep -q "nist/" || fail "OSCAL not validated against the official NIST schema ($schema)"
pass "OSCAL exported + validated against official NIST schema"

echo
echo "  ✔ full-stack smoke test passed"
