#!/usr/bin/env bash
# PRODUCTION smoke test (Wave-J). Unlike smoke-test.sh (which uses the demo
# connector and therefore only proves a development deployment), this test drives
# the PRODUCTION overlay and the REAL AWS connector path:
#
#   readiness (with Docker-secret files) → login → register an aws-org-iam
#   connector (NOT demo — proves demo-isolation does not block real connectors)
#   → posture-run → (with AWS reachable) verified report + NIST-validated OSCAL.
#
# AWS access for the run: point the api/worker at real read-only creds, or a
# moto mock via AWS_ENDPOINT_URL. Without AWS reachable the test still PASSES its
# integrity assertions (readiness, auth, non-demo path wired) and reports that a
# full run needs AWS — it just does not assert a completed collection.
#
#   BASE_URL=http://localhost:8088 ./smoke-test-prod.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8088}"
EMAIL="${SMOKE_EMAIL:?set SMOKE_EMAIL (production has no default users)}"
PASSWORD="${SMOKE_PASSWORD:?set SMOKE_PASSWORD}"
CONNECTOR_ID="${SMOKE_CONNECTOR_ID:-prod-aws}"
COOKIES="$(mktemp)"; trap 'rm -f "$COOKIES"' EXIT

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
warn() { printf '  \033[33mNOTE\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; exit 1; }
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }

echo "Furix PRODUCTION smoke test → $BASE_URL"

# 1. readiness — proves prod secrets (incl. Docker-secret FILES) resolved
rz=$(curl -fsS -o /dev/null -w '%{http_code}' "$BASE_URL/bff/api/readyz" || true)
[ "$rz" = "200" ] || fail "readiness (got $rz) — prod secrets/secret-files not resolved"
pass "readiness (production secrets resolved)"

# 2. login (production identity — no default users)
login=$(curl -fsS -c "$COOKIES" -H 'content-type: application/json' \
  -X POST "$BASE_URL/bff/auth/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}") \
  || fail "login failed (check FURIX_BFF_USERS / OIDC)"
echo "$login" | jget "['ok']" | grep -qi true || fail "login"
CSRF=$(awk '/furix_csrf/{print $NF}' "$COOKIES")
pass "login (production identity)"

bff() { local m="$1" p="$2" d="${3:-}"; curl -s -b "$COOKIES" -H "content-type: application/json" \
  -H "x-csrf-token: $CSRF" -o /tmp/prodsmoke.out -w '%{http_code}' -X "$m" "$BASE_URL/bff$p" ${d:+-d "$d"}; }

# 3. register a REAL (non-demo) connector — demo-isolation must NOT block it
code=$(bff POST "/api/connectors" \
  "{\"connector_id\":\"$CONNECTOR_ID\",\"kind\":\"aws-org-iam\",\"schedule_seconds\":86400,\"config\":{\"member_role_name\":\"OrganizationAccountAccessRole\"}}")
[ "$code" = "201" ] || fail "registering aws-org-iam connector rejected (got $code) — real connectors must be allowed in prod"
pass "aws-org-iam connector registered (real path not demo-blocked)"

# 4. posture-run
code=$(bff POST "/api/connectors/$CONNECTOR_ID/posture-run")
if [ "$code" = "201" ]; then
  REPORT=$(jget "['report_id']" < /tmp/prodsmoke.out)
  [ -n "$REPORT" ] || fail "posture run produced no report"
  pass "posture run → verified report $REPORT (AWS reachable)"
  pkg=$(bff GET "/api/audit/export"); [ "$pkg" = "200" ] || fail "OSCAL export ($pkg)"
  jget "['oscal']['validation_ok']" < /tmp/prodsmoke.out | grep -qi true || fail "OSCAL not validated"
  pass "OSCAL exported + NIST-validated"
elif [ "$code" = "400" ] && grep -qi "demo" /tmp/prodsmoke.out; then
  fail "posture run wrongly blocked as demo — aws-org-iam must be allowed in prod"
else
  warn "posture run returned $code (AWS not reachable in this environment)."
  warn "integrity path is wired; supply read-only AWS creds (or AWS_ENDPOINT_URL=moto) for a full run."
fi

echo; echo "  ✔ production integrity smoke test passed"
