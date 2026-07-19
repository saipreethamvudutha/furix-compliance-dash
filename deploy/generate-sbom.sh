#!/usr/bin/env bash
# generate-sbom.sh — Software Bill of Materials for engine + dashboard.
# Engine is stdlib-only (no runtime pip deps); the dashboard SBOM comes from npm.
# Emits CycloneDX JSON into ./sbom/. Safe to run locally or in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/sbom"
mkdir -p "$OUT"

echo "→ engine SBOM"
python3 - "$ROOT" > "$OUT/engine-sbom.json" <<'PY'
import json, sys, pathlib, datetime
root = pathlib.Path(sys.argv[1]) / "engine"
# The deterministic engine has no runtime pip dependencies (stdlib only); the
# optional extras are declared here so the SBOM is explicit about them.
optional = [
    {"name": "cryptography", "purpose": "AES-256-GCM evidence encryption at rest (optional)"},
    {"name": "pyjwt",        "purpose": "RS256/JWKS OIDC verification (optional)"},
    {"name": "fastapi",      "purpose": "HTTP API layer (serving only)"},
    {"name": "uvicorn",      "purpose": "ASGI server (serving only)"},
]
doc = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"type": "application", "name": "furix-engine",
                               "description": "Deterministic compliance engine (stdlib core)"}},
    "components": [{"type": "library", "name": c["name"], "scope": "optional",
                    "description": c["purpose"]} for c in optional],
    "properties": [{"name": "furix:runtime-pip-deps", "value": "none (stdlib only)"}],
}
print(json.dumps(doc, indent=2))
PY

echo "→ dashboard SBOM"
if command -v npm >/dev/null 2>&1 && [ -f "$ROOT/dashboard/package-lock.json" ]; then
  ( cd "$ROOT/dashboard" && npm sbom --sbom-format cyclonedx --omit=dev > "$OUT/dashboard-sbom.json" 2>/dev/null ) \
    || echo '{"note":"npm sbom unavailable on this npm version"}' > "$OUT/dashboard-sbom.json"
else
  echo '{"note":"npm/package-lock not present"}' > "$OUT/dashboard-sbom.json"
fi

echo "✓ SBOMs written to $OUT"
ls -la "$OUT"
