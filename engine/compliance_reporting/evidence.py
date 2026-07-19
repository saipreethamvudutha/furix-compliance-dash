"""
evidence.py
===========
The immutable evidence envelope + content-addressed object store (FUR-CMP-007).

Before this, a report kept only a 300-char excerpt of the value that triggered
a finding — an auditor could not reconstruct the source event, prove the source
population, or tell a collector failure from a healthy control. The Evidence
Kernel fixes that: every ingested event is stored **once, immutably, addressed
by the SHA-256 of its raw bytes**, wrapped in a canonical envelope that records
where it came from, when it was observed vs collected, and under which
collector/parser/schema versions.

Canonical record (audit §"Canonical Evidence and Control Graph"):
    EvidenceObject:
      id · source · tenant · boundary · sha256 · raw_uri · size_bytes
      observed_at (event time) · collected_at (ingestion time, volatile)
      collector_version · parser_version · schema_version

Identity is content-derived (`uuid5(sha256)`), so the same raw event always
yields the same evidence id regardless of when it was ingested — the lineage
seed the report's evidence rows point at.

Layout (per tenant, under the store root):
    evidence/objects/<sha256>.raw     the exact bytes, write-once
    evidence/objects/<sha256>.json    the envelope, write-once
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .versions import ENGINE_VERSION, REPORT_SCHEMA_VERSION

# Namespace for deterministic evidence identity (content-derived).
_EVIDENCE_NS = uuid.UUID("f2a7c9e1-3b4d-4e6a-8c1f-9d0e2a3b4c5d")
EVIDENCE_URI_SCHEME = "furix-evidence"


def evidence_uri(sha256: str) -> str:
    return f"{EVIDENCE_URI_SCHEME}://{sha256}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class EvidenceObject:
    """One immutable piece of raw evidence + its provenance envelope."""

    evidence_id: str
    source: str            # source system / log type (e.g. "cloudtrail")
    tenant: str
    boundary: str          # scope within the tenant (e.g. "prod-us", "default")
    sha256: str
    raw_uri: str
    size_bytes: int
    observed_at: str | None       # event time from the log (content-derived)
    collected_at: str             # ingestion time (VOLATILE — metadata only)
    collector_version: str
    parser_version: str
    schema_version: str

    def identity(self) -> dict[str, Any]:
        """Fields that make this object what it is — excludes volatile collected_at."""
        d = asdict(self)
        d.pop("collected_at", None)
        return d

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvidenceStore:
    """Content-addressed, write-once store of EvidenceObjects for one tenant.

    Encryption at rest (FUR-SEC-003) is transparent: when a master key is
    configured (and a real cipher is available) object bytes are sealed with a
    per-tenant key before writing and opened on read. The content address stays
    the SHA-256 of the PLAINTEXT, so dedup and raw_uri pointers are unchanged.
    Unconfigured → passthrough, and the envelope records `encrypted: false`.
    """

    def __init__(self, root: Path | str, sealer: "Any" = None):
        self.root = Path(root) / "evidence"
        self.objects_dir = self.root / "objects"
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        if sealer is None:
            from .evidence_crypto import EvidenceSealer, KeyRing  # noqa: PLC0415
            sealer = EvidenceSealer(KeyRing.from_env())
        self.sealer = sealer

    # ── write ────────────────────────────────────────────────────────────────
    def put(
        self,
        raw: str | bytes,
        *,
        source: str,
        tenant: str = "default",
        boundary: str = "default",
        observed_at: str | None = None,
        collected_at: str | None = None,
        parser_version: str | None = None,
    ) -> EvidenceObject:
        """
        Store raw evidence immutably and return its envelope. Idempotent: the
        same bytes never write twice and never overwrite — content addressing
        makes re-ingesting the same event a no-op on disk.
        """
        data = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
        sha = sha256_bytes(data)
        obj = EvidenceObject(
            evidence_id=str(uuid.uuid5(_EVIDENCE_NS, sha)),
            source=source,
            tenant=tenant,
            boundary=boundary,
            sha256=sha,
            raw_uri=evidence_uri(sha),
            size_bytes=len(data),
            observed_at=observed_at,
            # wall-clock ingestion time is volatile metadata, never identity.
            collected_at=collected_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            collector_version=ENGINE_VERSION,
            parser_version=parser_version or ENGINE_VERSION,
            schema_version=REPORT_SCHEMA_VERSION,
        )
        raw_path = self.objects_dir / f"{sha}.raw"
        env_path = self.objects_dir / f"{sha}.json"
        # seal at rest (per-tenant key); address stays sha256 of PLAINTEXT
        sealed, enc_meta = self.sealer.seal(data, tenant=tenant, sha256=sha)
        if not raw_path.exists():                    # write-once
            self._atomic_write_bytes(raw_path, sealed)
        if not env_path.exists():
            envelope = {**obj.to_dict(), "encryption": enc_meta}
            self._atomic_write_text(env_path, json.dumps(envelope, sort_keys=True, indent=2))
        return obj

    # ── read ─────────────────────────────────────────────────────────────────
    def exists(self, sha256: str) -> bool:
        return (self.objects_dir / f"{sha256}.raw").exists()

    def get_raw(self, sha256: str) -> bytes:
        """Return the PLAINTEXT bytes (transparently decrypting if sealed)."""
        sealed = (self.objects_dir / f"{sha256}.raw").read_bytes()
        env = self.get_envelope(sha256)
        meta = env.get("encryption", {"encrypted": False})
        return self.sealer.open(sealed, tenant=env.get("tenant", "default"),
                                sha256=sha256, meta=meta)

    def get_envelope(self, sha256: str) -> dict[str, Any]:
        return json.loads((self.objects_dir / f"{sha256}.json").read_text(encoding="utf-8"))

    def verify_object(self, sha256: str) -> bool:
        """Re-hash the decrypted bytes and confirm they match the address (tamper check)."""
        if not self.exists(sha256):
            return False
        return sha256_bytes(self.get_raw(sha256)) == sha256

    # ── internals ──────────────────────────────────────────────────────────────
    @staticmethod
    def _atomic_write_bytes(path: Path, data: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    @staticmethod
    def _atomic_write_text(path: Path, text: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)


def build_population_manifest(
    expected: int, observed: int, errored: int, *, excluded: int = 0, duplicate: int = 0
) -> dict[str, Any]:
    """
    A completeness manifest (FUR-CMP-003/007): reconciles the subjects a batch
    was expected to cover against what was actually observed, so partial
    telemetry can never masquerade as healthy. coverage_pct is observed of
    the non-excluded expected population.
    """
    considered = max(0, expected - excluded)
    coverage = round(100.0 * observed / considered, 1) if considered else 0.0
    reconciled = observed + errored + excluded + duplicate == expected
    return {
        "expected": expected,
        "observed": observed,
        "errored": errored,
        "excluded": excluded,
        "duplicate": duplicate,
        "coverage_pct": coverage,
        "reconciled": reconciled,
    }
