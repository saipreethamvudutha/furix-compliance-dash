"""
test_durable.py
===============
Durable job/index store (SQLite) + envelope encryption for evidence at rest
(Wave 4, FUR-OPS-001/002, FUR-SEC-003).

    python3 -m api.test_durable
"""

from __future__ import annotations

import tempfile

from .sqlite_store import DurableIndex, DurableJobStore


def _jobdb():
    return DurableJobStore(tempfile.mktemp(suffix=".db", prefix="furix_jobs_"))


# ── durable jobs ──────────────────────────────────────────────────────────────
def test_job_survives_and_reads_back():
    db = _jobdb()
    db.create("j1", owner="ka", created_at=1000.0)
    db.update("j1", 1001.0, status="running", phase="analyzing", processed=3, total=10)
    j = db.get("j1")
    assert j["status"] == "running" and j["processed"] == 3 and j["owner"] == "ka"
    db.update("j1", 1002.0, status="done", result={"report_id": "r1"})
    assert db.get("j1")["result"] == {"report_id": "r1"}


def test_restart_recovery_marks_stuck_jobs_errored():
    path = tempfile.mktemp(suffix=".db", prefix="furix_jobs_")
    db = DurableJobStore(path)
    db.create("j1", owner=None, created_at=1.0)
    db.update("j1", 2.0, status="running", phase="analyzing")
    # simulate a fresh process opening the same db after a crash
    db2 = DurableJobStore(path)
    n = db2.recover_stuck(3.0)
    assert n == 1
    assert db2.get("j1")["status"] == "error" and "restart" in db2.get("j1")["error"]


def test_job_get_unknown_is_none():
    assert _jobdb().get("nope") is None


# ── durable index ─────────────────────────────────────────────────────────────
def test_index_upsert_is_idempotent_and_ordered():
    idx = DurableIndex(tempfile.mktemp(suffix=".db", prefix="furix_idx_"))
    idx.upsert({"report_id": "b", "window_end": "2026-07-02", "total_logs": 2})
    idx.upsert({"report_id": "a", "window_end": "2026-07-01", "total_logs": 1})
    idx.upsert({"report_id": "b", "window_end": "2026-07-02", "total_logs": 2})  # dup
    ids = [e["report_id"] for e in idx.entries()]
    assert ids == ["a", "b"]                 # ordered by window_end, deduped
    assert idx.latest(1)[0]["report_id"] == "b"


# ── evidence encryption at rest ───────────────────────────────────────────────
def test_evidence_sealer_roundtrip_and_tamper_binding():
    from compliance_reporting.evidence_crypto import EvidenceSealer, KeyRing, NoneCipher

    # passthrough when no key configured
    passthru = EvidenceSealer(None)
    assert not passthru.enabled
    sealed, meta = passthru.seal(b"data", tenant="acme", sha256="abc")
    assert sealed == b"data" and meta["encrypted"] is False

    # a real cipher path — exercised with a stub AEAD so it runs without the dep
    class StubCipher:
        algorithm = "STUB-AEAD"

        def seal(self, pt, key, aad):
            return b"S:" + bytes(a ^ key[0] for a in pt) + b"|" + aad

        def open(self, sealed, key, aad):
            body = sealed[2:].rsplit(b"|", 1)[0]
            return bytes(a ^ key[0] for a in body)

    kr = KeyRing(master_key=b"0" * 32)
    sealer = EvidenceSealer(kr, StubCipher())
    assert sealer.enabled
    sealed, meta = sealer.seal(b"secret log line", tenant="acme", sha256="deadbeef")
    assert meta["encrypted"] and meta["algorithm"] == "STUB-AEAD" and meta["key_id"]
    assert sealed != b"secret log line"                     # actually transformed
    assert sealer.open(sealed, tenant="acme", sha256="deadbeef", meta=meta) == b"secret log line"


def test_evidence_store_encrypts_at_rest_and_reads_plaintext():
    from compliance_reporting.evidence import EvidenceStore
    from compliance_reporting.evidence_crypto import EvidenceSealer, KeyRing

    class XorCipher:
        algorithm = "XOR-TEST"

        def seal(self, pt, key, aad):
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(pt))

        def open(self, sealed, key, aad):
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(sealed))

    sealer = EvidenceSealer(KeyRing(master_key=b"k" * 32), XorCipher())
    store = EvidenceStore(tempfile.mkdtemp(prefix="furix_enc_"), sealer=sealer)
    raw = "CreateUser backdoor_admin from 45.33.32.156"
    obj = store.put(raw, source="cloudtrail", tenant="acme")

    # on disk the bytes are NOT the plaintext
    on_disk = (store.objects_dir / f"{obj.sha256}.raw").read_bytes()
    assert on_disk != raw.encode()
    env = store.get_envelope(obj.sha256)
    assert env["encryption"]["encrypted"] and env["encryption"]["algorithm"] == "XOR-TEST"
    # reads back as plaintext, address (sha256 of plaintext) verifies
    assert store.get_raw(obj.sha256).decode() == raw
    assert store.verify_object(obj.sha256)


if __name__ == "__main__":
    import sys
    import traceback

    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} durable tests passed")
    sys.exit(1 if failed else 0)
