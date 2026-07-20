"""
test_enterprise.py
=================
Enterprise runtime substrate (Wave-I / Epic 6): tamper-evident admin audit log,
asymmetric/KMS signatures, pluggable object storage, durable work queue, and
SCIM user provisioning. Live Postgres/KMS/S3 are guarded drop-ins tested here
against stubs / local crypto — no network.

    python3 -m compliance_reporting.test_enterprise
"""

from __future__ import annotations

import base64
import tempfile

from .admin_audit import AdminAuditLog
from .object_store import FilesystemObjectStore, S3ObjectStore
from .scim import ScimError, ScimUserStore
from .signing import KmsSigner, LocalRsaSigner, verify_signature
from .work_queue import WorkQueue, Worker

_NOW = "2026-07-19T12:00:00+00:00"


# ── admin audit log (hash chain) ──────────────────────────────────────────────
def _log():
    return AdminAuditLog(tempfile.mkdtemp(prefix="furix_audit_"))


def test_audit_log_appends_and_verifies():
    log = _log()
    for i in range(5):
        log.append(tenant="acme", actor="admin", action=f"act{i}", at=_NOW, target=f"t{i}")
    v = log.verify("acme")
    assert v["ok"] and v["checked"] == 5
    assert len(log.list("acme")) == 5


def test_audit_log_detects_tampering():
    log = _log()
    log.append(tenant="acme", actor="admin", action="a", at=_NOW)
    log.append(tenant="acme", actor="admin", action="b", at=_NOW)
    # tamper with entry 1's content directly in the DB
    log._conn.execute("UPDATE admin_audit SET action='HACKED' WHERE tenant='acme' AND seq=1")
    log._conn.commit()
    v = log.verify("acme")
    assert v["ok"] is False and v["break_at"] == 1


def test_audit_log_tenant_isolation():
    log = _log()
    log.append(tenant="acme", actor="a", action="x", at=_NOW)
    assert log.list("globex") == []
    assert log.verify("globex")["ok"] is True  # empty chain is valid


# ── asymmetric + KMS signatures ───────────────────────────────────────────────
def test_local_rsa_sign_and_public_key_verify():
    signer = LocalRsaSigner.generate()
    data = b"furix audit snapshot"
    sig = signer.sign(data)
    pub = signer.public_key_pem()
    assert verify_signature(data, sig, pub) is True
    assert verify_signature(b"tampered", sig, pub) is False


class _StubKms:
    """Mimics boto3 KMS Sign/GetPublicKey using a local RSA key."""

    def __init__(self):
        self._signer = LocalRsaSigner.generate()

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        return {"Signature": base64.b64decode(self._signer.sign(Message))}

    def get_public_key(self, KeyId):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(self._signer.public_key_pem().encode())
        der = pub.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"PublicKey": der}


def test_kms_signer_against_stub_client():
    kms = KmsSigner("arn:aws:kms:...:key/abc", _StubKms())
    data = b"signed by KMS"
    sig = kms.sign(data)
    pub = kms.public_key_pem()
    assert verify_signature(data, sig, pub) is True  # verifiable with the public key alone


# ── object storage ────────────────────────────────────────────────────────────
def test_filesystem_object_store_is_write_once():
    st = FilesystemObjectStore(tempfile.mkdtemp(prefix="furix_obj_"))
    st.put("abc", b"hello")
    st.put("abc", b"OVERWRITE ATTEMPT")  # content-addressed → no-op
    assert st.get("abc") == b"hello" and st.exists("abc")
    assert st.exists("missing") is False


class _StubS3:
    def __init__(self):
        self._data: dict[str, bytes] = {}

    def head_object(self, Bucket, Key):
        if Key not in self._data:
            err = Exception("not found")
            err.response = {"Error": {"Code": "404"}}
            raise err
        return {}

    def put_object(self, Bucket, Key, Body):
        self._data[Key] = Body

    def get_object(self, Bucket, Key):
        import io
        return {"Body": io.BytesIO(self._data[Key])}


def test_s3_object_store_put_get_write_once():
    st = S3ObjectStore("furix-evidence", _StubS3())
    st.put("sha1", b"evidence")
    st.put("sha1", b"tamper")  # write-once
    assert st.get("sha1") == b"evidence" and st.exists("sha1")
    assert st.exists("nope") is False


# ── durable work queue ────────────────────────────────────────────────────────
def _queue():
    return WorkQueue(tempfile.mkdtemp(prefix="furix_q_"), max_attempts=2, base_backoff=10)


def test_queue_enqueue_claim_complete():
    q = _queue()
    j = q.enqueue(tenant="acme", kind="collect", payload={"c": "demo"}, now=1000)
    assert j["status"] == "queued"
    claimed = q.claim(worker="w1", now=1000)
    assert claimed["status"] == "running" and claimed["worker"] == "w1"
    # a second worker gets nothing (job already leased)
    assert q.claim(worker="w2", now=1000) is None
    q.complete(claimed["job_id"])
    assert q.get(claimed["job_id"])["status"] == "done"


def test_queue_retries_with_backoff_then_dead():
    q = _queue()  # max_attempts=2
    j = q.enqueue(tenant="acme", kind="k", payload={}, now=1000)
    c1 = q.claim(worker="w", now=1000)
    r1 = q.fail(c1["job_id"], error="boom", now=1000)
    assert r1["status"] == "queued" and r1["run_after"] > 1000  # backoff
    c2 = q.claim(worker="w", now=r1["run_after"])
    r2 = q.fail(c2["job_id"], error="boom again", now=r1["run_after"])
    assert r2["status"] == "dead"  # exhausted attempts


def test_queue_requeues_expired_leases():
    q = _queue()
    q.enqueue(tenant="acme", kind="k", payload={}, now=1000)
    c = q.claim(worker="w", now=1000, lease_seconds=60)
    assert c["status"] == "running"
    # lease elapsed with no completion → crashed worker; job returns to the queue
    assert q.requeue_expired(now=2000) == 1
    assert q.get(c["job_id"])["status"] == "queued"


def test_worker_runs_handler():
    q = _queue()
    q.enqueue(tenant="acme", kind="k", payload={"x": 1}, now=1000)
    seen = []
    w = Worker(q, lambda job: seen.append(job["payload"]))
    res = w.run_once(now=1000)
    assert res["status"] == "done" and seen == [{"x": 1}]


# ── SCIM ──────────────────────────────────────────────────────────────────────
def _scim():
    return ScimUserStore(tempfile.mkdtemp(prefix="furix_scim_"), "acme")


def test_scim_create_get_list():
    s = _scim()
    u = s.create({"userName": "alice@acme", "externalId": "ext-1",
                  "emails": [{"value": "alice@acme", "primary": True}]}, now=_NOW)
    assert u["userName"] == "alice@acme" and u["active"] is True
    got = s.get(u["id"])
    assert got["id"] == u["id"]
    listed = s.list(user_name="alice@acme")
    assert listed["totalResults"] == 1 and listed["Resources"][0]["userName"] == "alice@acme"


def test_scim_deprovision_deactivates():
    s = _scim()
    u = s.create({"userName": "bob@acme"}, now=_NOW)
    assert s.is_active("bob@acme") is True
    s.set_active(u["id"], False, now=_NOW)  # IdP DELETE / PATCH active=false
    assert s.is_active("bob@acme") is False
    assert s.get(u["id"])["active"] is False


def test_scim_rejects_duplicate_and_missing_username():
    s = _scim()
    s.create({"userName": "dup@acme"}, now=_NOW)
    for bad, code in (({"userName": "dup@acme"}, 409), ({}, 400)):
        try:
            s.create(bad, now=_NOW)
            raise AssertionError("accepted invalid SCIM create")
        except ScimError as e:
            assert e.status == code


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
    print(f"\n{len(tests) - failed}/{len(tests)} enterprise-runtime tests passed")
    sys.exit(1 if failed else 0)
