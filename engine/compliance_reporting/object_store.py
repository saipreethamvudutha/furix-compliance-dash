"""
object_store.py
==============
Pluggable object storage for immutable evidence (Wave-I / Epic 6). The evidence
kernel is content-addressed (key = sha256), which is exactly what object storage
wants. This abstracts the raw-bytes backend so immutable evidence can live on the
filesystem (dev / single node) or in S3-compatible object storage (production,
durable, versioned, WORM-capable) behind one interface.

* `FilesystemObjectStore` — the current on-disk layout.
* `S3ObjectStore` — S3 put/get/head; the boto3 client is dependency-injected, so
  it is tested against a stub with no network. Content-addressed keys make writes
  idempotent; enabling S3 Object Lock gives true write-once (WORM) evidence.

Objects are write-once (content-addressed): re-`put` of the same key is a no-op.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def exists(self, key: str) -> bool: ...


class FilesystemObjectStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / key

    def put(self, key: str, data: bytes) -> None:
        p = self._path(key)
        if p.exists():
            return  # write-once (content-addressed)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).exists()


class S3ObjectStore:
    """S3-backed object store. `client` is a boto3 S3 client (or a stub)."""

    def __init__(self, bucket: str, client: Any, prefix: str = "evidence/"):
        self.bucket = bucket
        self.prefix = prefix
        self._client = client

    def _k(self, key: str) -> str:
        return f"{self.prefix}{key}"

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=self._k(key))
            return True
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def put(self, key: str, data: bytes) -> None:
        if self.exists(key):
            return  # write-once
        self._client.put_object(Bucket=self.bucket, Key=self._k(key), Body=data)

    def get(self, key: str) -> bytes:
        obj = self._client.get_object(Bucket=self.bucket, Key=self._k(key))
        return obj["Body"].read()
