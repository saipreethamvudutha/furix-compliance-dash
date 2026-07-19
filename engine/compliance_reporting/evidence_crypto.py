"""
evidence_crypto.py
==================
Envelope encryption for evidence at rest (Wave 4, FUR-SEC-003).

Raw evidence can contain sensitive log/config data, so the immutable evidence
store supports encrypting object bytes at rest. The design is envelope
encryption with a pluggable cipher:

  * A per-tenant data key is derived (HKDF-style, stdlib) from a configured
    master key + the tenant id, so tenants never share key material.
  * Object bytes are sealed with an authenticated cipher; the stored envelope
    records the key id and algorithm so the right key decrypts it and tampering
    is detected.

The cipher is pluggable. `AesGcmCipher` (AES-256-GCM) activates when the
`cryptography` library is present; otherwise the store reports `algorithm:
"none"` — it never silently pretends to encrypt. The content address stays the
SHA-256 of the PLAINTEXT, so deduplication and the report's raw_uri pointers are
unchanged whether or not encryption is on.

Config (env): FURIX_EVIDENCE_MASTER_KEY (hex/opaque) enables encryption when a
real cipher is available.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Protocol


class Cipher(Protocol):
    algorithm: str

    def seal(self, plaintext: bytes, key: bytes, aad: bytes) -> bytes: ...
    def open(self, sealed: bytes, key: bytes, aad: bytes) -> bytes: ...


class NoneCipher:
    """No encryption — passthrough. Reports 'none' so it is never mistaken."""

    algorithm = "none"

    def seal(self, plaintext: bytes, key: bytes, aad: bytes) -> bytes:
        return plaintext

    def open(self, sealed: bytes, key: bytes, aad: bytes) -> bytes:
        return sealed


class AesGcmCipher:
    """AES-256-GCM authenticated encryption (requires `cryptography`)."""

    algorithm = "AES-256-GCM"

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415
        self._AESGCM = AESGCM

    def seal(self, plaintext: bytes, key: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(12)
        ct = self._AESGCM(key).encrypt(nonce, plaintext, aad)
        return nonce + ct

    def open(self, sealed: bytes, key: bytes, aad: bytes) -> bytes:
        nonce, ct = sealed[:12], sealed[12:]
        return self._AESGCM(key).decrypt(nonce, ct, aad)


def default_cipher() -> Cipher:
    """AES-GCM when available, else the honest passthrough."""
    try:
        return AesGcmCipher()
    except Exception:
        return NoneCipher()


def _hkdf_sha256(master: bytes, info: bytes, length: int = 32) -> bytes:
    """Minimal HKDF-Expand (RFC 5869) over HMAC-SHA256 — stdlib only."""
    prk = hmac.new(b"furix-evidence-salt", master, hashlib.sha256).digest()
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


@dataclass(frozen=True)
class KeyRing:
    """Derives per-tenant data keys from a master key; tracks a key id."""

    master_key: bytes
    key_id: str = "furix-master-1"

    @classmethod
    def from_env(cls) -> "KeyRing | None":
        raw = os.environ.get("FURIX_EVIDENCE_MASTER_KEY", "")
        if not raw:
            return None
        try:
            master = bytes.fromhex(raw)
        except ValueError:
            master = raw.encode("utf-8")
        return cls(master_key=master)

    def data_key(self, tenant: str) -> bytes:
        return _hkdf_sha256(self.master_key, f"tenant:{tenant}".encode())


class EvidenceSealer:
    """Seals/opens evidence bytes with per-tenant keys and a chosen cipher."""

    def __init__(self, keyring: KeyRing | None = None, cipher: Cipher | None = None):
        self.keyring = keyring
        self.cipher = cipher or (default_cipher() if keyring else NoneCipher())

    @property
    def enabled(self) -> bool:
        return self.keyring is not None and self.cipher.algorithm != "none"

    def seal(self, plaintext: bytes, *, tenant: str, sha256: str) -> tuple[bytes, dict]:
        """Return (stored_bytes, envelope_meta). aad binds the ciphertext to its address."""
        if not self.enabled or self.keyring is None:
            return plaintext, {"algorithm": "none", "key_id": None, "encrypted": False}
        key = self.keyring.data_key(tenant)
        sealed = self.cipher.seal(plaintext, key, aad=sha256.encode())
        return sealed, {"algorithm": self.cipher.algorithm, "key_id": self.keyring.key_id,
                        "encrypted": True}

    def open(self, stored: bytes, *, tenant: str, sha256: str, meta: dict) -> bytes:
        if not meta.get("encrypted") or self.keyring is None:
            return stored
        key = self.keyring.data_key(tenant)
        return self.cipher.open(stored, key, aad=sha256.encode())
