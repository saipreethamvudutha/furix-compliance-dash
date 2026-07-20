"""
signing.py
==========
Asymmetric, KMS-backed signatures (Wave-I / Epic 6). The Wave-G manifests and
Wave-N attestations use HMAC — symmetric, so a verifier needs the secret. For an
enterprise audit trail you want **asymmetric** signatures: sign with a private
key that never leaves the signer (ideally a KMS/HSM), and let anyone verify with
the public key alone.

Two `Signer` implementations behind one interface:

* `LocalRsaSigner` — RSA-PSS/SHA-256 via `cryptography`. The private key lives in
  the process (dev / self-managed). Verification needs only the public key.
* `KmsSigner` — AWS KMS `Sign`/`Verify`; the private key never leaves KMS. The
  boto3 KMS client is dependency-injected, so it is fully tested against a stub
  with no network, and swapping in the real client is a constructor argument.

`verify_signature(data, signature, public_key_pem)` verifies with the public key
alone — no secret, so an external auditor can verify a Furix artifact.
"""

from __future__ import annotations

import base64
from typing import Any, Protocol


class SigningError(Exception):
    """Signing or verification failed."""


class Signer(Protocol):
    algorithm: str

    def sign(self, data: bytes) -> str: ...          # base64 signature
    def public_key_pem(self) -> str | None: ...      # None for verify-in-KMS-only


# ── local RSA (cryptography) ──────────────────────────────────────────────────
class LocalRsaSigner:
    """RSA-PSS/SHA-256 signer whose private key lives in-process."""

    algorithm = "RSASSA_PSS_SHA_256"

    def __init__(self, private_key_pem: str):
        try:
            from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover
            raise SigningError("LocalRsaSigner requires the `cryptography` package") from e
        self._key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)

    def sign(self, data: bytes) -> str:
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415
        sig = self._key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.b64encode(sig).decode()

    def public_key_pem(self) -> str | None:
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def private_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        return self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()

    @staticmethod
    def generate() -> "LocalRsaSigner":
        """Generate a fresh RSA key (dev/test)."""
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
        return LocalRsaSigner(pem)


# ── AWS KMS (boto3, injectable) ───────────────────────────────────────────────
class KmsSigner:
    """AWS KMS signer — the private key never leaves KMS. `client` is a boto3
    KMS client (or a stub in tests)."""

    algorithm = "RSASSA_PSS_SHA_256"

    def __init__(self, key_id: str, client: Any):
        self.key_id = key_id
        self._client = client

    def sign(self, data: bytes) -> str:
        resp = self._client.sign(KeyId=self.key_id, Message=data, MessageType="RAW",
                                 SigningAlgorithm=self.algorithm)
        return base64.b64encode(resp["Signature"]).decode()

    def public_key_pem(self) -> str | None:
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        der = self._client.get_public_key(KeyId=self.key_id)["PublicKey"]
        from cryptography.hazmat.primitives.serialization import load_der_public_key  # noqa: PLC0415
        pub = load_der_public_key(der)
        return pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()


# ── public-key verification (no secret) ───────────────────────────────────────
def verify_signature(data: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Verify an RSA-PSS/SHA-256 signature with the PUBLIC key only."""
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover
        raise SigningError("verify_signature requires the `cryptography` package") from e
    pub = serialization.load_pem_public_key(public_key_pem.encode())
    try:
        pub.verify(
            base64.b64decode(signature_b64), data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
