"""
jwt_auth.py
===========
OIDC / JWT bearer verification (Wave 4, FUR-CMP-004). This replaces the
API-key stopgap for real deployments: an identity provider (Okta, Entra,
Auth0, Keycloak…) issues signed JWTs and Furix verifies them and maps the
claims to a Principal (tenant + role).

Two verification paths:
  * HS256 (shared secret) — implemented with the standard library only, so it
    works and is testable with zero extra dependencies. Suitable for symmetric
    setups and testing.
  * RS256 (JWKS) — the asymmetric path used by most public IdPs. Implemented
    against the `cryptography`/`PyJWT` libraries when present; when they are
    absent the path raises a clear "RS256 verification requires ..." error
    rather than silently accepting anything.

Verification always enforces: signature, `exp` (not expired), `nbf` (not
before), and — when configured — the expected `iss` and `aud`. The tenant and
role come from configurable claims and are never trusted without a valid
signature first.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


class JWTError(Exception):
    """JWT verification failed."""


@dataclass(frozen=True)
class OIDCConfig:
    hs256_secret: str = ""
    issuer: str = ""
    audience: str = ""
    tenant_claim: str = "tenant"
    role_claim: str = "role"
    jwks_url: str = ""          # RS256 path (guarded)
    leeway_seconds: int = 60

    @property
    def enabled(self) -> bool:
        return bool(self.hs256_secret or self.jwks_url)

    @classmethod
    def from_env(cls) -> "OIDCConfig":
        import os
        return cls(
            hs256_secret=os.environ.get("FURIX_OIDC_HS256_SECRET", ""),
            issuer=os.environ.get("FURIX_OIDC_ISSUER", ""),
            audience=os.environ.get("FURIX_OIDC_AUDIENCE", ""),
            tenant_claim=os.environ.get("FURIX_OIDC_TENANT_CLAIM", "tenant"),
            role_claim=os.environ.get("FURIX_OIDC_ROLE_CLAIM", "role"),
            jwks_url=os.environ.get("FURIX_OIDC_JWKS_URL", ""),
        )


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2 and all(token.split("."))


def _verify_hs256(signing_input: bytes, signature: bytes, secret: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def verify_jwt(token: str, config: OIDCConfig, *, now: int | None = None) -> dict[str, Any]:
    """
    Verify a JWT and return its claims, or raise JWTError. `now` (unix seconds)
    is injectable for deterministic tests; defaults to the real clock.
    """
    if not looks_like_jwt(token):
        raise JWTError("not a JWT")
    now = int(time.time()) if now is None else now
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(_b64url_decode(h_b64))
        claims = json.loads(_b64url_decode(p_b64))
        signature = _b64url_decode(s_b64)
    except (ValueError, json.JSONDecodeError) as e:
        raise JWTError(f"malformed JWT: {e}") from e

    alg = header.get("alg")
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    if alg == "HS256":
        if not config.hs256_secret:
            raise JWTError("HS256 token but no FURIX_OIDC_HS256_SECRET configured")
        if not _verify_hs256(signing_input, signature, config.hs256_secret):
            raise JWTError("bad signature")
    elif alg == "RS256":
        _verify_rs256(header, signing_input, signature, config)  # guarded
    else:
        raise JWTError(f"unsupported alg: {alg!r}")

    # standard claim checks
    lee = config.leeway_seconds
    if "exp" in claims and now > int(claims["exp"]) + lee:
        raise JWTError("token expired")
    if "nbf" in claims and now + lee < int(claims["nbf"]):
        raise JWTError("token not yet valid")
    if config.issuer and claims.get("iss") != config.issuer:
        raise JWTError("issuer mismatch")
    if config.audience:
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if config.audience not in auds:
            raise JWTError("audience mismatch")
    return claims


def _verify_rs256(header: dict, signing_input: bytes, signature: bytes, config: OIDCConfig) -> None:
    """RS256/JWKS verification — requires an optional crypto dependency."""
    try:
        import jwt as _pyjwt  # noqa: PLC0415  (PyJWT, optional)
        from jwt import PyJWKClient  # noqa: PLC0415
    except ImportError as e:  # pragma: no cover - depends on optional dep
        raise JWTError(
            "RS256 verification requires PyJWT + cryptography (pip install 'pyjwt[crypto]') "
            "and FURIX_OIDC_JWKS_URL"
        ) from e
    if not config.jwks_url:  # pragma: no cover
        raise JWTError("RS256 token but no FURIX_OIDC_JWKS_URL configured")
    # PyJWT does the full verification against the JWKS; re-raise as JWTError
    try:  # pragma: no cover - exercised only when the dep is installed
        token = signing_input.decode() + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
        signing_key = PyJWKClient(config.jwks_url).get_signing_key_from_jwt(token)
        _pyjwt.decode(token, signing_key.key, algorithms=["RS256"],
                      audience=config.audience or None, issuer=config.issuer or None)
    except Exception as e:  # pragma: no cover
        raise JWTError(f"RS256 verification failed: {e}") from e


def make_hs256_token(claims: dict[str, Any], secret: str) -> str:
    """Mint an HS256 JWT (for tests and symmetric service-to-service tokens)."""
    def _enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    header = _enc({"alg": "HS256", "typ": "JWT"})
    payload = _enc(claims)
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"
