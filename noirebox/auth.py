from __future__ import annotations

import hashlib
import hmac
import os
import time

import jwt
from fastapi import HTTPException, Request

DEFAULT_CLIENTS = {"demo": "demo-secret"}


def load_clients() -> dict[str, str]:
    """Reads NOIREBOX_CLIENTS ("id:secret,id2:secret2"), otherwise the demo client."""
    raw = os.environ.get("NOIREBOX_CLIENTS", "")
    clients: dict[str, str] = {}
    for pair in raw.split(","):
        if ":" in pair:
            client_id, secret = pair.split(":", 1)
            clients[client_id.strip()] = secret.strip()
    return clients or dict(DEFAULT_CLIENTS)


TOKEN_TTL_SECONDS = 3600


def _jwt_secret() -> str:
    """JWT signing secret: NOIREBOX_JWT_SECRET, otherwise derived from the
    instance PRIVATE key (every deployment signs with something unique).

    The derivation must never touch public data: the public key ships in
    every export/attestation and is served openly at /api/v1/attestation —
    a secret derived from it is derivable by anyone (ADR 014). The private
    key file is chmod 600 and read by this process alone; whoever holds it
    already owns the journal.
    """
    secret = os.environ.get("NOIREBOX_JWT_SECRET")
    if secret:
        return secret
    from .chain import KeyPair

    key = KeyPair.load_or_create(os.environ.get("NOIREBOX_DB", "data/noirebox.db") + ".key")
    return hashlib.sha256(key.private_bytes_raw()).hexdigest()


def issue_token(client_id: str, client_secret: str, clients: dict[str, str] | None = None) -> str | None:
    """Exchanges an id/secret pair for a 1 h JWT. None if credentials are invalid.

    Constant-time comparison (`hmac.compare_digest`) — the SQL injection
    lesson applied to timing: reveal nothing through request duration.
    """
    clients = clients if clients is not None else load_clients()
    expected = clients.get(client_id)
    if expected is None or not hmac.compare_digest(expected.encode(), client_secret.encode()):
        return None
    now = int(time.time())
    payload = {"sub": client_id, "iat": now, "exp": now + TOKEN_TTL_SECONDS, "scope": "api"}
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def verify_token(token: str) -> str | None:
    """Verifies signature + expiration. Returns the client_id, None if invalid."""
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None
    return payload.get("sub")


class RateLimiter:
    """Per-client counter over a sliding window.

    In memory, not SQLite: rate limiting must cost ~0 ms and never write to
    the append-only journal (the journal records the business, not the
    traffic). Redis is the multi-process extension.
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max = max_requests
        self.window = window_seconds
        self._hits: dict[str, list[float]] = {}

    def allow(self, client_id: str, now: float | None = None) -> tuple[bool, int]:
        """Returns (allowed?, remaining quota). Purges expired hits along the way."""
        now = now if now is not None else time.monotonic()
        bucket = [t for t in self._hits.get(client_id, []) if now - t < self.window]
        if len(bucket) >= self.max:
            self._hits[client_id] = bucket
            return False, 0
        bucket.append(now)
        self._hits[client_id] = bucket
        return True, self.max - len(bucket)


def build_auth_dependency(clients: dict[str, str] | None = None,
                          limiter: RateLimiter | None = None,
                          enabled: bool = True):
    """Returns the FastAPI dependency `require_auth`.

    Why a factory: tests inject their own clients/limits without touching
    env vars — same pattern as `create_app(db_path)`.
    Auth DISABLED by default locally (enabled=False when no client is
    configured): the quickstart stays friction-free `./start.sh`; enabling
    it means setting NOIREBOX_CLIENTS. Security must not break the demo,
    and activation must be an explicit choice.
    """
    clients = clients if clients is not None else load_clients()
    limiter = limiter or RateLimiter()

    def require_auth(request: Request) -> str:
        if not enabled:
            return "anonymous"
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization: Bearer <token> required",
                                headers={"WWW-Authenticate": "Bearer"})
        client_id = verify_token(header.removeprefix("Bearer ").strip())
        if client_id is None:
            raise HTTPException(status_code=401, detail="invalid or expired token",
                                headers={"WWW-Authenticate": "Bearer"})
        allowed, remaining = limiter.allow(client_id)
        if not allowed:
            raise HTTPException(status_code=429, detail="rate limit exceeded (60 req/min)",
                                headers={"Retry-After": "60"})
        request.state.client_id = client_id
        request.state.quota_remaining = remaining
        return client_id

    return require_auth
