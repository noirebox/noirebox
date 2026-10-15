from __future__ import annotations

import hashlib
import hmac
import os
import time

import jwt
from fastapi import HTTPException, Request

DEFAULT_CLIENTS = {"demo": "demo-secret"}


def load_clients() -> dict[str, str]:
    """Reads NOIREBOX_CLIENTS ("id:secret,id2:secret2"), otherwise the demo client.

    NB-01: a SET-but-unparseable NOIREBOX_CLIENTS is a misconfiguration,
    never a silent fallback. An operator who wrote a malformed value
    believes their credentials are live; falling back to the publicly-known
    demo pair behind that belief is the fail-open. The process refuses to
    start instead (id:secret pairs with an empty half are skipped; the
    raise fires only when NOTHING valid remains).
    """
    raw = os.environ.get("NOIREBOX_CLIENTS")
    if raw is None or not raw.strip():
        return dict(DEFAULT_CLIENTS)
    clients: dict[str, str] = {}
    for pair in raw.split(","):
        if ":" in pair:
            client_id, secret = pair.split(":", 1)
            if client_id.strip() and secret.strip():
                clients[client_id.strip()] = secret.strip()
    if not clients:
        raise RuntimeError(
            "NOIREBOX_CLIENTS is set but holds no valid id:secret pair — "
            "refusing to fall back to the demo credentials (NB-01); fix the "
            "value (format: id:secret,id2:secret2) or unset it")
    return clients


TOKEN_TTL_SECONDS = 3600

# NB-01: the derived secret is cached per key PATH — _jwt_secret is called
# on every token issue and every authenticated request, and re-reading (or,
# worse, re-creating) the key file per request was both a disk round-trip
# on the hot path and a parasite-file creator for embedders.
_jwt_secret_cache: dict[str, str] = {}

# NB-07: the limiter's identity table is bounded even against a flood of
# FRESH ids (each attacker-chosen client_id opens a new bucket inside the
# window, which no expiry sweep can drop): past 2048 identities the
# insertion-order oldest loses its bucket first.
_MAX_TRACKED_IDENTITIES = 2048


def jwt_secret_from_key(key) -> str:
    """Derives the JWT signing secret from an ALREADY-LOADED instance key —
    the same derivation as `_jwt_secret`, without touching the disk.
    `create_app` holds the key in memory; threading the derivation through
    it means the token path can never race ahead and load_or_create a key
    file the app did not choose (the NB-01 desync)."""
    return hashlib.sha256(key.private_bytes_raw()).hexdigest()


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

    key_path = os.environ.get("NOIREBOX_DB", "data/noirebox.db") + ".key"
    cached = _jwt_secret_cache.get(key_path)
    if cached is None:
        cached = hashlib.sha256(
            KeyPair.load_or_create(key_path).private_bytes_raw()).hexdigest()
        _jwt_secret_cache[key_path] = cached
    return cached


def issue_token(client_id: str, client_secret: str, clients: dict[str, str] | None = None,
                jwt_secret: str | None = None) -> str | None:
    """Exchanges an id/secret pair for a 1 h JWT. None if credentials are invalid.

    Constant-time comparison (`hmac.compare_digest`) — the SQL injection
    lesson applied to timing: reveal nothing through request duration.
    `jwt_secret` (NB-01): the app's already-loaded key derivation — when
    omitted, the env/derived default resolves as before (tests, CLI).
    """
    clients = clients if clients is not None else load_clients()
    expected = clients.get(client_id)
    if expected is None or not hmac.compare_digest(expected.encode(), client_secret.encode()):
        return None
    now = int(time.time())
    payload = {"sub": client_id, "iat": now, "exp": now + TOKEN_TTL_SECONDS, "scope": "api"}
    return jwt.encode(payload, jwt_secret or _jwt_secret(), algorithm="HS256")


def verify_token(token: str, jwt_secret: str | None = None) -> str | None:
    """Verifies signature + expiration. Returns the client_id, None if invalid."""
    try:
        payload = jwt.decode(token, jwt_secret or _jwt_secret(), algorithms=["HS256"])
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
        """Returns (allowed?, remaining quota). Purges expired hits along the way.

        NB-07: when the table grows past 1000 identities (a limiter keyed by
        IP or by ephemeral ids), identities that never come back held their
        buckets forever — an opportunistic sweep drops every expired bucket;
        a hard cap evicts the insertion-order oldest when a fresh-id flood
        keeps the table above the bound anyway."""
        now = now if now is not None else time.monotonic()
        if len(self._hits) > 1000:
            self._hits = {cid: hits for cid, hits in self._hits.items()
                          if any(now - t < self.window for t in hits)}
        while len(self._hits) >= _MAX_TRACKED_IDENTITIES:
            self._hits.pop(next(iter(self._hits)))
        bucket = [t for t in self._hits.get(client_id, []) if now - t < self.window]
        if len(bucket) >= self.max:
            self._hits[client_id] = bucket
            return False, 0
        bucket.append(now)
        self._hits[client_id] = bucket
        return True, self.max - len(bucket)


def build_auth_dependency(clients: dict[str, str] | None = None,
                          limiter: RateLimiter | None = None,
                          enabled: bool = True,
                          jwt_secret: str | None = None):
    """Returns the FastAPI dependency `require_auth`.

    Why a factory: tests inject their own clients/limits without touching
    env vars — same pattern as `create_app(db_path)`.
    `jwt_secret` (NB-01): the app's derived signing secret, resolved once
    from the loaded instance key; verification then never re-reads a key
    file behind the app's back.
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
        client_id = verify_token(header.removeprefix("Bearer ").strip(),
                                 jwt_secret=jwt_secret)
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
