from __future__ import annotations

import base64
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .chain import GENESIS, KeyPair
from .store import EventStore

GENESIS_HASH = GENESIS

# Egress from the journal server is allowlisted (ADR 008): a TSA profile can
# only reach a host the operator explicitly allowed. Loopback is in the
# default set because the self-hosted TSA (`make tsa`) runs on 127.0.0.1.
DEFAULT_ALLOWED_HOSTS = ("127.0.0.1", "::1", "localhost")

# Single shared client: the no-redirect policy is set ONCE, centrally (an
# anchored endpoint cannot bounce a request elsewhere), connections are reused.
_TSA_HTTP = httpx.Client(follow_redirects=False, timeout=10)


def _allowed_hosts() -> set[str]:
    raw = os.environ.get("NOIREBOX_TSA_ALLOWED_HOSTS")
    if raw:
        return {h.strip().lower() for h in raw.split(",") if h.strip()}
    return set(DEFAULT_ALLOWED_HOSTS)


def tsa_configured() -> bool:
    return bool(os.environ.get("NOIREBOX_TSA_URL")
                or os.environ.get("NOIREBOX_TSA_PROFILES"))


def load_profiles() -> list[dict]:
    """TSA profiles (ADR 008 — multi-witness anchoring).

    NOIREBOX_TSA_PROFILES: JSON list of
        {"name": str,                       # matches verifier/tsa_roots/<name>.pem if pinned
         "url": str,                        # direct RFC 3161 POST endpoint (external TSAs)
         "cert_url": str (optional)}        # where to fetch the TSA certificate;
                                            # absent → the chain is extracted from the token
                                            # (the query always asks for it, RFC 3161 certReq)
    NOIREBOX_TSA_URL (legacy, self-hosted): base URL — the client appends /tsa and /cert.
    """
    raw = os.environ.get("NOIREBOX_TSA_PROFILES")
    if raw:
        profiles = json.loads(raw)
        if not isinstance(profiles, list) or not profiles:
            raise RuntimeError("NOIREBOX_TSA_PROFILES must be a non-empty JSON list")
        return profiles
    legacy = os.environ.get("NOIREBOX_TSA_URL")
    if legacy:
        return [{"name": "self-hosted", "base_url": legacy.rstrip("/")}]
    return []


def _checked_endpoint(url: str) -> str:
    """Egress control on TSA endpoints before any request (ADR 008).

    Fail-closed allowlist: the host must be in NOIREBOX_TSA_ALLOWED_HOSTS
    (default: loopback only, for `make tsa`). The URL must be a plain
    http(s) endpoint without embedded credentials. After the allowlist, the
    host is DNS-resolved and link-local results (169.254.0.0/16 — the
    cloud-metadata SSRF prize, fe80::/10) are refused even if the name was
    allowlisted: no legitimate TSA lives there, and resolution-time checking
    is what closes the rebinding window. Redirects are never followed
    (shared client, follow_redirects=False), so an endpoint cannot bounce
    the request elsewhere.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or (parsed.username or parsed.password):
        raise RuntimeError(f"TSA endpoint must be a plain http(s) URL: {url[:80]}")
    host = (parsed.hostname or "").lower()
    if host not in _allowed_hosts():
        raise RuntimeError(
            f"TSA host {host!r} is not allowed — add it to NOIREBOX_TSA_ALLOWED_HOSTS "
            f"(explicit egress allowlist, ADR 008)")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise RuntimeError(f"TSA endpoint does not resolve: {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_link_local:
            raise RuntimeError(f"allowlisted TSA host {host!r} resolves to a "
                               f"link-local address (cloud-metadata range)")
    return url


def build_query(head_hash: str) -> bytes:
    """Builds the timestamp request (TimeStampReq, DER) via OpenSSL.

    The DIGEST (hex) is passed directly — the TSA never sees the data;
    a 32-byte hash tells no one anything.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out = f"{tmp}/req.tsq"
        proc = subprocess.run(
            ["openssl", "ts", "-query", "-digest", head_hash, "-sha256", "-cert", "-out", out],
            capture_output=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"openssl ts -query failed: {proc.stderr.decode()[:200]}")
        with open(out, "rb") as f:
            return f.read()


def request_token_at(head_hash: str, post_url: str) -> bytes:
    """Sends the request to a concrete RFC 3161 endpoint, returns the
    TimeStampResp token (DER)."""
    response = _TSA_HTTP.post(
        _checked_endpoint(post_url).rstrip("/"),
        content=build_query(head_hash),
        headers={"Content-Type": "application/timestamp-query"},
    )
    if response.status_code != 200:
        raise RuntimeError(f"TSA {post_url} responded {response.status_code}")
    return response.content


def request_token(head_hash: str, tsa_url: str | None = None) -> bytes:
    """Legacy self-hosted style: base URL, the client appends /tsa."""
    base = (tsa_url or os.environ.get("NOIREBOX_TSA_URL", "")).rstrip("/")
    return request_token_at(head_hash, f"{base}/tsa")


def fetch_tsa_cert(tsa_url: str | None = None) -> str:
    """Fetches the TSA certificate (it travels INSIDE the anchor — the third
    party needs it to verify the token; TOFU + pinning possible, ADR 006)."""
    base = (tsa_url or os.environ["NOIREBOX_TSA_URL"]).rstrip("/")
    response = _TSA_HTTP.get(_checked_endpoint(f"{base}/cert"))
    response.raise_for_status()
    return response.text


def _fetch_cert_url(cert_url: str) -> str:
    response = _TSA_HTTP.get(_checked_endpoint(cert_url))
    response.raise_for_status()
    return response.text


def extract_token_certs(token: bytes) -> str:
    """Certificate chain carried INSIDE the token (the query asks for it with
    certReq=true — DigiCert embeds root+intermediate+signer this way).
    Returns a PEM bundle, or "" when the TSA omitted its chain: such a
    profile must be given a cert_url instead."""
    with tempfile.TemporaryDirectory() as tmp:
        resp, p7, out = Path(tmp) / "resp.tsr", Path(tmp) / "token.p7", Path(tmp) / "chain.pem"
        resp.write_bytes(token)
        proc = subprocess.run(
            ["openssl", "ts", "-reply", "-in", str(resp), "-token_out", "-out", str(p7)],
            capture_output=True,
        )
        if proc.returncode != 0:
            return ""
        proc = subprocess.run(
            ["openssl", "pkcs7", "-inform", "DER", "-in", str(p7),
             "-print_certs", "-out", str(out)],
            capture_output=True,
        )
        if proc.returncode != 0:
            return ""
        return out.read_text(encoding="ascii")


def _token_for(profile: dict, head_hash: str) -> dict:
    """One witness token: the TSA signs the head hash, we attach its certificate."""
    if "base_url" in profile:
        post_url = f"{_checked_endpoint(profile['base_url']).rstrip('/')}/tsa"
        cert_pem = fetch_tsa_cert(profile["base_url"])
    else:
        post_url = profile["url"]
        cert_pem = ""
    token = request_token_at(head_hash, post_url)
    if not cert_pem:
        cert_url = profile.get("cert_url")
        cert_pem = (_fetch_cert_url(cert_url) if cert_url
                    else extract_token_certs(token))
    if not cert_pem:
        raise RuntimeError(f"TSA {profile.get('name', post_url)}: no certificate "
                           f"embedded in the token and no cert_url configured")
    return {"tsa": profile.get("name", post_url),
            "tsr": base64.b64encode(token).decode("ascii"),
            "tsa_cert_pem": cert_pem}


def anchor_now(store: EventStore, key: KeyPair, tsa_url: str | None = None,
               profiles: list[dict] | None = None) -> dict:
    """Seals the current chain head to one or several TSAs (ADR 006 + 008).

    Single profile → the payload keeps the exact legacy flat shape
    (tsr + tsa_cert_pem): old verifiers stay happy. Several profiles → the
    flat fields mirror the PRIMARY token (first in the list — put the
    qualified eIDAS TSA first) so an OLD verifier still checks a real token,
    and the full witness list travels in `tokens` for the new verifier.
    """
    events = store.all()
    head_seq = len(events)
    head_hash = events[-1]["event_hash"] if events else GENESIS_HASH

    if profiles is None:
        if tsa_url:
            profiles = [{"name": "self-hosted", "base_url": tsa_url.rstrip("/")}]
        else:
            profiles = load_profiles()

    tokens = [_token_for(profile, head_hash) for profile in profiles]
    primary = tokens[0]
    payload = {"head_seq": head_seq, "head_hash": head_hash,
               "tsr": primary["tsr"], "tsa_cert_pem": primary["tsa_cert_pem"],
               "tsa": primary["tsa"]}
    if len(tokens) > 1:
        payload["tokens"] = tokens

    event = store.append("anchor", payload, key)
    return {
        "anchor_event_seq": event.seq,
        "anchored_head_seq": head_seq,
        "anchored_head_hash": head_hash,
        "tsr_bytes": len(primary["tsr"]),
        "tsas": [t["tsa"] for t in tokens],
    }
