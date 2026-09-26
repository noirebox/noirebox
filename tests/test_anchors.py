import base64
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from noirebox.anchors import build_query, request_token
from noirebox.attestation import build_attestation
from noirebox.chain import KeyPair
from noirebox.main import create_app
from noirebox.store import EventStore

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    subprocess.run(["which", "openssl"], capture_output=True).returncode != 0,
    reason="openssl not available",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def tsa_url(tmp_path_factory):
    """Generate the TSA material and start the local TSA server once for all tests."""
    material = tmp_path_factory.mktemp("tsa_material")
    gen = subprocess.run(
        ["bash", str(ROOT / "tsa" / "gen_tsa.sh"), str(material)],
        capture_output=True,
    )
    assert gen.returncode == 0, gen.stderr.decode()
    port = _free_port()
    server = subprocess.Popen(
        [sys_executable(), str(ROOT / "tsa" / "tsa_server.py"),
         "--material", str(material), "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            import httpx

            httpx.get(f"{base}/cert", timeout=1)
            break
        except Exception:
            time.sleep(0.05)
    yield base
    server.terminate()


def sys_executable() -> str:
    import sys

    return sys.executable


@pytest.fixture()
def client_tsa(tsa_url, tmp_path, monkeypatch):
    """App with TSA configured + auth disabled."""
    monkeypatch.setenv("NOIREBOX_TSA_URL", tsa_url)
    return TestClient(create_app(str(tmp_path / "anchor.db")))


def test_anchor_503_without_tsa(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_TSA_URL", raising=False)
    monkeypatch.delenv("NOIREBOX_TSA_PROFILES", raising=False)
    client = TestClient(create_app(str(tmp_path / "notsa.db")))
    r = client.post("/api/v1/anchors")
    assert r.status_code == 503
    assert "NOIREBOX_TSA_URL" in r.json()["detail"]


def test_anchor_seals_chain_head(client_tsa):
    client_tsa.post("/api/v1/events", json={"type": "llm_call", "payload": {"prompt": "résume"}})
    r = client_tsa.post("/api/v1/anchors")
    assert r.status_code == 201
    body = r.json()
    assert body["anchored_head_seq"] == 1
    assert body["anchor_event_seq"] == 2


def test_export_with_anchor_verifies_as_third_party(client_tsa):
    """The full auditor scenario: chain + TSA token + certificate."""
    client_tsa.post("/api/v1/events", json={"type": "llm_call", "payload": {"p": 1}})
    client_tsa.post("/api/v1/anchors")
    export = client_tsa.get("/api/v1/export").json()

    from verifier.verifier import verify_export

    report = verify_export(export)
    assert report["valid"] is True, report["errors"]
    assert report["anchors_checked"] == 1


def test_insider_regeneration_is_caught_by_anchor(tsa_url, tmp_path):
    """THE threat-model test: an insider with the PRIVATE key regenerates the
    whole chain (consistent fingerprints, real signatures). The chain becomes
    "valid"... but the old TSA token does not cover the new head.
    This is the only control that exposes it."""

    h_old = "ab" * 32
    token = request_token(h_old, tsa_url)
    cert_pem = __import__("httpx").get(f"{tsa_url}/cert", timeout=5).text



    key = KeyPair.generate()
    store = EventStore(str(tmp_path / "forged.db"))
    store.append("llm_output", {"compte_rendu": "FALSIFIÉ, chaîne régénérée"}, key)
    h_new = store.all()[-1]["event_hash"]
    store.append("anchor", {"head_seq": 2, "head_hash": h_new,
                            "tsr": base64.b64encode(token).decode("ascii"),
                            "tsa_cert_pem": cert_pem}, key)
    export = {"format_version": 1, "public_key": key.public_hex(),
              "events": store.all(), "attestation": build_attestation(store, key)}

    from verifier.verifier import verify_export

    report = verify_export(export)
    assert report["valid"] is False
    assert any("anchor" in e["reason"] for e in report["errors"])


def test_query_contains_only_a_hash_not_data():
    """The TSA never sees the data: the request only carries a digest."""
    query = build_query("cd" * 32)
    assert len(query) < 200

    assert query[0] == 0x30


def test_single_profile_keeps_legacy_flat_payload(client_tsa):
    """One TSA → the payload shape is exactly the v0.3.0 flat one: an OLD
    verifier (which reads tsr/tsa_cert_pem directly) must keep working."""
    client_tsa.post("/api/v1/anchors")
    payload = client_tsa.get("/api/v1/export").json()["events"][-1]["payload"]
    assert "tokens" not in payload
    assert payload["tsr"] and payload["tsa_cert_pem"]


def test_multi_tsa_anchor_all_tokens_verified(tsa_url, tmp_path, monkeypatch):
    """Two witnesses behind ONE anchor event. The flat fields mirror the
    primary token (old-verifier compatibility) and the new verifier checks
    every token."""
    monkeypatch.setenv("NOIREBOX_TSA_PROFILES", json.dumps([
        {"name": "primary", "base_url": tsa_url},
        {"name": "witness", "url": f"{tsa_url}/tsa", "cert_url": f"{tsa_url}/cert"},
    ]))
    client = TestClient(create_app(str(tmp_path / "multi.db")))
    client.post("/api/v1/events", json={"type": "llm_call", "payload": {"p": 1}})
    r = client.post("/api/v1/anchors")
    assert r.status_code == 201
    assert r.json()["tsas"] == ["primary", "witness"]

    export = client.get("/api/v1/export").json()
    payload = [e for e in export["events"] if e["type"] == "anchor"][0]["payload"]
    assert len(payload["tokens"]) == 2
    assert payload["tsr"] == payload["tokens"][0]["tsr"]

    from verifier.verifier import verify_export

    report = verify_export(export)
    assert report["valid"] is True, report["errors"]
    assert report["anchors_checked"] == 2
    assert report["anchors_pinned"] == 0  # no roots pinned for these names


def test_pinned_root_stronger_than_tofu_and_catches_swapped_tsa(
        tsa_url, tmp_path, monkeypatch):
    """ADR 008 policy: a pinned root makes the verifier independent from the
    certificate the operator ships. Positive: the honest bundle verifies and
    is reported as pinned. Negative: swap the pinned root for a rogue TSA's
    root — the same (honest) token must now FAIL, proving the pin actually
    binds the verification to the auditor's choice of root."""
    rogue_material = tmp_path / "rogue_material"
    gen = subprocess.run(["bash", str(ROOT / "tsa" / "gen_tsa.sh"), str(rogue_material)],
                         capture_output=True)
    assert gen.returncode == 0, gen.stderr.decode()
    rogue_root = (rogue_material / "root.pem").read_text()

    roots = tmp_path / "roots"
    roots.mkdir()
    import httpx

    good_bundle = httpx.get(f"{tsa_url}/cert", timeout=5).text
    (roots / "witness.pem").write_text(good_bundle)
    monkeypatch.setenv("NOIREBOX_TSA_ROOTS_DIR", str(roots))
    monkeypatch.setenv("NOIREBOX_TSA_PROFILES",
                       json.dumps([{"name": "witness", "base_url": tsa_url}]))
    client = TestClient(create_app(str(tmp_path / "pinned.db")))
    client.post("/api/v1/events", json={"type": "llm_call", "payload": {"p": 1}})
    client.post("/api/v1/anchors")
    export = client.get("/api/v1/export").json()

    from verifier.verifier import verify_export

    report = verify_export(export)
    assert report["valid"] is True, report["errors"]
    assert report["anchors_pinned"] == 1

    # The swap: same honest journal, auditor pins a DIFFERENT TSA root.
    (roots / "witness.pem").write_text(rogue_root)
    report = verify_export(export)
    assert report["valid"] is False
    assert any("pinned root" in e["reason"] for e in report["errors"])


def test_egress_allowlist_blocks_unknown_host(tmp_path, monkeypatch):
    """SSRF egress control (ADR 008): a TSA endpoint on a non-allowlisted
    host is refused before any request; link-local (cloud metadata) is
    refused even if allowlisted."""
    from noirebox.anchors import _checked_endpoint
    import pytest

    monkeypatch.setenv("NOIREBOX_TSA_ALLOWED_HOSTS", "timestamp.example.com")
    with pytest.raises(RuntimeError, match="not allowed"):
        _checked_endpoint("http://169.254.169.254/tsr")
    with pytest.raises(RuntimeError, match="not allowed"):
        _checked_endpoint("http://evil.internal/tsr")
    with pytest.raises(RuntimeError, match="not allowed"):
        _checked_endpoint("https://freetsa.org/tsr")

    monkeypatch.setenv("NOIREBOX_TSA_ALLOWED_HOSTS", "freetsa.org,169.254.169.254")
    with pytest.raises(RuntimeError, match="link-local"):
        _checked_endpoint("http://169.254.169.254/tsr")
    assert _checked_endpoint("https://freetsa.org/tsr") == "https://freetsa.org/tsr"


@pytest.mark.skipif(shutil.which("ots") is None,
                    reason="ots (opentimestamps-client) not installed")
def test_ots_witness_alongside_tsa(tsa_url, tmp_path, monkeypatch):
    """ADR 009: an OpenTimestamps witness rides in the same anchor event as
    an RFC 3161 TSA. The flat mirror stays the RFC 3161 token (old
    verifiers); the new verifier checks both kinds."""
    monkeypatch.setenv("NOIREBOX_TSA_PROFILES", json.dumps([
        {"name": "witness", "base_url": tsa_url},
        {"name": "bitcoin", "kind": "ots"},
    ]))
    client = TestClient(create_app(str(tmp_path / "ots.db")))
    client.post("/api/v1/events", json={"type": "llm_call", "payload": {"p": 1}})
    r = client.post("/api/v1/anchors")
    assert r.status_code == 201
    assert r.json()["tsas"] == ["witness", "bitcoin"]

    export = client.get("/api/v1/export").json()
    payload = [e for e in export["events"] if e["type"] == "anchor"][0]["payload"]
    kinds = [t.get("kind", "rfc3161") for t in payload["tokens"]]
    assert kinds == ["rfc3161", "ots"]
    assert payload["tsr"] == payload["tokens"][0]["tsr"]  # flat mirror = the RFC 3161 token

    from verifier.verifier import verify_export, verify_ots_token

    report = verify_export(export)
    assert report["valid"] is True, report["errors"]
    assert report["anchors_checked"] >= 1          # the RFC 3161 token
    assert report["anchors_unverifiable"] >= 1     # the fresh OTS receipt: pending, reported

    # The manifest check is pure Python — a manifest naming ANOTHER head is
    # caught even if the `ots` CLI were absent.
    anchor_ev = [e for e in export["events"] if e["type"] == "anchor"][0]
    ots_tok = [t for t in anchor_ev["payload"]["tokens"] if t.get("kind") == "ots"][0]
    ok, reason, _ = verify_ots_token(anchor_ev["payload"], ots_tok)
    assert ok is True  # honest manifest (receipt itself is pending)

    forged = dict(ots_tok)
    manifest = json.loads(base64.b64decode(ots_tok["manifest_b64"]))
    manifest["head_hash"] = "ff" * 32
    forged["manifest_b64"] = base64.b64encode(json.dumps(manifest).encode()).decode()
    ok, reason, _ = verify_ots_token(anchor_ev["payload"], forged)
    assert ok is False and "manifest" in reason


@pytest.mark.skipif(shutil.which("ots") is None,
                    reason="ots (opentimestamps-client) not installed")
def test_ots_only_profile_has_no_flat_mirror(tsa_url, tmp_path, monkeypatch):
    """An OTS-only anchor has no RFC 3161 fields at all — the tokens list is
    the only carrier (documented old-verifier limitation, ADR 009)."""
    monkeypatch.setenv("NOIREBOX_TSA_PROFILES",
                       json.dumps([{"name": "bitcoin", "kind": "ots"}]))
    client = TestClient(create_app(str(tmp_path / "ots_only.db")))
    client.post("/api/v1/anchors")
    payload = client.get("/api/v1/export").json()["events"][-1]["payload"]
    assert "tsr" not in payload
    assert len(payload["tokens"]) == 1 and payload["tokens"][0]["kind"] == "ots"
