import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from noirebox.attestation import build_attestation
from noirebox.chain import KeyPair
from noirebox.store import EventStore
ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent

from verifier.verifier import verify_export


def _export(tmp_path, nb=3) -> dict:
    store = EventStore(str(tmp_path / "v.db"))
    key = KeyPair.load_or_create(str(tmp_path / "v.key"))
    for i in range(nb):
        store.append("test", {"i": i}, key)
    return {
        "format_version": 1,
        "public_key": key.public_hex(),
        "events": store.all(),
        "attestation": build_attestation(store, key),
    }


def test_valid_export_passes(tmp_path):
    report = verify_export(_export(tmp_path))
    assert report["valid"] is True
    assert report["nb_events_checked"] == 3
    assert report["errors"] == []


def test_modified_payload_fails(tmp_path):
    export = _export(tmp_path)
    export["events"][1]["payload"]["i"] = 999
    report = verify_export(export)
    assert report["valid"] is False
    assert any("invalid hash" in e["reason"] for e in report["errors"])


def test_deleted_event_fails(tmp_path):
    export = _export(tmp_path)
    del export["events"][1]
    report = verify_export(export)
    assert report["valid"] is False


def test_swapped_signature_fails(tmp_path):
    export = _export(tmp_path)
    export["events"][0]["signature"], export["events"][2]["signature"] = (
        export["events"][2]["signature"],
        export["events"][0]["signature"],
    )
    report = verify_export(export)
    assert report["valid"] is False


def test_attestation_head_mismatch_fails(tmp_path):
    export = _export(tmp_path)
    export["attestation"]["head_seq"] = 42
    report = verify_export(export)
    assert report["valid"] is False
    assert any("head_seq" in e["reason"] for e in report["errors"])


def test_missing_attestation_fails(tmp_path):
    export = _export(tmp_path)
    export.pop("attestation")
    report = verify_export(export)
    assert report["valid"] is False
    assert any("attestation missing" in e["reason"] for e in report["errors"])


def test_anchors_without_tooling_are_counted_and_flagged(tmp_path, monkeypatch, capsys):
    """Chain intact ≠ anchoring proven: with openssl absent, the tokens are
    reported (never hidden) but none is cryptographically checked — the CLI
    must print a distinct UNPROVEN warning instead of a clean-looking
    INTACT line, and the report must expose the gap in numbers."""
    import json as _json

    from verifier import verifier as vmod

    store = EventStore(str(tmp_path / "w.db"))
    key = KeyPair.load_or_create(str(tmp_path / "w.key"))
    store.append("test", {"i": 0}, key)
    # An anchor event carrying a token nobody can check without openssl.
    store.append("anchor", {
        "head_seq": 1, "head_hash": store.all()[-1]["event_hash"],
        "tsa": "freetsa", "tsr": "AAAA", "tsa_cert_pem": "-----BEGIN CERTIFICATE-----\n",
    }, key)
    export = {
        "format_version": 1, "public_key": key.public_hex(),
        "events": store.all(), "attestation": build_attestation(store, key),
    }
    monkeypatch.setattr(vmod.shutil, "which", lambda _: None)
    report = vmod.verify_export(export)
    assert report["valid"] is True                       # the chain itself is intact
    assert report["anchors_in_journal"] == 1
    assert report["anchors_checked"] == 0                # nothing cryptographically checked
    assert report["anchors_unverifiable"] == 1           # reported, not hidden

    path = tmp_path / "export.json"
    path.write_text(_json.dumps(export), encoding="utf-8")
    monkeypatch.setattr(vmod.sys, "argv", ["verifier.py", str(path)])
    assert vmod.main() == 0
    out = capsys.readouterr().out
    assert "INTACT" in out
    assert "UNPROVEN" in out and "reported-not-verified" in out


def test_fleet_anchor_root_token_is_verified(tmp_path, monkeypatch):
    """ADR 017 + verifier: a fleet_anchor event carries a TSA token over the
    Merkle ROOT — the verifier checks it like any anchor, digest = root."""
    import json
    import subprocess
    import sys
    import time

    from noirebox.fleet import fleet_anchor

    material = tmp_path / "tsa_material"
    material.mkdir()
    gen = subprocess.run(
        ["bash", str(ROOT / "tsa" / "gen_tsa.sh"), str(material)], capture_output=True)
    assert gen.returncode == 0, gen.stderr.decode()
    import socket as _socket
    with _socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "tsa" / "tsa_server.py"),
         "--material", str(material), "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                import socket as _s2
                _s2.create_connection(("127.0.0.1", port), 0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        monkeypatch.setenv("NOIREBOX_TSA_ALLOWED_HOSTS", "127.0.0.1")
        monkeypatch.setenv("NOIREBOX_TSA_PROFILES", json.dumps(
            [{"name": "self-hosted", "base_url": f"http://127.0.0.1:{port}"}]))

        hub_store = EventStore(str(tmp_path / "hub.db"))
        hub_key = KeyPair.load_or_create(str(tmp_path / "hub.key"))
        member = EventStore(str(tmp_path / "a.db"))
        member.append("test", {"i": 0}, KeyPair.generate())
        result = fleet_anchor([str(tmp_path / "a.db")], hub_store, hub_key)
        root = result["root"]

        # the third-party verifier receives the HUB's export
        events = hub_store.all()
        att = build_attestation(hub_store, hub_key)
        export = {"format_version": 1, "public_key": hub_key.public_hex(),
                  "events": events, "attestation": att}
        report = verify_export(export)
        assert report["valid"] is True
        assert report["fleet_anchors_in_journal"] == 1
        assert report["fleet_anchors_checked"] == 1   # the ROOT token, really checked
        # and the root is the digest the token actually covers
        assert root == events[-1]["payload"]["root"]
    finally:
        server.terminate()


def test_local_witness_fleet_seal_is_not_counted_as_checked(tmp_path):
    """A `witness: local` fleet seal says so in the payload: no token, no
    pretend verification — the counters stay at zero, the report stays honest."""
    from noirebox.fleet import fleet_anchor

    hub_store = EventStore(str(tmp_path / "hub.db"))
    hub_key = KeyPair.generate()
    member = EventStore(str(tmp_path / "a.db"))
    member.append("test", {"i": 0}, KeyPair.generate())
    fleet_anchor([str(tmp_path / "a.db")], hub_store, hub_key, require_witness=False)
    export = {"format_version": 1, "public_key": hub_key.public_hex(),
              "events": hub_store.all(),
              "attestation": build_attestation(hub_store, hub_key)}
    report = verify_export(export)
    assert report["valid"] is True
    assert report["fleet_anchors_in_journal"] == 1
    assert report["fleet_anchors_checked"] == 0   # nothing pretended
