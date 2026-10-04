import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from noirebox.attestation import build_attestation
from noirebox.chain import KeyPair
from noirebox.store import EventStore
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
