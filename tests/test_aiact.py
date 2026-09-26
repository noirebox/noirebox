"""ADR 010 — AI-Act-shaped event vocabulary + audit-pack."""

import json
from pathlib import Path

import pytest

from noirebox.aiact import (ART12_MAPPING, annexe_iv_2f, audit_pack,
                            incident_event, use_event, verification_event)
from noirebox.chain import KeyPair
from noirebox.store import EventStore

ROOT = Path(__file__).resolve().parent.parent


# --- the builders validate art. 12(3) shapes -------------------------------

def test_use_event_accepts_art12_fields_and_digest_only():
    p = use_event(use_start="2026-09-26T10:00:00+02:00",
                  use_end="2026-09-26T10:00:03+02:00",
                  system_ref="cv-screening#v2",
                  reference_db="candidats-2026",
                  input_digest="ab" * 32,
                  client_id="CLI-42")
    assert p["use_start"] < p["use_end"]
    assert p["input_digest"] == "ab" * 32
    assert p["context"] == {"client_id": "CLI-42"}


def test_use_event_rejects_raw_data_and_bad_shapes():
    with pytest.raises(ValueError, match="sha256"):
        use_event(use_start="2026-09-26T10:00:00Z", use_end="2026-09-26T10:01:00Z",
                  system_ref="s", input_digest="Jean Dupont, 12 rue…")  # raw data!
    with pytest.raises(ValueError, match="use_start"):
        use_event(use_start="2026-09-26T10:01:00Z", use_end="2026-09-26T10:00:00Z",
                  system_ref="s")
    with pytest.raises(ValueError, match="ISO 8601"):
        use_event(use_start="demain matin", use_end="2026-09-26T10:00:00Z",
                  system_ref="s")


def test_verification_and_incident_events():
    p = verification_event(human_verifier="j.martin", decision="confirmé",
                           use_seq=3)
    assert p["human_verifier"] == "j.martin" and p["use_seq"] == 3
    with pytest.raises(ValueError, match="human_verifier"):
        verification_event(human_verifier="  ", decision="ok")
    inc = incident_event(severity="serious", description="output leak detected",
                         detected_at="2026-09-26T12:00:00Z")
    assert inc["severity"] == "serious"
    with pytest.raises(ValueError, match="severity"):
        incident_event(severity="catastrophic", description="x",
                       detected_at="2026-09-26T12:00:00Z")
    assert {m["event"] for m in ART12_MAPPING} >= {"ai_use", "ai_verification", "ai_incident"}


# --- the audit-pack: export + verifier report + Annexe IV §2(f) ------------

def test_audit_pack_end_to_end(tmp_path):
    db = str(tmp_path / "journal.db")
    key = KeyPair.load_or_create(db + ".key")
    store = EventStore(db)
    store.append("ai_use", use_event(use_start="2026-09-26T10:00:00Z",
                                     use_end="2026-09-26T10:00:02Z",
                                     system_ref="cv-screening#v2",
                                     input_digest="cd" * 32), key)
    store.append("ai_verification",
                 verification_event(human_verifier="j.martin", decision="confirmé"), key)
    store.append("ai_incident", incident_event(severity="minor",
                                               description="false positive reviewed",
                                               detected_at="2026-09-26T10:05:00Z"), key)

    outdir = tmp_path / "pack"
    from verifier.verifier import verify_export  # noqa: F401  (import path bootstrap)

    report = audit_pack(store, key, outdir)
    assert report["valid"] is True and report["nb_events_checked"] == 3

    export = json.loads((outdir / "export.json").read_text())
    assert len(export["events"]) == 3
    rep = json.loads((outdir / "verifier_report.json").read_text())
    assert rep == report
    annexe = (outdir / "ANNEXE-IV-2f.md").read_text()
    assert "Annexe IV §2(f)" in annexe
    assert "`ai_use` ×1" in annexe          # real histogram, not boilerplate
    assert "12(3)(a)" in annexe             # the mapping table
    assert key.public_hex() in annexe       # auditor can pin the key
    assert "none yet" in annexe             # honest: no anchors configured here


def test_annexe_reports_witnesses_when_anchored(tmp_path):
    db = str(tmp_path / "j2.db")
    key = KeyPair.load_or_create(db + ".key")
    store = EventStore(db)
    store.append("ai_use", use_event(use_start="2026-09-26T10:00:00Z",
                                     use_end="2026-09-26T10:00:02Z",
                                     system_ref="s"), key)
    # a hand-built anchor payload (no network in this test — the annexe only
    # reads witness names out of the events)
    head = store.all()[-1]["event_hash"]
    store.append("anchor", {"head_seq": 1, "head_hash": head, "tsa": "witness-test",
                            "tsr": "AAA", "tsa_cert_pem": "-----"},
                 key)
    text = annexe_iv_2f(store.all(), {"valid": True, "nb_events_checked": 2,
                                      "anchors_checked": 0, "anchors_pinned": 0},
                        key.public_hex())
    assert "`witness-test`" in text
