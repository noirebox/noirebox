"""The admission receipt (ADR 026 — You-An Lin, *Capability Is Not
Authority*): build-time gate tests + the `check_admission_basis` join.
A promotion without an independent basis is the reordering a hash chain
catches — except nothing caught it until the promotion itself became a
sealed event."""
from __future__ import annotations

import pytest

from noirebox.chain import KeyPair
from noirebox.reconcile import check_admission_basis, seal_admission
from noirebox.store import EventStore


def _ok(**over) -> dict:
    base = {
        "actor": "agent-7",
        "source_origin": "resident:marlow",
        "source_surface": "shared memory",
        "transition": "visibility→admission",
        "basis": "user instruction 2026-10-17 14:02 ('use marlow's notes')",
        "decision": "admitted",
        "participation_ownership": "foreign",
    }
    base.update(over)
    return base


def _journal(tmp_path, name: str) -> tuple[EventStore, KeyPair]:
    return (EventStore(str(tmp_path / f"{name}.db")),
            KeyPair.load_or_create(str(tmp_path / f"{name}.key")))


# --- the happy path --------------------------------------------------------------

def test_happy_payload_shape(tmp_path):
    store, key = _journal(tmp_path, "adm")
    seal_admission(store, key, **_ok())
    event = store.all()[-1]
    assert event["type"] == "admission"
    p = event["payload"]
    assert p["schema"] == "admission/0.1"
    assert p["source"] == {"origin": "resident:marlow",
                           "surface": "shared memory"}
    assert p["participation_ownership"] == "foreign"
    assert "scope" not in p
    seal_admission(store, key, **_ok(scope=["notes/", "inbox/"]))
    assert store.all()[-1]["payload"]["scope"] == ["notes/", "inbox/"]


# --- the closed vocabularies ------------------------------------------------------

def test_transition_is_lins_four_promotions_named(tmp_path):
    for i, transition in enumerate(("visibility→admission", "capability→move",
                                    "relevance→payload", "style→stance")):
        store, key = _journal(tmp_path, f"adm-t{i}")
        seal_admission(store, key, **_ok(transition=transition))
        assert "transition" in store.all()[-1]["payload"]


def test_unknown_transition_refused(tmp_path):
    store, key = _journal(tmp_path, "adm-tx")
    with pytest.raises(ValueError, match="transition must be one of"):
        seal_admission(store, key, **_ok(transition="vibes→promotion"))


def test_decision_fails_closed_with_named_skips(tmp_path):
    for i, decision in enumerate(("admitted", "denied", "admission_undecidable",
                                  "admission_check_not_run")):
        store, key = _journal(tmp_path, f"adm-d{i}")
        seal_admission(store, key, **_ok(decision=decision))
        assert "decision" in store.all()[-1]["payload"]
    store, key = _journal(tmp_path, "adm-dx")
    with pytest.raises(ValueError, match="undecidable is never clean"):
        seal_admission(store, key, **_ok(decision="fine_presumably"))


def test_participation_ownership_is_a_closed_set(tmp_path):
    store, key = _journal(tmp_path, "adm-p")
    with pytest.raises(ValueError, match="participation_ownership"):
        seal_admission(store, key, **_ok(participation_ownership="mine_now"))


# --- the laundering vocabulary is refused at the door ------------------------------

def test_the_four_never_bases_are_refused(tmp_path):
    """Laws 1–8 name the resources that are never a basis: presence,
    relevance, plausibility, usefulness. The field that exists to carry
    an independent warrant refuses to carry the laundering words."""
    for i, basis in enumerate(("presence", "Relevance",
                               "  plausibility  ", "usefulness")):
        store, key = _journal(tmp_path, f"adm-b{i}")
        with pytest.raises(ValueError, match="never a basis"):
            seal_admission(store, key, **_ok(basis=basis))


def test_empty_basis_refused(tmp_path):
    store, key = _journal(tmp_path, "adm-be")
    with pytest.raises(ValueError, match="basis is required"):
        seal_admission(store, key, **_ok(basis="   "))


def test_scope_validation(tmp_path):
    store, key = _journal(tmp_path, "adm-s")
    with pytest.raises(ValueError, match="scope must be a non-empty list"):
        seal_admission(store, key, **_ok(scope=[""]))
    with pytest.raises(ValueError, match="scope must be a non-empty list"):
        seal_admission(store, key, **_ok(scope="notes/"))


# --- the reconciliation join --------------------------------------------------------

def test_foreign_content_without_admission_is_a_gap(tmp_path):
    """Lin §6.3: attribution correct, admission invalid, every
    output-level metric green — the gap is the finding, not the
    attribution."""
    store, key = _journal(tmp_path, "adm-j1")
    store.append("content", {"origin": "resident:marlow",
                             "text_digest": "a" * 64}, key)
    findings = check_admission_basis(store.all())
    assert [f.status for f in findings] == ["admission_gap"]
    assert findings[0].correlation_id == "resident:marlow"


def test_admitted_before_use_is_clean(tmp_path):
    store, key = _journal(tmp_path, "adm-j2")
    seal_admission(store, key, **_ok())
    store.append("content", {"origin": "resident:marlow",
                             "text_digest": "a" * 64}, key)
    assert check_admission_basis(store.all()) == []


def test_admission_after_the_use_clears_nothing(tmp_path):
    """The basis must precede the promotion it warrants — sealing the
    admission after the material already shaped the output is the
    retroactive warrant, and retroactive warrants are reordering."""
    store, key = _journal(tmp_path, "adm-j3")
    store.append("content", {"origin": "resident:marlow",
                             "text_digest": "a" * 64}, key)
    seal_admission(store, key, **_ok())
    assert [f.status for f in check_admission_basis(store.all())] == \
        ["admission_gap"]


def test_undecidable_and_denied_clear_nothing(tmp_path):
    """Fail closed: an admission that is not `admitted` is not a basis —
    undecidable is never clean."""
    store, key = _journal(tmp_path, "adm-j4")
    seal_admission(store, key, **_ok(decision="admission_undecidable"))
    store.append("content", {"origin": "resident:marlow",
                             "text_digest": "a" * 64}, key)
    assert [f.status for f in check_admission_basis(store.all())] == \
        ["admission_gap"]


def test_content_without_origin_is_out_of_scope(tmp_path):
    store, key = _journal(tmp_path, "adm-j5")
    store.append("content", {"text_digest": "b" * 64}, key)
    assert check_admission_basis(store.all()) == []
