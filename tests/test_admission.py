"""Admission receipts (ADR 026 — the schema, the check, the fixtures):
the promotion itself is a signed event with a BOUNDED vocabulary, and
downstream use of foreign-sourced material joins against the citing
actor's OWN receipt, sealed EARLIER, decided `admitted`. The statuses
fail closed: a receipt that does not admit proves nothing, a receipt
sealed after the use resurrects nothing, an undeclared ownership is
reported — never folded into clean."""
from __future__ import annotations

import pytest

from noirebox.chain import KeyPair, verify_chain_multi
from noirebox.reconcile import check_admission_basis, seal_admission
from noirebox.store import EventStore


def _store(tmp_path, name="admission.db"):
    return EventStore(str(tmp_path / name)), KeyPair.generate()


def _admit(store, key, *, decision="admitted", origin="resident-7/history",
           surface="session-handoff", actor="agent-a", refs=None,
           transition="visibility→admission", basis_kind="user-instruction",
           basis_ref="turn-12", participation_ownership="foreign"):
    return seal_admission(store, key, actor=actor, origin=origin,
                          surface=surface,
                          transition=transition,
                          basis_kind=basis_kind, basis_ref=basis_ref,
                          decision=decision,
                          participation_ownership=participation_ownership,
                          refs=refs or {"session_id": "s1"})


def _use(store, key, *, origin="resident-7/history", actor="agent-a",
         ownership="foreign", refs=None, use_type="payload_content"):
    return store.append(use_type, {
        "session_id": (refs or {}).get("session_id", "s1"),
        "source": {"origin": origin, "surface": "session-handoff"},
        "participation_ownership": ownership,
        "actor": actor,
    }, key)


# --- the schema: bounded vocabularies, fail-closed at seal time --------------

def test_seal_admission_seals_and_chains(tmp_path):
    store, key = _store(tmp_path)
    event = _admit(store, key)
    assert event.type == "admission"
    payload = event.payload
    assert payload["schema"] == "admission/0.1"
    assert payload["source"] == {"origin": "resident-7/history",
                                 "surface": "session-handoff"}
    assert payload["basis"] == {"kind": "user-instruction", "ref": "turn-12"}
    assert payload["participation_ownership"] == "foreign"
    assert payload["session_id"] == "s1"
    assert verify_chain_multi([key.public_hex()], store.all())["valid"]


def test_transition_vocabulary_is_lins_four_promotions(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="protocol vocabulary"):
        _admit(store, key, transition="it seemed important")
    with pytest.raises(ValueError, match="protocol vocabulary"):
        _admit(store, key, transition="presence→admission")


def test_basis_refuses_the_negative_space(tmp_path):
    """Presence, relevance, plausibility, usefulness are laws 1–8's
    negative space — the enum refuses to encode them as a basis."""
    store, key = _store(tmp_path)
    for kind in ("presence", "relevance", "plausibility", "usefulness", ""):
        with pytest.raises(ValueError, match="negative space"):
            _admit(store, key, basis_kind=kind)


def test_receipt_seq_basis_cites_digits(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="digits, not prose"):
        _admit(store, key, basis_kind="receipt-seq", basis_ref="the big one")
    event = seal_admission(store, key, actor="agent-a",
                           origin="resident-7/history",
                           surface="session-handoff",
                           transition="visibility→admission",
                           basis_kind="receipt-seq", basis_ref="41",
                           decision="admitted",
                           participation_ownership="foreign",
                           refs={"session_id": "s1"})
    assert event.payload["basis"] == {"kind": "receipt-seq", "ref": "41"}


def test_decision_fails_closed(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="decision must be one of"):
        _admit(store, key, decision="ok i guess")
    with pytest.raises(ValueError, match="decision must be one of"):
        _admit(store, key, decision="clean")


def test_ownership_and_required_fields(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="participation_ownership must be one of"):
        _admit(store, key, participation_ownership="mine")
    with pytest.raises(ValueError, match="actor is required"):
        _admit(store, key, actor="  ")
    with pytest.raises(ValueError, match="origin is required"):
        _admit(store, key, origin="")
    with pytest.raises(ValueError, match="surface is required"):
        _admit(store, key, surface="")
    with pytest.raises(ValueError, match="basis_ref is required"):
        _admit(store, key, basis_ref="  ")


# --- the check: foreign use joins against the actor's OWN earlier receipt ----

def test_foreign_use_with_earlier_admitted_receipt_is_clean(tmp_path):
    store, key = _store(tmp_path)
    _admit(store, key)
    _use(store, key)
    assert check_admission_basis(store.all(), use_type="payload_content") == []


def test_same_ownership_owes_nothing(tmp_path):
    store, key = _store(tmp_path)
    _use(store, key, ownership="same")
    assert check_admission_basis(store.all(), use_type="payload_content") == []


def test_foreign_use_with_no_receipt_is_the_gap(tmp_path):
    store, key = _store(tmp_path)
    _use(store, key)
    findings = check_admission_basis(store.all(), use_type="payload_content")
    assert [f.status for f in findings] == ["admission_gap"]
    assert "admission basis absent" in findings[0].note


def test_receipt_sealed_after_the_use_resurrects_nothing(tmp_path):
    store, key = _store(tmp_path)
    _use(store, key)
    _admit(store, key)  # sealed after — the count stays broken
    findings = check_admission_basis(store.all(), use_type="payload_content")
    assert [f.status for f in findings] == ["admission_gap"]
    assert "resurrect the count" in findings[0].note


def test_receipt_that_does_not_admit_proves_nothing(tmp_path):
    """`admission_check_not_run` and `denied` on file: the receipt exists,
    the admission does not — undecidable is never clean."""
    for decision in ("admission_check_not_run", "denied",
                     "admission_undecidable"):
        store, key = _store(tmp_path, name=f"adm-{decision}.db")
        _admit(store, key, decision=decision)
        _use(store, key)
        findings = check_admission_basis(store.all(), use_type="payload_content")
        assert [f.status for f in findings] == ["admission_gap"]
        assert f"reads {decision}" in findings[0].note


def test_someone_elses_receipt_is_not_yours(tmp_path):
    """A receipt proves an earlier actor's decision; it never becomes the
    citing actor's autobiography (ADR 026, participation_ownership)."""
    store, key = _store(tmp_path)
    _admit(store, key, actor="agent-b")
    _use(store, key, actor="agent-a")
    findings = check_admission_basis(store.all(), use_type="payload_content")
    assert [f.status for f in findings] == ["admission_gap"]
    assert "admission basis absent" in findings[0].note


def test_shared_material_needs_the_receipt_too(tmp_path):
    """Shared = contains foreign material: the receipt is owed. And the
    receipt only cures uses sealed AFTER it — the first use stays a gap."""
    store, key = _store(tmp_path)
    _use(store, key, ownership="shared")
    findings = check_admission_basis(store.all(), use_type="payload_content")
    assert [f.status for f in findings] == ["admission_gap"]
    first_gap_seq = findings[0].decision_seq
    _admit(store, key)
    _use(store, key, ownership="shared")
    findings = check_admission_basis(store.all(), use_type="payload_content")
    assert len(findings) == 1
    assert findings[0].status == "admission_gap"
    assert findings[0].decision_seq == first_gap_seq
    assert "resurrect the count" in findings[0].note


def test_undeclared_ownership_is_reported_not_clean(tmp_path):
    """The skip is a named state: a use carrying source with no
    participation_ownership is the invisibility the schema refuses."""
    store, key = _store(tmp_path)
    store.append("payload_content", {
        "session_id": "s1",
        "source": {"origin": "resident-7/history",
                   "surface": "session-handoff"},
        "actor": "agent-a",
    }, key)
    findings = check_admission_basis(store.all(), use_type="payload_content")
    assert [f.status for f in findings] == ["admission_ownership_undeclared"]


def test_gaps_are_per_origin_within_one_session(tmp_path):
    """The join is (key, origin, actor): an admission for one origin does
    not cover a second one riding the same session."""
    store, key = _store(tmp_path)
    _admit(store, key, origin="resident-7/history")
    _use(store, key, origin="resident-7/history")
    _use(store, key, origin="resident-9/notes")
    findings = check_admission_basis(store.all(), use_type="payload_content")
    assert len(findings) == 1
    assert findings[0].status == "admission_gap"
    assert findings[0].correlation_id == "s1"


def test_use_type_is_required(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="use_type is required"):
        check_admission_basis(store.all(), use_type="  ")
