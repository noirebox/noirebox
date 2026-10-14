"""The custody grade (§20 — the rudratosh/fluffydesk thread): a witness
is worth min(authoring, retention). Receipts authored grade-1 but retained
in operator-controlled storage sit at grade 3 — and retention is the only
grade that is wrong by DRIFT, so the drift is monitored: bounded, named,
and disclosed. Retention changes are sealed events, not ops-layer edits."""
from __future__ import annotations


from noirebox.chain import KeyPair, verify_chain_multi
from noirebox.reconcile import (check_custody_drift, custody_grade,
                                journal_report, seal_retention)
from noirebox.store import EventStore


def _store(tmp_path, name="custody.db"):
    return EventStore(str(tmp_path / name)), KeyPair.generate()


def _anchored(store, key, head_seq, ts=None):
    payload = {"head_seq": head_seq, "head_hash": f"hash-{head_seq}"}
    if ts:
        payload = {"head_seq": head_seq, "head_hash": f"hash-{head_seq}"}
    ev = store.append("anchor", payload, key)
    if ts:  # rewrite the timestamp post-hoc would break the hash — instead
        pass  # cadence tests inject `now` into the check, never the event
    return ev


def test_seal_retention_validates_and_seals(tmp_path):
    """Retention changes are protocol events with a BOUNDED vocabulary
    (the v0.3.0 lesson, one layer over) — and they chain like everything
    else."""
    store, key = _store(tmp_path)
    event = seal_retention(store, key, action="prune",
                           scope="events older than 90d",
                           note="Q4 retention pass")
    assert event.type == "retention"
    assert event.payload["schema"] == "retention/0.1"
    assert event.payload["action"] == "prune"
    assert verify_chain_multi([key.public_hex()], store.all())["valid"]

    import pytest as _pytest
    with _pytest.raises(ValueError, match="protocol vocabulary"):
        seal_retention(store, key, action="deleted some stuff quietly")


def test_unanchored_journal_is_a_named_state(tmp_path):
    """No anchor at all: every receipt rests on operator custody — the
    finding says so instead of the dashboard staying green."""
    store, key = _store(tmp_path)
    store.append("receipt", {"schema": "receipt/0.2.2", "run_id": "r1"}, key)
    findings = check_custody_drift(store.all(), max_tail_events=10)
    assert [f.status for f in findings] == ["custody_unanchored"]
    assert "grade-3 by retention" in findings[0].note
    assert "min(authoring, retention)" in findings[0].note


def test_anchored_tail_within_bounds_is_clean(tmp_path):
    store, key = _store(tmp_path)
    for i in range(5):
        store.append("receipt", {"schema": "receipt/0.2.2", "run_id": f"r{i}"}, key)
    _anchored(store, key, head_seq=5)
    store.append("receipt", {"schema": "receipt/0.2.2", "run_id": "r9"}, key)
    assert check_custody_drift(store.all(), max_tail_events=10) == []


def test_tail_beyond_the_bound_is_the_drift(tmp_path):
    store, key = _store(tmp_path)
    for i in range(3):
        store.append("receipt", {"schema": "receipt/0.2.2", "run_id": f"r{i}"}, key)
    anchor = _anchored(store, key, head_seq=3)
    for i in range(4):
        store.append("receipt", {"schema": "receipt/0.2.2", "run_id": f"x{i}"}, key)
    findings = check_custody_drift(store.all(), max_tail_events=2)
    assert [f.status for f in findings] == ["custody_drift"]
    assert findings[0].correlation_id == f"tail:{anchor.payload['head_seq']}"
    assert "4 events live beyond the newest external witness" in findings[0].note  # the anchor event itself is the witness — the tail starts after it
    assert "the dashboard does not see this one" in findings[0].note


def test_drift_by_time_not_by_count(tmp_path):
    """Retention drifts by TIME too — no event count can show a stale
    witness, so the cadence bound exists."""
    store, key = _store(tmp_path)
    store.append("receipt", {"schema": "receipt/0.2.2", "run_id": "r1"}, key)
    _anchored(store, key, head_seq=1, ts="2026-01-01T00:00:00+00:00")
    # force the anchor ts by building one with an old envelope: simplest
    # honest path — the check takes `now`, and the anchor's real ts is
    # seconds old, so craft the bound against a stale anchor via a custom
    # event list
    events = store.all()
    stale = dict(events[1])
    stale["ts"] = "2026-01-01T00:00:00+00:00"
    findings = check_custody_drift([events[0], stale], max_tail_seconds=3600,
                                   now="2026-01-01T02:00:00+00:00")
    assert [f.status for f in findings] == ["custody_drift"]
    assert "drifted by time" in findings[0].note


def test_custody_grade_discloses_the_tail(tmp_path):
    """The grade is the TAIL's grade — what the current head rests on:
    2 while anchored within cadence, 3 the moment it drifts, and the
    formula is stated, not implied."""
    store, key = _store(tmp_path)
    for i in range(3):
        store.append("receipt", {"schema": "receipt/0.2.2", "run_id": f"r{i}"}, key)
    _anchored(store, key, head_seq=3)
    seal_retention(store, key, action="policy-change",
                   note="anchor cadence: hourly")
    d = custody_grade(store.all(), max_tail_events=10)
    assert d["schema"] == "custody-grade/0.1"
    assert d["grade"] == 2 and d["mode"] == "anchored-within-cadence"
    assert d["grade_label"] == "disinterested custodian"
    assert d["formula"] == "witness = min(authoring, retention)"
    assert d["retention_events"] == 1

    for i in range(5):
        store.append("receipt", {"schema": "receipt/0.2.2", "run_id": f"x{i}"}, key)
    d2 = custody_grade(store.all(), max_tail_events=2)
    assert d2["grade"] == 3 and d2["mode"] == "drifted"
    assert d2["tail_events"] == 6  # the retention event + the 5 new receipts

    # unanchored: grade 3 from the start, named honestly (a SEPARATE
    # journal — the grade reads its own events, nobody else's)
    store2, key2 = _store(tmp_path, name="second.db")
    store2.append("receipt", {"schema": "receipt/0.2.2", "run_id": "r1"}, key2)
    assert custody_grade(store2.all())["grade"] == 3
    assert custody_grade(store2.all())["mode"] == "unanchored"


def test_disclosure_rides_the_report_without_touching_clean_pass(tmp_path):
    store, key = _store(tmp_path)
    seal_retention(store, key, action="policy-change")
    from noirebox.reconcile import Invariant
    event = journal_report(
        store, key, [Invariant("i", "receipt", "receipt", "run_id")],
        [], events=store.all(),
        custody_disclosure=custody_grade(store.all()))
    assert event.payload["custody_disclosure"]["grade"] == 3
    assert event.payload["clean_pass"] is True  # disclosure is not a violation
    assert verify_chain_multi([key.public_hex()], store.all())["valid"]
