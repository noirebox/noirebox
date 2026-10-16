"""Cross-chain reconciliation (ADR 024, issue #41) — the fleet's graph gets
its edges: consumption edges sealed in BOTH journals, ancestry and temporal
admissibility derived from the anchors (never asserted), fan-in blast paths
along recorded edges."""
from __future__ import annotations

from pathlib import Path

from noirebox.chain import KeyPair, verify_chain
from noirebox.crosschain import (crosschain_report, reconcile_crosschain,
                                 seal_consumption_edge, seal_produced_edge,
                                 seal_supersede)
from noirebox.store import EventStore


def _journal(tmp_path: Path, name: str) -> tuple[EventStore, KeyPair]:
    return (EventStore(str(tmp_path / f"{name}.db")),
            KeyPair.load_or_create(str(tmp_path / f"{name}.key")))


def _anchor(store: EventStore, key: KeyPair) -> None:
    """Seals an anchor over the current head — the only clock (ADR 024 §3)."""
    head = store.all()[-1]
    store.append("anchor",
                 {"head_seq": head["seq"], "head_hash": head["event_hash"]}, key)


def test_recorded_edge_with_anchors_is_clean(tmp_path):
    """The dependency entered both journals and the anchors cover it:
    nothing to report — and the clean pass still seals (see report test)."""
    producer, pk = _journal(tmp_path, "fraud")
    consumer, ck = _journal(tmp_path, "underwriting")

    out = producer.append("llm_output", {"report": "digest-only"}, pk)
    seal_produced_edge(producer, pk, edge_id="e1", consumer="underwriting")
    seal_consumption_edge(consumer, ck, edge_id="e1", producer="fraud",
                          consumed_head=out.event_hash)
    _anchor(producer, pk)
    _anchor(consumer, ck)

    findings = reconcile_crosschain({"fraud": producer.all(),
                                     "underwriting": consumer.all()})
    assert findings == []


def test_unrecorded_half_fires_in_both_directions(tmp_path):
    """The dependency must enter BOTH journals (ADR 024 §1): a missing half
    is a finding whichever side stayed silent (§6)."""
    producer, pk = _journal(tmp_path, "fraud")
    consumer, ck = _journal(tmp_path, "underwriting")
    out = producer.append("llm_output", {"report": "digest-only"}, pk)

    seal_consumption_edge(consumer, ck, edge_id="e1", producer="fraud",
                          consumed_head=out.event_hash)   # producer never did
    seal_produced_edge(producer, pk, edge_id="e2",
                       consumer="underwriting")            # consumer never did
    _anchor(producer, pk)
    _anchor(consumer, ck)

    findings = reconcile_crosschain({"fraud": producer.all(),
                                     "underwriting": consumer.all()})
    notes = {f.correlation_id: f.note for f in findings
             if f.status == "unrecorded_edge"}
    assert "e1" in notes and "e2" in notes
    assert "never recorded being consumed" in notes["e1"]
    assert "never recorded consuming" in notes["e2"]


def test_head_absent_from_producer_chain_is_stale(tmp_path):
    """The consumed head is unknown to the producer's chain — rewritten away
    or fabricated. The absence itself is derivable; the anchors decide who
    is lying (the verifier's job), the finding is the reconciler's."""
    producer, pk = _journal(tmp_path, "fraud")
    consumer, ck = _journal(tmp_path, "underwriting")
    producer.append("llm_output", {"report": "v1"}, pk)
    _anchor(producer, pk)

    seal_consumption_edge(consumer, ck, edge_id="e1", producer="fraud",
                          consumed_head="ab" * 32)
    _anchor(consumer, ck)

    findings = reconcile_crosschain({"fraud": producer.all(),
                                     "underwriting": consumer.all()})
    assert any(f.status == "stale_consumed_head" and "absent" in (f.note or "")
               for f in findings)


def test_unanchored_consumed_head_is_underivable_not_stale(tmp_path):
    """A head present in the producer's chain but not yet covered by an
    anchor is UNDERIVABLE, not stale: anchoring cadence is ops, not
    admissibility (ADR 024 §4 — the latency tax stays rejected)."""
    producer, pk = _journal(tmp_path, "fraud")
    consumer, ck = _journal(tmp_path, "underwriting")
    out = producer.append("llm_output", {"report": "fresh"}, pk)
    seal_produced_edge(producer, pk, edge_id="e1", consumer="underwriting")
    seal_consumption_edge(consumer, ck, edge_id="e1", producer="fraud",
                          consumed_head=out.event_hash)
    _anchor(consumer, ck)   # producer never anchored

    findings = reconcile_crosschain({"fraud": producer.all(),
                                     "underwriting": consumer.all()})
    assert [f for f in findings if f.correlation_id == "e1"] == []


def test_temporal_inversion_consumed_after_the_consumption_was_anchored():
    """fraud@41 consumed by underwriting@39: the consumed event's seal time
    postdates the anchor covering the consumer's edge — per the anchors, the
    consumption preceded the thing consumed (ADR 024 §3)."""
    producer_events = [
        {"seq": 1, "ts": "2026-10-09T12:00:00+00:00", "type": "llm_output",
         "payload": {}, "prev_hash": "0" * 64, "event_hash": "cd" * 32,
         "signature": "ff" * 64},
    ]
    consumer_events = [
        {"seq": 1, "ts": "2026-10-09T11:00:00+00:00", "type": "consumption_edge",
         "payload": {"edge_id": "e9", "producer": "fraud",
                     "consumed_head": "cd" * 32},
         "prev_hash": "0" * 64, "event_hash": "ab" * 32, "signature": "ff" * 64},
        {"seq": 2, "ts": "2026-10-09T11:05:00+00:00", "type": "anchor",
         "payload": {"head_seq": 1, "head_hash": "ab" * 32},
         "prev_hash": "ab" * 32, "event_hash": "ef" * 32, "signature": "ff" * 64},
    ]
    findings = reconcile_crosschain({"fraud": producer_events,
                                     "underwriting": consumer_events})
    inversions = [f for f in findings if f.status == "temporal_inversion"]
    assert len(inversions) == 1
    assert inversions[0].correlation_id == "e9"
    assert "AFTER" in inversions[0].note


def test_supersede_propagates_the_precise_blast_path(tmp_path):
    """sinarezaei's fan-in: the producer's supersede kills the head; the
    finding propagates along the RECORDED edges to every downstream journal
    — a precise path set, not 'everything downstream, maybe'."""
    fraud, fk = _journal(tmp_path, "fraud")
    underwriting, uk = _journal(tmp_path, "underwriting")
    claims, clk = _journal(tmp_path, "claims")

    fraud_out = fraud.append("llm_output", {"verdict": "fraud-flagged"}, fk)
    seal_consumption_edge(underwriting, uk, edge_id="e1", producer="fraud",
                          consumed_head=fraud_out.event_hash)
    uw_report = underwriting.append("llm_output", {"verdict": "insurable"}, uk)
    seal_produced_edge(underwriting, uk, edge_id="e2", consumer="claims")
    seal_consumption_edge(claims, clk, edge_id="e2", producer="underwriting",
                          consumed_head=uw_report.event_hash)
    _anchor(fraud, fk)
    _anchor(underwriting, uk)
    _anchor(claims, clk)
    seal_supersede(fraud, fk, superseded_head=fraud_out.event_hash,
                   reason="the source event was orphaned")

    findings = reconcile_crosschain({"fraud": fraud.all(),
                                     "underwriting": underwriting.all(),
                                     "claims": claims.all()})
    notes = {f.correlation_id: f.note for f in findings
             if f.status == "stale_consumed_head"}
    assert "superseded" in notes["e1"]
    assert "downstream of a dead head" in notes["e2"]
    # the path set: fraud → underwriting → claims, each hop located
    for fragment in ("fraud#", "underwriting#", "claims#"):
        assert fragment in notes["e2"]


def test_malformed_edge_is_loud_not_silent():
    """A consumption_edge that is neither half is the sealer's bug: surfaced
    at reconciliation time, never skipped silently."""
    import pytest

    bad = [{"seq": 1, "ts": "2026-10-09T12:00:00+00:00",
            "type": "consumption_edge", "payload": {"edge_id": "e1"},
            "prev_hash": "0" * 64, "event_hash": "ab" * 32,
            "signature": "ff" * 64}]
    with pytest.raises(ValueError, match="malformed"):
        reconcile_crosschain({"a": bad})


def test_edge_referencing_unloaded_journal_is_refused(tmp_path):
    """Reconciling a graph you only half-loaded would produce findings that
    look like absences — refused loudly instead."""
    import pytest

    consumer, ck = _journal(tmp_path, "underwriting")
    seal_consumption_edge(consumer, ck, edge_id="e1", producer="ghost",
                          consumed_head="ab" * 32)
    with pytest.raises(ValueError, match="not loaded"):
        reconcile_crosschain({"underwriting": consumer.all()})


def test_sealers_validate(tmp_path):
    import pytest

    store = EventStore(str(tmp_path / "a.db"))
    key = KeyPair.generate()
    with pytest.raises(ValueError, match="consumed_head"):
        seal_consumption_edge(store, key, edge_id="e", producer="p",
                              consumed_head="nope")
    with pytest.raises(ValueError, match="edge_id"):
        seal_consumption_edge(store, key, edge_id=" ", producer="p",
                              consumed_head="ab" * 32)
    with pytest.raises(ValueError, match="consumer is required"):
        seal_produced_edge(store, key, edge_id="e", consumer="")
    with pytest.raises(ValueError, match="reason"):
        seal_supersede(store, key, superseded_head="ab" * 32, reason=" ")


def test_report_sealed_even_when_clean(tmp_path):
    """ADR 019's rule holds across chains: the report is sealed even on a
    clean pass, carrying what it examined."""
    producer, pk = _journal(tmp_path, "fraud")
    consumer, ck = _journal(tmp_path, "underwriting")
    out = producer.append("llm_output", {"report": "digest-only"}, pk)
    seal_produced_edge(producer, pk, edge_id="e1", consumer="underwriting")
    seal_consumption_edge(consumer, ck, edge_id="e1", producer="fraud",
                          consumed_head=out.event_hash)
    _anchor(producer, pk)
    _anchor(consumer, ck)

    journals = {"fraud": producer.all(), "underwriting": consumer.all()}
    findings = reconcile_crosschain(journals)
    assert findings == []

    event = crosschain_report(consumer, ck, findings, journals)
    assert event.type == "crosschain_reconciliation"
    assert event.payload["clean_pass"] is True
    assert event.payload["journals_examined"] == {"fraud": 3, "underwriting": 2}
    assert verify_chain(ck.public_hex(), consumer.all())["valid"]
