"""Reconciliation plugin v0.1 — invariants over the journal (issue #3,
schema refined by the Axiru review).

The two-event pattern (decision ↔ outcome) is sealed by the integrator;
this plugin pairs them by correlation key and journals its findings.
The checker is itself audited: its report is sealed as a `reconciliation`
event in the same journal."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from noirebox.chain import KeyPair, verify_chain
from noirebox.reconcile import Invariant, journal_report, reconcile
from noirebox.store import EventStore

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


def _store(tmp_path: Path) -> tuple[EventStore, KeyPair]:
    return EventStore(str(tmp_path / "recon.db")), KeyPair.load_or_create(str(tmp_path / "recon.key"))


def _pair(store: EventStore, key, intent: str, decision: str = "allow",
          seq_start: int = 0, expected_by: datetime | None = None) -> None:
    payload = {"payment_intent_id": intent, "decision_id": f"d_{intent}",
               "decision": decision, "policy_version": "2.4.1"}
    if expected_by:
        payload["expected_by"] = _iso(expected_by)
    store.append("policy_decision", payload, key)


def _outcome(store: EventStore, key, intent: str, status: str = "succeeded",
             unauthorized: bool | None = None) -> None:
    payload = {"payment_intent_id": intent, "decision_id": f"d_{intent}", "status": status}
    if unauthorized is not None:
        payload["unauthorized"] = unauthorized
    store.append("provider_response", payload, key)


INV = [Invariant(name="every-decision-has-an-outcome",
                 decision_type="policy_decision",
                 outcome_type="provider_response",
                 correlation_key="decision_id")]


def test_matched_pairs_produce_matched_finding(tmp_path):
    """The report lists everything — matched pairs appear as `matched`."""
    store, key = _store(tmp_path)
    _pair(store, key, "pi_1")
    _outcome(store, key, "pi_1")
    findings = reconcile(store.all(), INV, now=NOW)
    assert len(findings) == 1
    assert findings[0].status == "matched"
    assert findings[0].correlation_id == "d_pi_1"


def test_decision_without_deadline_stays_open_gap(tmp_path):
    """No deadline in the payload and no `within` in the invariant: the gap
    is visible only in hindsight (status open_gap)."""
    store, key = _store(tmp_path)
    _pair(store, key, "pi_crash")
    findings = reconcile(store.all(), INV, now=NOW)
    assert len(findings) == 1
    assert findings[0].status == "open_gap"


def test_unconfirmed_when_deadline_passed(tmp_path):
    """Axiru's point 2: the decision carries its execution window — when it
    passes with no outcome, the gap flips to `unconfirmed` (not hindsight)."""
    store, key = _store(tmp_path)
    _pair(store, key, "pi_crash", expected_by=NOW - timedelta(minutes=5))
    findings = reconcile(store.all(), INV, now=NOW)
    assert len(findings) == 1
    assert findings[0].status == "unconfirmed"


def test_pending_before_deadline(tmp_path):
    """The window is not passed yet: the gap is `pending`, not a failure."""
    store, key = _store(tmp_path)
    _pair(store, key, "pi_running", expected_by=NOW + timedelta(minutes=5))
    findings = reconcile(store.all(), INV, now=NOW)
    assert len(findings) == 1
    assert findings[0].status == "pending"


def test_unauthorized_explicit_flag(tmp_path):
    """Axiru's point 3: an outcome explicitly flagged `unauthorized: true`
    (never authorized) is a distinct finding — auditors search for the flag,
    not for silence."""
    store, key = _store(tmp_path)
    _outcome(store, key, "pi_orphan", unauthorized=True)
    findings = reconcile(store.all(), INV, now=NOW)
    assert len(findings) == 1
    assert findings[0].status == "unauthorized"


def test_unflagged_outcome_is_inferred_orphan(tmp_path):
    """No flag, no decision: inferred by absence — `orphan_outcome`."""
    store, key = _store(tmp_path)
    _outcome(store, key, "pi_orphan")
    findings = reconcile(store.all(), INV, now=NOW)
    assert len(findings) == 1
    assert findings[0].status == "orphan_outcome"


def test_correlate_on_decision_id_not_intent(tmp_path):
    """Axiru's point 1: one intent, TWO decisions (a retry) — each attempt
    gets its own decision. Intent-level matching would hide the second one;
    decision-id matching surfaces both."""
    store, key = _store(tmp_path)
    # attempt 1: decision d_1 → outcome d_1
    _pair(store, key, "pi_1")
    _outcome(store, key, "pi_1")
    # attempt 2 on the same intent: a SECOND decision, no outcome yet
    store.append("policy_decision",
                 {"payment_intent_id": "pi_1", "decision_id": "d_1_retry",
                  "decision": "allow", "policy_version": "2.4.1"}, key)
    findings = reconcile(store.all(), INV, now=NOW)
    statuses = {f.correlation_id: f.status for f in findings}
    assert statuses == {"d_pi_1": "matched", "d_1_retry": "open_gap"}


def test_late_outcome_flagged_beyond_within():
    """The invariant `within` turns a matched pair into `late` when the
    outcome came after the window (handcrafted timestamps)."""
    events = [
        {"seq": 1, "ts": "2026-09-23T10:00:00.000+00:00", "type": "policy_decision",
         "payload": {"decision_id": "d_late"}},
        {"seq": 2, "ts": "2026-09-23T10:10:00.000+00:00", "type": "provider_response",
         "payload": {"decision_id": "d_late"}},
    ]
    inv = [Invariant(name="inv", decision_type="policy_decision",
                     outcome_type="provider_response",
                     correlation_key="decision_id", within_seconds=300)]
    findings = reconcile(events, inv, now=NOW)
    assert len(findings) == 1
    assert findings[0].status == "late"
    assert findings[0].lag_seconds == 600.0


def test_expected_within_on_decision_payload():
    """The decision payload can carry the window instead of the invariant
    (`expected_within`) — per-event deadline beats the global fallback."""
    events = [
        {"seq": 1, "ts": "2026-09-23T10:00:00.000+00:00", "type": "policy_decision",
         "payload": {"decision_id": "d_x", "expected_within": "10m"}},
        {"seq": 2, "ts": "2026-09-23T10:11:00.000+00:00", "type": "provider_response",
         "payload": {"decision_id": "d_x"}},
    ]
    inv = [Invariant(name="inv", decision_type="policy_decision",
                     outcome_type="provider_response",
                     correlation_key="decision_id", within_seconds=300)]
    findings = reconcile(events, inv, now=NOW)
    # 11 min > 10 min window from the decision payload → late
    assert len(findings) == 1
    assert findings[0].status == "late"


def test_load_config_reads_json(tmp_path):
    cfg = tmp_path / "reconciliation.json"
    cfg.write_text('{"invariants": [{"name": "inv", "decision_type": "policy_decision",'
                   ' "outcome_type": "provider_response", "correlation_key": "decision_id",'
                   ' "within": "5m"}]}', encoding="utf-8")
    from noirebox.reconcile import load_config
    invariants, probes = load_config(str(cfg))
    assert probes == []  # no negative controls in this fixture
    assert invariants[0].name == "inv"
    assert invariants[0].within_seconds == 300


def test_report_is_sealed_and_chain_stays_valid(tmp_path):
    """The checker journals its findings — and the journal audits its auditor."""
    store, key = _store(tmp_path)
    _pair(store, key, "pi_1")
    _outcome(store, key, "pi_1")
    _pair(store, key, "pi_gap", expected_by=NOW - timedelta(minutes=1))
    findings = reconcile(store.all(), INV, now=NOW)
    event = journal_report(store, key, INV, findings)
    assert event.type == "reconciliation"
    assert event.payload["total_findings"] == 2  # matched + unconfirmed
    assert event.payload["findings"][1]["status"] == "unconfirmed"
    assert event.payload["findings"][1]["correlation_id"] == "d_pi_gap"
    assert verify_chain(key.public_hex(), store.all())["valid"]


# --- ADR 020 — the denominator: attempt-first sealing ------------------------

def test_outcome_without_sealed_attempt_is_the_omission(tmp_path):
    """20 attempts, one success sealed, and the chain is intact — the lie by
    omission. With attempt_type set, the outcome with no EARLIER attempt
    surfaces as unlogged_attempt."""
    store, key = _store(tmp_path)
    inv = Invariant("pay", "policy_decision", "provider_response",
                    "decision_id", attempt_type="payment_attempt")
    # outcome sealed, no attempt at all
    _outcome(store, key, "pi_ghost")
    findings = reconcile(store.all(), [inv], now=NOW)
    statuses = [f.status for f in findings]
    assert "unlogged_attempt" in statuses  # the omission, surfaced
    assert "orphan_outcome" in statuses     # the no-decision half, unchanged

    # attempt sealed AFTER the outcome: does not resurrect the count
    store2, key2 = _store(tmp_path)
    _outcome(store2, key2, "pi_late_attempt")
    store2.append("payment_attempt", {"decision_id": "d_pi_late_attempt"}, key2)
    findings2 = reconcile(store2.all(), [inv], now=NOW)
    assert any(f.status == "unlogged_attempt" for f in findings2)


def test_attempt_sealed_before_outcome_is_clean(tmp_path):
    store, key = _store(tmp_path)
    inv = Invariant("pay", "policy_decision", "provider_response",
                    "decision_id", attempt_type="payment_attempt")
    store.append("payment_attempt", {"decision_id": "d_ok"}, key)
    _pair(store, key, "ok")
    _outcome(store, key, "ok")
    findings = reconcile(store.all(), [inv], now=NOW)
    assert not any(f.status == "unlogged_attempt" for f in findings)


# --- ADR 019 — negative controls and the always-sealed report ----------------

def test_negative_probe_must_bite(tmp_path):
    """The probe injects a deliberately-broken fixture: the checker MUST flag
    it. A checker that never says false carries no information."""
    from noirebox.reconcile import run_probes

    store, key = _store(tmp_path)
    probes = [{"name": "must_flag_unconfirmed", "invariant": INV[0].name,
               "expect": "unconfirmed"}]
    results = run_probes(store.all(), INV, probes, now=NOW)
    assert results == []  # the probe bit: the expected finding came out

    # a BROKEN checker (invariant renamed → probe hits nothing) is itself caught
    broken = [Invariant("renamed", "policy_decision", "provider_response", "decision_id")]
    results = run_probes(store.all(), broken, probes, now=NOW)
    assert [f.status for f in results] == ["probe_did_not_bite"]


def test_report_sealed_even_when_clean_with_counts_and_probes(tmp_path):
    """A checker that only journals findings has no proof it ever ran: the
    report is sealed on a CLEAN pass too, carrying the run counts and the
    negative-control results (sum-to-n evidence)."""
    from noirebox.reconcile import run_probes

    store, key = _store(tmp_path)
    _pair(store, key, "pi_1")
    _outcome(store, key, "pi_1")
    events = store.all()
    findings = reconcile(events, INV, now=NOW)
    assert findings and all(f.status == "matched" for f in findings)
    probes = run_probes(events, INV,
                        [{"name": "bite", "invariant": INV[0].name, "expect": "unconfirmed"}],
                        now=NOW)
    event = journal_report(store, key, INV, [], probes=probes, events=events)
    assert event.type == "reconciliation"
    assert event.payload["clean_pass"] is True
    assert event.payload["events_examined"]["policy_decision"] >= 1
    assert event.payload["probes_ok"] is True
    assert verify_chain(key.public_hex(), store.all())["valid"]


# --- ADR 019 §7 — the two-key pairing, enforced by the schema -----------------

def test_same_key_pairing_is_a_finding_and_two_keys_are_clean(tmp_path):
    """The default state of every pipeline: one writer on both sides. When
    the invariant demands two writers, same-key pairing is the finding —
    resolved by SIGNATURE, not by claim."""
    from noirebox.chain import KeyPair
    from noirebox.store import EventStore

    store = EventStore(str(tmp_path / "pair.db"))
    writer_a, writer_b = KeyPair.generate(), KeyPair.generate()
    now = "2026-10-06T12:00:00+00:00"
    store.append("policy_decision", {"decision_id": "d1", "expected_by": "2026-10-07T12:00:00+00:00"}, writer_a)
    store.append("provider_response", {"decision_id": "d1"}, writer_a)  # same key: the pipeline default
    store.append("policy_decision", {"decision_id": "d2", "expected_by": "2026-10-07T12:00:00+00:00"}, writer_a)
    store.append("provider_response", {"decision_id": "d2"}, writer_b)  # two writers: enforced

    inv = Invariant("pay", "policy_decision", "provider_response",
                    "decision_id", require_two_key=True)
    signers = [(writer_a.public_hex(), "agent"), (writer_b.public_hex(), "gate")]
    findings = reconcile(store.all(), [inv], now=now, signers=signers)
    got = {f.correlation_id: f.status for f in findings}
    assert got["d1"] == "same_key_pairing"   # the pipeline default, surfaced
    assert got["d2"] == "matched"            # the two-writer receipt, clean


def test_two_key_check_passes_handcrafted_unsigned_events(tmp_path):
    """Events whose signatures resolve to nothing: pairing is not judged
    (the verifier judges signatures separately) — no false finding."""
    store, key = _store(tmp_path)
    inv = Invariant("pay", "policy_decision", "provider_response",
                    "decision_id", require_two_key=True)
    _pair(store, key, "h")
    _outcome(store, key, "h")
    events = [{**e, "signature": "ff" * 64} for e in store.all()]  # signatures resolve to nothing
    findings = reconcile(events, [inv], now=NOW,
                         signers=[(key.public_hex(), "someone")])
    assert all(f.status != "same_key_pairing" for f in findings)


# --- issue #35 — the precedence policy, journaled before the incident --------

def test_precedence_policy_seals_with_a_name(tmp_path):
    from noirebox.reconcile import seal_policy

    store, key = _store(tmp_path)
    event = seal_policy(store, key, {
        "scope": "payouts", "winner": "outcome",
        "absorbs_cost": "the initiating party, during the open window",
        "decided_by": "jane (treasury ops)",
    })
    assert event.type == "reconciliation_policy"
    assert event.payload["winner"] == "outcome"
    assert verify_chain(key.public_hex(), store.all())["valid"]

    import pytest
    with pytest.raises(ValueError, match="winner"):
        seal_policy(store, key, {"winner": "whoever-shouts-loudest"})
    with pytest.raises(ValueError, match="a name"):
        seal_policy(store, key, {"winner": "decision"})  # no decided_by


# --- issue #36 — per-parameter negative controls on lookups ------------------

def test_lookup_control_known_zero_must_return_zero():
    from noirebox.reconcile import check_lookup_control

    ok = check_lookup_control("vendor=rare-kind-1987", expected_count=0, got_count=0)
    assert ok.status == "lookup_control_ok"
    miss = check_lookup_control("vendor=rare-kind-1987", expected_count=0, got_count=4)
    assert miss.status == "lookup_silently_unfiltered"  # the operation STAYS Unknown

    import pytest
    with pytest.raises(ValueError, match="known-zero"):
        check_lookup_control("not-a-negative-control", expected_count=3, got_count=3)


# --- issue #37 — the outbound half: unwitnessed expectations ------------------

def test_outbound_expectation_without_witness_is_a_wish_with_a_hash(tmp_path):
    """The outbound case (email sent, reply expected): a pending expectation
    is provable only if its head is ANCHORED or the expectation was
    CO-SIGNED by a different known writer — otherwise it's a wish with a
    hash (david_ilands)."""
    from noirebox.chain import KeyPair
    from noirebox.store import EventStore

    inv = Invariant("mail", "policy_decision", "provider_response",
                    "decision_id", witnessed_expectations=True)
    from datetime import datetime as _dt
    now = _dt.fromisoformat("2026-10-08T12:00:00+00:00")

    # unwitnessed: a lone decision with a future deadline
    store = EventStore(str(tmp_path / "unw.db"))
    key = KeyPair.generate()
    store.append("policy_decision",
                 {"decision_id": "d1", "expected_by": "2026-10-09T12:00:00+00:00"}, key)
    findings = reconcile(store.all(), [inv], now=now)
    assert [f.status for f in findings] == ["unwitnessed_expectation"]

    # witnessed by ANCHOR: an anchor event provably covering the decision
    store2 = EventStore(str(tmp_path / "anch.db"))
    key2 = KeyPair.generate()
    store2.append("policy_decision",
                  {"decision_id": "d2", "expected_by": "2026-10-09T12:00:00+00:00"}, key2)
    events = store2.all()
    head = events[-1]["event_hash"]
    store2.append("anchor", {"head_seq": 1, "head_hash": head}, key2)
    findings2 = reconcile(store2.all(), [inv], now=now)
    assert [f.status for f in findings2] == ["pending"]  # witnessed → pending is provable

    # witnessed by CO-SIGN: an expectation_ack from a DIFFERENT known writer
    store3 = EventStore(str(tmp_path / "cosign.db"))
    writer, notary = KeyPair.generate(), KeyPair.generate()
    store3.append("policy_decision",
                  {"decision_id": "d3", "expected_by": "2026-10-09T12:00:00+00:00"}, writer)
    store3.append("expectation_ack", {"decision_id": "d3"}, notary)
    signers = [(writer.public_hex(), "agent"), (notary.public_hex(), "notary")]
    findings3 = reconcile(store3.all(), [inv], now=now, signers=signers)
    assert [f.status for f in findings3] == ["pending"]


# --- issue #42 — calibration: an a-priori bound, never observed spread -------

def test_calibration_seals_the_a_priori_range(tmp_path):
    """The control's known value is a RANGE declared BEFORE the run, with its
    a-priori derivation and a name behind it — value AND width predate the
    run (pm25coder, verifier thread round 4)."""
    from noirebox.reconcile import seal_calibration

    store, key = _store(tmp_path)
    event = seal_calibration(store, key, {
        "name": "defect-score-control",
        "known_range": {"low": 0.60, "high": 0.80},
        "derivation": "the conditional law licenses [0.6, 0.8] for a defective build",
        "declared_by": "pm25 (checker owner)",
    })
    assert event.type == "calibration"
    assert event.payload["source"] == "a-priori"
    assert verify_chain(key.public_hex(), store.all())["valid"]

    import pytest
    with pytest.raises(ValueError, match="range, not a point"):
        seal_calibration(store, key, {"name": "x", "known_range": {"low": 1},
                                      "derivation": "d", "declared_by": "j"})
    with pytest.raises(ValueError, match="low > high"):
        seal_calibration(store, key, {"name": "x",
                                      "known_range": {"low": 2, "high": 1},
                                      "derivation": "d", "declared_by": "j"})
    with pytest.raises(ValueError, match="derivation is required"):
        seal_calibration(store, key, {"name": "x",
                                      "known_range": {"low": 0, "high": 1},
                                      "declared_by": "j"})
    with pytest.raises(ValueError, match="a name"):
        seal_calibration(store, key, {"name": "x",
                                      "known_range": {"low": 0, "high": 1},
                                      "derivation": "d"})  # no declared_by
    with pytest.raises(ValueError, match="source"):
        seal_calibration(store, key, {"name": "x",
                                      "known_range": {"low": 0, "high": 1},
                                      "derivation": "d", "declared_by": "j",
                                      "source": "vibes"})


def test_fitted_in_sample_range_is_itself_a_finding():
    """The schema labels, the layer above refuses (ADR 019 §3's split): an
    observed-spread range is `calibration_fitted_in_sample` — in-sample, the
    first correct construction the checker has never met reads as a failure."""
    from noirebox.reconcile import check_calibration

    assert check_calibration({"control": "c", "source": "a-priori"}) is None
    fitted = check_calibration({"control": "c", "source": "observed-spread"})
    assert fitted is not None and fitted.status == "calibration_fitted_in_sample"


def test_control_range_grades_the_run():
    """The runtime half: inside the a-priori range or the control fails."""
    from noirebox.reconcile import check_control_range

    ok = check_control_range("defect", {"low": 0.60, "high": 0.80}, 0.71)
    assert ok.status == "control_in_range"
    drifted = check_control_range("defect", {"low": 0.60, "high": 0.80}, 0.55)
    assert drifted.status == "control_out_of_range"
    assert "outside" in drifted.note


def test_observed_spread_travels_as_history_never_refits(tmp_path):
    """The observed spread is HISTORY, not the bound: it postdates the run
    and never re-fits what was declared a priori."""
    from noirebox.reconcile import record_observation, seal_calibration

    store, key = _store(tmp_path)
    seal_calibration(store, key, {
        "name": "defect-score-control",
        "known_range": {"low": 0.60, "high": 0.80},
        "derivation": "the conditional law, a priori",
        "declared_by": "pm25 (checker owner)",
    })
    record_observation(store, key, "defect-score-control", 0.469, "run 12")
    record_observation(store, key, "defect-score-control", 0.778, "run 13")
    events = store.all()
    assert sum(1 for e in events if e["type"] == "calibration_observation") == 2
    cal = [e for e in events if e["type"] == "calibration"][0]
    assert cal["payload"]["known_range"] == {"low": 0.60, "high": 0.80}  # untouched
    assert verify_chain(key.public_hex(), events)["valid"]


def test_report_carries_calibration_results(tmp_path):
    """The report grades its calibrations the way it grades its probes —
    even on a clean pass."""
    from noirebox.reconcile import check_calibration, journal_report

    store, key = _store(tmp_path)
    findings = reconcile(store.all(), INV, now=NOW)
    cals = [check_calibration({"control": "c", "source": "observed-spread"})]
    event = journal_report(store, key, INV, findings, calibrations=cals)
    assert event.payload["calibrations_ok"] is False
    assert event.payload["calibrations"][0]["status"] == "calibration_fitted_in_sample"


# --- issue #43 — the channel rung: admissibility upstream of delivery --------

def test_expectation_rows_carry_their_channel_grade(tmp_path):
    """david_ilands (3h0bj): an expectation is only admissible against a
    counterparty already reachable where the answer will be visible. The
    grade travels ON the finding row."""
    store, key = _store(tmp_path)
    deadline = _iso(NOW + timedelta(minutes=5))
    store.append("policy_decision",
                 {"decision_id": "d_cold", "expected_by": deadline,
                  "channel": {"kind": "email", "reachability": "assumed"}}, key)
    store.append("policy_decision",
                 {"decision_id": "d_warm", "expected_by": deadline,
                  "channel": {"kind": "live-thread", "reachability": "demonstrated"}}, key)
    store.append("policy_decision",
                 {"decision_id": "d_dark", "expected_by": deadline}, key)
    findings = reconcile(store.all(), INV, now=NOW)
    notes = {f.correlation_id: f.note for f in findings}
    assert all(f.status == "pending" for f in findings)
    assert "measures the sender" in notes["d_cold"]
    assert "measures the exchange" in notes["d_warm"]
    assert "undeclared" in notes["d_dark"]


def test_cold_silence_after_deadline_is_unconfirmed_but_graded(tmp_path):
    """The status stays `unconfirmed` — the grade says what the silence
    measures: the sender's channel choice, not the recipient's conduct."""
    store, key = _store(tmp_path)
    store.append("policy_decision",
                 {"decision_id": "d_cold",
                  "expected_by": _iso(NOW - timedelta(minutes=5)),
                  "channel": {"kind": "email", "reachability": "assumed"}}, key)
    findings = reconcile(store.all(), INV, now=NOW)
    assert findings[0].status == "unconfirmed"
    assert "sender" in findings[0].note


# --- issue #48 — the two-sided denominator: receipt_gap (mickyarun) ----------

def test_receipt_gap_zero_sum_is_the_only_clean_answer():
    """The server's sealed counter vs the consumer's sealed counter: equal
    is the only clean answer (mickyarun)."""
    from noirebox.reconcile import check_receipt_gap

    ok = check_receipt_gap("vendor-api", fetches_served=12, receipts_held=12)
    assert ok.status == "receipt_coverage_ok"


def test_receipt_gap_flags_the_omission_and_the_fabrication():
    """Shortfall = fetches went out with no receipt held (the omission,
    two-party). Surplus = receipts beyond anything served (the fabricated
    half, worse) — same finding, the note names the direction."""
    from noirebox.reconcile import check_receipt_gap

    short = check_receipt_gap("vendor-api", fetches_served=12, receipts_held=9)
    assert short.status == "receipt_gap"
    assert "3 fetch(es) served with no receipt held" in short.note

    fabricated = check_receipt_gap("vendor-api", fetches_served=5, receipts_held=9)
    assert fabricated.status == "receipt_gap"
    assert "fabricated half" in fabricated.note
    assert "beyond anything the server served" in fabricated.note


def test_receipt_gap_refuses_negative_counters():
    import pytest
    from noirebox.reconcile import check_receipt_gap

    with pytest.raises(ValueError, match="counts are counts"):
        check_receipt_gap("vendor-api", fetches_served=-1, receipts_held=0)
