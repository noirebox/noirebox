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
