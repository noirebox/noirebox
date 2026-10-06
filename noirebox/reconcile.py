"""Reconciliation plugin (v0.2) — business invariants over the journal.

The journal proves integrity and order. It deliberately does NOT know what a
"missing half" is: that knowledge is domain-specific, and this plugin is where
it lives — the same plugin pattern as the guardrail (journal domain-blind,
domain knowledge pluggable). Community request: issue #3, schema refined by
Axiru (payout side).

The pattern it checks (two-event flow, e.g. payouts):

    policy_decision (allow/hold/deny + reason_code + policy_version
                     + expected_by or expected_within)
    provider_response (provider status, optional unauthorized flag)
    ... linked by a correlation key: decision_id

Schema notes (from the Axiru review, v0.1):

1. **Correlate on a decision id, not the payment intent** — one intent can
   produce several attempts, each with its own decision. Matching on the
   intent would hide a second decision for the same intent.
2. **A decision carries its deadline** — `expected_by` (absolute ISO) or
   `expected_within` (duration from the decision timestamp). A decision
   whose window passed with no outcome flips to `unconfirmed` — the gap is
   flagged in real time, not discovered in hindsight. Without a deadline the
   gap stays `open_gap` (visible only in hindsight).
3. **An orphan outcome should carry an explicit flag** — `unauthorized: true`
   in the outcome payload means "never authorized": auditors search for the
   flag, they do not search for silence. Unflagged orphans stay inferred
   (`orphan_outcome`).

Every finding is evidence, not an action: the plugin never repairs, it
reports. And the report is sealed into the journal like any event — the
journal's auditor is audited by the journal it audits.

v0.1 boundaries:
- config is JSON (stdlib) — YAML would add a dependency for syntax
- one correlation key per invariant, first event wins on duplicates
- `now` is injectable for tests; defaults to the real clock
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

_DURATION = re.compile(r"^\s*(\d+)\s*([smh]?)\s*$", re.IGNORECASE)
_UNITS = {"s": 1, "m": 60, "h": 3600}


@dataclass(frozen=True)
class Invariant:
    """One business invariant: every decision_type must get its outcome_type.

    `attempt_type` (ADR 020, optional): the type sealing each ATTEMPT before
    its outcome. When set, every outcome must have an attempt with the same
    correlation key sealed EARLIER — an outcome without one is the omission
    the hash chain cannot see on its own (status `unlogged_attempt`)."""

    name: str
    decision_type: str
    outcome_type: str
    correlation_key: str
    within_seconds: int | None = None
    attempt_type: str | None = None


@dataclass(frozen=True)
class Finding:
    """One reconciliation result — evidence sealed into the journal.

    Statuses:
        matched         — decision and outcome both sealed
        late            — both sealed, but the outcome came after the deadline
        pending         — decision sealed, window not passed yet, no outcome yet
        unconfirmed     — decision sealed, deadline passed, no outcome
        open_gap        — decision sealed with NO deadline at all
        orphan_outcome  — outcome with no decision (inferred by absence)
        unauthorized    — outcome explicitly flagged `unauthorized: true`
                          ("never authorized" — auditors search for the flag)
        unlogged_attempt — outcome with NO attempt sealed earlier (ADR 020):
                           the denominator lied — outcomes > attempts
        probe_did_not_bite — a negative control produced the wrong verdict:
                             the checker itself is broken (ADR 019)
    """

    invariant: str
    status: str
    correlation_id: str
    decision_seq: int | None = None
    outcome_seq: int | None = None
    lag_seconds: float | None = None


def parse_duration(value: int | str | None) -> int | None:
    """`"5m"` → 300 · `"90s"` → 90 · `"1h"` → 3600 · `90` → 90 · None → None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    m = _DURATION.match(value)
    if not m:
        raise ValueError(f"invalid duration: {value!r} (expected Ns, Nm or Nh)")
    return int(m.group(1)) * _UNITS[m.group(2).lower()]


def load_config(path: str) -> list[Invariant]:
    """Loads invariants from a JSON file (see reconciliation.example.json)."""
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    invariants = [
        Invariant(
            name=inv["name"],
            decision_type=inv["decision_type"],
            outcome_type=inv["outcome_type"],
            correlation_key=inv["correlation_key"],
            within_seconds=parse_duration(inv.get("within")),
            attempt_type=inv.get("attempt_type"),
        )
        for inv in cfg.get("invariants", [])
    ]
    probes = [
        {"name": pr["name"], "invariant": pr["invariant"],
         "expect": pr.get("expect", "unconfirmed")}
        for pr in cfg.get("negative_probes", [])
    ]
    return invariants, probes


def _ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["ts"])


def _deadline(decision: dict, inv: Invariant) -> datetime | None:
    """The per-event deadline from the decision: `expected_by` (absolute ISO)
    wins over `expected_within` (duration from the decision timestamp); the
    invariant's `within` is the last-resort fallback."""
    payload = decision.get("payload", {})
    if payload.get("expected_by"):
        return datetime.fromisoformat(payload["expected_by"])
    if payload.get("expected_within"):
        return _ts(decision) + timedelta(
            seconds=parse_duration(payload["expected_within"]) or 0
        )
    if inv.within_seconds is not None:
        return _ts(decision) + timedelta(seconds=inv.within_seconds)
    return None


def reconcile(events: list[dict], invariants: list[Invariant],
              now: datetime | None = None) -> list[Finding]:
    """Runs every invariant over the events, returns the findings.

    `events` is what `store.all()` returns — or any handcrafted list with
    the same shape (seq, ts, type, payload). First occurrence wins on
    duplicate correlation ids: the original decision, the first response.
    `now` is the reference clock for deadline checks (injectable in tests).
    """
    ref = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    for inv in invariants:
        decisions: dict[str, dict] = {}
        outcomes: dict[str, dict] = {}
        attempts: dict[str, dict] = {}
        for e in events:
            key = e.get("payload", {}).get(inv.correlation_key)
            if key is None:
                continue
            key = str(key)
            if e.get("type") == inv.decision_type:
                decisions.setdefault(key, e)
            elif e.get("type") == inv.outcome_type:
                outcomes.setdefault(key, e)
            elif inv.attempt_type and e.get("type") == inv.attempt_type:
                attempts.setdefault(key, e)
        # ADR 020 — the denominator: an outcome whose attempt was never
        # sealed is the lie by omission, surfaced structurally. The attempt
        # must be sealed EARLIER: an attempt appended after the fact does not
        # resurrect the count.
        if inv.attempt_type:
            for cid, outcome in outcomes.items():
                attempt = attempts.get(cid)
                if attempt is None or attempt["seq"] > outcome["seq"]:
                    findings.append(Finding(inv.name, "unlogged_attempt", cid,
                                            outcome_seq=outcome["seq"]))

        for cid, decision in decisions.items():
            outcome = outcomes.get(cid)
            if outcome is None:
                deadline = _deadline(decision, inv)
                if deadline is None:
                    findings.append(Finding(inv.name, "open_gap", cid,
                                            decision_seq=decision["seq"]))
                elif ref > deadline:
                    findings.append(Finding(inv.name, "unconfirmed", cid,
                                            decision_seq=decision["seq"]))
                else:
                    findings.append(Finding(inv.name, "pending", cid,
                                            decision_seq=decision["seq"]))
                continue
            lag = (_ts(outcome) - _ts(decision)).total_seconds()
            if inv.within_seconds is not None and lag > inv.within_seconds:
                findings.append(Finding(inv.name, "late", cid,
                                        decision_seq=decision["seq"],
                                        outcome_seq=outcome["seq"],
                                        lag_seconds=lag))
            else:
                findings.append(Finding(inv.name, "matched", cid,
                                        decision_seq=decision["seq"],
                                        outcome_seq=outcome["seq"]))

        for cid, outcome in outcomes.items():
            if cid in decisions:
                continue
            if outcome.get("payload", {}).get("unauthorized") is True:
                findings.append(Finding(inv.name, "unauthorized", cid,
                                        outcome_seq=outcome["seq"]))
            else:
                findings.append(Finding(inv.name, "orphan_outcome", cid,
                                        outcome_seq=outcome["seq"]))
    return findings


def run_probes(events: list[dict], invariants: list[Invariant],
               probes: list[dict], now: datetime | None = None) -> list[Finding]:
    """Negative controls (ADR 019): deliberately-broken fixtures that MUST
    produce a finding. A checker that never says false carries no
    information — each probe injects a synthetic pair (decision with an
    expired deadline, no outcome) and demands the expected status. A probe
    that does not bite is itself a finding: the checker is broken."""
    ref = now or datetime.now(timezone.utc)
    inv_by_name = {inv.name: inv for inv in invariants}
    findings: list[Finding] = []
    for probe in probes:
        inv = inv_by_name.get(probe["invariant"])
        if inv is None:
            findings.append(Finding("probe", "probe_did_not_bite", probe["name"]))
            continue
        cid = f"__probe__{probe['name']}"
        expired = (ref - timedelta(seconds=3600)).isoformat()
        fixtures = [
            {"seq": 0, "ts": expired, "type": inv.decision_type,
             "payload": {inv.correlation_key: cid, "expected_by": expired}},
        ]
        results = reconcile(events + fixtures, [inv], now=ref)
        got = {f.correlation_id: f.status for f in results if f.correlation_id == cid}
        if got.get(cid) != probe["expect"]:
            findings.append(Finding("probe", "probe_did_not_bite", probe["name"]))
    return findings


def journal_report(store, key, invariants: list[Invariant],
                   findings: list[Finding], probes: list[Finding] | None = None,
                   events: list[dict] | None = None) -> dict:
    """Seals the reconciliation report as a `reconciliation` event.

    v0.2 (ADR 019): the report is sealed EVEN WHEN EVERYTHING MATCHED — a
    checker that only journals findings has no proof it ever ran. The report
    carries the run counts (how many decisions, attempts, outcomes were
    actually examined — the sum-to-n evidence) and the negative-control
    results. The journal audits its auditor.
    """
    by_status: dict[str, int] = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
    counts: dict[str, int] = {}
    for e in events or []:
        counts[e["type"]] = counts.get(e["type"], 0) + 1
    report = {
        "invariants": [inv.name for inv in invariants],
        "total_findings": len(findings),
        "findings": [f.__dict__ for f in findings],
        "findings_by_status": by_status,
        "events_examined": counts,
        "clean_pass": len(findings) == 0,
        "negative_probes": [f.__dict__ for f in (probes or [])],
        "probes_ok": not any(f.status == "probe_did_not_bite" for f in (probes or [])),
    }
    return store.append("reconciliation", report, key)
