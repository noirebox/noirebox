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
    the hash chain cannot see on its own (status `unlogged_attempt`).

    `terminal_type` (SCAR-PROC-110, optional): the type sealing a run's END
    state for the same correlation key (transcript digest, terminal verdict).
    When set, an outcome contradicted by a LATER terminal event — different
    witness digest or different verdict — is the mid-flight forgery, surfaced
    as `verdict_predates_terminal`. Pairing reads the terminal, not the first
    response."""

    name: str
    decision_type: str
    outcome_type: str
    correlation_key: str
    within_seconds: int | None = None
    attempt_type: str | None = None
    terminal_type: str | None = None
    require_two_key: bool = False
    witnessed_expectations: bool = False
    precedence: str | None = None  # which side wins on disagreement — decided BEFORE (issue #35)


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
        same_key_pairing — receipt and check-name sealed under the SAME key
                           while the invariant demands two writers (ADR 019 §7)
        unwitnessed_expectation — an outbound expectation (deadline, no
                           outcome yet) that is neither anchored nor
                           co-signed: "a wish with a hash" (ADR 020, the
                           outbound half — david_ilands)
        calibration_fitted_in_sample — a control's declared range was fitted
                           from the observed constructions, not derived a
                           priori: the first correct construction it has
                           never met reads as a failure (issue #42)
        control_out_of_range — a run's value fell outside the control's
                           a-priori range: the checker drifted, or the range
                           was fitted (issue #42)
        receipt_gap        — the two-sided denominator: fetches served by one
                           side vs receipts held by the other do not sum to
                           zero — the omission or the fabricated half
                           (issue #48, the ADR 020 family)
        verdict_predates_terminal — a verdict contradicted by a LATER
                           terminal event for the same run: different
                           transcript digest bound as witness, or a
                           different verdict — the mid-flight forgery
                           surfaced (SCAR-PROC-110, issue #53; "the scar
                           becomes the spec")
        label_llm_call_mismatch — a receipt declaring judged_by=
                           "deterministic" while the journal contains an
                           llm_call for the same key: the label vs the
                           out-of-band observation (v0.2.3, howcani)
        dangling_requirement_ref — a receipt citing requirement_ref that no
                           sealed requirement carries: decoration until it
                           resolves (v0.2.3, howcani)
        independence_undecidable — the receipt's writer does not resolve
                           against the known-writer set: cross-writer
                           independence is undecidable, and undecidable is
                           never clean (v0.2.5, howcani's probe — the
                           third input the v0.2.4 branch answered as clean)
        judge_defined_before_spec_read — a judge defined with no sealed read
                           of its bytecode BEFORE the definition: the
                           parallel-call race, the prompt hallucinated from
                           priors (SCAR-PROC-114, Randal/gde)
        spec_not_canonical — a receipt's spec_hash matching no sealed spec:
                           the canary witness says the judge read bytes
                           nobody committed (SCAR-PROC-114)
        uncovered_write    — a write/exec event that reconciles against no
                           gate receipt on the same key: the gate never
                           vouched for it (issue #44, sinarezaei)
        unverified_label   — a receipt declaring judged_by="deterministic"
                           with no transport attempt on the same key, or
                           only attempts sealed by its own writer: the
                           label nobody else witnessed (v0.2.4, howcani —
                           the absence a chain cannot see)
        requirement_out_of_scope — a receipt citing a scoped requirement
                           while the diff touches nothing in the scope:
                           the obligation cited does not govern this work
                           (v0.2.4)
        gui_served_unobserved — a served action with no OS-level
                           observation on the same key: the app passed the
                           test by doing nothing (§16 — reid, SoftwareGym)
        gui_observation_unserved — OS state moved with no served action on
                           the same key: something happened nobody served
                           (§16)
        registry_duplicate_undecidable — the PINNED registrar attested one
                           key under two domains: the operator contradicts
                           itself, the key's domain is undecidable — emitted
                           AT ASSEMBLY, never resolved first-write-wins
                           (v0.2.7, howcani's write race)
        custody_unanchored — the journal has NO external witness: every
                           receipt is grade-3 by retention (§20, the
                           rudratosh/fluffydesk custody thread)
        custody_drift      — more events (or more time) live beyond the
                           newest anchor than the cadence allows: the
                           custody grade drifted, silently — retention is
                           the only grade that is wrong by drift (§20)
    """

    invariant: str
    status: str
    correlation_id: str
    decision_seq: int | None = None
    outcome_seq: int | None = None
    lag_seconds: float | None = None
    note: str | None = None


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
            witnessed_expectations=bool(inv.get("witnessed_expectations")),
            precedence=inv.get("precedence"),
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


def _signer(event: dict, signers: list[tuple[str, str]] | None) -> str:
    """Resolves WHICH known key sealed this event — by signature, not by
    claim (ADR 021: a name, not a role). None passed or no match →
    "unknown" (handcrafted fixtures are not judged on pairing; the verifier
    judges their signatures separately)."""
    if not signers:
        return "unknown"
    try:
        sig = bytes.fromhex(event["signature"])
        digest = bytes.fromhex(event["event_hash"])
    except (KeyError, ValueError):
        return "unknown"
    from .chain import ed25519_verify

    for public_hex, label in signers:
        if ed25519_verify(public_hex, sig.hex(), digest):
            return label
    return "unknown"


def _signer_key(event: dict, signers: list[tuple[str, str]]) -> str | None:
    """Resolves the public hex of the known key whose signature seals this
    event. None when no known key matches — and unresolved is its own
    state, never folded into clean (v0.2.5, howcani's probe: a verdict
    taken on a label string flips when a second agent-controlled key
    carries a different label)."""
    if not signers:
        return None
    try:
        sig = bytes.fromhex(event["signature"])
        digest = bytes.fromhex(event["event_hash"])
    except (KeyError, ValueError):
        return None
    from .chain import ed25519_verify

    for public_hex, _label in signers:
        if ed25519_verify(public_hex, sig.hex(), digest):
            return public_hex
    return None


def _carries_witness_token(payload: dict) -> bool:
    """True when an anchor payload actually carries a witness token — a tsr
    (RFC 3161), an ots_b64 receipt, or a multi-witness `tokens` list. An
    anchor CLAIM without one is prose, not custody (NB-03: a writer cannot
    grade its own retention up by sealing an anchor-shaped event)."""
    return bool(payload.get("tsr") or payload.get("ots_b64")
                or payload.get("tokens"))


def _anchored_upto(events: list[dict], seq: int) -> bool:
    """True when an anchor event provably covers `seq` — head_seq >= seq
    AND the cited head_hash recomputes to the chain's event at that seq
    (the same verification the third-party verifier performs), AND the
    anchor carries a witness token: a hash match without a token proves
    nothing external."""
    from .chain import GENESIS

    by_seq = {e["seq"]: e for e in events}
    for e in events:
        if e["type"] != "anchor":
            continue
        payload = e.get("payload", {})
        head_seq = payload.get("head_seq")
        head_hash = payload.get("head_hash")
        if not isinstance(head_seq, int) or head_seq < 0 or head_seq > len(events):
            continue
        expected = by_seq[head_seq]["event_hash"] if head_seq else GENESIS
        if head_hash != expected:
            continue
        if not _carries_witness_token(payload):
            continue
        if head_seq >= seq:
            return True
    return False


def _co_signed(events: list[dict], decision: dict, correlation_key: str,
               signers: list[tuple[str, str]] | None) -> bool:
    """True when an expectation_ack for the same correlation key was sealed
    by a DIFFERENT known writer than the decision's — co-signing in a
    one-signature-per-event chain is a second event, not a second signature.
    Without a known-writer set, co-signing is not provable (honest default)."""
    if not signers:
        return False
    decision_signer = _signer(decision, signers)
    cid = decision.get("payload", {}).get(correlation_key)
    for e in events:
        if e.get("type") != "expectation_ack":
            continue
        if e.get("payload", {}).get(correlation_key) != cid:
            continue
        if _signer(e, signers) not in ("unknown", decision_signer):
            return True
    return False


def expectation_channel(decision: dict) -> str:
    """Grades an outbound expectation's channel admissibility (issue #43 —
    david_ilands): sent/accepted/delivered sit ON TOP of a reachable space —
    an expectation is only admissible against a counterparty already present
    where the answer will be visible. The decision payload MAY declare
    `channel: {kind, reachability: "demonstrated" | "assumed"}`:

      "demonstrated" — the counterparty answered in this space before: the
        expectation is admissible, and its silence (deadline passed, no
        outcome) measures the exchange;
      "assumed" — cold: the silence will classify `unconfirmed` and measure
        the SENDER's channel choice, not the recipient's conduct (his own
        numbers: same agent, same month — 0 replies from 10 cold emails vs 3
        from live-thread comments);
      "undeclared" — no channel field: the admissibility story is absent,
        the same invisibility the schema refuses elsewhere.

    Convention, not enforcement: the journal records the grade — it cannot
    make the counterparty answer."""
    ch = decision.get("payload", {}).get("channel")
    if not isinstance(ch, dict) or not str(ch.get("kind", "")).strip():
        return "undeclared"
    return "demonstrated" if ch.get("reachability") == "demonstrated" else "assumed"


def reconcile(events: list[dict], invariants: list[Invariant],
              now: datetime | None = None,
              signers: list[tuple[str, str]] | None = None) -> list[Finding]:
    """Runs every invariant over the events, returns the findings.

    `events` is what `store.all()` returns — or any handcrafted list with
    the same shape (seq, ts, type, payload). First occurrence wins on
    duplicate correlation ids: the original decision, the first response.
    `now` is the reference clock for deadline checks (injectable in tests).
    `signers` is the known-writer set (public_hex, label) — required by
    invariants that demand two-key pairing (ADR 019 §7): the receipt and
    the check-name under the SAME key is the default state of every
    pipeline, and the schema treats it as a finding when the invariant
    demands two writers.
    """
    ref = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    for inv in invariants:
        decisions: dict[str, dict] = {}
        outcomes: dict[str, dict] = {}
        attempts: dict[str, dict] = {}
        terminals: dict[str, dict] = {}
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
            elif inv.terminal_type and e.get("type") == inv.terminal_type:
                # a run's terminal state: the LAST sealed terminal event wins —
                # the end of a run is where the run ended, not where it first
                # claimed to end.
                terminals[key] = e
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
                # ADR 020, the outbound half (issue #37): a PENDING
                # expectation must be witnessed — its head anchored, or the
                # expectation co-signed by a different known writer.
                # Otherwise it is a wish with a hash.
                if inv.witnessed_expectations:
                    witnessed = (_anchored_upto(events, decision["seq"])
                                 or _co_signed(events, decision, inv.correlation_key, signers))
                    if not witnessed:
                        findings.append(Finding(inv.name, "unwitnessed_expectation", cid,
                                                decision_seq=decision["seq"]))
                        continue
                deadline = _deadline(decision, inv)
                # The channel grade travels ON the finding row (issue #43):
                # an expectation's admissibility is decided upstream of
                # delivery, and the report should say which way.
                grade = expectation_channel(decision)
                note = {"demonstrated": "channel: demonstrated — silence "
                                        "measures the exchange",
                        "assumed": "channel: assumed (cold) — silence "
                                   "measures the sender's channel choice, "
                                   "not the recipient",
                        "undeclared": "channel: undeclared — no admissibility "
                                      "story on record"}[grade]
                if deadline is None:
                    findings.append(Finding(inv.name, "open_gap", cid,
                                            decision_seq=decision["seq"],
                                            note=note))
                elif ref > deadline:
                    findings.append(Finding(inv.name, "unconfirmed", cid,
                                            decision_seq=decision["seq"],
                                            note=note))
                else:
                    findings.append(Finding(inv.name, "pending", cid,
                                            decision_seq=decision["seq"],
                                            note=note))
                continue
            if (inv.require_two_key and signers
                    and _signer(decision, signers) != "unknown"
                    and _signer(decision, signers) == _signer(outcome, signers)):
                findings.append(Finding(inv.name, "same_key_pairing", cid,
                                        decision_seq=decision["seq"],
                                        outcome_seq=outcome["seq"]))
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

        # SCAR-PROC-110 (issue #53, Randal/gde) — pairing reads the TERMINAL,
        # not the first response: a verdict sealed BEFORE the run ended, that
        # the later terminal event CONTRADICTS (different transcript digest
        # bound as witness, or a different verdict), is the mid-flight
        # forgery, surfaced as `verdict_predates_terminal`. A terminal sealed
        # before the outcome, or one that confirms it, is the sound
        # waitpid()-equivalent order — no finding.
        if inv.terminal_type:
            for cid, outcome in outcomes.items():
                terminal = terminals.get(cid)
                if terminal is None or terminal["seq"] <= outcome["seq"]:
                    continue
                o_payload = outcome.get("payload", {})
                t_payload = terminal.get("payload", {})
                bound = (o_payload.get("witness") or {}).get("transcript_sha256")
                t_digest = t_payload.get("transcript_sha256")
                o_verdict, t_verdict = o_payload.get("verdict"), t_payload.get("verdict")
                digest_diverged = bool(bound and t_digest and bound != t_digest)
                verdict_diverged = bool(o_verdict and t_verdict and o_verdict != t_verdict)
                if digest_diverged or verdict_diverged:
                    detail = (f"witness binds {str(bound)[:12]}…, terminal sealed "
                              f"{str(t_digest)[:12]}…" if digest_diverged else
                              f"verdict {o_verdict} vs terminal {t_verdict}")
                    findings.append(Finding(
                        inv.name, "verdict_predates_terminal", cid,
                        outcome_seq=outcome["seq"],
                        note=f"outcome at seq {outcome['seq']} contradicted by a "
                             f"LATER terminal event (seq {terminal['seq']}) — "
                             f"{detail}; the race the receipt died in"))

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


# --- §16 — the GUI lane: served vs observed (reid, SoftwareGym) --------------

def check_gui_gap(events: list[dict], *, served_type: str = "click_served",
                  observed_type: str = "os_state_touched",
                  correlation_key: str = "session_id") -> list[Finding]:
    """The receipt_gap invariant at the GUI layer (§16 — reid, SoftwareGym):
    clicks (or actions) SERVED by the app vs OS state OBSERVED by the
    system — the gap is the finding.

    - a served action with no OS observation on the same key is
      `gui_served_unobserved`: the app passed the test by doing nothing —
      "an app that survives twenty clicks without touching OS state
      passed the test by doing nothing";
    - an OS observation with no served action is
      `gui_observation_unserved`: something moved that nobody served.

    Domain-blind as always: the runner counts the served side, the OS
    counts the observed side — the harness is the runner's, the
    denominator is ours."""
    if not str(served_type or "").strip() or not str(observed_type or "").strip():
        raise ValueError("gui_gap: served_type and observed_type are required")
    served: dict[str, dict] = {}
    observed: set[str] = set()
    for e in events:
        value = e.get("payload", {}).get(correlation_key)
        if value is None:
            continue
        value = str(value)
        if e.get("type") == served_type:
            served.setdefault(value, e)
        elif e.get("type") == observed_type:
            observed.add(value)
    findings: list[Finding] = []
    for value, e in served.items():
        if value not in observed:
            findings.append(Finding(
                "gui", "gui_served_unobserved", value,
                decision_seq=e["seq"],
                note=f"the {served_type} at seq {e['seq']} reconciles against "
                     f"no {observed_type} — the app passed the test by doing "
                     f"nothing"))
    for value in sorted(observed - set(served)):
        findings.append(Finding(
            "gui", "gui_observation_unserved", value,
            note="OS state moved with no served action — something happened "
                 "nobody served"))
    return findings


# --- issue #44 — coverage vs binding (sinarezaei) ----------------------------

def check_coverage(events: list[dict], *, write_type: str,
                   receipt_type: str = "receipt",
                   correlation_key: str = "run_id") -> list[Finding]:
    """Coverage vs binding (issue #44 — sinarezaei): every WRITE event must
    reconcile against a gate receipt — an exec with no matching receipt is
    the finding `uncovered_write`. Pitched at K8s/platform teams: the
    mutating calls are `write_type` ("pod_delete", "orders.capture"…), the
    gate's verdicts are `receipt_type`, and the join runs on
    `correlation_key` — the journal's correlation convention applies.

    A write covered by a receipt is clean; a write whose key no receipt
    carries is the omission, surfaced. (The reverse — a receipt with no
    write — is the orphan half, `orphan_outcome`, elsewhere.) Clean
    coverage returns an empty list; seal the findings like any report."""
    if not str(write_type or "").strip():
        raise ValueError("coverage: write_type is required — which event type "
                         "is the mutating call?")
    writes: dict[str, dict] = {}
    receipts: set[str] = set()
    for e in events:
        value = e.get("payload", {}).get(correlation_key)
        if value is None:
            continue
        value = str(value)
        if e.get("type") == write_type:
            writes.setdefault(value, e)
        elif e.get("type") == receipt_type:
            receipts.add(value)
    findings: list[Finding] = []
    for value, e in writes.items():
        if value not in receipts:
            findings.append(Finding(
                "coverage", "uncovered_write", value,
                decision_seq=e["seq"],
                note=f"the {write_type} at seq {e['seq']} reconciles against "
                     f"no gate receipt — an exec the gate never vouched for"))
    return findings


# --- v0.2.3 — the receipt joins (howcani's audit; Randal: Bell's theorem) ----

def seal_requirement(store, key, *, ref: str, obligation: str,
                     scope: list[str] | None = None) -> dict:
    """Seals one entry of the OBLIGATIONS REGISTRY as a `requirement` event
    (v0.2.3; v0.2.4 makes citations load-bearing). `ref` is the citation the
    receipts carry ("AI-Act art. 12(1)", "SOP-114 §3"); `obligation` is what
    the requirement demands, in prose. `scope` (v0.2.4) names the paths the
    requirement GOVERNS, declared at seal time — so the reconcile join can
    confront the citation with the diff's touched set, the first observation
    the citing agent does not author. A scope-less requirement is global and
    never scope-checked."""
    if not str(ref or "").strip():
        raise ValueError("requirement: ref is required — the citation receipts carry")
    if not str(obligation or "").strip():
        raise ValueError("requirement: obligation is required — WHAT the "
                         "requirement demands, in prose")
    payload: dict = {
        "schema": "requirement/0.2",
        "ref": ref.strip(),
        "obligation": obligation.strip(),
    }
    if scope is not None:
        if not isinstance(scope, list) or not scope or \
                any(not isinstance(p, str) or not p.strip() for p in scope):
            raise ValueError("requirement: scope must be a non-empty list of "
                             "non-empty paths — WHAT the requirement governs")
        payload["scope"] = [p.strip() for p in scope]
    return store.append("requirement", payload, key)


def seal_spec(store, key, *, spec_id: str, text: str, canary: str,
              source_ref: str = "") -> dict:
    """Seals the CANONICAL judge bytecode as a `spec` event (v0.2.3 —
    SCAR-PROC-114's canary witness, Randal/gde): the reference manual the
    judge is supposed to load, committed to the journal with its CANARY
    TOKEN planted inside. The canary is a phrase cut from private history —
    never in any pre-training prior — so its presence in a loaded prompt
    proves WHICH bytes the judge actually read; a judge that hallucinated
    the bytecode from priors invents generic headings ("Security",
    "Performance") and trips it immediately.

    The canary is PLANTED, not declared: a seal whose text does not contain
    it is refused at build time. The reconciliation (`reconcile_spec`) then
    checks every receipt's spec_hash against this registry."""
    if not str(spec_id or "").strip():
        raise ValueError("spec: spec_id is required — receipts and reads resolve to it")
    if not str(text or "").strip():
        raise ValueError("spec: text is required — the canonical bytecode itself")
    if not str(canary or "").strip():
        raise ValueError("spec: canary is required — a key cut from private "
                         "history, never from a textbook template")
    if canary not in text:
        raise ValueError("spec: the canary must be PLANTED in the text — a "
                         "canary declared outside the bytecode proves nothing")
    import hashlib

    return store.append("spec", {
        "schema": "spec/0.1",
        "spec_id": spec_id.strip(),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "canary": canary.strip(),
        "source_ref": source_ref.strip(),
    }, key)


def reconcile_spec(events: list[dict], *, spec_id: str) -> list[Finding]:
    """The SCAR-PROC-114 joins (v0.2.3 — Randal's live race, slabb's
    translation): the judge's definition must postdate its bytecode's read,
    and the bytes it judged must be the sealed canonical ones.

    1. **The race** — a `judge_define` event for this spec with NO
       `spec_read` sealed EARLIER is the finding
       `judge_defined_before_spec_read`: the judge was defined in the same
       turn its bytecode was (or before it returned), so its system prompt
       was necessarily hallucinated from priors — t_return(view_file) <
       t_call(define_subagent), the waitpid discipline applied to prompt
       loading.
    2. **The canary** — a receipt carrying a `spec_hash` that matches NO
       sealed spec event is the finding `spec_not_canonical`: the bytes the
       judge read were never committed to the journal. The hallucinated
       bytecode hashes differently than the canonical one — the drift
       surfaces as a registry miss instead of a soft reviewer."""
    specs: dict[str, dict] = {}
    for e in events:
        if e.get("type") == "spec":
            sid = str(e.get("payload", {}).get("spec_id", "")).strip()
            if sid:
                specs.setdefault(sid, e)
    canonical = specs.get(spec_id)
    reads: list[dict] = []
    defines: list[dict] = []
    for e in events:
        payload = e.get("payload", {})
        if e.get("type") == "spec_read" and str(payload.get("spec_id", "")) == spec_id:
            reads.append(e)
        elif e.get("type") == "judge_define" and str(payload.get("spec_id", "")) == spec_id:
            defines.append(e)
    if canonical is None:
        raise ValueError(f"spec: no sealed spec {spec_id!r} — reconcile the "
                         f"canonical bytecode or none of it")

    findings: list[Finding] = []
    for define in defines:
        earlier_read = any(r["seq"] < define["seq"] for r in reads)
        if not earlier_read:
            findings.append(Finding(
                "spec", "judge_defined_before_spec_read", spec_id,
                decision_seq=define["seq"],
                note="the judge was defined with no sealed read of its "
                     "bytecode BEFORE the definition — the system prompt was "
                     "necessarily hallucinated from priors (the parallel-call "
                     "race: never define the judge in the same turn you read "
                     "its bytecode)"))
    for e in events:
        payload = e.get("payload", {})
        if e.get("type") == "receipt" and payload.get("spec_hash"):
            bound = str(payload["spec_hash"])
            if bound != canonical["payload"]["sha256"]:
                findings.append(Finding(
                    "spec", "spec_not_canonical", spec_id,
                    decision_seq=e["seq"],
                    note="the judged spec hash matches no sealed canonical "
                         "bytecode — the canary witness says the judge read "
                         "bytes nobody committed (hallucinated headings hash "
                         "differently than the planted canary)"))
    return findings


def seal_writer(store, key, *, public_hex: str, domain: str,
                declared_by: str) -> dict:
    """Seals one entry of the KNOWN-WRITERS REGISTRY as a `writer` event
    (v0.2.6 — the §15 structural design, ADR 021's "a name, not a role"
    applied to domains): `public_hex` → declared domain, attested at
    REGISTRATION by `declared_by` — before any run the writer could
    influence. The caller of `reconcile_receipts` stops supplying the
    domain: the verifier's sealed registry holds it, derived from the
    signature. Pattern: `seal_requirement`, extended to writers."""
    ph = str(public_hex or "")
    if len(ph) != 64 or any(c not in "0123456789abcdef" for c in ph):
        raise ValueError("writer: public_hex must be a 64-char sha256 hex digest")
    if not str(domain or "").strip():
        raise ValueError("writer: domain is required — what this key is, "
                         "declared before it acts")
    if not str(declared_by or "").strip():
        raise ValueError("writer: declared_by is required — a name, not a "
                         "role (ADR 021)")
    return store.append("writer", {
        "schema": "writer/0.1",
        "public_hex": ph,
        "domain": domain.strip(),
        "declared_by": declared_by.strip(),
    }, key)


def _resolve_key(event: dict, hexes: list[str]) -> str | None:
    """Resolves WHICH registered key sealed this event — by signature, never
    by label. None when none matches: the writer is outside the sealed
    registry, and outside is unattested."""
    try:
        sig = bytes.fromhex(event["signature"])
        digest = bytes.fromhex(event["event_hash"])
    except (KeyError, ValueError):
        return None
    from .chain import ed25519_verify

    for ph in hexes:
        if ed25519_verify(ph, sig.hex(), digest):
            return ph
    return None


def _validate_public_hex(value: str, what: str) -> str:
    ph = str(value or "")
    if len(ph) != 64 or any(c not in "0123456789abcdef" for c in ph):
        raise ValueError(f"{what}: must be a 64-char sha256 hex digest")
    return ph


def _assemble_registry(events: list[dict],
                       registrar_public_hex: str | None) -> tuple[dict, dict]:
    """(v0.2.7 — §17, howcani's write race) Assembles the known-writers
    registry from the journal's `writer` events.

    PINNED (registrar key supplied out-of-band): only entries the pinned
    registrar SEALED are admitted — filtered at assembly, so the agent's
    own registration cannot vote no matter which order the writes landed
    in. A key the registrar attested under TWO domains is the operator
    contradicting itself: it lands in `contested`, undecidable, never
    first-wins.

    UNPINNED: the v0.2.6 store-derived scan — every writer event votes,
    first write wins. The weaker mode on purpose: without a pin there is
    no referent for "operator", and pretending otherwise is the one thing
    the disclosure (registry_disclosure) exists to prevent."""
    registry: dict[str, dict] = {}
    contested: dict[str, list[str]] = {}
    if registrar_public_hex:
        reg = _validate_public_hex(registrar_public_hex,
                                   "registrar_public_hex")
        by_hex: dict[str, list[dict]] = {}
        for w in events:
            if w.get("type") == "writer" and _resolve_key(w, [reg]) == reg:
                ph = str(w.get("payload", {}).get("public_hex", ""))
                if ph:
                    by_hex.setdefault(ph, []).append(w)
        for ph, ws in by_hex.items():
            domains = sorted({str(w.get("payload", {}).get("domain", ""))
                              for w in ws})
            if len(domains) > 1:
                contested[ph] = domains
            else:
                registry[ph] = ws[0].get("payload", {})
    else:
        for w in events:
            if w.get("type") == "writer":
                ph = w.get("payload", {}).get("public_hex")
                if ph:
                    registry.setdefault(str(ph), w.get("payload", {}))
    return registry, contested


def registry_disclosure(events: list[dict],
                        registrar_public_hex: str | None = None, *,
                        signer_mode: str | None = None,
                        uid_gate: str | None = None) -> dict:
    """The DISCLOSURE ROW (v0.2.7 — §17, howcani's descent floor; v0.2.8
    — 3hkpp, the custody mode): the verdict states WHO registered the
    writers, at what evidence grade, and WHAT THE SIGNATURE RESTS ON.
    The drop-in property makes the journal blind to custody — a writer
    event sealed through the keyholder reads exactly as one signed
    in-process — so the custody mode is a disclosure field, not something
    the artifact can prove: `signer_mode` ("in-process" | "socket" |
    "pkcs11" | the deployment's own word) and `uid_gate` ("enforced" |
    "off" | "unavailable(<platform>)"). Both default to None — serialized
    as null, meaning the caller did NOT state it: the same honesty as the
    unpinned mode line. Derive it with `SocketSigner.uid_gate()`: the
    daemon reports BOTH facts (peer_uid_checked AND uid_gate_configured)
    — 'off' when no gate is configured, even where the platform could
    have checked (3hl4l: peer_uid_checked alone answered "could the
    platform tell", and read 'checked' for a daemon that checks
    nothing).

    Pinned: the registrant is the pinned registrar key and the counts are
    the registrar-sealed assembly. Unpinned: the mode line says
    "store-derived (first-write-wins)" — the registry nobody vouched for.
    Seal it into the report beside the findings (journal_report)."""
    from .aiact import evidence_grade

    registry, contested = _assemble_registry(events, registrar_public_hex)
    grade = evidence_grade("writer")  # journal-local → grade 3, by default
    writer_events = [w for w in events if w.get("type") == "writer"]
    pinned = registrar_public_hex is not None
    if pinned:
        reg = _validate_public_hex(registrar_public_hex,
                                   "registrar_public_hex")
        registrar_sealed = sum(1 for w in writer_events
                               if _resolve_key(w, [reg]) == reg)
    else:
        registrar_sealed = len(writer_events)
    return {
        "schema": "registry-disclosure/0.2",
        "signer_mode": signer_mode,
        "uid_gate": uid_gate,
        "mode": "pinned" if pinned else
                "store-derived (first-write-wins — no registrar pinned)",
        "registrar": (f"pinned {registrar_public_hex}" if pinned else None),
        "grade": grade["grade"],
        "grade_label": grade["label"],
        "proof": grade["proof"],
        "obligation": grade["obligation"],
        "registered_keys": len(registry),
        "writer_events_total": len(writer_events),
        "registrar_sealed_events": registrar_sealed,
        "filtered_writer_events": len(writer_events) - registrar_sealed,
        "contested_keys": sorted(contested),
    }


def reconcile_receipts(events: list[dict], *,
                       judge_call_type: str = "llm_call",
                       requirement_type: str = "requirement",
                       correlation_key: str = "run_id",
                       transport_attempt_type: str = "agent_tool_use",
                       signers: list[tuple[str, str]] | None = None,
                       touched_paths: list[str] | None = None,
                       registrar_public_hex: str | None = None) -> list[Finding]:
    """(v0.2.7 — §17, howcani's write race: `registrar_public_hex` pins the
    registrar's key OUT-OF-BAND — ADR 008's TSA-root pattern, never read
    from the artifact under audit. The registry assembles from
    registrar-sealed entries only, a key the registrar attested under two
    domains is `registry_duplicate_undecidable` — emitted at assembly,
    never first-write-wins — and `registry_disclosure` states the
    registrant and the grade. v0.2.6 adds the writer registry —
    `seal_writer` — and the explicit check states: a skipped check is
    reported, never clean; `signers=None` (no set supplied) and
    `signers=[]` (known-empty) are distinct, and each note says which one
    it was."""
    """The receipt joins (v0.2.3 — howcani's audit; v0.2.4 — the ceiling,
    closed): a receipt's sealed declarations are checked against
    OBSERVATIONS the declaring party did not author.

    1. **Label vs journal** — a receipt declaring `judged_by="llm"` is not
       checked here (the judge's own call event is the observation); a
       receipt declaring `judged_by="deterministic"` while the journal
       contains a `{judge_call_type}` event on the same correlation key is
       `label_llm_call_mismatch`: a judge WAS invoked.
    2. **The transport-writer invariant (v0.2.4 — the absence a chain
       cannot see)**: a receipt declaring `judged_by="deterministic"` with
       NO `{transport_attempt_type}` attempt on the same key — or only
       attempts sealed by the receipt's OWN writer — is
       `unverified_label`. The join v0.2.3 was structurally blind to the
       CONSISTENT agent that never journals an llm_call; the burden
       inverts: the label is verified only by an attempt from the
       transport (the hook process), sealed by a writer the agent does
       not control. Absence becomes a missing event, not a missing
       negative.
    3. **Citation resolution + scope (v0.2.4 — load-bearing)**: a receipt
       citing `requirement_ref` that no sealed requirement carries is
       `dangling_requirement_ref`. When the resolved requirement declares
       a SCOPE (paths it governs, sealed at requirement time) and
       `touched_paths` is provided (the diff's touched set, from git —
       the first observation the agent does not author), a citation whose
       scope intersects NOTHING in the touched set is
       `requirement_out_of_scope`: the obligation cited does not govern
       this work.

    Receipts are events of type `receipt` (payload schema `receipt/0.2.*`).
    Clean joins return an empty list; seal the findings like any report."""
    receipts = [e for e in events
                if e.get("type") == "receipt"
                and str(e.get("payload", {}).get("schema", "")).startswith("receipt/")]
    judge_calls: dict[str, dict] = {}
    for e in events:
        if e.get("type") == judge_call_type:
            value = e.get("payload", {}).get(correlation_key)
            if value is not None:
                judge_calls.setdefault(str(value), e)
    requirements: dict[str, dict] = {}
    for e in events:
        if e.get("type") == requirement_type:
            ref = e.get("payload", {}).get("ref")
            if ref:
                requirements.setdefault(str(ref), e.get("payload", {}))
    transports: dict[str, list[dict]] = {}
    for e in events:
        if e.get("type") == transport_attempt_type:
            value = e.get("payload", {}).get(correlation_key)
            if value is not None:
                transports.setdefault(str(value), []).append(e)

    findings: list[Finding] = []
    # (v0.2.6 §15; v0.2.7 §17) — the registry is assembled ONCE, before the
    # row loop, and a contested key is emitted AT ASSEMBLY: the verdict
    # reads the registry the operator sealed, not the registry that
    # arrived first.
    registry, contested = _assemble_registry(events, registrar_public_hex)
    assembly_findings: list[Finding] = []
    for ph, domains in contested.items():
        assembly_findings.append(Finding(
            "receipts", "registry_duplicate_undecidable", ph,
            note="the pinned registrar attested this key under "
                 f"{len(domains)} domains ({', '.join(domains)}) — the "
                 "operator contradicts itself, the key's domain is "
                 "undecidable, never first-wins (v0.2.7, howcani's "
                 "write race)"))
    for e in receipts:
        payload = e.get("payload", {})
        join_value = payload.get(correlation_key)
        if join_value is None:
            continue
        join_value = str(join_value)
        judged_by = payload.get("judged_by")

        # v0.2.6 (§15) — REGISTRY MODE: when a sealed known-writers registry
        # exists, it is the authority. Key resolution, domains and
        # independence all come from it; the caller supplies nothing.
        # v0.2.7 (§17) — PINNED REGISTRY MODE: the registry itself was
        # assembled from registrar-sealed entries only (filter at
        # assembly), so the agent's self-registration cannot vote in
        # either order, and a contested key is undecidable here too.
        attempts = transports.get(join_value, [])
        row_undecidable = False
        witnessed = False

        if attempts and registrar_public_hex is not None:
            hexes = list(registry) + list(contested)
            receipt_key = _resolve_key(e, hexes)
            if receipt_key is None:
                row_undecidable = True
                findings.append(Finding(
                    "receipts", "independence_undecidable", join_value,
                    decision_seq=e["seq"],
                    note="the receipt's writer does not resolve against "
                         "the registry sealed by the pinned registrar — "
                         "the receipt's own domain is unattested, and "
                         "undecidable is never clean (v0.2.7)"))
            elif receipt_key in contested:
                row_undecidable = True
                findings.append(Finding(
                    "receipts", "independence_undecidable", join_value,
                    decision_seq=e["seq"],
                    note="the receipt's key is one the pinned registrar "
                         f"attested under {len(contested[receipt_key])} "
                         "domains — the registrar contradicts itself and "
                         "the domain is undecidable, never first-wins "
                         "(v0.2.7, howcani's write race)"))
            else:
                r_dom = registry[receipt_key].get("domain", "")
                for a in attempts:
                    wk = _resolve_key(a, hexes)
                    if wk is None:
                        continue  # unattested: outside the pinned registry
                    if wk in contested:
                        row_undecidable = True
                        findings.append(Finding(
                            "receipts", "independence_undecidable",
                            join_value, decision_seq=e["seq"],
                            note="a transport writer's domain is one the "
                                 "pinned registrar attested under "
                                 f"{len(contested[wk])} domains — the "
                                 "witness is undecidable, never clean "
                                 "(v0.2.7)"))
                        break
                    if registry[wk].get("domain", "") != r_dom:
                        witnessed = True
        elif attempts and registry:
            # REGISTRY MODE: resolution by signature against the sealed
            # public hexes; a witness is a REGISTERED writer whose domain
            # differs from the receipt's own.
            hexes = list(registry.keys())
            receipt_key = _resolve_key(e, hexes)
            if receipt_key is None:
                row_undecidable = True
                findings.append(Finding(
                    "receipts", "independence_undecidable", join_value,
                    decision_seq=e["seq"],
                    note="the receipt's writer does not resolve against the "
                         "sealed known-writers registry — the receipt's own "
                         "domain is unattested, and undecidable is never "
                         "clean (v0.2.6)"))
            else:
                r_dom = registry[receipt_key].get("domain", "")
                witnessed = any(
                    (wk := _resolve_key(a, hexes)) is not None
                    and registry[wk].get("domain", "") != r_dom
                    for a in attempts)
        elif attempts and signers:
            # SIGNERS MODE (v0.2.5, the probe's BUG A fix): the cross-writer
            # check compares KEY MATERIAL, never labels — two
            # agent-controlled keys with different labels are one trust
            # domain; an unresolved receipt writer is undecidable, never
            # clean (BUG B).
            receipt_key = _signer_key(e, signers)
            if receipt_key is not None:
                witnessed = any(
                    k != receipt_key
                    for k in ({_signer_key(a, signers)
                               for a in attempts} - {None}))
            else:
                row_undecidable = True
                findings.append(Finding(
                    "receipts", "independence_undecidable", join_value,
                    decision_seq=e["seq"],
                    note="the receipt's writer does not resolve against the "
                         "known-writer set — undecidable is never clean "
                         "(v0.2.5, BUG B)"))

        # the deterministic label vs the journal (v0.2.3): a judge WAS
        # invoked — re-probe invited
        if judged_by == "deterministic" and join_value in judge_calls:
            findings.append(Finding(
                "receipts", "label_llm_call_mismatch", join_value,
                decision_seq=e["seq"],
                note="receipt declares 'deterministic' while the journal "
                     f"contains a {judge_call_type} event for the same key — "
                     "the label checked against an observation the labelled "
                     "party did not author; re-probe invited"))

        # the transport-writer invariant (v0.2.4; registry-aware v0.2.6):
        # a deterministic label is verified only by a transport attempt
        # sealed by a writer the agent does not control
        if judged_by == "deterministic" and join_value not in judge_calls \
                and not witnessed and not row_undecidable:
            if not attempts:
                reason = "no transport attempt on this key"
            elif registry and not witnessed:
                if registrar_public_hex is not None:
                    reason = ("no writer the pinned registrar registered "
                              "carries a domain distinct from the "
                              "receipt's own — same trust domain (ADR "
                              "021, one layer down)")
                else:
                    reason = ("no registered writer with a domain distinct from "
                              "the receipt's own witnessed the attempt — same "
                              "trust domain (ADR 021, one layer down)")
            elif signers is not None and len(signers) == 0:
                reason = ("the known-writer set is EMPTY — nobody else could "
                          "have sealed the attempt, so the label cannot "
                          "verify")
            elif signers is None:
                reason = ("independence NOT RUN — no known-writer set "
                          "supplied, so the transport writer cannot be "
                          "resolved; re-probe with the signers set")
            else:
                reason = ("the only transport attempts on this key carry the "
                          "receipt's own key — same trust domain (ADR 021, "
                          "one layer down)")
            findings.append(Finding(
                "receipts", "unverified_label", join_value,
                decision_seq=e["seq"],
                note=f"receipt declares 'deterministic' and {reason} — the "
                     f"label is a claim the agent authored; the transport is "
                     f"the observation it did not; re-probe invited"))

        # the citation (v0.2.4 load-bearing; v0.2.6 names its skips)
        cited = payload.get("requirement_ref")
        if cited:
            req = requirements.get(str(cited))
            if req is None:
                findings.append(Finding(
                    "receipts", "dangling_requirement_ref", str(cited),
                    decision_seq=e["seq"],
                    note=f"requirement_ref {cited!r} resolves to nothing sealed — "
                         f"the citation is decoration until it resolves; "
                         f"re-probe invited"))
            elif touched_paths is not None:
                scope = req.get("scope")
                if isinstance(scope, list) and scope and \
                        not any(str(p).rstrip("*") and
                                any(str(t).startswith(str(p).rstrip("*"))
                                    for t in touched_paths)
                                for p in scope):
                    findings.append(Finding(
                        "receipts", "requirement_out_of_scope", str(cited),
                        decision_seq=e["seq"],
                        note=f"requirement_ref {cited!r} governs {scope}, and "
                             f"the diff touches none of it — the obligation "
                             f"cited does not govern this work; re-probe "
                             f"invited"))
            elif isinstance(req.get("scope"), list) and req.get("scope"):
                findings.append(Finding(
                    "receipts", "scope_check_not_run", str(cited),
                    decision_seq=e["seq"],
                    note="the scope check did not run — touched_paths not "
                         "supplied; never confused with clean (v0.2.6)"))
    return assembly_findings + findings


def journal_report(store, key, invariants: list[Invariant],
                   findings: list[Finding], probes: list[Finding] | None = None,
                   events: list[dict] | None = None,
                   calibrations: list[Finding] | None = None,
                   registry_disclosure: dict | None = None,
                   custody_disclosure: dict | None = None) -> dict:
    """Seals the reconciliation report as a `reconciliation` event.

    v0.2 (ADR 019): the report is sealed EVEN WHEN EVERYTHING MATCHED — a
    checker that only journals findings has no proof it ever ran. The report
    carries the run counts (how many decisions, attempts, outcomes were
    actually examined — the sum-to-n evidence) and the negative-control
    results. The journal audits its auditor.

    v0.2.7 (§17): `registry_disclosure` — the disclosure row
    (`registry_disclosure()`), stating WHO registered the writers and at
    what evidence grade. A disclosure is not a violation: it never touches
    `clean_pass`, it only stops a clean verdict from pretending to rest on
    more than the operator's own custody.
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
        "calibrations": [f.__dict__ for f in (calibrations or [])],
        "calibrations_ok": not any(f.status in ("calibration_fitted_in_sample",
                                                "control_out_of_range")
                                   for f in (calibrations or [])),
    }
    if registry_disclosure is not None:
        report["registry_disclosure"] = registry_disclosure
    if custody_disclosure is not None:
        report["custody_disclosure"] = custody_disclosure
    # ADR 019 §8 — the report witnesses its own run: byte counts of the
    # sealed payload, normalized (no wall-clock, no content beyond counts).
    from .chain import canonical
    from .witness import canonical_witness

    report["witness"] = canonical_witness(0, canonical(report))
    return store.append("reconciliation", report, key)


def seal_policy(store, key, policy: dict) -> dict:
    """Seals the reconciliation PRECEDENCE policy as a
    `reconciliation_policy` event (issue #35 — mickyarun): when two
    independently sealed streams disagree, which record wins and who is out
    of pocket during the open window is a rule decided BEFORE the incident
    and journaled like everything else — otherwise the argument is settled
    by whoever is more senior.

    Shape: {"scope", "winner": "decision"|"outcome"|"external", "absorbs_cost",
    "decided_by"} — validated: winner is enum, decided_by required (a name,
    not a role — ADR 021)."""
    winner = policy.get("winner")
    if winner not in ("decision", "outcome", "external"):
        raise ValueError("precedence.winner must be decision | outcome | external")
    if not policy.get("decided_by", "").strip():
        raise ValueError("precedence.decided_by is required — a name, not a role (ADR 021)")
    return store.append("reconciliation_policy", {
        "schema": "reconciliation-policy/0.1",
        "scope": policy.get("scope", "all"),
        "winner": winner,
        "absorbs_cost": policy.get("absorbs_cost", ""),
        "decided_by": policy["decided_by"],
    }, key)


def check_lookup_control(name: str, expected_count: int, got_count: int) -> Finding:
    """Per-parameter negative control on lookups (issue #36 — anp2network):
    before a reconciler moves an operation out of Unknown, the destination
    must have passed a negative control FOR EACH filter parameter used — a
    query whose correct answer is known-zero must return zero, and the
    control row must be one the degraded response wouldn't contain anyway
    (an older row, a rare kind — not the newest). A miss is the finding
    `lookup_silently_unfiltered`: the operation STAYS Unknown."""
    if expected_count != 0:
        raise ValueError("negative controls assert a known-zero answer — "
                         "expected_count must be 0")
    if got_count != expected_count:
        return Finding("lookup", "lookup_silently_unfiltered", name)
    return Finding("lookup", "lookup_control_ok", name)


# --- issue #42 — calibration: an a-priori bound, never observed spread -------

_CALIBRATION_SOURCES = ("a-priori", "observed-spread")


def seal_calibration(store, key, control: dict) -> dict:
    """Seals a negative control's calibration as a `calibration` event
    (issue #42 — pm25coder, verifier thread round 4).

    The control's known value is a RANGE, not a point — and the range is
    declared BEFORE the run, derived from what the construction licenses a
    priori (the bound the conditional law sets), never fitted from the
    enumerated constructions: a range fitted in-sample fails on the first
    correct construction it has never met. Value AND width predate the run —
    sealed first, like every belief (ADR 023's shape).

    `source` grades the derivation, the ADR 019 §3 split — the schema LABELS,
    the layer above REFUSES (see `check_calibration`):
      "a-priori"        — the bound the construction licenses; the only kind
                          a control may bite with;
      "observed-spread" — a range fitted from the observed runs: a LABELED
                          weakness, never a hidden one.

    The observed spread is not lost — it travels with the witness as
    calibration HISTORY (`record_observation`), never as the bound."""
    name = control.get("name", "")
    if not name.strip():
        raise ValueError("calibration: control name is required")
    rng = control.get("known_range")
    if (not isinstance(rng, dict) or not isinstance(rng.get("low"), (int, float))
            or not isinstance(rng.get("high"), (int, float))):
        raise ValueError("calibration: known_range must be {low, high} numbers — "
                         "a control's known value is a range, not a point")
    if rng["low"] > rng["high"]:
        raise ValueError("calibration: known_range low > high")
    if not control.get("derivation", "").strip():
        raise ValueError("calibration: derivation is required — WHERE the bound "
                         "comes from a priori (the conditional law, the spec)")
    if not control.get("declared_by", "").strip():
        raise ValueError("calibration: declared_by is required — a name, not a "
                         "role (ADR 021); the range predates the run and someone "
                         "declared it")
    source = control.get("source", "a-priori")
    if source not in _CALIBRATION_SOURCES:
        raise ValueError(f"calibration: source must be one of {_CALIBRATION_SOURCES}")
    return store.append("calibration", {
        "schema": "calibration/0.1",
        "control": name,
        "known_range": {"low": rng["low"], "high": rng["high"]},
        "derivation": control["derivation"],
        "declared_by": control["declared_by"],
        "source": source,
    }, key)


def check_calibration(decl: dict) -> Finding | None:
    """The layer above the label REFUSES (ADR 019 §3's split): a range whose
    source is "observed-spread" is the finding `calibration_fitted_in_sample`
    — in-sample, the first correct construction the checker has never met
    reads as a failure. A control may only bite with an a-priori bound.
    None = clean."""
    if decl.get("source") == "observed-spread":
        return Finding("calibration", "calibration_fitted_in_sample",
                       decl.get("control", "?"),
                       note="range fitted from the enumerated constructions — "
                            "re-derive it from what the construction licenses a priori")
    return None


def check_control_range(control: str, known_range: dict, observed: float) -> Finding:
    """The runtime half of the calibration: the run's value falls INSIDE the
    a-priori range or the control fails — `control_out_of_range` means the
    checker drifted, or the range was fitted (the first correct construction
    it has never met reads as a failure)."""
    low, high = known_range["low"], known_range["high"]
    if not low <= observed <= high:
        return Finding("calibration", "control_out_of_range", control,
                       note=f"observed {observed} outside [{low}, {high}]")
    return Finding("calibration", "control_in_range", control)


def record_observation(store, key, control: str, observed: float,
                       note: str = "") -> dict:
    """Calibration HISTORY — the observed spread travels with the witness as
    history, postdating the run. It never re-fits the bound: the range was
    declared a priori (`seal_calibration`) and stays what it was declared."""
    return store.append("calibration_observation", {
        "schema": "calibration-observation/0.1",
        "control": control,
        "observed": observed,
        "note": note,
    }, key)


# --- issue #48 — the two-sided denominator: receipt_gap (mickyarun) ----------

def check_receipt_gap(name: str, fetches_served: int, receipts_held: int) -> Finding:
    """The two-sided denominator (issue #48 — mickyarun): ADR 020 counted
    attempts against outcomes in ONE journal; across a trust boundary the
    denominator needs BOTH journals. The server seals how many fetches it
    served (`fetches_served`), the consumer seals how many receipts it holds
    (`receipts_held`) — both counters sealed like everything else — and the
    gap is the finding:

      receipts_held < fetches_served → fetches went out with no receipt
          held: the omission, two-party — the consumer's chain intact AND
          incomplete;
      receipts_held > fetches_served → receipts for fetches the server
          never served: the fabricated half, worse — surfaced with the same
          status, the note naming the direction.

    Zero-sum coverage is the only clean answer."""
    if fetches_served < 0 or receipts_held < 0:
        raise ValueError("receipt_gap: counts are counts — negative sealed "
                         "counters are not a thing")
    gap = fetches_served - receipts_held
    if gap > 0:
        return Finding("denominator", "receipt_gap", name,
                       note=f"{gap} fetch(es) served with no receipt held — "
                            f"the omission, two-party")
    if gap < 0:
        return Finding("denominator", "receipt_gap", name,
                       note=f"{-gap} receipt(s) beyond anything the server "
                            f"served — the fabricated half")
    return Finding("denominator", "receipt_coverage_ok", name)


# --- §20 — the custody grade: retention is the witness's other half ---------

_RETENTION_ACTIONS = frozenset({"prune", "migrate", "policy-change", "restore"})


def seal_retention(store, key, *, action: str, scope: str | None = None,
                   note: str | None = None) -> dict:
    """Seals a RETENTION change as a journal event (v0.1 — §20, the
    rudratosh/fluffydesk thread): prunes, migrations and policy changes
    become SIGNED EVENTS instead of ops-layer actions around the journal.
    A retention change with no sealed trace is an invisible grade change —
    the dashboard keeps showing green while the receipts' custody moved.

    `action` is a BOUNDED enum (v0.3.0's lesson, one layer over):
    "prune" | "migrate" | "policy-change" | "restore" — never prose."""
    if action not in _RETENTION_ACTIONS:
        raise ValueError(
            f"action must be one of {sorted(_RETENTION_ACTIONS)} — a "
            "retention action is a protocol vocabulary, not a sentence")
    payload = {"schema": "retention/0.1", "action": action}
    if scope:
        payload["scope"] = str(scope)
    if note:
        payload["note"] = str(note)
    return store.append("retention", payload, key)


def _newest_anchor(events: list[dict]) -> dict | None:
    """The newest external witness: the anchor event with the highest
    anchored head_seq (fluffydesk's retention half — the head hash is
    provable to a TSA the operator key cannot rewrite).

    NB-03: "newest anchor" means an anchor that WITNESSES — the cited
    head_hash must recompute to the chain's event at that seq (head_seq 0
    anchoring the empty chain against GENESIS), and the payload must carry
    a token (`_carries_witness_token`). `_anchored_upto` always checked the
    hash and the third-party verifier checks both; this path checked
    neither, so an anchor-shaped event with a fake hash and no token could
    walk `custody_grade` up to grade 2. A claim is not a witness."""
    from .chain import GENESIS

    by_seq = {e["seq"]: e for e in events}
    newest = None
    for e in events:
        if e.get("type") != "anchor":
            continue
        payload = e.get("payload", {})
        seq = payload.get("head_seq")
        if not isinstance(seq, int) or seq < 0 or seq > len(events):
            continue
        expected = by_seq[seq]["event_hash"] if seq else GENESIS
        if payload.get("head_hash") != expected:
            continue
        if not _carries_witness_token(payload):
            continue
        if newest is None or seq > newest["head_seq"]:
            newest = {"head_seq": seq, "ts": e.get("ts"),
                      "event_seq": e["seq"]}
    return newest
    # the anchor EVENT is the trusted prefix's last member (it carries the
    # external token): the unanchored tail starts AFTER it, so every
    # consumer measures from event_seq, never head_seq


def check_custody_drift(events: list[dict], *, max_tail_events: int = 1000,
                        max_tail_seconds: int | None = None,
                        now: str | None = None) -> list[Finding]:
    """The retention half of the custody grade (§20 — the thread's
    doctrine: **a witness is worth min(authoring, retention)** — receipts
    authored grade-1 but retained in operator-controlled storage sit at
    grade 3, and retention is the only grade that is WRONG BY DRIFT, so
    it wants monitoring, not just an audit):

    - `custody_unanchored` — the journal has NO external witness at all:
      every receipt rests on operator custody end to end.
    - `custody_drift` — more than `max_tail_events` events (or more than
      `max_tail_seconds` of wall clock) live beyond the newest anchor:
      the grade drifted silently, and the dashboard would still show
      green. The repair is an anchor (the head, to a witness the key
      cannot rewrite) or a sealed retention event — never a config edit
      outside the journal."""
    if max_tail_events is None and max_tail_seconds is None:
        raise ValueError(
            "give at least one bound — a drift check without a bound "
            "would never fire, which is the silence it exists to prevent")
    newest = _newest_anchor(events)
    total = len(events)
    if newest is None:
        if total == 0:
            return []
        return [Finding(
            "custody", "custody_unanchored", "journal",
            decision_seq=total,
            note=f"{total} event(s) with NO external witness — every "
                 "receipt is grade-3 by retention: authored grade-1, "
                 "retained in operator-controlled storage "
                 "(min(authoring, retention)). Seal an anchor — the head "
                 "hash, to a point the operator key cannot rewrite "
                 "(TSA / counterparty)")]
    tail = total - newest["event_seq"]
    findings: list[Finding] = []
    if max_tail_events is not None and tail > max_tail_events:
        findings.append(Finding(
            "custody", "custody_drift", f"tail:{newest['head_seq']}",
            decision_seq=newest["event_seq"],
            note=f"{tail} events live beyond the newest external witness "
                 f"(seq {newest['head_seq']}) — the custody grade drifted: "
                 "the tail is grade-3 by retention while its receipts are "
                 "authored grade-1. Seal an anchor or a retention event; "
                 "the dashboard does not see this one"))
    if max_tail_seconds is not None:
        anchor_ts = newest["ts"]
        ref = now or (events[-1]["ts"] if events else None)
        if anchor_ts and ref:
            from datetime import datetime
            delta = (datetime.fromisoformat(ref.replace("Z", "+00:00"))
                     - datetime.fromisoformat(
                         anchor_ts.replace("Z", "+00:00"))).total_seconds()
            if delta > max_tail_seconds:
                findings.append(Finding(
                    "custody", "custody_drift", f"tail-age:{newest['head_seq']}",
                    decision_seq=newest["event_seq"],
                    note=f"{int(delta)}s since the newest external witness "
                         f"(seq {newest['head_seq']}) — beyond the "
                         f"{max_tail_seconds}s cadence: the grade drifted "
                         "by time, which no event count can show"))
    return findings


def custody_grade(events: list[dict], *, max_tail_events: int = 1000,
                  max_tail_seconds: int | None = None,
                  now: str | None = None) -> dict:
    """The DISCLOSURE row for custody (§20): the journal's evidence grade
    as the thread prices it — **witness = min(authoring, retention)**
    (fluffydesk). The grade is the TAIL's grade, because that is what the
    current head rests on: 2 ("disinterested custodian") while an anchor
    witnesses the head within cadence, 3 ("anchored self") the moment the
    tail drifts — plus the counts that make the drift visible instead of
    silent. Seal it into the report via `journal_report(
    custody_disclosure=...)`; a disclosure never touches `clean_pass`."""
    from .aiact import evidence_grade

    newest = _newest_anchor(events)
    total = len(events)
    retention_events = sum(1 for e in events if e.get("type") == "retention")
    tail = (total - newest["event_seq"]) if newest else total
    drifted = False
    if newest is not None and max_tail_events is not None \
            and tail > max_tail_events:
        drifted = True
    if newest is not None and max_tail_seconds is not None:
        anchor_ts = newest["ts"]
        ref = now or (events[-1]["ts"] if events else None)
        if anchor_ts and ref:
            from datetime import datetime
            delta = (datetime.fromisoformat(ref.replace("Z", "+00:00"))
                     - datetime.fromisoformat(
                         anchor_ts.replace("Z", "+00:00"))).total_seconds()
            if delta > max_tail_seconds:
                drifted = True
    if newest is None:
        grade, mode = 3, "unanchored"
    elif drifted:
        grade, mode = 3, "drifted"
    else:
        grade, mode = 2, "anchored-within-cadence"
    g = evidence_grade("writer")  # grade-3 vocabulary, reused honestly
    return {
        "schema": "custody-grade/0.1",
        "grade": grade,
        "grade_label": ("disinterested custodian" if grade == 2
                        else g["label"]),
        "mode": mode,
        "formula": "witness = min(authoring, retention)",
        "newest_witness": newest,
        "tail_events": tail,
        "retention_events": retention_events,
        "obligation": g["obligation"] if grade == 3 else
                      "the TSA's signing duty (RFC 3161) covers the "
                      "anchored prefix; the tail rests on the operator",
    }
