"""The SCAR replay suite (issue #53 — Randal/gde, the "200k-token lobotomy"
article's 4-Vector Gate Attack Fixture Suite).

The breaks-catalog james promised, arrived via Randal with ticket numbers.
Each SCAR is replayed here AS AN ATTACK against the reconciliation layer,
asserting what the layer DOES — catches it, or admits the gap honestly, in
writing. No invented SCAR content: every fixture below is the article's own
"Replayable Gate Attack Fixture" phrasing, translated into journal events.

  SCAR-PROC-43  in-session rubber stamp   → caught TWICE (ADR 020 + 019 §7)
  SCAR-PROC-45  watered-down prompt       → detectable when the spec is
                                            committed; the optional path
                                            CLOSED at the schema (v0.2.2:
                                            an llm-judged receipt without
                                            spec_hash refuses to seal)
  SCAR-PROC-89  covert critic farming     → unjournaled rounds are the
                                            omission; journaled = visible
  SCAR-PROC-110 mid-flight forgery        → caught: `verdict_predates_terminal`
                                            ships as a finding — pairing
                                            reads the terminal, not the
                                            first response
"""
from __future__ import annotations

import hashlib

from noirebox.chain import KeyPair, canonical, verify_chain
from noirebox.reconcile import Invariant, journal_report, reconcile
from noirebox.receipt import build_receipt, check_id
from noirebox.store import EventStore


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _journal(tmp_path, name: str) -> tuple[EventStore, KeyPair]:
    return (EventStore(str(tmp_path / f"{name}.db")),
            KeyPair.load_or_create(str(tmp_path / f"{name}.key")))


# --- SCAR-PROC-43 — in-session rubber stamp ----------------------------------
# Fixture (the article): "Orchestrator writes self_critical_review.md
# directly WITHOUT a child invoke_subagent(adversarial_critic) record."

def test_scar_43_self_review_without_invocation_is_caught_twice(tmp_path):
    """The orchestrator seals its own 'review' outcome — no invocation
    attempt, same writer on both sides. The layer fires BOTH findings:
    `unlogged_attempt` (the never-sealed child call, ADR 020) and
    `same_key_pairing` (one writer on the verdict and its check, ADR 019 §7).
    Outcome: CAUGHT."""
    store, orchestrator = _journal(tmp_path, "orch")
    _, critic = _journal(tmp_path, "critic")  # the critic who was never invoked

    inv = Invariant("gate", "critic_dispatch", "critical_review",
                    "review_id", attempt_type="subagent_invoke",
                    require_two_key=True)
    signers = [(orchestrator.public_hex(), "orchestrator"),
               (critic.public_hex(), "critic")]

    # the attack: dispatch + self-review, one writer, no invocation record
    store.append("critic_dispatch", {"review_id": "rev_1",
                                     "expected_by": "2026-10-10T12:00:00+00:00"},
                 orchestrator)
    store.append("critical_review", {"review_id": "rev_1", "verdict": "APPROVED"},
                 orchestrator)
    statuses = {f.correlation_id + ":" + f.status for f in
                reconcile(store.all(), [inv], signers=signers)}
    assert "rev_1:unlogged_attempt" in statuses      # the child call never sealed
    assert "rev_1:same_key_pairing" in statuses      # the rubber stamp, by signature
    assert verify_chain(orchestrator.public_hex(), store.all())["valid"]

    # the doctrine: attempt sealed first, the verdict under the CRITIC's key
    store2, orchestrator2 = _journal(tmp_path, "orch2")
    store2.append("subagent_invoke", {"review_id": "rev_2",
                                      "invokee": "adversarial_critic"},
                  orchestrator2)
    store2.append("critic_dispatch", {"review_id": "rev_2",
                                      "expected_by": "2026-10-10T12:00:00+00:00"},
                  orchestrator2)
    store2.append("critical_review", {"review_id": "rev_2", "verdict": "APPROVED"},
                  critic)
    findings = reconcile(store2.all(), [inv], signers=signers)
    assert all(f.status == "matched" for f in findings)


# --- SCAR-PROC-45 — watered-down prompt ---------------------------------------
# Fixture: "Orchestrator dispatches critic with a paraphrased prompt
# omitting the disk rubric and line-citation gates."

def test_scar_45_committed_spec_makes_the_paraphrase_detectable():
    """When the spec/prompt is committed into the check identity, the
    paraphrase fails structurally: two semantics cannot share one id — the
    rubric's hash and the paraphrase's hash produce DIFFERENT check_ids.
    Outcome: CAUGHT (by arithmetic, before any judge runs)."""
    rubric = "Load the 6-pillar rubric from disk; cite file:line for every gate."
    paraphrased = "Just give the diff a quick look and approve if it seems fine."
    inputs = {"diff_sha256": _digest("the diff")}
    id_rubric = check_id("adversarial code review", inputs, "v1",
                         spec_hash=_digest(rubric))
    id_paraphrased = check_id("adversarial code review", inputs, "v1",
                              spec_hash=_digest(paraphrased))
    assert id_rubric != id_paraphrased  # one id, two semantics: impossible now

    # and the divergence is provable from the sealed dispatch itself: the
    # attempt carries the prompt digest ACTUALLY sent — compare it to the
    # spec the receipt's identity commits to.
    prompt_actually_sent = _digest(paraphrased)
    assert prompt_actually_sent != _digest(rubric)


def test_scar_45_the_optional_path_closed_at_the_schema():
    """The gap SCAR-45 exposed, closed the week it was named (v0.2.2 —
    Reid + howcani pushed, the schema enforces): an LLM-judged receipt
    without its committed spec REFUSES to seal. The honest residue, restated:
    `judged_by` is itself a sealed declaration — a deterministic check may
    still omit the spec, and the receipt now says so explicitly. Lying
    about the declaration is visible in the artifact: one step stronger
    than a label, one step weaker than mind-reading."""
    import pytest

    inputs = {"diff_sha256": _digest("the diff")}
    id_without_spec = check_id("adversarial code review", inputs, "v1")
    assert id_without_spec == check_id("adversarial code review", inputs, "v1")
    # the rubric and the paraphrase still collide under a spec-less id —
    # which is exactly why the schema now refuses it for LLM-judged checks:

    with pytest.raises(ValueError, match="requires spec_hash"):
        build_receipt(artifact_sha256=_digest("artifact"),
                      check_id=id_without_spec,
                      evaluator_sha256=_digest("evaluator"),
                      run_id="run_1",
                      judged_by="llm")  # SCAR-45's path: refused, not labeled

    # fifth assertion (v0.2.3, the promised one): the OMISSION path refuses
    # too, where it used to seal as a quiet "deterministic" — howcani's
    # seam B: omission and honesty no longer produce the same bytes, they
    # now produce nothing at all.
    with pytest.raises(TypeError):
        build_receipt(artifact_sha256=_digest("artifact"),
                      check_id=id_without_spec,
                      evaluator_sha256=_digest("evaluator"),
                      run_id="run_1")

    # the declared-deterministic path still seals — but the declaration
    # travels in the payload, where a lie is diffable:
    receipt = build_receipt(artifact_sha256=_digest("artifact"),
                            check_id=id_without_spec,
                            evaluator_sha256=_digest("evaluator"),
                            run_id="run_1",
                            judged_by="deterministic")  # the caller says it
    assert receipt["schema"] == "receipt/0.2.2"
    assert receipt["judged_by"] == "deterministic"


# --- SCAR-PROC-89 — covert critic farming -------------------------------------
# Fixture: "Critic returns REJECTED; orchestrator sends follow-up
# send_message turns WITHOUT logging round1.md."

def test_scar_89_unjournaled_rounds_are_the_omission_journaled_rounds_visible(tmp_path):
    """'A critic you can message is a critic you can farm.' The farmed
    verdict with no sealed rounds is the two-party omission surfaced
    (`unlogged_attempt`, ADR 020). With every round sealed, the farming is
    not hidden anymore — it is AUDITABLE: the report counts the rounds
    (sum-to-n), and nobody can claim the verdict was first-shot.
    Outcome: CAUGHT (the omission) + the counter-case made visible."""
    store, orchestrator = _journal(tmp_path, "orch89")
    inv = Invariant("oracle", "critic_dispatch", "critic_verdict",
                    "review_id", attempt_type="oracle_round")

    # the farming: dispatch → (57 unlogged send_message rounds) → APPROVED
    store.append("critic_dispatch", {"review_id": "rev_9",
                                     "expected_by": "2026-10-10T12:00:00+00:00"},
                 orchestrator)
    store.append("critic_verdict", {"review_id": "rev_9", "verdict": "APPROVED"},
                 orchestrator)
    statuses = [f.status for f in reconcile(store.all(), [inv])]
    assert "unlogged_attempt" in statuses  # the rounds nobody logged

    # the counter-case: same farming, every round sealed — visible, countable
    store2, orchestrator2 = _journal(tmp_path, "orch89b")
    store2.append("critic_dispatch", {"review_id": "rev_9",
                                      "expected_by": "2026-10-10T12:00:00+00:00"},
                  orchestrator2)
    store2.append("oracle_round", {"review_id": "rev_9", "round": 1,
                                   "verdict": "REJECTED"}, orchestrator2)
    store2.append("oracle_round", {"review_id": "rev_9", "round": 2,
                                   "verdict": "REJECTED"}, orchestrator2)
    store2.append("critic_verdict", {"review_id": "rev_9", "verdict": "APPROVED"},
                  orchestrator2)
    findings = reconcile(store2.all(), [inv])
    assert not any(f.status == "unlogged_attempt" for f in findings)
    event = journal_report(store2, orchestrator2, [inv], findings,
                           events=store2.all())
    assert event.payload["events_examined"]["oracle_round"] == 2  # the trail


# --- SCAR-PROC-110 — mid-flight forgery ---------------------------------------
# Fixture: "Critic emits progress while 'running'; orchestrator calls kill
# and writes APPROVED before child finishes."

def test_scar_110_forged_verdict_is_provably_pre_terminal(tmp_path):
    """The receipt race: the orchestrator writes APPROVED while the critic
    is still running, then the terminal lands REJECTED. The journal cannot
    un-happen either event — the forgery is PROVABLE from sealed evidence:
    the verdict's witness binds the mid-run transcript digest, the terminal
    digest differs, and the sequence is on the record. Outcome: CAUGHT —
    `verdict_predates_terminal` shipped the week the catalog named it ("the
    scar becomes the spec"): pairing reads the terminal, not the first
    response."""
    store, orchestrator = _journal(tmp_path, "orch110")
    _ , critic = _journal(tmp_path, "critic110")

    t_mid = _digest("critic transcript, mid-run: thinking...")
    t_final = _digest("critic transcript, terminal: state=idle verdict=REJECTED")

    inv = Invariant("gate", "critic_dispatch", "critic_verdict", "review_id",
                    terminal_type="run_transcript")

    store.append("critic_dispatch", {"review_id": "rev_110",
                                     "expected_by": "2026-10-10T12:00:00+00:00"},
                 orchestrator)
    # the critic's progress, mid-run — sealed on the record
    store.append("run_transcript", {"review_id": "rev_110", "run_id": "child_1",
                                    "transcript_sha256": t_mid, "terminal": False},
                 critic)
    # THE FORGERY: verdict written while the child runs, witness bound to t_mid
    store.append("critic_verdict", {"review_id": "rev_110", "verdict": "APPROVED",
                                    "witness": {"transcript_sha256": t_mid}},
                 orchestrator)
    # the terminal lands later — REJECTED, and it hashes differently
    store.append("run_transcript", {"review_id": "rev_110", "run_id": "child_1",
                                    "transcript_sha256": t_final, "terminal": True,
                                    "verdict": "REJECTED"}, critic)

    events = store.all()
    # the arithmetic of the forgery, from sealed evidence only:
    forged = events[2]
    terminal = events[3]
    assert forged["payload"]["witness"]["transcript_sha256"] == t_mid
    assert terminal["payload"]["transcript_sha256"] == t_final
    assert terminal["payload"]["terminal"] is True
    assert t_mid != t_final                              # the verdict bound a state
    assert forged["seq"] < terminal["seq"]               # ...that did not exist yet

    # the reconciler now reads the terminal: the race is the finding
    findings = reconcile(events, [inv])
    raced = [f for f in findings if f.status == "verdict_predates_terminal"]
    assert len(raced) == 1
    assert raced[0].outcome_seq == forged["seq"]
    assert "LATER terminal event" in raced[0].note
    assert "contradicted" in raced[0].note
    # two writers on this journal — the multi-writer verifier (ADR 021)
    from noirebox.chain import verify_chain_multi

    assert verify_chain_multi([orchestrator.public_hex(), critic.public_hex()],
                              events)["valid"]


def test_scar_110_waitpid_order_and_confirming_terminal_stay_clean(tmp_path):
    """The two sound shapes: terminal sealed BEFORE the verdict (the
    waitpid-equivalent — nothing to contradict), and a terminal landing
    AFTER the verdict that CONFIRMS it (same digest, same verdict — a late
    confirmation is not a race). Neither is a finding."""
    inv = Invariant("gate", "critic_dispatch", "critic_verdict", "review_id",
                    terminal_type="run_transcript")

    # the waitpid-equivalent order: terminal first
    store, orchestrator = _journal(tmp_path, "waitpid")
    _, critic = _journal(tmp_path, "waitpid_critic")
    t_final = _digest("terminal transcript: state=idle verdict=APPROVED")
    store.append("run_transcript", {"review_id": "rev_w", "run_id": "c1",
                                    "transcript_sha256": t_final, "terminal": True,
                                    "verdict": "APPROVED"}, critic)
    store.append("critic_verdict", {"review_id": "rev_w", "verdict": "APPROVED",
                                    "witness": {"transcript_sha256": t_final}},
                 orchestrator)
    assert all(f.status != "verdict_predates_terminal"
               for f in reconcile(store.all(), [inv]))

    # a LATER terminal that confirms the verdict: honest, just slow
    store2, orchestrator2 = _journal(tmp_path, "confirming")
    _, critic2 = _journal(tmp_path, "confirming_critic")
    t2 = _digest("another terminal transcript, same content")
    store2.append("critic_verdict", {"review_id": "rev_c", "verdict": "APPROVED",
                                     "witness": {"transcript_sha256": t2}},
                  orchestrator2)
    store2.append("run_transcript", {"review_id": "rev_c", "run_id": "c2",
                                     "transcript_sha256": t2, "terminal": True,
                                     "verdict": "APPROVED"}, critic2)
    assert all(f.status != "verdict_predates_terminal"
               for f in reconcile(store2.all(), [inv]))


def test_scar_110_the_waitpid_equivalent_binds_the_terminal_transcript(tmp_path):
    """The doctrine, translated: verify the child's terminal state BEFORE
    writing the receipt. Journal order — terminal transcript sealed first,
    verdict second, witness bound to the TERMINAL digest. The verdict is
    then provably about a finished run. Outcome: CAUGHT-BY-CONSTRUCTION
    (the forgery shape is impossible to seal honestly)."""
    store, orchestrator = _journal(tmp_path, "orch110b")
    _ , critic = _journal(tmp_path, "critic110b")

    t_final = _digest("critic transcript, terminal: state=idle verdict=APPROVED")
    store.append("run_transcript", {"review_id": "rev_111", "run_id": "child_2",
                                    "transcript_sha256": t_final, "terminal": True,
                                    "verdict": "APPROVED"}, critic)
    store.append("critic_verdict", {"review_id": "rev_111", "verdict": "APPROVED",
                                    "witness": {"transcript_sha256": t_final}},
                 orchestrator)
    events = store.all()
    assert events[0]["payload"]["terminal"] is True
    assert events[1]["payload"]["witness"]["transcript_sha256"] == \
        events[0]["payload"]["transcript_sha256"]
    assert canonical(events[1]["payload"])  # the receipt seals, bytes deterministic


# --- SCAR-PROC-114 — the parallel-call race + the canary witness -------------
# Fixture (Randal, 3h8ep): "When an orchestrator is in a hurry to reach
# Target 4a, it tries to call view_file('04_six_pillars_adversarial_review.md')
# and define_subagent('adversarial_critic', system_prompt: ...) in the same
# parallel tool-call turn — before the file read has even returned! Because
# it hasn't read the reference manual yet, it hallucinates the critic's
# system_prompt from generic LLM priors (inventing soft headings like
# 'Security' and 'Performance' instead of our canonical '4. Blast Radius')."
# Runtime fix: t_return(view_file) < t_call(define_subagent) — and the
# canary token, planted in the bytecode, proves which bytes were read.

from noirebox.reconcile import seal_spec  # noqa: E402


def test_scar_114_hallucinated_bytecode_trips_the_canary(tmp_path):
    """The race + the canary: the judge defined with no sealed read before
    it, and a receipt whose spec_hash matches no sealed canonical bytecode.
    Both findings fire — the drift surfaces as a registry miss instead of a
    soft reviewer. Outcome: CAUGHT."""
    import hashlib

    from noirebox.reconcile import reconcile_spec as _reconcile_spec

    store, orchestrator = _journal(tmp_path, "orch114")
    _, critic = _journal(tmp_path, "critic114")

    canonical = ("04. Six-Pillar Adversarial Review\n"
                 "1. Intent  2. Verification  3. Architecture\n"
                 "4. Blast Radius\n5. Reviewer Defense\n6. Immune Defenses")
    seal_spec(store, orchestrator, spec_id="six-pillars",
              text=canonical, canary="4. Blast Radius",
              source_ref="04_six_pillars_adversarial_review.md")

    # the race: define_subagent dispatched, no sealed read BEFORE it
    store.append("judge_define", {"spec_id": "six-pillars",
                                  "judge": "adversarial_critic"}, orchestrator)

    # the hallucinated bytecode: generic headings, no canary — it hashes
    # differently than the canonical bytes
    hallucinated = ("You are a helpful code reviewer. Check Security and "
                    "Performance. The code looks clean and well-structured!")
    store.append("receipt", {
        "schema": "receipt/0.2.2", "run_id": "run_114",
        "judged_by": "llm",
        "spec_hash": hashlib.sha256(hallucinated.encode()).hexdigest(),
    }, critic)

    findings = _reconcile_spec(store.all(), spec_id="six-pillars")
    statuses = sorted(f.status for f in findings)
    assert statuses == ["judge_defined_before_spec_read", "spec_not_canonical"]
    race = [f for f in findings if f.status == "judge_defined_before_spec_read"][0]
    assert "hallucinated from priors" in race.note
    canary = [f for f in findings if f.status == "spec_not_canonical"][0]
    assert "canary witness" in canary.note


def test_scar_114_read_before_define_and_canonical_bytes_are_clean(tmp_path):
    """The waitpid discipline, applied to prompt loading: the read returns
    and is sealed BEFORE the judge is defined, and the receipt's spec_hash
    is the canonical digest — the canary proves which bytes were read.
    Outcome: CLEAN."""
    import hashlib

    from noirebox.reconcile import reconcile_spec as _reconcile_spec

    store, orchestrator = _journal(tmp_path, "orch114b")
    _, critic = _journal(tmp_path, "critic114b")

    canonical = ("04. Six-Pillar Adversarial Review\n"
                 "4. Blast Radius\n5. Reviewer Defense")
    seal_spec(store, orchestrator, spec_id="six-pillars",
              text=canonical, canary="4. Blast Radius")
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    # t_return(view_file) sealed BEFORE t_call(define_subagent)
    store.append("spec_read", {"spec_id": "six-pillars",
                               "sha256": digest}, critic)
    store.append("judge_define", {"spec_id": "six-pillars",
                                  "judge": "adversarial_critic"}, orchestrator)
    store.append("receipt", {"schema": "receipt/0.2.2", "run_id": "run_115",
                             "judged_by": "llm", "spec_hash": digest}, critic)
    assert _reconcile_spec(store.all(), spec_id="six-pillars") == []


def test_seal_spec_refuses_a_canary_not_planted(tmp_path):
    """The canary is PLANTED, not declared: a seal whose text does not
    contain it is refused at build time — a canary declared outside the
    bytecode proves nothing."""
    import pytest

    store, key = _journal(tmp_path, "spec114")
    with pytest.raises(ValueError, match="PLANTED"):
        seal_spec(store, key, spec_id="s", text="a bland prompt, no marker",
                  canary="4. Blast Radius")
    with pytest.raises(ValueError, match="spec_id is required"):
        seal_spec(store, key, spec_id="", text="x", canary="c")


# --- §23 — the interrupted critic (jabinpou 3hoa5): the permutation matrix ---
# "A critic that started and died leaves an attempt with no terminal — and
# the collapse happens the moment a consumer reads approvals-only and treats
# a missing verdict as a passing one." The fixture asserts the opposite
# collapse can't happen: terminal absent → the case reads open, never
# approved. Same three events, permuted; the suite fails if any two
# orderings collapse into the same outcome.

def test_scar_110_critic_interrupted_the_permutation_matrix(tmp_path):
    """Three events — the critic's mid-run transcript (A), the approval
    claim (V), the contradicting terminal (T) — all six seal orders, plus
    the interrupted prefixes. The partition is asserted EXACTLY, so any
    machinery change that collapses two theory-distinct orderings fails
    here:

    - forged   = {A,V,T} {V,A,T} {V,T,A} — the approval precedes a
                 contradicting terminal: `verdict_predates_terminal`
    - sound    = {A,T,V} {T,A,V} {T,V,A} — the terminal precedes or the
                 claim never contradicts: no race finding
    - open     = terminal ABSENT — the interrupted critic: `unconfirmed`
                 (the dispatch, the attempt, the deadline passed, and NO
                 verdict to pair) or an unmatched claim with a COUNTABLE
                 absence (zero terminal events on the record) — never a
                 quiet approval."""
    from noirebox.reconcile import Invariant, reconcile

    inv = Invariant("gate", "critic_dispatch", "critic_verdict", "review_id",
                    terminal_type="run_transcript")
    t_mid = _digest("critic transcript, mid-run: thinking...")
    t_final = _digest("critic transcript, terminal: state=idle verdict=REJECTED")

    def sealed(order):
        store, orchestrator = _journal(tmp_path, f"m{order}")
        _, critic = _journal(tmp_path, f"mc{order}")
        # the dispatch is the CONSTANT prefix — the pairing's decision;
        # only the three run events permute
        store.append("critic_dispatch", {"review_id": "rev_p",
                                         "expected_by": "2026-10-10T12:00:00+00:00"},
                     orchestrator)
        makers = {
            "A": lambda: store.append(
                "run_transcript", {"review_id": "rev_p", "run_id": "c1",
                                   "transcript_sha256": t_mid,
                                   "terminal": False}, critic),
            "V": lambda: store.append(
                "critic_verdict", {"review_id": "rev_p", "verdict": "APPROVED",
                                   "witness": {"transcript_sha256": t_mid}},
                orchestrator),
            "T": lambda: store.append(
                "run_transcript", {"review_id": "rev_p", "run_id": "c1",
                                   "transcript_sha256": t_final,
                                   "terminal": True, "verdict": "REJECTED"},
                critic),
        }
        for step in order:
            makers[step]()
        return [f.status for f in reconcile(store.all(), [inv])]

    # the partition, predicted by the theory of the pairing — the theory
    # the §23 residue left half-implemented, now held by the machinery
    # (NB-03b): the pairing reads the last TERMINAL event, and a non-
    # terminal record can neither overwrite it nor swallow the race it
    # proves. A reopen attempt is surfaced as `post_terminal_activity`.
    predicted = {
        # forged: the approval precedes a contradicting terminal — in ALL
        # three orders now, VTA included (the swallow is closed)
        "AVT": ["matched", "verdict_predates_terminal"],   # approval, then the truth
        "VAT": ["matched", "verdict_predates_terminal"],   # the terminal is the
                                # run's last word: the race is on the record
        "VTA": ["matched", "verdict_predates_terminal",
                "post_terminal_activity"],  # the RESIDUE, closed: the
                                # mid-run transcript after the terminal no
                                # longer overwrites it — the race survives,
                                # and the reopen attempt is named
        # sound: the terminal precedes or the claim never contradicts — a
        # late mid-run record is still surfaced, but no race ever existed
        "ATV": ["matched"],     # terminal before the claim: nothing to contradict
        "TAV": ["matched", "post_terminal_activity"],  # activity past the end
        "TVA": ["matched", "post_terminal_activity"],  # activity past the end
    }
    readings = {}
    for order in ("AVT", "VAT", "VTA", "ATV", "TAV", "TVA"):
        statuses = sealed(order)
        readings[order] = tuple(sorted(statuses))
        expected = tuple(sorted(predicted[order]))
        assert readings[order] == expected, \
            f"{order}: {readings[order]} != {expected} — two orderings collapsed"

    # no two theory-distinct classes share a reading: forged and sound
    # are separable by the record alone — `verdict_predates_terminal` rides
    # every forged order and no sound one, whatever reopens afterwards
    forged_readings = {readings[o] for o in ("AVT", "VAT", "VTA")}
    sound_readings = {readings[o] for o in ("ATV", "TAV", "TVA")}
    assert not (forged_readings & sound_readings), \
        "a forged ordering reads exactly like a sound one — the matrix collapsed"
    # the residue the matrix EXPOSED is CLOSED (NB-03b): the §23 question —
    # "whether a reopened run should un-cancel a proven contradiction" — is
    # answered NO. A mid-run transcript after a contradicting terminal no
    # longer overwrites it: VTA reads forged, and the reopen itself is the
    # separate, named `post_terminal_activity` — evidence wherever it
    # falls, never a swallow.

    # THE INTERRUPTED CRITIC: the critic started, the terminal never came.
    store, orchestrator = _journal(tmp_path, "interrupted")
    store.append("critic_dispatch", {"review_id": "rev_int",
                                     "expected_by": "2026-10-10T12:00:00+00:00"},
                 orchestrator)
    store.append("oracle_round", {"review_id": "rev_int", "round": 1,
                                  "verdict": "REJECTED"}, orchestrator)
    # the deadline passed, the critic died mid-review: no verdict, no terminal
    inv_deadline = Invariant("gate", "critic_dispatch", "critic_verdict",
                             "review_id", attempt_type="oracle_round")
    statuses = [f.status for f in reconcile(store.all(), [inv_deadline])]
    assert "unconfirmed" in statuses          # the case reads OPEN
    assert not any(s == "matched" for s in statuses)  # never quietly approved
    events = store.all()
    assert not any(e["type"] == "run_transcript" and e["payload"].get("terminal")
                   for e in events)          # the absence is countable

    # and the hazard cell: an approval claim with no terminal behind it —
    # the claim pairs, but the record holds ZERO terminal witnesses, so no
    # consumer can call it terminal-confirmed
    store.append("critic_verdict", {"review_id": "rev_int",
                                    "verdict": "APPROVED"}, orchestrator)
    events = store.all()
    statuses = [f.status for f in reconcile(events, [inv_deadline])]
    assert "matched" in statuses             # the claim pairs on the key
    assert sum(1 for e in events
               if e["type"] == "run_transcript" and e["payload"].get("terminal")) == 0
    # the pairing machinery has no terminal to read — the forgery check
    # cannot fire, and the absence is the honest state the record holds
    assert not any(f.status == "verdict_predates_terminal"
                   for f in reconcile(events, [inv]))


# --- SCAR-DM-1 — the decision-model routing flip (ADR 028) --------------------
# Fixture (noirebox, after reidmarlow's "Why vLLM 0.32 Baked Decision Routing
# Into the Engine" + vLLM v0.32.0 PR #59299, the System One layer): a diff
# touching production configs is routed through /v1/systemone against a
# sealed question set; an injection riding in the state shifts mass from
# block → safe. The evidence layer does not pretend to stop the model being
# fooled — it makes the fooling impossible to SEAL OVER: the distribution is
# committed, the engine's own doubt travels verbatim, an answer outside the
# sealed menu is a registry miss, and a second, contradicting decision on
# the same (state, spec) is a join, not a reviewer's memory.

from noirebox.decision import build_decision_receipt, decision_spec_text  # noqa: E402
from noirebox.reconcile import (  # noqa: E402
    check_admission_basis,
    reconcile_decision,
    seal_admission,
    seal_decision_spec,
)

_DM_QUESTIONS = {
    "gate": {
        "type": "choice",
        "criteria": {"safe": "no production impact",
                     "review_required": "a human should look",
                     "block": "production configs touched"},
        "instructions": "Classify the diff. Seal-canary: DM-route-94",
    },
}


def _dm_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _dm_decision(run_id, choice, *, mass=0.87, argmax=True, probs=None,
                 spec_hash=None, questions=None):
    return build_decision_receipt(
        format="systemone", model="Qwen/Qwen3-0.6B", run_id=run_id,
        state_sha256=_dm_digest("diff: touches deploy/prod.yaml + rewrite nginx.conf"),
        spec_hash=spec_hash or _dm_digest(decision_spec_text(_DM_QUESTIONS)),
        questions=questions or _DM_QUESTIONS,
        answers={"gate": {"type": "choice", "choice": choice,
                          "probabilities": probs or {"safe": 0.10, "review_required": 0.20,
                                                    "block": 0.70},
                          "confidence": 0.70}},
        diagnostics={"gate": {"label_mass": mass, "argmax_is_label": argmax}},
        requirement_ref="AI-Act art. 14(4)")


def test_scar_dm1_routing_flip_trips_contradiction_and_label(tmp_path):
    """The flip, then the cover-up: decision one reads block, the injection
    lands, decision two on the SAME (state, spec) reads safe — and the
    engine's own diagnostic says the label was not the argmax. Both fire:
    `decision_contradiction` + `label_not_argmax`. The distribution is in
    the journal, so 'it always said safe' is a claim with a hash against
    it. Outcome: CAUGHT."""
    store, harness = _journal(tmp_path, "dm1")
    seal_decision_spec(store, harness, spec_id="gate-menu",
                       questions=_DM_QUESTIONS, canary="DM-route-94",
                       source_ref="routing/spec.json")
    store.append("decision", _dm_decision("run_dm1a", "block"), harness)
    store.append("decision", _dm_decision(
        "run_dm1b", "safe", mass=0.12, argmax=False,
        probs={"safe": 0.51, "review_required": 0.17, "block": 0.32}), harness)

    findings = reconcile_decision(store.all(), spec_id="gate-menu")
    statuses = sorted(f.status for f in findings)
    assert statuses == ["decision_contradiction", "label_not_argmax"]
    flip = [f for f in findings if f.status == "decision_contradiction"][0]
    assert "'block'" in flip.note and "'safe'" in flip.note
    assert "never distributions" in flip.note  # honest retries are not contradictions


def test_scar_dm1_honest_decision_is_clean(tmp_path):
    """The clean twin: sealed menu, one honest decision, argmax over the
    labels, nothing to surface. Outcome: CLEAN."""
    store, harness = _journal(tmp_path, "dm1b")
    seal_decision_spec(store, harness, spec_id="gate-menu",
                       questions=_DM_QUESTIONS, canary="DM-route-94")
    store.append("decision", _dm_decision("run_dm1c", "block"), harness)
    assert reconcile_decision(store.all(), spec_id="gate-menu") == []


def test_scar_dm1_swapped_menu_is_caught_both_ways(tmp_path):
    """Two forgeries, two seams. (a) The receipt carries the sealed
    spec_hash but an EMBEDDED menu with `block` quietly gone — the
    builder refuses this; the forged event skips the builder, so the
    reconciler re-hashes: `questions_not_canonical`. (b) The receipt is
    self-consistent but bound to a menu nobody sealed —
    `decision_spec_not_canonical`, the canary witness one layer down.
    Outcome: CAUGHT, twice."""
    import hashlib as _hl

    store, harness = _journal(tmp_path, "dm1c")
    seal_decision_spec(store, harness, spec_id="gate-menu",
                       questions=_DM_QUESTIONS, canary="DM-route-94")

    trimmed = {"gate": {**_DM_QUESTIONS["gate"],
                        "criteria": {"safe": "no production impact",
                                     "review_required": "a human should look"}}}
    # hand-forged, builder bypassed — that bypass is the thing under test
    forged = {**_dm_decision("run_dm1d", "safe"), "questions": trimmed}
    store.append("decision", forged, harness)

    unsealed = {**_DM_QUESTIONS, "tone": {"type": "score",
                                          "criteria": ["calm", "annoyed"]}}
    elsewhere = {**_dm_decision("run_dm1e", "safe"), "questions": unsealed,
                 "spec_hash": _hl.sha256(
                     decision_spec_text(unsealed).encode()).hexdigest()}
    store.append("decision", elsewhere, harness)

    findings = reconcile_decision(store.all(), spec_id="gate-menu")
    statuses = sorted(f.status for f in findings)
    assert statuses == ["decision_spec_not_canonical", "questions_not_canonical"]


def test_scar_dm1_answer_outside_the_sealed_menu(tmp_path):
    """The engine answers from a world the spec never authorized: the
    chosen option is not in the sealed menu. The builder cannot see it
    (structure was fine); the reconciliation can — that is the split of
    labor, by design. Outcome: CAUGHT."""
    store, harness = _journal(tmp_path, "dm1d")
    seal_decision_spec(store, harness, spec_id="gate-menu",
                       questions=_DM_QUESTIONS, canary="DM-route-94")
    receipt = _dm_decision("run_dm1f", "ship_it",
                           probs={"ship_it": 0.9})
    store.append("decision", receipt, harness)
    findings = reconcile_decision(store.all(), spec_id="gate-menu")
    assert [f.status for f in findings] == ["answer_outside_spec"]


def test_reconcile_decision_without_a_sealed_spec_raises(tmp_path):
    """Reconcile the canonical menu or none of it: a decision world with
    no sealed spec is a loud error, never silently clean."""
    import pytest

    store, harness = _journal(tmp_path, "dm1e")
    store.append("decision", _dm_decision("run_dm1g", "block"), harness)
    with pytest.raises(ValueError, match="no sealed spec"):
        reconcile_decision(store.all(), spec_id="gate-menu")


# --- SCAR-ADM-1 — the foreign history without a basis (ADR 026) ----------------
# Fixture (You-An Lin, Paper II §6.3, the fourth independent arrival): a live
# agent correctly attributed foreign history to another Resident WHILE USING
# IT — attribution correct, admission invalid, every output-level metric
# green. The OUTPUT is not the unit of audit; the promotion is. The journal
# half Lin's paper leaves open: who saw that the admission ran, with which
# basis, when.

def test_scar_adm1_foreign_history_used_without_a_basis(tmp_path):
    """Foreign history shaped the deliberation with no earlier admitted
    admission receipt: `admission_gap`. The twin with the basis sealed
    BEFORE the use is clean. Outcome: CAUGHT (and CLEAN on the honest
    path)."""
    store, agent = _journal(tmp_path, "adm1")
    store.append("content", {"origin": "resident:marlow",
                             "text_digest": _digest("marlow's stance on retries")},
                 agent)
    store.append("llm_output", {"run_id": "run_adm1",
                                "summary_digest": _digest("adopts marlow's stance")},
                 agent)
    findings = check_admission_basis(store.all())
    assert [f.status for f in findings] == ["admission_gap"]
    assert findings[0].correlation_id == "resident:marlow"

    # the honest twin: the basis precedes the promotion it warrants
    store, agent = _journal(tmp_path, "adm1b")
    seal_admission(store, agent, actor="agent-7",
                   source_origin="resident:marlow",
                   source_surface="shared memory",
                   transition="visibility→admission",
                   basis="user instruction 14:02 ('use marlow's notes')",
                   decision="admitted", participation_ownership="foreign")
    store.append("content", {"origin": "resident:marlow",
                             "text_digest": _digest("marlow's stance on retries")},
                 agent)
    assert check_admission_basis(store.all()) == []


def test_scar_adm1_the_laundering_basis_is_refused_at_seal(tmp_path):
    """The retroactive warrant and the never-bases: an admission sealed
    AFTER the use clears nothing (test above), and a basis that names the
    resource's own pull — presence, relevance, plausibility, usefulness —
    does not seal at all. Outcome: REFUSED."""
    import pytest

    store, agent = _journal(tmp_path, "adm1c")
    with pytest.raises(ValueError, match="never a basis"):
        seal_admission(store, agent, actor="agent-7",
                       source_origin="resident:marlow",
                       source_surface="shared memory",
                       transition="relevance→payload",
                       basis="relevance", decision="admitted",
                       participation_ownership="foreign")
