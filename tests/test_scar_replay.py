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
