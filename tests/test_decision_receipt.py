"""The decision receipt (ADR 028): build-time gate tests — a malformed or
self-inconsistent decision cannot be sealed, because the schema is the
contract and the builder is its gate."""
from __future__ import annotations

import hashlib

import pytest

from noirebox.chain import KeyPair
from noirebox.decision import (build_decision_receipt, decision_spec_text,
                               validate_questions)
from noirebox.reconcile import seal_decision_spec
from noirebox.store import EventStore

_QUESTIONS = {
    "gate": {
        "type": "choice",
        "criteria": {"safe": "no production impact",
                     "review_required": "a human should look",
                     "block": "production configs touched"},
        "instructions": "Classify the diff. Seal-canary: 7Q-vault-heron",
    },
    "urgent": {"type": "noul", "criteria": None,
               "instructions": "Is the ticket urgent?"},
    "tone": {"type": "score", "criteria": ["calm", "annoyed", "furious"]},
}

_ANSWERS = {
    "gate": {"type": "choice", "choice": "block",
             "probabilities": {"safe": 0.10, "review_required": 0.20,
                               "block": 0.70},
             "confidence": 0.70},
    "urgent": {"type": "noul", "noul": 0.02,
               "probabilities": {"yes": 0.02, "no": 0.98}},
    "tone": {"type": "score", "score": 1},
}

_DIAGNOSTICS = {"gate": {"label_mass": 0.87, "argmax_is_label": True}}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _spec_hash(questions: dict) -> str:
    return _sha(decision_spec_text(questions))


def _ok(**over) -> dict:
    base = {
        "format": "systemone",
        "model": "Qwen/Qwen3-0.6B",
        "run_id": "run_dm1",
        "state_sha256": _sha("the diff under routing"),
        "spec_hash": _spec_hash(_QUESTIONS),
        "questions": _QUESTIONS,
        "answers": _ANSWERS,
        "diagnostics": _DIAGNOSTICS,
    }
    base.update(over)
    return base


# --- the happy path -----------------------------------------------------------

def test_happy_payload_shape():
    p = build_decision_receipt(**_ok())
    assert p["schema"] == "decision/0.1"
    assert p["judged_by"] == "llm"  # a decision model IS an LLM judgment
    assert p["state_sha256"] == _sha("the diff under routing")
    assert p["questions"] == _QUESTIONS
    assert "requirement_ref" not in p  # optional, omitted stays omitted
    p2 = build_decision_receipt(**_ok(requirement_ref="AI-Act art. 14(4)"))
    assert p2["requirement_ref"] == "AI-Act art. 14(4)"


def test_state_is_sealed_as_digest_never_as_data():
    """The use_event rule: the state the decision was about is data — the
    receipt carries the DIGEST, so sealing proves the decision without
    archiving the payload."""
    p = build_decision_receipt(**_ok())
    assert "state" not in p
    assert "state_sha256" in p


# --- the closed enums ---------------------------------------------------------

def test_format_is_a_closed_enum():
    for fmt in ("systemone", "openai-decisions"):
        assert build_decision_receipt(**_ok(format=fmt))["format"] == fmt
    with pytest.raises(ValueError, match="format must be one of"):
        build_decision_receipt(**_ok(format="jev-prose-vibes"))


def test_model_and_run_id_are_required():
    with pytest.raises(ValueError, match="model is required"):
        build_decision_receipt(**_ok(model="   "))
    with pytest.raises(ValueError, match="run_id is required"):
        build_decision_receipt(**_ok(run_id=""))


# --- the SCAR-45 door, welded at birth -----------------------------------------

def test_spec_hash_is_required_with_no_exception_path():
    """receipt/0.2.x spent v0.2.2 + v0.2.3 learning this; decision/0.1
    starts where that one landed — there is no judged_by tier that
    excuses a missing spec."""
    with pytest.raises(ValueError, match="spec_hash is required"):
        build_decision_receipt(**_ok(spec_hash=""))
    with pytest.raises(ValueError, match="spec_hash is required"):
        build_decision_receipt(**_ok(spec_hash="deadbeef"))


# --- the question set is validated ---------------------------------------------

def test_unknown_question_type_refused():
    q = {**_QUESTIONS, "mood": {"type": "vibes", "criteria": ["good"]}}
    with pytest.raises(ValueError, match="type must be one of"):
        validate_questions(q)


def test_choice_without_menu_and_score_with_one_level_refused():
    with pytest.raises(ValueError, match="needs criteria"):
        validate_questions({"gate": {"type": "choice"}})
    with pytest.raises(ValueError, match="at least two levels"):
        validate_questions({"tone": {"type": "score", "criteria": ["calm"]}})


def test_empty_questions_refused():
    with pytest.raises(ValueError, match="non-empty map"):
        validate_questions({})


def test_embedded_questions_must_hash_to_spec_hash():
    """The receipt cannot claim a menu it does not carry: swap the question
    set after computing the spec hash and the builder refuses."""
    swapped = {k: v for k, v in _QUESTIONS.items() if k != "tone"}
    with pytest.raises(ValueError, match="do not hash to spec_hash"):
        build_decision_receipt(**_ok(questions=swapped))


# --- the answers are validated --------------------------------------------------

def test_answer_to_an_unasked_question_refused():
    """An answer to a question nobody asked is the laundering door:
    unaskable, therefore unsealable."""
    answers = {**_ANSWERS, "mood": {"type": "score", "score": 0}}
    with pytest.raises(ValueError, match="never asked"):
        build_decision_receipt(**_ok(answers=answers))


def test_answer_type_contradicting_the_question_refused():
    answers = {**_ANSWERS, "gate": {"type": "noul", "noul": 0.5}}
    with pytest.raises(ValueError, match="contradicts the question"):
        build_decision_receipt(**_ok(answers=answers))


def test_probability_out_of_range_refused():
    answers = {**_ANSWERS, "gate": {**_ANSWERS["gate"],
                                    "probabilities": {"safe": 1.2}}}
    with pytest.raises(ValueError, match="in \\[0, 1\\]"):
        build_decision_receipt(**_ok(answers=answers))


def test_named_refusal_answer_travels_honestly():
    answers = {"gate": {"type": "refusal"}}
    p = build_decision_receipt(**_ok(answers=answers, diagnostics=None))
    assert p["answers"]["gate"]["type"] == "refusal"


# --- the engine's doubt is sealed verbatim ---------------------------------------

def test_diagnostics_validated_but_never_interpreted():
    with pytest.raises(ValueError, match="label_mass"):
        build_decision_receipt(**_ok(
            diagnostics={"gate": {"label_mass": 7.0}}))
    with pytest.raises(ValueError, match="argmax_is_label"):
        build_decision_receipt(**_ok(
            diagnostics={"gate": {"argmax_is_label": "true"}}))
    d = build_decision_receipt(**_ok(
        diagnostics={"gate": {"label_mass": 0.31, "argmax_is_label": False}}))
    assert d["diagnostics"]["gate"]["argmax_is_label"] is False  # sealed, not judged


# --- the spec sealer ---------------------------------------------------------------

def test_seal_decision_spec_commits_the_canonical_menu(tmp_path):
    store = EventStore(str(tmp_path / "dspec.db"))
    key = KeyPair.load_or_create(str(tmp_path / "dspec.key"))
    seal_decision_spec(store, key, spec_id="gate-menu",
                       questions=_QUESTIONS,
                       canary="7Q-vault-heron",
                       source_ref="routing/spec.json")
    event = store.all()[-1]
    assert event["type"] == "spec"
    assert event["payload"]["schema"] == "spec/0.1"
    assert event["payload"]["sha256"] == _spec_hash(_QUESTIONS)


def test_seal_decision_spec_refuses_a_canary_not_in_the_menu(tmp_path):
    store = EventStore(str(tmp_path / "dspec2.db"))
    key = KeyPair.load_or_create(str(tmp_path / "dspec2.key"))
    with pytest.raises(ValueError, match="PLANTED"):
        seal_decision_spec(store, key, spec_id="gate-menu",
                           questions=_QUESTIONS, canary="not-in-the-menu")
