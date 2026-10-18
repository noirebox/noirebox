"""The decision receipt (ADR 028): a verdict from a DECISION MODEL — the
System One layer (`POST /v1/systemone`: vLLM v0.32.0, Ollama v0.35,
Cloudflare Clef, LiteLLM; OpenAI serves the same seam as `/v1/decisions`)
— sealed like every other judgment the journal attestes.

A decision model maps a state to typed questions and returns a
probability for EVERY allowed answer in one read. That is a better
evidence substrate than a parsed prose label — and a worse audit
surface: the call happens inside the inference engine, the caller sees
an enum-shaped answer, and nothing outside the engine remembers HOW the
answer was reached. The decision receipt closes that the same way
receipt/0.2.x closed the check-report gap: everything that makes the
verdict meaningful is committed at seal time, and a malformed or
self-inconsistent decision cannot be sealed at all.

  - the state judged         (state_sha256 — the DIGEST, never the state:
                              seal what the decision was about, not the
                              data itself — the use_event rule)
  - the questions asked      (questions, embedded in full — they must hash
                              back to spec_hash, so the receipt cannot
                              claim a menu it does not carry)
  - the committed menu       (spec_hash — REQUIRED, unconditionally: the
                              question set IS the predicate, so the
                              SCAR-45 door is welded shut at this
                              schema's birth, not closed after an
                              incident)
  - the answers              (per question, with the probability
                              distribution when the engine returned one —
                              a bare label is what an attacker edits; a
                              distribution is what they must explain)
  - the engine's own doubt   (diagnostics — label_mass, argmax_is_label:
                              the engine confessing where its answer came
                              from; sealed verbatim, surfaced by the
                              reconciler)

Everything here is validated at build time: the schema is the contract
and the builder is its gate. Semantic violations — an answer outside the
sealed menu, two decisions contradicting each other — are the
reconciler's job (`reconcile_decision`): the receipt seals honestly what
came back; the reconciliation makes it impossible to miss.
"""
from __future__ import annotations

import hashlib

from .chain import canonical

_FORMATS = ("systemone", "openai-decisions")
_QUESTION_TYPES = ("choice", "noul", "score")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _is_probability(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) \
        and 0.0 <= float(value) <= 1.0


def decision_spec_text(questions: dict) -> str:
    """The canonical text of a decision-question spec — the bytes
    `seal_spec` commits and a decision's embedded questions must hash
    back to. One helper, two callers (the sealer and the builder), so
    the sealer's bytes and the receipt's bytes cannot drift."""
    return canonical({"questions": questions}).decode("utf-8")


def validate_questions(questions: dict) -> None:
    """The build-time shape of a question set: known types only, every
    choice carrying its menu, every score carrying its ordered levels.
    Engine-side limits (vLLM's 26 options / 10 levels) are the engine's
    business — a 400 there is honest; a malformed set HERE would seal a
    decision against a menu nobody can confront it with."""
    if not isinstance(questions, dict) or not questions:
        raise ValueError(
            "decision: questions must be a non-empty map of question id "
            "→ definition — a decision without its questions binds nothing")
    for qid, q in questions.items():
        if not isinstance(qid, str) or not qid.strip():
            raise ValueError("decision: every question needs a non-empty id")
        if not isinstance(q, dict):
            raise ValueError(f"decision: question {qid!r} must be a definition map")
        qtype = q.get("type")
        if qtype not in _QUESTION_TYPES:
            raise ValueError(
                f"decision: question {qid!r} type must be one of "
                f"{_QUESTION_TYPES}, got {qtype!r}")
        criteria = q.get("criteria")
        if qtype == "choice" and (not isinstance(criteria, dict) or not criteria):
            raise ValueError(
                f"decision: choice question {qid!r} needs criteria — the "
                "sealed menu of options the answer must come from")
        if qtype == "score" and (not isinstance(criteria, list) or len(criteria) < 2):
            raise ValueError(
                f"decision: score question {qid!r} needs an ordered criteria "
                "list of at least two levels")


def _validate_answer(qid: str, question: dict, answer: object) -> None:
    if not isinstance(answer, dict):
        raise ValueError(f"decision: answer {qid!r} must be a map")
    atype = answer.get("type")
    if atype == "refusal":
        return  # the Decisions format's named refusal — an answer, honestly typed
    if atype != question.get("type"):
        raise ValueError(
            f"decision: answer {qid!r} type {atype!r} contradicts the "
            f"question's type {question.get('type')!r}")
    probabilities = answer.get("probabilities")
    if probabilities is not None:
        if not isinstance(probabilities, dict) or not probabilities:
            raise ValueError(f"decision: answer {qid!r} probabilities must be "
                             "a non-empty map of option → probability")
        for option, p in probabilities.items():
            if not _is_probability(p):
                raise ValueError(
                    f"decision: answer {qid!r} probability for {option!r} "
                    "must be a number in [0, 1]")
    confidence = answer.get("confidence")
    if confidence is not None and not _is_probability(confidence):
        raise ValueError(f"decision: answer {qid!r} confidence must be in [0, 1]")
    qtype = question.get("type")
    if qtype == "noul":
        noul = answer.get("noul")
        if noul is not None and not _is_probability(noul):
            raise ValueError(f"decision: answer {qid!r} noul must be in [0, 1]")
    if qtype == "score":
        score = answer.get("score")
        if score is not None and (isinstance(score, bool) or not isinstance(score, int)):
            raise ValueError(f"decision: answer {qid!r} score must be a level index (int)")


def build_decision_receipt(*, format: str, model: str, run_id: str,
                           state_sha256: str, spec_hash: str,
                           questions: dict, answers: dict,
                           diagnostics: dict | None = None,
                           requirement_ref: str | None = None) -> dict:
    """Builds the validated decision payload (`decision/0.1`, ADR 028).

    `spec_hash` is REQUIRED with no exception path: a decision model's
    question set is its predicate, and receipt/0.2.x spent v0.2.2 and
    v0.2.3 learning that an LLM-judged verdict without its committed spec
    seals exactly the receipt an attacker needs. This schema starts where
    that one landed.

    `questions` must hash back to `spec_hash` — the receipt carries the
    menu it was judged against, provably the sealed one (the reconciler
    re-checks the hash against the journal's sealed spec; a hand-forged
    event that skips this builder is the drift that check exists for).

    `answers` keys must be a subset of the question ids: an answer to a
    question nobody asked is the laundering door — unaskable, therefore
    unsealable. A `refusal` answer travels honestly (`{"type":
    "refusal"}`) — the Decisions format's named non-answer.

    `diagnostics` seals the engine's per-question doubt verbatim
    (`label_mass`, `argmax_is_label`): the receipt never interprets them,
    the reconciler surfaces them — the engine's confession is evidence,
    not a verdict.

    `requirement_ref` cites the obligation the decision serves (the #47
    tie): a routing that gates a human review names WHICH obligation.
    """
    if format not in _FORMATS:
        raise ValueError(
            f"decision: format must be one of {_FORMATS}, got {format!r}")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("decision: model is required (which engine decided?)")
    if not run_id or not run_id.strip():
        raise ValueError("decision: run_id is required (correlation)")
    if not _is_sha256(state_sha256):
        raise ValueError("decision: state_sha256 must be a 64-char sha256 "
                         "hex digest — seal the DIGEST, never the state")
    if not _is_sha256(spec_hash):
        raise ValueError(
            "decision: spec_hash is required and must be a 64-char sha256 "
            "hex digest — a decision without its committed question set "
            "does not seal (the SCAR-45 door, welded at birth)")
    validate_questions(questions)
    if _sha256_hex(decision_spec_text(questions)) != spec_hash:
        raise ValueError(
            "decision: the embedded questions do not hash to spec_hash — "
            "a receipt claiming a menu it does not carry does not seal")
    if not isinstance(answers, dict) or not answers:
        raise ValueError("decision: answers must be a non-empty map of "
                         "question id → answer")
    for qid, answer in answers.items():
        if qid not in questions:
            raise ValueError(
                f"decision: answer {qid!r} answers a question the receipt "
                "never asked — refuse to seal what cannot be confronted "
                "with its menu")
        _validate_answer(qid, questions[qid], answer)
    if diagnostics is not None:
        if not isinstance(diagnostics, dict):
            raise ValueError("decision: diagnostics must be a map of "
                             "question id → engine diagnostics")
        for qid, d in diagnostics.items():
            if qid not in questions:
                raise ValueError(
                    f"decision: diagnostics {qid!r} reports on a question "
                    "the receipt never asked")
            if not isinstance(d, dict):
                raise ValueError(f"decision: diagnostics {qid!r} must be a map")
            mass = d.get("label_mass")
            if mass is not None and not _is_probability(mass):
                raise ValueError(
                    f"decision: diagnostics {qid!r} label_mass must be in [0, 1]")
            argmax = d.get("argmax_is_label")
            if argmax is not None and not isinstance(argmax, bool):
                raise ValueError(
                    f"decision: diagnostics {qid!r} argmax_is_label must be "
                    "a boolean (the engine's confession, verbatim)")
    if requirement_ref is not None and \
            (not isinstance(requirement_ref, str) or not requirement_ref.strip()):
        raise ValueError(
            "decision: requirement_ref, when present, must be a non-empty "
            "string — WHICH obligation this decision serves")

    payload: dict = {
        "schema": "decision/0.1",
        "format": format,
        "model": model.strip(),
        "run_id": run_id.strip(),
        "judged_by": "llm",
        "state_sha256": state_sha256,
        "spec_hash": spec_hash,
        "questions": questions,
        "answers": answers,
    }
    if diagnostics is not None:
        payload["diagnostics"] = diagnostics
    if requirement_ref is not None:
        payload["requirement_ref"] = requirement_ref.strip()
    return payload
