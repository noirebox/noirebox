"""ADR 019 receipt schema — v0.2.1: state binding (TOCTOU) and the spec hash
inside the check identity. A receipt that cannot name the state it judged
binds nothing; a check whose spec can drift under one id is not one check."""
import hashlib

import pytest

from noirebox.chain import canonical
from noirebox.receipt import build_receipt, check_id

_OK = {
    "artifact_sha256": hashlib.sha256(b"artifact").hexdigest(),
    "check_id": check_id("tests pass", {}, "1.0"),
    "evaluator_sha256": hashlib.sha256(b"evaluator script bytes").hexdigest(),
    "run_id": "run-42",
    "judged_by": "deterministic",  # v0.2.3: required, no default — say it or don't seal
}


def test_build_receipt_minimal_is_valid_and_labeled():
    r = build_receipt(**_OK)
    assert r["schema"] == "receipt/0.2.2"
    assert r["pairing"] == "single-key"  # the default is the LABELED weakness


def test_judged_by_omitted_refuses_to_seal():
    """v0.2.3 — the alg:none door (howcani's seam B): omission and honesty
    used to produce the same bytes. They no longer produce ANY bytes: the
    omission path is a TypeError, not a quiet 'deterministic'."""
    ok_without = {k: v for k, v in _OK.items() if k != "judged_by"}
    with pytest.raises(TypeError):
        build_receipt(**ok_without)


def test_two_key_pairing_is_explicit_not_default():
    r = build_receipt(**_OK, pairing="two-key")
    assert r["pairing"] == "two-key"


def test_malformed_receipts_cannot_be_sealed():
    bad_artifact = dict(_OK, artifact_sha256="deadbeef")
    with pytest.raises(ValueError, match="64-char"):
        build_receipt(**bad_artifact)
    with pytest.raises(ValueError, match="run_id"):
        build_receipt(**{**_OK, "run_id": "  "})
    with pytest.raises(ValueError, match="pairing"):
        build_receipt(**{**_OK, "pairing": "triple-key"})
    with pytest.raises(ValueError, match="base_commit"):
        build_receipt(**{**_OK, "base_commit": "nope"})


def test_check_id_changes_with_predicate_inputs_version_and_spec():
    base = check_id("tests pass", {"suite": "unit"}, "1.0")
    assert base != check_id("tests pass", {"suite": "unit"}, "1.1")   # version drift
    assert base != check_id("lint passes", {"suite": "unit"}, "1.0")  # predicate drift
    assert base != check_id("tests pass", {"suite": "all"}, "1.0")    # input drift


def test_spec_hash_in_the_check_identity_sunnydachs_step():
    """v0.2.1 §4: the spec paragraph is part of the predicate's semantics —
    one check_version must not validate two semantics under one id."""
    spec_a = hashlib.sha256(b"prompt v1").hexdigest()
    spec_b = hashlib.sha256(b"prompt v2").hexdigest()
    assert check_id("judge", {}, "1.0", spec_hash=spec_a) \
        != check_id("judge", {}, "1.0", spec_hash=spec_b)
    with pytest.raises(ValueError, match="spec_hash"):
        check_id("judge", {}, "1.0", spec_hash="short")


def test_state_binding_binds_the_judged_state():
    """v0.2.1 TOCTOU: the receipt names the state version the gate evaluated —
    the executor's precondition currency (K8s resourceVersion shape)."""
    r = build_receipt(**_OK, state_binding={
        "resource": "/apis/batch/v1/namespaces/prod/jobs/export",
        "resource_version": "18421",
    })
    assert r["state_binding"]["resource_version"] == "18421"
    assert r["state_binding"]["resource"].endswith("/jobs/export")


def test_state_binding_without_a_version_is_refused():
    with pytest.raises(ValueError, match="state_binding"):
        build_receipt(**_OK, state_binding={"resource": "/x"})
    with pytest.raises(ValueError, match="state_binding"):
        build_receipt(**_OK, state_binding="18421")  # not a dict: no shape, no binding


# --- issue #38 — legitimate transformations ----------------------------------

def test_transformation_binds_input_output_and_transformer():
    from noirebox.receipt import transformation_payload

    t = transformation_payload(
        before_sha256=hashlib.sha256(b"raw.md").hexdigest(),
        after_sha256=hashlib.sha256(b"raw.html").hexdigest(),
        transformer="pandoc", version="3.1")
    assert t["schema"] == "content-transformation/0.1"
    assert t["transformer"] == {"tool": "pandoc", "version": "3.1"}

    import pytest
    with pytest.raises(ValueError, match="64-char"):
        transformation_payload(before_sha256="x", after_sha256="y" * 64,
                               transformer="pandoc", version="3.1")
    with pytest.raises(ValueError, match="transformer identity"):
        transformation_payload(before_sha256="a" * 64, after_sha256="b" * 64,
                               transformer="  ", version="3.1")


# --- issue #39 — witness != author, enforced at seal and serve time ----------

def test_self_witnessing_is_refused_at_build_time():
    with pytest.raises(RuntimeError, match="self-witnessing"):
        build_receipt(**_OK, witness={"identity": "drafter-1", "author": "drafter-1"})


def test_distinct_witness_is_accepted():
    r = build_receipt(**_OK, witness={"identity": "notary-7", "author": "drafter-1"})
    assert r["witness"]["identity"] == "notary-7"


def test_ensure_witness_distinct_for_the_serving_layer():
    from noirebox.receipt import ensure_witness_distinct

    ensure_witness_distinct({"identity": "notary-7"}, "drafter-1")  # fine
    with pytest.raises(RuntimeError, match="skip the slot"):
        ensure_witness_distinct({"identity": "drafter-1"}, "drafter-1")  # failover caught the same model


# --- issue #55 — the named expectation: the reason travels with the verdict --

def test_reason_travels_in_the_payload():
    r = build_receipt(**_OK, reason="the 2024 pin is a business rule, not a default")
    assert r["reason"] == "the 2024 pin is a business rule, not a default"


def test_reason_absent_is_absent_not_empty():
    r = build_receipt(**_OK)
    assert "reason" not in r  # labeled absence, never a quiet empty string


def test_reason_whitespace_only_is_rejected():
    with pytest.raises(ValueError, match="non-empty string"):
        build_receipt(**_OK, reason="   ")


def test_reason_change_is_visible_in_the_sealed_payload():
    # the reason is not part of the check_id (intent, not semantics) — but a
    # re-worded reason lands in a different sealed payload, so its drift is
    # a diffable event instead of a quiet one
    import hashlib
    r1 = build_receipt(**_OK, reason="the pin is intentional")
    r2 = build_receipt(**_OK, reason="the pin was a mistake, kept for compat")
    assert r1["reason"] != r2["reason"]
    assert r1["check_id"] == r2["check_id"]  # same semantics, different story
    d1 = hashlib.sha256(canonical(r1)).hexdigest()
    d2 = hashlib.sha256(canonical(r2)).hexdigest()
    assert d1 != d2


# --- v0.2.2 — spec_hash required for llm-judged checks (Reid + howcani) ------

def test_llm_judged_without_spec_hash_refuses_to_seal():
    """The schema REFUSES, it no longer labels: for an LLM-judged check the
    prompt IS the predicate — SCAR-45's optional path is closed."""
    import pytest

    with pytest.raises(ValueError, match="requires spec_hash"):
        build_receipt(**{**_OK, "judged_by": "llm"})


def test_llm_judged_with_spec_travels_the_commitment():
    """The commitment rides IN the payload, not just inside the opaque id:
    the artifact carries what it was judged against."""
    spec = _sha("Load the rubric from disk; cite file:line for every gate.")
    r = build_receipt(**{**_OK, "judged_by": "llm"}, spec_hash=spec)
    assert r["judged_by"] == "llm"
    assert r["spec_hash"] == spec
    assert r["schema"] == "receipt/0.2.2"


def test_judged_by_is_an_enum_with_no_quiet_tier():
    import pytest

    r = build_receipt(**_OK)
    assert r["judged_by"] == "deterministic"  # because the CALLER said it
    with pytest.raises(ValueError, match="judged_by"):
        build_receipt(**{**_OK, "judged_by": "vibes"})


def test_requirement_ref_names_the_obligation():
    """The #47 tie: evidence proves an obligation was met — the receipt
    names WHICH."""
    import pytest

    r = build_receipt(**_OK, requirement_ref="AI-Act art. 12(1); SOP-114 §3")
    assert r["requirement_ref"] == "AI-Act art. 12(1); SOP-114 §3"
    with pytest.raises(ValueError, match="non-empty"):
        build_receipt(**_OK, requirement_ref="   ")


def _sha(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()
