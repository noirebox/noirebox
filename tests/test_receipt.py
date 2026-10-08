"""ADR 019 receipt schema — v0.2.1: state binding (TOCTOU) and the spec hash
inside the check identity. A receipt that cannot name the state it judged
binds nothing; a check whose spec can drift under one id is not one check."""
import hashlib

import pytest

from noirebox.receipt import build_receipt, check_id

_OK = {
    "artifact_sha256": hashlib.sha256(b"artifact").hexdigest(),
    "check_id": check_id("tests pass", {}, "1.0"),
    "evaluator_sha256": hashlib.sha256(b"evaluator script bytes").hexdigest(),
    "run_id": "run-42",
}


def test_build_receipt_minimal_is_valid_and_labeled():
    r = build_receipt(**_OK)
    assert r["schema"] == "receipt/0.2"
    assert r["pairing"] == "single-key"  # the default is the LABELED weakness


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
