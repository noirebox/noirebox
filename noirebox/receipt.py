"""The receipt (ADR 019): a verdict that binds its artifact, its check, its
evaluator, and the questions asked.

A bare verdict ("verified: true") is a self-report — a stub and a real check
emit identical records. The receipt schema closes that by committing to:

  - the artifact bytes        (artifact_sha256)
  - the CHECK itself          (check_id = predicate + declared inputs +
                               version, hashed — a no-op verifier's check_id
                               differs from a real one's, by construction)
  - the evaluator             (evaluator_sha256 — touch the test suite and
                               every receipt produced after the touch dies)
  - the questions asked       (base_commit — the predicate_id resolves in the
                               BASE branch's tree, outside the judged party's
                               working tree)
  - the run                   (run_id — correlation; counting becomes
                               sum-to-n)
  - the pairing grade         ("two-key": the receipt and the check-name
                               travel under DIFFERENT keys, enforced by the
                               reconciliation layer; "single-key": a labeled
                               weakness — a labeled weakness beats an
                               invisible one)

Everything here is validated at build time: a malformed receipt cannot be
sealed, because the schema is the contract and the builder is its gate.
"""
from __future__ import annotations

import hashlib

from .chain import canonical

_PAIRING_GRADES = ("two-key", "single-key")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def check_id(predicate: str, inputs: dict, version: str) -> str:
    """The identity of a check: sha256 over canonical({inputs, predicate,
    version}). Declared inputs are part of the commitment — the same
    predicate over undeclared inputs produces a different check_id, which is
    how a silently-changed test environment stops being invisible."""
    if not predicate or not predicate.strip():
        raise ValueError("check_id: predicate is required (what does this check assert?)")
    if not version:
        raise ValueError("check_id: version is required (which version of the check ran?)")
    if not isinstance(inputs, dict):
        raise ValueError("check_id: inputs must be a dict of declared inputs")
    return _sha256_hex(canonical({"inputs": inputs, "predicate": predicate,
                                  "version": version}))


def evaluator_sha256(path: str) -> str:
    """The hash of the checker script itself (ADR 019 §3): a receipt whose
    evaluator was modified after the fact verifies against a different hash —
    the exam and the candidate hash together."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build_receipt(*, artifact_sha256: str, check_id: str, evaluator_sha256: str,
                  run_id: str, base_commit: str | None = None,
                  pairing: str = "single-key", witness: dict | None = None,
                  counts: dict | None = None) -> dict:
    """Builds the validated receipt payload (ADR 019 §1-7).

    `pairing` grades the receipt honestly: "two-key" means the reconciliation
    layer ENFORCED that the check-name and the receipt travel under different
    keys; "single-key" means one writer did both — a labeled weakness, never
    a hidden one. `base_commit` anchors the predicate in the base branch's
    tree (the questions live outside the judged party's working tree).
    """
    for name, value in (("artifact_sha256", artifact_sha256),
                        ("check_id", check_id), ("evaluator_sha256", evaluator_sha256)):
        if not isinstance(value, str) or not _is_sha256(value):
            raise ValueError(f"receipt: {name} must be a 64-char sha256 hex digest")
    if not run_id or not run_id.strip():
        raise ValueError("receipt: run_id is required (correlation and sum-to-n)")
    if pairing not in _PAIRING_GRADES:
        raise ValueError(f"receipt: pairing must be one of {_PAIRING_GRADES}")
    if base_commit is not None and not _is_sha256(base_commit):
        raise ValueError("receipt: base_commit must be a 64-char sha256 hex digest")

    payload: dict = {
        "schema": "receipt/0.2",
        "artifact_sha256": artifact_sha256,
        "check_id": check_id,
        "evaluator_sha256": evaluator_sha256,
        "run_id": run_id,
        "pairing": pairing,
    }
    if base_commit is not None:
        payload["base_commit"] = base_commit
    if witness is not None:
        payload["witness"] = witness
    if counts is not None:
        payload["counts"] = counts
    return payload
