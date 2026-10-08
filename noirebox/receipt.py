"""The receipt (ADR 019, v0.2.1): a verdict that binds its artifact, its
check, its evaluator, the questions asked — and THE STATE IT WAS JUDGED
AGAINST (v0.2.1, TOCTOU: the world moves between verification and
execution; a receipt that doesn't name the state it saw is a receipt about
a world that may no longer exist).

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
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def check_id(predicate: str, inputs: dict, version: str,
             spec_hash: str | None = None) -> str:
    """The identity of a check: sha256 over canonical({inputs, predicate,
    version, spec_hash?}). Declared inputs are part of the commitment — the
    same predicate over undeclared inputs produces a different check_id,
    which is how a silently-changed test environment stops being invisible.

    `spec_hash` (v0.2.1, sunnydachs's "step I had not taken"): the hash of
    the spec/PROMPT that defines the predicate's semantics. Without it, one
    check_version can validate two different semantics under one id — the
    spec paragraph is part of what the verdict means, so its hash belongs in
    the canonical form. Required for LLM-judged checks (the prompt IS the
    predicate), optional for deterministic ones."""
    if not predicate or not predicate.strip():
        raise ValueError("check_id: predicate is required (what does this check assert?)")
    if not version:
        raise ValueError("check_id: version is required (which version of the check ran?)")
    if not isinstance(inputs, dict):
        raise ValueError("check_id: inputs must be a dict of declared inputs")
    if spec_hash is not None and not _is_sha256(spec_hash):
        raise ValueError("check_id: spec_hash must be a 64-char sha256 hex digest")
    core = {"inputs": inputs, "predicate": predicate, "version": version}
    if spec_hash is not None:
        core["spec_hash"] = spec_hash
    return _sha256_hex(canonical(core))


def evaluator_sha256(path: str) -> str:
    """The hash of the checker script itself (ADR 019 §3): a receipt whose
    evaluator was modified after the fact verifies against a different hash —
    the exam and the candidate hash together."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build_receipt(*, artifact_sha256: str, check_id: str, evaluator_sha256: str,
                  run_id: str, base_commit: str | None = None,
                  pairing: str = "single-key", witness: dict | None = None,
                  counts: dict | None = None,
                  state_binding: dict | None = None) -> dict:
    """Builds the validated receipt payload (ADR 019 §1-7 + v0.2.1).

    `pairing` grades the receipt honestly: "two-key" means the reconciliation
    layer ENFORCED that the check-name and the receipt travel under different
    keys; "single-key" means one writer did both — a labeled weakness, never
    a hidden one. `base_commit` anchors the predicate in the base branch's
    tree (the questions live outside the judged party's working tree).

    `state_binding` (v0.2.1, the TOCTOU field): {resource, resource_version}
    — the state version the gate evaluated, in the executor's own currency
    (Kubernetes resourceVersion, git tree-ish, ETag…). The executor applies
    it as a precondition: a call carrying the sealed version fails loudly
    when the state moved (409 conflict — optimistic concurrency). Divergence
    is then a sealed event (`receipt_expired_by_state_change` → new gate
    pass → new receipt), never silent reuse.
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
    if state_binding is not None:
        if not isinstance(state_binding, dict) or not state_binding.get("resource") \
                or not state_binding.get("resource_version"):
            raise ValueError(
                "receipt: state_binding requires {resource, resource_version} — "
                "a receipt about a state it cannot name binds nothing")
        if not isinstance(str(state_binding["resource_version"]),
                          str) or not str(state_binding["resource_version"]).strip():
            raise ValueError("receipt: state_binding.resource_version must be a non-empty string")

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
    if state_binding is not None:
        payload["state_binding"] = {
            "resource": state_binding["resource"],
            "resource_version": str(state_binding["resource_version"]),
        }
    if witness is not None:
        payload["witness"] = witness
    if counts is not None:
        payload["counts"] = counts
    return payload
