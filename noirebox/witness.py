"""The normalized witness (ADR 019 §8): bind what HAPPENED without binding
the noise.

Binding exit_code + raw stdout is noise — timestamps, locale, progress bars
change between two honest runs and the hash screams tampering where nothing
happened. The witness binds the normalized shape instead:

  - exit code
  - byte counts of stdout/stderr (volume without volatile content)
  - the SHA-256 tree of the files touched, BEFORE and AFTER — a rewrite of
    any file flips the tree, and the before/after pair shows which
  - the container image digest, when the run happened in one

When the CONTENT of an output is required, canonicalize first (volatile
fields stripped, fixed locale, no wall-clock) and hash the canonical bytes —
hashing the raw stream would make two honest runs disagree.

The payload carries no wall-clock and no locale-dependent text by
construction: two honest runs of the same work produce the same witness.
"""
from __future__ import annotations

import hashlib

from .chain import canonical


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_tree_sha256(files: dict[str, str]) -> str:
    """One hash over a set of (path → sha256): canonical JSON over the
    SORTED entries. A rename, a content edit or an insertion flips it; the
    order of computation never matters."""
    entries = [{"path": path, "sha256": files[path]} for path in sorted(files)]
    return sha256_hex(canonical(entries))


def _diff(before: dict[str, str] | None, after: dict[str, str] | None) -> dict:
    before = before or {}
    after = after or {}
    changed = sorted(
        p for p in (set(before) & set(after)) if before[p] != after[p]
    )
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": changed,
    }


def canonical_witness(exit_code: int,
                      stdout_bytes: bytes = b"",
                      stderr_bytes: bytes = b"",
                      files_before: dict[str, str] | None = None,
                      files_after: dict[str, str] | None = None,
                      image_digest: str | None = None) -> dict:
    """Builds the normalized witness payload — digest-only, no wall-clock,
    no volatile text. Files are given as (path → sha256) maps captured
    before and after the run; the payload carries the diff plus one tree
    hash per side, so the seal commits to the file SET as a whole."""
    payload: dict = {
        "exit_code": exit_code,
        "stdout_bytes": len(stdout_bytes),
        "stderr_bytes": len(stderr_bytes),
    }
    if files_before is not None or files_after is not None:
        diff = _diff(files_before, files_after)
        payload["files"] = {
            **{f"{k}_sha256": file_tree_sha256(f)
               for k, f in (("before", files_before), ("after", files_after))
               if f is not None},
            **diff,
        }
    if image_digest:
        payload["image_digest"] = image_digest
    return payload


def verify_file_tree(payload: dict, side: str, files: dict[str, str]) -> str | None:
    """Recomputes one side's tree against the sealed witness. Accepts the
    full witness payload or its `files` sub-object. House convention:
    None = intact, otherwise the reason."""
    key = f"{side}_sha256"
    scope = payload.get("files", payload) if isinstance(payload.get("files"), dict) else payload
    if key not in scope:
        return f"witness has no {key} to check against"
    if scope[key] != file_tree_sha256(files):
        return f"{side} file tree mismatch: the files are not what was witnessed"
    return None


def witness_payload_is_normalized(witness: dict) -> bool:
    """Guard for sealers: a witness carrying wall-clock or raw-stream keys
    is NOT normalized — refuse to seal it rather than launder it."""
    forbidden = {"timestamp", "ts", "stdout", "stderr", "stdout_text", "stderr_text",
                 "locale", "wall_clock", "started_at", "ended_at"}
    return not (forbidden & set(witness))
