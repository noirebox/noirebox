"""The shared sealing machinery of ADR 012/013 — one construction, one policy.

Everything below was once implemented twice (trajectory.py for the model-io
shape, transcripts.py for the generic shapes). The crypto and the corruption
policy are shape-independent: one order-committed digest chain, one honest
JSONL reader. What stays per-shape is the metadata extraction and the verify
wording — those are the audit surface, and each format names its own fields.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .chain import GENESIS, canonical


def digest_chain(records: list[dict]) -> str:
    """Order-committed digest chain over canonical records (ADR 012).

    d0 = GENESIS, d_i = sha256(d_{i-1} + sha256(canonical(record_i))).
    A Merkle root over a set would not do — the order is semantic (a
    trajectory, not a pile): the same calls in a different order is a
    different behavior, and a rewrite of history accuses. This is the same
    commit construction the journal itself uses.
    """
    digest = GENESIS
    for record in records:
        digest = hashlib.sha256(
            (digest + hashlib.sha256(canonical(record)).hexdigest()).encode("ascii")
        ).hexdigest()
    return digest


def read_jsonl_records(path: str | Path) -> tuple[list[dict], str, bool]:
    """Reads a JSONL log with the house corruption policy (ADR 012).

    Returns (records, file_sha256, truncated_tail). The policy — honest by
    construction: a line that fails to parse is an incomplete trailing write
    ONLY if it is the last line (reported as `truncated_tail`, never hidden);
    anywhere else it is a hard error, because silently sealing a
    partially-read log would manufacture exactly the fake evidence this
    project exists against. Every record must be a JSON object.
    """
    data = Path(path).read_bytes()
    lines = data.decode("utf-8").splitlines()
    if not any(line.strip() for line in lines):
        raise ValueError(f"{path}: no records to seal (empty file)")

    records: list[dict] = []
    truncated_tail = False
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            if i == len(lines) - 1:
                truncated_tail = True
                break
            raise ValueError(
                f"{path}: line {i + 1} is not valid JSON in the middle of the "
                "log — refusing to seal a partially readable log"
            ) from exc
        if not isinstance(record, dict):
            raise ValueError(f"{path}: line {i + 1} is not a JSON object")
        records.append(record)

    if not records:
        raise ValueError(f"{path}: no parseable record — refusing to seal nothing")
    return records, hashlib.sha256(data).hexdigest(), truncated_tail
