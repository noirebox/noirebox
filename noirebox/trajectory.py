"""Sealing of an agent's model trajectory (ADR 012).

Coding agents already keep a flight recorder: one JSONL file per session
(`model-io-*.jsonl`), one line per LLM call — request, response, tool calls,
usage, timings. Agent's "view model trajectory" menu reads it. But the file
is local, unsigned and unanchored: an edited log looks exactly like an honest
one. This module seals it so the trace becomes evidence instead of a claim.

What is sealed — digests only, never content (minimization by construction,
as in ADR 010: these files contain full conversation text):
  - `file_sha256`       the exact bytes as observed
  - `trajectory_digest` an ORDER-COMMITTED digest chain over per-record
                        digests: d0 = 0*64, d_i = sha256(d_{i-1} + record_i),
                        where record_i = sha256(canonical(parsed JSON line)).
                        A Merkle root over a set would not do — the order of
                        calls is semantic (a trajectory, not a pile); this is
                        the chain construction the journal itself uses.
  - counters and metadata: record count, session ids, models, query sources,
    first/last timestamps (the period of use — the art. 12(3)(a) shape).

What is deliberately NOT done: no reconstruction of the logical trajectory
(delta records are not stitched) — reconstruction is the viewer's job; the
seal commits to the log AS OBSERVED, per record, byte-faithful.

The payload names its sealer (`source`: tool + version): a proof is only as
good as the binding agent, and from now on the binding agent says who it is.

Verification follows the house convention: `verify_trajectory` returns None
when intact, otherwise the reason — a tampered file recomputes to a different
digest and the seal accuses, without trusting anyone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .digests import digest_chain, read_jsonl_records

TOOL = "noirebox"
ORIGIN = "agent-model-io"


@dataclass
class TrajectorySummary:
    """Everything the seal commits to, computed from one observed file."""

    file_sha256: str
    record_count: int
    trajectory_digest: str
    session_ids: list[str]
    truncated_tail: bool
    models: list[str] = field(default_factory=list)
    query_sources: dict[str, int] = field(default_factory=dict)
    first_started_at: str | None = None
    last_completed_at: str | None = None


def read_model_io(path: str | Path) -> TrajectorySummary:
    """Reads a model-io JSONL file and computes the seal summary.

    Corruption policy and digest chain live in digests.py — the single
    construction of ADR 012/013 (last-line parse failure = `truncated_tail`,
    mid-file = hard error; digests only, never content).
    """
    records, file_sha256, truncated_tail = read_jsonl_records(path)

    session_ids: set[str] = set()
    models: set[str] = set()
    query_sources: dict[str, int] = {}
    started: list[str] = []
    completed: list[str] = []

    for record in records:
        if isinstance(record.get("sessionId"), str) and record["sessionId"]:
            session_ids.add(record["sessionId"])
        model = record.get("model")
        if isinstance(model, dict) and isinstance(model.get("modelId"), str):
            models.add(model["modelId"])
        source = record.get("querySource")
        if isinstance(source, str):
            query_sources[source] = query_sources.get(source, 0) + 1
        if isinstance(record.get("startedAt"), str):
            started.append(record["startedAt"])
        if isinstance(record.get("completedAt"), str):
            completed.append(record["completedAt"])

    return TrajectorySummary(
        file_sha256=file_sha256,
        record_count=len(records),
        trajectory_digest=digest_chain(records),
        session_ids=sorted(session_ids) or ["unknown"],
        truncated_tail=truncated_tail,
        models=sorted(models),
        query_sources=dict(sorted(query_sources.items())),
        first_started_at=min(started) if started else None,
        last_completed_at=max(completed) if completed else None,
    )


def trajectory_payload(summary: TrajectorySummary, *, version: str = __version__) -> dict:
    """Builds the validated `model_trajectory` event payload.

    The only entry point to the event type: the payload takes the summary —
    which carries digests, never content — so a raw trajectory cannot enter
    the journal by construction. `source` names the sealing tool and version:
    the seal says who sealed it, and a later audit can weigh that identity.
    """
    payload: dict = {
        "source": {"tool": TOOL, "version": version},
        "origin": ORIGIN,
        "session_ids": summary.session_ids,
        "file_sha256": summary.file_sha256,
        "record_count": summary.record_count,
        "trajectory_digest": summary.trajectory_digest,
        "truncated_tail": summary.truncated_tail,
    }
    if summary.models:
        payload["models"] = summary.models
    if summary.query_sources:
        payload["query_sources"] = summary.query_sources
    if summary.first_started_at:
        payload["first_started_at"] = summary.first_started_at
    if summary.last_completed_at:
        payload["last_completed_at"] = summary.last_completed_at
    return payload


def verify_trajectory(payload: dict, path: str | Path) -> str | None:
    """Recomputes the summary from the file and confronts it with the payload.

    Convention of the house (as `verify_event`): None = intact, otherwise the
    reason. The file is the evidence, the payload the accusation — or the
    alibi. Every committed field is compared, so the seal detects content
    edits (digest mismatch), record insertion/removal (count), reordering
    (order is baked into the digest chain) and a swapped file (file_sha256).
    """
    if payload.get("origin") != ORIGIN:
        return f"origin mismatch: expected {ORIGIN!r}"
    source = payload.get("source")
    if not isinstance(source, dict) or source.get("tool") != TOOL:
        return "source mismatch: payload was not sealed by noirebox"
    try:
        summary = read_model_io(path)
    except ValueError as exc:
        return f"unreadable trajectory: {exc}"
    if payload.get("file_sha256") != summary.file_sha256:
        return "file content changed (file_sha256 mismatch)"
    if payload.get("record_count") != summary.record_count:
        return f"record count changed: sealed {payload.get('record_count')}, file has {summary.record_count}"
    if payload.get("trajectory_digest") != summary.trajectory_digest:
        return "trajectory digest mismatch: a call was modified, reordered, added or removed"
    if payload.get("session_ids") != summary.session_ids:
        return "session ids changed"
    if payload.get("truncated_tail") != summary.truncated_tail:
        return "truncated-tail flag changed: the file's end does not match what was sealed"
    for key, value in (("models", summary.models),
                       ("query_sources", summary.query_sources),
                       ("first_started_at", summary.first_started_at),
                       ("last_completed_at", summary.last_completed_at)):
        if key in payload and payload[key] != value:
            return f"{key} changed since sealing"
    return None
