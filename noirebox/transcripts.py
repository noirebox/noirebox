"""Transcript-agnostic sealing (ADR 013): any agent's per-call or per-message
JSONL log becomes journal evidence, whatever app produced it.

Agents keep different JSONL shapes — per-call model I/O logs (request,
response, usage), per-message session transcripts (role, message, model),
or plain logs. The sealing machinery does not care: each line is a record,
each record is committed by digest, the digests form an order-committed
chain (ADR 012's construction — a trajectory is ordered, a rewrite of
history must accuse). What differs per shape is only the metadata
extraction, so this module sniffs the shape and reads metadata tolerantly:
whatever fields are present are counted; absent fields are simply not
committed. Schema drift degrades gracefully by design.

Formats (named by SHAPE, deliberately not by product — the convention is
agent-agnostic and today's names should not become tomorrow's debt):

  `model-io`            one line per LLM call: request/response bodies,
                        model object, per-call origin, call timings.
  `session-transcript`  one line per conversation event: role/message
                        records, often session-scoped with timestamps and
                        model name on assistant messages.
  `generic-jsonl`       none of the above: still sealable — digests and
                        count only.

Corruption policy is the house one (ADR 012): an unparseable LAST line is
an incomplete trailing write, reported (`truncated_tail`) and sealed as
seen; an unparseable line mid-file is a hard error. Digests only, never
content — these logs contain conversations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .digests import digest_chain, read_jsonl_records

TOOL = "noirebox"

MODEL_IO = "model-io"
SESSION_TRANSCRIPT = "session-transcript"
GENERIC_JSONL = "generic-jsonl"

_SESSION_KEYS = ("sessionId", "session_id", "conversationId", "threadId")
_TIME_KEYS = ("timestamp", "startedAt", "completedAt", "createdAt", "ts")


def sniff_format(records: list[dict]) -> str:
    """Classifies a parsed JSONL log by its shape (see module doc)."""
    for record in records:
        if isinstance(record.get("model"), dict) and "modelId" in record["model"]:
            return MODEL_IO
        if isinstance(record.get("request"), dict) or isinstance(record.get("response"), dict):
            return MODEL_IO
        message = record.get("message")
        if isinstance(message, dict) and isinstance(message.get("role"), str):
            return SESSION_TRANSCRIPT
        if record.get("type") in ("user", "assistant") and isinstance(message, (dict, str)):
            return SESSION_TRANSCRIPT
    return GENERIC_JSONL


@dataclass
class TranscriptSummary:
    """Everything the seal commits to, computed from one observed file."""

    origin: str
    file_sha256: str
    record_count: int
    trajectory_digest: str
    session_ids: list[str]
    truncated_tail: bool
    models: list[str] = field(default_factory=list)
    query_sources: dict[str, int] = field(default_factory=dict)
    first_event_at: str | None = None
    last_event_at: str | None = None


def _extract_metadata(records: list[dict]) -> dict:
    """Tolerant metadata extraction: present fields are committed, absent
    fields are omitted. Nothing here reads message CONTENT — only envelope
    fields (session ids, timestamps, model names, per-call origins)."""
    sessions: set[str] = set()
    models: set[str] = set()
    sources: dict[str, int] = {}
    times: list[str] = []
    for record in records:
        for key in _SESSION_KEYS:
            if isinstance(record.get(key), str) and record[key]:
                sessions.add(record[key])
                break
        model = record.get("model")
        if isinstance(model, str):
            models.add(model)
        elif isinstance(model, dict) and isinstance(model.get("modelId"), str):
            models.add(model["modelId"])
        elif isinstance(record.get("message"), dict) and isinstance(
            record["message"].get("model"), str
        ):
            models.add(record["message"]["model"])
        if isinstance(record.get("querySource"), str):
            sources[record["querySource"]] = sources.get(record["querySource"], 0) + 1
        for key in _TIME_KEYS:
            if isinstance(record.get(key), str):
                times.append(record[key])
                break
    return {
        "session_ids": sorted(sessions),
        "models": sorted(models),
        "query_sources": dict(sorted(sources.items())),
        "first_event_at": min(times) if times else None,
        "last_event_at": max(times) if times else None,
    }


def read_summary(path: str | Path, origin: str | None = None) -> TranscriptSummary:
    """Reads a JSONL log, sniffs its shape (or trusts an explicit `origin`)
    and computes the seal summary. Corruption policy and digest chain live
    in digests.py — the single construction of ADR 012/013."""
    records, file_sha256, truncated_tail = read_jsonl_records(path)

    meta = _extract_metadata(records)
    return TranscriptSummary(
        origin=origin or sniff_format(records),
        file_sha256=file_sha256,
        record_count=len(records),
        trajectory_digest=digest_chain(records),
        session_ids=meta["session_ids"] or ["unknown"],
        truncated_tail=truncated_tail,
        models=meta["models"],
        query_sources=meta["query_sources"],
        first_event_at=meta["first_event_at"],
        last_event_at=meta["last_event_at"],
    )


def transcript_payload(summary: TranscriptSummary, *,
                       version: str = __version__) -> dict:
    """Builds the validated `model_trajectory` payload for any format.

    Same event type as ADR 012 (a per-call log and a session transcript are
    the same kind of claim: this agent behavior existed, in this order);
    `origin` carries the shape, `source` names the sealer."""
    payload: dict = {
        "source": {"tool": TOOL, "version": version},
        "origin": summary.origin,
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
    if summary.first_event_at:
        payload["first_event_at"] = summary.first_event_at
    if summary.last_event_at:
        payload["last_event_at"] = summary.last_event_at
    return payload


_KNOWN_ORIGINS = (MODEL_IO, SESSION_TRANSCRIPT, GENERIC_JSONL)


def verify_transcript(payload: dict, path: str | Path) -> str | None:
    """Recomputes the summary from the file and confronts it with the payload.

    House convention (None = intact, otherwise the reason). Dispatches on the
    payload's own `origin`, so a seal made by any adapter verifies with this
    single entry point; an unknown origin is a mismatch, not a crash.
    """
    origin = payload.get("origin")
    if origin not in _KNOWN_ORIGINS:
        return f"unknown origin: {origin!r} (expected one of {', '.join(_KNOWN_ORIGINS)})"
    if payload.get("source", {}).get("tool") != TOOL:
        return "source mismatch: payload was not sealed by noirebox"
    try:
        summary = read_summary(path, origin=origin)
    except ValueError as exc:
        return f"unreadable log: {exc}"
    checks = [
        ("file_sha256", "file content changed (file_sha256 mismatch)"),
        ("record_count", None),
        ("trajectory_digest",
         "trajectory digest mismatch: a record was modified, reordered, added or removed"),
        ("session_ids", "session ids changed"),
        ("truncated_tail", "truncated-tail flag changed"),
        ("models", None), ("query_sources", None),
        ("first_event_at", None), ("last_event_at", None),
    ]
    for key, message in checks:
        expected = getattr(summary, key)
        if key in payload and payload[key] != expected:
            return message or f"{key} changed since sealing"
    return None
