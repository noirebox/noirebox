"""ADR 013 — transcript-agnostic sealing: any agent's JSONL log, by shape."""

import json
from pathlib import Path

import pytest

from noirebox.transcripts import (GENERIC_JSONL, MODEL_IO, SESSION_TRANSCRIPT,
                                  read_summary, sniff_format,
                                  transcript_payload, verify_transcript)

SECRET = "CONFIDENTIAL-CONVERSATION-NEVER-TO-JOURNAL"


def _transcript_line(n: int, model: str = "claude-sonnet-4-5") -> str:
    if n == 1:
        return json.dumps({"type": "user", "sessionId": "sess_c", "uuid": f"u{n}",
                           "timestamp": f"2026-09-28T10:00:0{n}.000Z",
                           "message": {"role": "user", "content": SECRET}})
    return json.dumps({"type": "assistant", "sessionId": "sess_c", "uuid": f"u{n}",
                       "timestamp": f"2026-09-28T10:00:0{n}.000Z",
                       "message": {"role": "assistant", "model": model,
                                   "content": [{"type": "text", "text": f"answer {n}"}]}})


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


# --- shape sniffing ----------------------------------------------------------

def test_sniff_by_shape_not_by_product():
    session = [json.loads(_transcript_line(1)), json.loads(_transcript_line(2))]
    assert sniff_format(session) == SESSION_TRANSCRIPT
    model_io = [{"model": {"modelId": "GLM-5.3-Flash"}, "request": {}}]
    assert sniff_format(model_io) == MODEL_IO
    assert sniff_format([{"anything": 1}]) == GENERIC_JSONL


# --- summary: tolerant metadata, strict digests ------------------------------

def test_summary_extracts_envelope_metadata_only(tmp_path):
    log = tmp_path / "session.jsonl"
    _write(log, [_transcript_line(1), _transcript_line(2), _transcript_line(3)])
    s = read_summary(log)
    assert s.origin == SESSION_TRANSCRIPT
    assert s.session_ids == ["sess_c"]
    assert s.models == ["claude-sonnet-4-5"]
    assert s.first_event_at == "2026-09-28T10:00:01.000Z"
    assert s.last_event_at == "2026-09-28T10:00:03.000Z"
    assert s.record_count == 3
    assert SECRET not in json.dumps(transcript_payload(s))  # digests only


def test_digest_is_order_committed_across_formats():
    import hashlib as h

    def chained(recs):
        d = "0" * 64
        for r in recs:
            rd = h.sha256(h.sha256(
                json.dumps(r, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")).hexdigest().encode()
            ).hexdigest()
            d = h.sha256((d + rd).encode("ascii")).hexdigest()
        return d

    a, b = {"n": 1}, {"n": 2}
    assert chained([a, b]) != chained([b, a])


def test_generic_format_seals_with_minimal_metadata(tmp_path):
    log = tmp_path / "generic.jsonl"
    _write(log, [json.dumps({"k": "v"}), json.dumps({"k": "w"})])
    s = read_summary(log)
    assert s.origin == GENERIC_JSONL
    assert s.session_ids == ["unknown"]
    assert s.models == []
    p = transcript_payload(s)
    assert "models" not in p and "first_event_at" not in p  # absent = omitted
    assert verify_transcript(p, log) is None


# --- verification ------------------------------------------------------------

def test_verify_intact_then_detects_forgery(tmp_path):
    log = tmp_path / "session.jsonl"
    lines = [_transcript_line(1), _transcript_line(2)]
    _write(log, lines)
    p = transcript_payload(read_summary(log))
    assert verify_transcript(p, log) is None

    tampered = [json.loads(lines[0]), json.loads(lines[1])]
    tampered[1]["message"]["content"][0]["text"] = "rewritten answer"
    _write(log, [json.dumps(t) for t in tampered])
    assert "file content changed" in verify_transcript(p, log)

    p2 = transcript_payload(read_summary(log))
    forged = dict(p2, trajectory_digest="0" * 64)
    assert "trajectory digest mismatch" in verify_transcript(forged, log)


def test_unknown_origin_is_a_mismatch_not_a_crash(tmp_path):
    log = tmp_path / "session.jsonl"
    _write(log, [_transcript_line(1)])
    assert "unknown origin" in verify_transcript({"origin": "mystery"}, log)


# --- corruption policy (the house one) ---------------------------------------

def test_truncated_tail_reported_and_mid_file_corruption_hard_error(tmp_path):
    log = tmp_path / "session.jsonl"
    _write(log, [_transcript_line(1)])
    with open(log, "a", encoding="utf-8") as f:
        f.write('{"type": "assistant", "sess')  # crash mid-write
    s = read_summary(log)
    assert s.truncated_tail is True and s.record_count == 1
    assert verify_transcript(transcript_payload(s), log) is None

    corrupt = tmp_path / "corrupt.jsonl"
    corrupt.write_text(_transcript_line(1) + "\n{'broken':\n" + _transcript_line(2) + "\n",
                       encoding="utf-8")
    with pytest.raises(ValueError, match="middle of the log"):
        read_summary(corrupt)


# --- CLI: auto dispatch, legacy model-io behavior unchanged ------------------

def test_cli_auto_routes_by_shape(tmp_path):
    from noirebox.cli import main as cli_main

    db = tmp_path / "journal.db"
    transcript = tmp_path / "session.jsonl"
    _write(transcript, [_transcript_line(1), _transcript_line(2)])
    assert cli_main(["seal-trajectory", str(transcript), "--format", "auto",
                     "--db", str(db)]) == 0
    events = [e for e in __import__("noirebox.store", fromlist=["EventStore"])
              .EventStore(str(db)).all() if e["type"] == "model_trajectory"]
    assert len(events) == 1
    assert events[0]["payload"]["origin"] == SESSION_TRANSCRIPT
