"""ADR 012 — sealing a coding agent's model trajectory (model-io JSONL)."""

import json
from pathlib import Path

import pytest

from noirebox import __version__
from noirebox.cli import main as cli_main
from noirebox.chain import KeyPair, verify_chain
from noirebox.store import EventStore
from noirebox.trajectory import (read_model_io, trajectory_payload,
                                 verify_trajectory)


def _record(session: str, source: str, model: str, text: str,
            started: str, completed: str) -> dict:
    """A realistic model_io record, in the observed Agent shape."""
    return {
        "requestId": f"req-{text[:8]}",
        "attempt": 1,
        "sessionId": session,
        "traceId": "trace-1",
        "turnId": "turn-1",
        "type": "model_io",
        "model": {"modelId": model, "providerId": "test"},
        "querySource": source,
        "startedAt": started,
        "completedAt": completed,
        "durationMs": 1200,
        "request": {"messages": [{"role": "user", "content": text}]},
        "response": {"text": f"answer to {text}"},
    }


def _write_log(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


T0, T1, T2 = "2026-09-28T01:00:00.000Z", "2026-09-28T01:00:02.000Z", "2026-09-28T01:00:04.000Z"
SECRET = "CONFIDENTIAL-DRAFT-TEXT-NEVER-TO-JOURNAL"


# --- the summary: digests and counters over the observed file ---------------

def test_summary_fields_over_a_two_call_log(tmp_path):
    log = tmp_path / "model-io-sess_x.jsonl"
    _write_log(log, [
        _record("sess_x", "main", "GLM-5.3-Flash", SECRET, T0, T1),
        _record("sess_x", "subagent", "GLM-5.3-Flash", "second call", T1, T2),
    ])
    s = read_model_io(log)
    assert s.record_count == 2
    assert s.session_ids == ["sess_x"]
    assert s.models == ["GLM-5.3-Flash"]
    assert s.query_sources == {"main": 1, "subagent": 1}
    assert s.first_started_at == T0
    assert s.last_completed_at == T2
    assert s.truncated_tail is False
    assert len(s.file_sha256) == 64 and len(s.trajectory_digest) == 64


def test_digest_is_order_committed():
    """The calls form a trajectory: same records, different order → different
    digest. A set-committing root (Merkle) could not see a rewrite of history."""
    a = _record("s", "main", "m", "first", T0, T1)
    b = _record("s", "main", "m", "second", T1, T2)
    import hashlib

    def chained(recs):
        d = "0" * 64
        for r in recs:
            d = hashlib.sha256((d + hashlib.sha256(
                json.dumps(r, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")).hexdigest()
            ).encode("ascii")).hexdigest()
        return d

    assert chained([a, b]) != chained([b, a])


# --- the payload: sealer identity + minimization by construction ------------

def test_payload_names_its_sealer_and_carries_no_content(tmp_path):
    log = tmp_path / "model-io-sess_x.jsonl"
    _write_log(log, [_record("sess_x", "main", "GLM-5.3-Flash", SECRET, T0, T1)])
    p = trajectory_payload(read_model_io(log))
    assert p["source"] == {"tool": "noirebox", "version": __version__}
    assert p["origin"] == "agent-model-io"
    assert SECRET not in json.dumps(p)  # the draft never enters the journal
    assert "request" not in p and "response" not in p


# --- verification: None = intact, otherwise the reason ----------------------

def test_verify_intact_then_detects_each_forgery(tmp_path):
    log = tmp_path / "model-io-sess_x.jsonl"
    records = [
        _record("sess_x", "main", "GLM-5.3-Flash", "call one", T0, T1),
        _record("sess_x", "subagent", "GLM-4.6", "call two", T1, T2),
    ]
    _write_log(log, records)
    p = trajectory_payload(read_model_io(log))
    assert verify_trajectory(p, log) is None

    # a call was rewritten (the classic rewrite-history forgery)
    tampered = json.loads(json.dumps(records))
    tampered[1]["response"]["text"] = "a very different answer"
    _write_log(log, tampered)
    assert verify_trajectory(p, log) is not None

    # a call was removed — bytes and digest both change; the module reports
    # the first divergence (file_sha256), the tamper is caught regardless
    _write_log(log, records[:1])
    assert "file content changed" in verify_trajectory(p, log)
    forged = dict(trajectory_payload(read_model_io(log)), record_count=99)
    assert "record count changed" in verify_trajectory(forged, log)

    # the whole file was swapped
    other = tmp_path / "other.jsonl"
    _write_log(other, [_record("sess_y", "main", "m", "other", T0, T1)])
    assert verify_trajectory(p, other) is not None


# --- corruption policy: honest about the tail, loud about the middle --------

def test_incomplete_trailing_write_is_reported_not_hidden(tmp_path):
    log = tmp_path / "model-io-sess_x.jsonl"
    _write_log(log, [_record("s", "main", "m", "ok", T0, T1)])
    with open(log, "a", encoding="utf-8") as f:
        f.write('{"requestId": "cut-off", "started')  # crash mid-write
    s = read_model_io(log)
    assert s.record_count == 1
    assert s.truncated_tail is True
    p = trajectory_payload(read_model_io(log))
    assert p["truncated_tail"] is True
    assert verify_trajectory(p, log) is None  # the seal matches what was seen


def test_mid_file_corruption_is_a_hard_error(tmp_path):
    log = tmp_path / "model-io-sess_x.jsonl"
    lines = [json.dumps(_record("s", "main", "m", "ok", T0, T1))]
    log.write_text(lines[0] + "\n" + '{"broken":\n' + lines[0] + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="middle of the log"):
        read_model_io(log)


def test_empty_file_is_rejected(tmp_path):
    log = tmp_path / "model-io-empty.jsonl"
    log.write_text("\n\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no records"):
        read_model_io(log)


# --- the CLI command seals into a real, verifiable journal -------------------

def test_cli_seals_and_chain_stays_valid(tmp_path):
    log = tmp_path / "model-io-sess_x.jsonl"
    _write_log(log, [_record("sess_x", "main", "GLM-5.3-Flash", "call one", T0, T1)])
    db = tmp_path / "journal.db"
    key = KeyPair.load_or_create(str(db) + ".key")  # the CLI loads the same key
    store = EventStore(str(db))
    store.append("note", {"hello": "world"}, key)  # pre-existing event
    assert cli_main(["seal-trajectory", str(log), "--db", str(db)]) == 0

    events = store.all()
    traj = [e for e in events if e["type"] == "model_trajectory"]
    assert len(traj) == 1
    assert traj[0]["payload"]["origin"] == "agent-model-io"
    check = verify_chain(KeyPair.load_or_create(str(db) + ".key").public_hex(), events)
    assert check["valid"] is True


def test_cli_refuses_an_unreadable_file(tmp_path):
    log = tmp_path / "model-io-empty.jsonl"
    log.write_text("", encoding="utf-8")
    assert cli_main(["seal-trajectory", str(log),
                     "--db", str(tmp_path / "journal.db")]) == 1
