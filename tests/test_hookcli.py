"""ADR 013 — integration hooks: hook JSON on stdin, journal events out."""

import io
import json
from pathlib import Path

from noirebox import hookcli
from noirebox.store import EventStore


def _tool_hook(tmp_path: Path, command: str = "ls") -> dict:
    return {"hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "session_id": "sess_hook",
            "cwd": str(tmp_path)}


def _transcript_file(tmp_path: Path) -> str:
    path = tmp_path / "session.jsonl"
    lines = [
        json.dumps({"type": "user", "sessionId": "sess_hook",
                    "timestamp": "2026-09-28T11:00:00.000Z",
                    "message": {"role": "user", "content": "internal question"}}),
        json.dumps({"type": "assistant", "sessionId": "sess_hook",
                    "timestamp": "2026-09-28T11:00:02.000Z",
                    "message": {"role": "assistant", "model": "claude-sonnet-4-5",
                                "content": [{"type": "text", "text": "answer"}]}}),
    ]
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return str(path)


def _events(tmp_path: Path) -> list[dict]:
    db = tmp_path / ".noirebox" / "journal.db"
    return EventStore(str(db)).all()


def test_tool_use_seals_into_the_per_project_journal(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    line = hookcli.tool_use(_tool_hook(tmp_path))
    assert "agent_tool_use" in line
    events = _events(tmp_path)
    assert events[0]["type"] == "agent_tool_use"
    payload = events[0]["payload"]
    assert payload["tool"] == "Bash"
    assert payload["session_id"] == "sess_hook"
    assert payload["source"]["tool"] == "noirebox"
    assert payload["input_preview"] == '{"command": "ls"}'


def test_preview_is_truncated(tmp_path):
    hook = _tool_hook(tmp_path, command="x" * 5000)
    hookcli.tool_use(hook)
    payload = _events(tmp_path)[0]["payload"]
    assert len(payload["input_preview"]) == hookcli.MAX_PREVIEW_CHARS


def test_session_end_seals_the_transcript(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    line = hookcli.session_end({"transcript_path": _transcript_file(tmp_path),
                                "cwd": str(tmp_path)})
    assert "model_trajectory" in line
    payload = _events(tmp_path)[-1]["payload"]
    assert payload["origin"] == "session-transcript"
    assert payload["record_count"] == 2
    assert "internal question" not in json.dumps(payload)  # digests only


def test_session_end_without_transcript_seals_nothing(tmp_path):
    assert "nothing to seal" in hookcli.session_end({"cwd": str(tmp_path)})
    assert _events(tmp_path) == []  # no evidence manufactured


def test_run_is_best_effort_and_loud(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    broken = io.StringIO("this is not json")
    assert hookcli.run("tool-use", stdin=broken) == 0  # never blocks the agent
    assert "failed" in capsys.readouterr().err

    ok = io.StringIO(json.dumps(_tool_hook(tmp_path)))
    assert hookcli.run("tool-use", stdin=ok) == 0
    assert "sealed tool-use" in capsys.readouterr().err


def test_global_disable(tmp_path, monkeypatch):
    monkeypatch.setenv("NOIREBOX_HOOK_DISABLE", "1")
    assert hookcli.run("tool-use", stdin=io.StringIO("{}")) == 0
    assert not (tmp_path / ".noirebox").exists()
