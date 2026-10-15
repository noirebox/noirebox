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


def test_preview_is_truncated(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
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


def test_session_end_without_transcript_seals_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
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
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    monkeypatch.setenv("NOIREBOX_HOOK_DISABLE", "1")
    assert hookcli.run("tool-use", stdin=io.StringIO("{}")) == 0
    assert not (tmp_path / ".noirebox").exists()


# --- NB-10 — a secret in a tool input never reaches the immutable journal -----

def test_preview_redacts_bearer_and_keys(tmp_path, monkeypatch):
    """NB-10: the preview is sealed immutably and leaves in every export —
    a curl with an Authorization header or a written .env must not become
    permanent, third-party-readable secret material."""
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    monkeypatch.delenv("NOIREBOX_PREVIEW_MODE", raising=False)
    hook = _tool_hook(tmp_path, command='curl -H "Authorization: Bearer sk-live-abcdef123456"')
    hookcli.tool_use(hook)
    preview = _events(tmp_path)[0]["payload"]["input_preview"]
    assert "sk-live-abcdef123456" not in preview
    assert "Bearer [REDACTED]" in preview


def test_preview_redacts_env_and_json_secret_shapes(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    monkeypatch.delenv("NOIREBOX_PREVIEW_MODE", raising=False)
    hook = _tool_hook(
        tmp_path,
        command="export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIandmore00 --token ghp_0123456789abcdefghijklmnop")
    hookcli.tool_use(hook)
    preview = _events(tmp_path)[0]["payload"]["input_preview"]
    assert "wJalrXUtnFEMIandmore00" not in preview
    assert "ghp_0123456789" not in preview
    assert "[REDACTED]" in preview

    hook2 = _tool_hook(tmp_path, command='echo ok')  # second event: JSON shape
    hook2["tool_input"] = {"file": ".env", "content": '{"api_key": "super-secret-value-42"}'}
    hookcli.tool_use(hook2)
    preview2 = _events(tmp_path)[-1]["payload"]["input_preview"]
    assert "super-secret-value-42" not in preview2


def test_redaction_runs_before_truncation(tmp_path, monkeypatch):
    """NB-10: a secret cut in half at char 800 is still half a secret —
    redact first, truncate after: nothing raw of it survives the cap."""
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    monkeypatch.delenv("NOIREBOX_PREVIEW_MODE", raising=False)
    padding = "z" * 700
    hook = _tool_hook(tmp_path,
                      command=f"{padding} && curl -H 'Authorization: Bearer sk-tail-secret-999999'")
    hookcli.tool_use(hook)
    preview = _events(tmp_path)[0]["payload"]["input_preview"]
    assert len(preview) <= hookcli.MAX_PREVIEW_CHARS  # redaction shrinks, never grows
    assert "sk-tail-secret-999999" not in preview     # past the cap, still redacted


def test_preview_hash_mode_seals_zero_content(tmp_path, monkeypatch):
    """NOIREBOX_PREVIEW_MODE=hash: deployments that want NOTHING of the
    input in the journal get the digest, and it verifies."""
    import hashlib

    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    monkeypatch.setenv("NOIREBOX_PREVIEW_MODE", "hash")
    detail = _tool_hook(tmp_path, command="sensitive but hashed")["tool_input"]
    hookcli.tool_use(_tool_hook(tmp_path, command="sensitive but hashed"))
    preview = _events(tmp_path)[0]["payload"]["input_preview"]
    assert preview == "sha256:" + hashlib.sha256(
        json.dumps(detail, ensure_ascii=False).encode("utf-8")).hexdigest()
