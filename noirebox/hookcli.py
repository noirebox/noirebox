"""Integration-hook handlers: hook JSON in (stdin), journal events out.

Every coding agent with a hook system can drive NoireBox the same way:
a hook fires, feeds its payload as JSON on stdin, and the noirebox CLI
seals one event into the per-project journal. This module holds the two
generic handlers — they know nothing about any specific agent:

  `tool-use`     one agent tool action (file write, shell command…)
                 → `agent_tool_use` event, with a truncated preview of the
                 tool input only (data minimization: the journal proves
                 what was done, it is not a log dump).
  `session-end`  the session's transcript file (path comes from the hook
                 payload) → one `model_trajectory` event over its digests
                 (ADR 012/013), format sniffed by shape.

Best-effort by contract: a recorder must never block the agent, so errors
surface loudly on stderr and the process still exits 0. The journal is the
per-project one (ADR 013's discovery: NOIREBOX_DB, then the nearest
`.noirebox/` directory upward).
"""
from __future__ import annotations

import datetime
import json
import os
import sys

from . import __version__
from . import locate, transcripts
from .chain import KeyPair
from .store import EventStore

MAX_PREVIEW_CHARS = 800


def _journal(hook: dict) -> str:
    return locate.ensure_journal_dir(hook.get("cwd"))


def _store_and_key(db: str) -> tuple[EventStore, KeyPair]:
    return EventStore(db), KeyPair.load_or_create(db + ".key")


def tool_use(hook: dict) -> str:
    """Seals one agent tool action. Returns a one-line description."""
    tool = str(hook.get("tool_name") or "unknown")
    detail = hook.get("tool_input") or {}
    try:
        preview = json.dumps(detail, ensure_ascii=False)[:MAX_PREVIEW_CHARS]
    except (TypeError, ValueError):
        preview = "<unserializable tool input>"
    db = _journal(hook)
    store, key = _store_and_key(db)
    payload: dict = {
        "source": {"tool": "noirebox", "version": __version__},
        "tool": tool,
        "input_preview": preview,
        "sealed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    if isinstance(hook.get("session_id"), str) and hook["session_id"]:
        payload["session_id"] = hook["session_id"]
    event = store.append("agent_tool_use", payload, key)
    return f"seq={event.seq} agent_tool_use ({tool})"


def session_end(hook: dict) -> str:
    """Seals the session transcript named by the hook payload.

    The transcript file is the agent's own record of what happened; only
    its digests enter the journal. A missing path is reported, never
    invented — no evidence is manufactured here."""
    transcript = hook.get("transcript_path")
    if not isinstance(transcript, str) or not transcript:
        return "no transcript_path in hook payload — nothing to seal"
    summary = transcripts.read_summary(transcript)
    payload = transcripts.transcript_payload(summary)
    db = _journal(hook)
    store, key = _store_and_key(db)
    event = store.append("model_trajectory", payload, key)
    return (f"seq={event.seq} model_trajectory ({summary.origin}, "
            f"{summary.record_count} record(s))")


HANDLERS = {"tool-use": tool_use, "session-end": session_end}


def run(kind: str, stdin=sys.stdin) -> int:
    """CLI entry: reads the hook JSON, dispatches, prints the outcome on
    stderr (visible in the session) — exit 0 whatever happens, per the
    best-effort contract. A parse failure of the hook payload is reported
    and NOT sealed: nothing is manufactured from an unreadable input."""
    if os.environ.get("NOIREBOX_HOOK_DISABLE") == "1":
        print("[noirebox] hook disabled (NOIREBOX_HOOK_DISABLE)", file=sys.stderr)
        return 0
    try:
        hook = json.load(stdin)
        if not isinstance(hook, dict):
            raise ValueError("hook payload is not a JSON object")
        line = HANDLERS[kind](hook)
    except Exception as exc:  # noqa: BLE001 — best-effort boundary
        print(f"[noirebox] hook {kind} failed: {exc}", file=sys.stderr)
        return 0
    print(f"[noirebox] sealed {kind}: {line}", file=sys.stderr)
    return 0
