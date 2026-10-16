"""Rollout-directory sealing (ADR 012): turn the agent's own flight recorder
into journal evidence.

Coding agents keep one model-io JSONL per session (one line per LLM call).
This module scans such a directory and seals every new-or-changed file into
the journal — digests only, each file committed AS OBSERVED. A session
sealed mid-flight carries `truncated_tail: true`; the next scan over the
changed file seals the complete log. Progressive, honest, append-only.

Design constraints, in order:
- The journal is the ONLY register. Dedup first compares content digests
  against `file_sha256` values already sealed in `model_trajectory` events;
  a lost cache can never cause a double seal of identical content to go
  unnoticed — it would leave two events in plain sight. The cache file
  (beside the journal, derived from its RESOLVED path via `with_name`) only
  saves re-hashing, and the scan throttle lives there.
- Containment: the rollout dir is resolved once and every candidate must
  resolve INSIDE it. A symlink planted in the rollout dir must not pull an
  outside file into the journal. Candidates are enumerated by glob, never
  user-supplied; the check makes that structural.
- Never manufacture evidence: a file that fails to parse (except an honest
  incomplete trailing write, reported) or vanishes mid-read is skipped
  loudly and retried on the next scan.

No environment variables here: callers (CLI, plugin hook) resolve toggles
and paths themselves and pass them explicitly.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

from . import transcripts
from .chain import KeyPair
from .store import EventStore

STATE_SUFFIX = ".trajstate"


def state_file(db: str) -> Path:
    """The cache lives beside the journal — derived from the RESOLVED db
    path via with_name, never from a raw string, so no `..` or symlinked
    prefix can move it outside the journal's directory."""
    resolved = Path(db).expanduser().resolve()
    return resolved.with_name(resolved.name + STATE_SUFFIX)


def contained_candidates(rollout: Path) -> tuple[list[Path], list[Path]]:
    """Globs `model-io-*.jsonl` and enforces containment (see module doc)."""
    inside, outside = [], []
    for path in sorted(rollout.glob("model-io-*.jsonl")):
        try:
            resolved = path.resolve()
            contained = resolved.is_relative_to(rollout)
        except OSError:
            contained = False
        if contained and path.is_file():
            inside.append(path)
        else:
            outside.append(path)
    return inside, outside


def _load_state(path: Path) -> dict:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path: Path, state: dict) -> None:
    path.write_text(json.dumps(state), encoding="utf-8")


def _sealed_digests(store: EventStore) -> set[str]:
    """Digests of trajectories already in the journal — the real register."""
    return {
        ev["payload"]["file_sha256"]
        for ev in store.all()
        if ev["type"] == "model_trajectory"
        and isinstance(ev["payload"], dict)
        and isinstance(ev["payload"].get("file_sha256"), str)
    }


def seal_rollout(rollout: Path, db: str, *, now: float | None = None,
                 interval_min: int = 10) -> list[str]:
    """Seals every new-or-changed model-io file of `rollout` into `db`.

    Returns one line per sealed file (caller decides where to print them).
    `now`/`interval_min` implement the scan throttle: within the interval,
    nothing is scanned and [] comes back. Idempotent at constant content:
    an unchanged file is never sealed twice, whatever the cache says.
    """
    rollout = Path(rollout).expanduser().resolve()
    cache = state_file(db)
    state = _load_state(cache)
    now = time.time() if now is None else now
    if now - state.get("last_scan", 0) < interval_min * 60:
        return []
    state["last_scan"] = now
    if not rollout.is_dir():
        _save_state(cache, state)
        return []
    inside, outside = contained_candidates(rollout)
    for path in outside:
        print(f"[noirebox] trajectory skipped, escapes the rollout dir: {path}",
              file=sys.stderr)

    store: EventStore | None = None
    journal_hashes: set[str] = set()
    sealed: list[str] = []
    seen: set[str] = set()
    for path in inside:
        seen.add(str(path))
        try:
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            print(f"[noirebox] trajectory unreadable ({path.name}): {exc}",
                  file=sys.stderr)
            continue
        cached_sha = state.get(str(path))
        if cached_sha == sha:
            continue
        if sha not in {v for v in state.values() if isinstance(v, str)}:
            if store is None:
                store = EventStore(db)
                journal_hashes = _sealed_digests(store)
            if sha in journal_hashes:
                state[str(path)] = sha  # content already sealed elsewhere
                continue
        try:
            summary = transcripts.read_summary(path, origin=transcripts.MODEL_IO)
            payload = transcripts.transcript_payload(summary)
        except ValueError as exc:
            print(f"[noirebox] trajectory not sealed ({path.name}): {exc}",
                  file=sys.stderr)
            continue
        if payload["file_sha256"] != sha:  # changed mid-read: next scan
            continue
        if store is None:
            store = EventStore(db)
            journal_hashes = _sealed_digests(store)
        event = store.append("model_trajectory", payload,
                             KeyPair.load_or_create(db + ".key"))
        state[str(path)] = sha
        sealed.append(f"seq={event.seq} {path.name} "
                      f"({summary.record_count} call(s))")
    for known in list(state):
        if known != "last_scan" and known not in seen:
            del state[known]  # rotated away — nothing left to re-seal
    _save_state(cache, state)
    return sealed
