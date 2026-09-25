from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import UTC, datetime

from .chain import Event, KeyPair, compute_event_hash

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    type       TEXT NOT NULL,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    signature  TEXT NOT NULL
);
"""


def now_iso() -> str:
    """ISO 8601 UTC timestamp with milliseconds.

    Always UTC (`timezone.utc`): an audit log mixing local times with and
    without daylight saving would be unusable. `timespec="ms"` fixes the
    precision — without it, two close calls would produce strings of
    different lengths depending on execution speed.
    """
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class EventStore:
    def __init__(self, path: str):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        # Hardening: the journal may contain personal data (transcripts,
        # payloads), so the file must never be readable by other local
        # accounts. O_CREAT gives 0600 at creation time (no window at 0644);
        # the unconditional chmod also tightens databases created before
        # this fix or by another tool. WAL sidecars inherit looser modes.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        for sidecar in (f"{path}-wal", f"{path}-shm"):
            if os.path.exists(sidecar):
                os.chmod(sidecar, 0o600)

        # isolation_level=None: manual transaction control, so sealing can be
        # one atomic BEGIN IMMEDIATE transaction (see append).
        self._conn = sqlite3.connect(path, check_same_thread=False,
                                     isolation_level=None, timeout=5.0)
        self._lock = threading.Lock()
        # Switching the journal mode requires exclusive access and does NOT
        # invoke the busy handler: a hook opening the journal while the server
        # holds a lock would crash here (and, before the hook reported loudly,
        # crash silently). The common case — file already in WAL — is skipped;
        # the rare switch retries briefly.
        mode = self._conn.execute("PRAGMA journal_mode").fetchone()[0]
        if mode.lower() != "wal":
            for attempt in range(50):
                try:
                    self._conn.execute("PRAGMA journal_mode=WAL")
                    break
                except sqlite3.OperationalError:
                    if attempt == 49:
                        raise
                    time.sleep(0.1)
        self._conn.executescript(_SCHEMA)

    def append(self, type_: str, payload: dict, key: KeyPair) -> Event:
        """Inserts a chained, signed event.

        Two levels of serialization, because the journal is written by
        independent processes (the MCP server AND one hook process per tool
        call), not just threads:
        - the threading.Lock serializes threads sharing this connection;
        - BEGIN IMMEDIATE takes SQLite's write lock BEFORE reading the last
          event, so a concurrent sealer waits first, then reads our committed
          row. Two events can never compute the same seq — the PK constraint
          stops being a silent drop path — and a transaction that dies
          mid-seal rolls back whole: no gap, no half-written event.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT seq, event_hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = (row[0] + 1) if row else 1
                prev_hash = row[1] if row else "0" * 64
                ts = now_iso()
                event_hash = compute_event_hash(seq, ts, type_, payload, prev_hash)
                signature = key.sign(bytes.fromhex(event_hash))
                event = Event(seq, ts, type_, payload, prev_hash, event_hash, signature)
                self._conn.execute("INSERT INTO events (seq, ts, type, payload, prev_hash, event_hash, signature) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                   (seq, ts, type_, json.dumps(payload, ensure_ascii=False, sort_keys=True),
                                    prev_hash, event_hash, signature))
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            return event

    def all(self) -> list[dict]:
        """All events, oldest to newest, payload deserialized to a dict
        (the JSON is stored as TEXT)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, ts, type, payload, prev_hash, event_hash, signature "
                "FROM events ORDER BY seq ASC"
            ).fetchall()
        return [
            {
                "seq": r[0], "ts": r[1], "type": r[2],
                "payload": json.loads(r[3]), "prev_hash": r[4],
                "event_hash": r[5], "signature": r[6],
            }
            for r in rows
        ]
