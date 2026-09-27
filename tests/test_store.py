"""Database file permissions (the journal may contain personal data, so the
file and its WAL sidecars must never be readable by other local accounts) and
cross-process sealing (the MCP server and the ZCode hook are independent
processes writing the same journal).
"""
from __future__ import annotations

import multiprocessing
import stat
from pathlib import Path

from noirebox.chain import KeyPair, verify_chain
from noirebox.store import EventStore


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _sidecar(db: Path, suffix: str, root: Path) -> Path:
    """WAL/SHM sidecar path — containment in the test sandbox is asserted,
    not assumed."""
    sidecar = db.with_name(db.name + suffix).resolve()
    assert sidecar.is_relative_to(root)
    return sidecar


def test_new_database_is_created_owner_only(tmp_path):
    """A freshly created database is 0600 — no window at 0644."""
    db = tmp_path / "box.db"
    EventStore(str(db))
    assert _mode(db) == 0o600


def test_loose_permissions_are_tightened_on_open(tmp_path):
    """A pre-existing world-readable database (created before the fix, or by
    another tool) is tightened to 0600 on the next open."""
    db = tmp_path / "box.db"
    db.write_text("")
    db.chmod(0o644)
    EventStore(str(db))
    assert _mode(db) == 0o600


def test_wal_sidecars_are_owner_only(tmp_path):
    """WAL/SHM sidecars appear on first write — they must be 0600 too."""
    db = tmp_path / "box.db"
    store = EventStore(str(db))
    key = KeyPair.load_or_create(str(tmp_path / "box.key"))
    store.append("llm_call", {"agent": "perm-test"}, key)
    for suffix in ("-wal", "-shm"):
        sidecar = _sidecar(db, suffix, tmp_path)
        if sidecar.exists():
            assert _mode(sidecar) == 0o600


def _seal_worker(db, key_path, count, rank, start):
    """Body of one sealing process, mirroring production: the MCP server and
    the PostToolUse hook are separate OS processes that each open their own
    connection to the same journal. The barrier makes all workers hit their
    first append simultaneously, to maximize contention; the wait is bounded
    so a crashed worker breaks the barrier instead of hanging the suite."""
    store = EventStore(db)
    key = KeyPair.load_or_create(key_path)
    start.wait(timeout=30)
    for i in range(count):
        store.append("proc_test", {"worker": rank, "i": i}, key)


def test_concurrent_processes_seal_every_event_without_gap(tmp_path):
    """Regression: seq allocation used to be guarded by a threading.Lock only
    (intra-process), so the MCP server and a hook process could read the same
    max(seq); the loser of the race hit the seq PRIMARY KEY and its event was
    silently dropped — an unexplained gap in a tamper-evident journal. With
    BEGIN IMMEDIATE the read-then-insert is one write transaction: every
    process seals every event, seqs are contiguous, the chain verifies.
    """
    db = str(tmp_path / "box.db")
    key_path = db + ".key"
    # Created up front: this test isolates the seq race, not key creation and
    # not journal-mode switching.
    key = KeyPair.load_or_create(key_path)
    EventStore(db)

    # spawn: fresh interpreters, no fork into a threaded pytest process.
    ctx = multiprocessing.get_context("spawn")
    start = ctx.Barrier(4)
    procs = [
        ctx.Process(target=_seal_worker, args=(db, key_path, 6, rank, start))
        for rank in range(4)
    ]
    for proc in procs:
        proc.start()
    for rank, proc in enumerate(procs):
        proc.join(timeout=90)
        assert proc.exitcode == 0, f"worker {rank} exited {proc.exitcode}"

    # Read back from a fresh connection: 4 workers x 6 events, no gap.
    events = EventStore(db).all()
    assert [e["seq"] for e in events] == list(range(1, 25))
    assert verify_chain(key.public_hex(), events)["valid"]


def test_activity_empty_journal(tmp_path):
    """An empty journal has no activity rows — not a zero-filled year."""
    store = EventStore(str(tmp_path / "empty.db"))
    assert store.activity() == []


def test_since_returns_the_strict_tail(tmp_path):
    """The live tail: strictly newer than the cursor, ascending, capped —
    the contract the radar's seq cursor rides on (no skip, no replay)."""
    store = EventStore(str(tmp_path / "tail.db"))
    key = KeyPair.load_or_create(str(tmp_path / "tail.key"))
    for i in range(3):
        store.append("llm_call", {"i": i}, key)
    assert [e["seq"] for e in store.since(0)] == [1, 2, 3]
    assert [e["seq"] for e in store.since(1)] == [2, 3]
    assert [e["seq"] for e in store.since(3)] == []
    assert [e["seq"] for e in store.since(0, limit=2)] == [1, 2]


def test_activity_buckets_days_utc(monkeypatch, tmp_path):
    """The heatmap's source: one row per UTC day, anchor events tallied
    separately. Bucketing rides on now_iso's fixed format — a drifted
    timestamp format would silently merge days."""
    store = EventStore(str(tmp_path / "act.db"))
    key = KeyPair.load_or_create(str(tmp_path / "act.key"))
    monkeypatch.setattr("noirebox.store.now_iso",
                        lambda: "2026-03-23T22:10:05.123+00:00")
    store.append("llm_call", {}, key)
    store.append("llm_call", {}, key)
    monkeypatch.setattr("noirebox.store.now_iso",
                        lambda: "2026-03-24T01:00:00.000+00:00")
    store.append("anchor", {}, key)
    assert store.activity() == [
        {"day": "2026-03-23", "count": 2, "anchors": 0},
        {"day": "2026-03-24", "count": 1, "anchors": 1},
    ]
