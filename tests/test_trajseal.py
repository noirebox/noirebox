"""ADR 012 — rollout sealing (`noirebox.trajseal`): the plugin hook's engine."""

import json
from pathlib import Path

from noirebox.chain import KeyPair, verify_chain
from noirebox.store import EventStore
from noirebox.trajseal import seal_rollout, state_file

SECRET = "CONFIDENTIAL-DRAFT-NEVER-TO-JOURNAL"


def _record(n: int) -> dict:
    return {
        "requestId": f"req-{n}", "attempt": 1, "sessionId": "sess_t",
        "type": "model_io", "querySource": "main",
        "model": {"modelId": "GLM-5.3-Flash", "providerId": "test"},
        "startedAt": f"2026-09-28T01:0{n}:00.000Z",
        "completedAt": f"2026-09-28T01:0{n}:00.500Z",
        "request": {"messages": [{"role": "user", "content": SECRET}]},
        "response": {"text": f"answer {n}"},
    }


def _rollout(tmp_path: Path, calls: int = 1) -> Path:
    rollout = tmp_path / "rollout"
    rollout.mkdir(exist_ok=True)
    log = rollout / "model-io-sess_t.jsonl"
    log.write_text("".join(json.dumps(_record(i)) + "\n" for i in range(1, calls + 1)),
                   encoding="utf-8")
    return rollout


def test_seals_once_at_constant_content(tmp_path):
    db = str(tmp_path / "journal.db")
    assert len(seal_rollout(_rollout(tmp_path), db, now=1000.0)) == 1
    # same content, cache present, cache wiped: the JOURNAL is the register
    assert seal_rollout(_rollout(tmp_path), db, now=2000.0) == []
    state_file(db).unlink()
    assert seal_rollout(_rollout(tmp_path), db, now=3000.0) == []


def test_progressive_seal_of_a_live_session(tmp_path):
    db = str(tmp_path / "journal.db")
    rollout = _rollout(tmp_path, calls=1)
    assert len(seal_rollout(rollout, db, now=1000.0)) == 1
    log = rollout / "model-io-sess_t.jsonl"
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(_record(2)) + "\n")
    sealed = seal_rollout(rollout, db, now=2000.0)
    assert len(sealed) == 1  # changed content always seals
    events = [e for e in EventStore(db).all() if e["type"] == "model_trajectory"]
    assert len(events) == 2
    assert events[0]["payload"]["truncated_tail"] is False  # 1 full line, \n-terminated
    assert events[1]["payload"]["record_count"] == 2


def test_throttle_skips_the_scan_within_the_interval(tmp_path):
    db = str(tmp_path / "journal.db")
    rollout = _rollout(tmp_path)
    assert len(seal_rollout(rollout, db, now=1000.0, interval_min=10)) == 1
    assert seal_rollout(rollout, db, now=1000.0 + 599, interval_min=10) == []
    assert seal_rollout(rollout, db, now=1000.0 + 601, interval_min=10) == []


def test_symlink_escaping_the_rollout_dir_is_never_sealed(tmp_path):
    db = str(tmp_path / "journal.db")
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps(_record(1)) + "\n", encoding="utf-8")
    rollout = _rollout(tmp_path)
    (rollout / "model-io-evil.jsonl").symlink_to(outside)
    sealed = seal_rollout(rollout, db, now=1000.0)
    assert len(sealed) == 1  # only the real file
    assert "evil" not in "".join(sealed)
    digests = {e["payload"]["file_sha256"]
               for e in EventStore(db).all() if e["type"] == "model_trajectory"}
    assert len(digests) == 1


def test_sealed_journal_stays_valid_and_content_free(tmp_path):
    db = str(tmp_path / "journal.db")
    rollout = _rollout(tmp_path, calls=2)
    seal_rollout(rollout, db, now=1000.0)
    events = EventStore(db).all()
    check = verify_chain(KeyPair.load_or_create(db + ".key").public_hex(), events)
    assert check["valid"] is True
    assert SECRET not in json.dumps(events)  # digests only, by construction


def test_cli_scan_mode(tmp_path):
    from noirebox.cli import main as cli_main

    db = tmp_path / "journal.db"
    assert cli_main(["seal-trajectory", "--rollout", str(_rollout(tmp_path)),
                     "--db", str(db)]) == 0
    assert cli_main(["seal-trajectory", "--rollout", str(_rollout(tmp_path)),
                     "--db", str(db)]) == 0  # throttled within the interval
    traj = [e for e in EventStore(str(db)).all() if e["type"] == "model_trajectory"]
    assert len(traj) == 1
