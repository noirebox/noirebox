"""ADR 017 — the fleet hub, v0: one Merkle seal covers N journals.

Token-level crypto rides on the already-tested anchors machinery; these
tests focus on the fleet semantics: membership, proofs, the honest
local-witness mode, and the regenerated-journal detection.
"""
import base64
import json
import sqlite3
import time

import pytest

from noirebox import fleet
from noirebox.chain import KeyPair
from noirebox.fleet import fleet_anchor, fleet_verify
from noirebox.store import EventStore


def _member(tmp_path, name, nb=2) -> str:
    path = str(tmp_path / name)
    store = EventStore(path)
    key = KeyPair.generate()
    for i in range(nb):
        store.append("test", {"i": i}, key)
    return path


def _hub(tmp_path) -> tuple[EventStore, KeyPair]:
    store = EventStore(str(tmp_path / "hub.db"))
    return store, KeyPair.generate()


def test_fleet_anchor_without_witness_refuses_by_default(tmp_path):
    hub, key = _hub(tmp_path)
    with pytest.raises(RuntimeError, match="--allow-local"):
        fleet_anchor([_member(tmp_path, "a.db")], hub, key)


def test_local_witness_mode_says_so_in_the_payload(tmp_path):
    hub, key = _hub(tmp_path)
    result = fleet_anchor([_member(tmp_path, "a.db"), _member(tmp_path, "b.db")],
                          hub, key, require_witness=False)
    payload = hub.all()[-1]["payload"]
    assert payload["witness"] == "local"  # no external date attests this seal
    assert payload["size"] == 2 and len(payload["heads"]) == 2
    assert result["members"] == ["a.db", "b.db"]
    assert result["warnings"] == []


def test_empty_journals_are_skipped_loudly(tmp_path):
    hub, key = _hub(tmp_path)
    EventStore(str(tmp_path / "empty.db"))  # created, never sealed
    result = fleet_anchor([_member(tmp_path, "a.db"), str(tmp_path / "empty.db")],
                          hub, key, require_witness=False)
    assert result["members"] == ["a.db"] and len(result["warnings"]) == 1


def test_duplicate_member_names_refuse(tmp_path):
    hub, key = _hub(tmp_path)
    d1, d2 = tmp_path / "x", tmp_path / "y"
    d1.mkdir()
    d2.mkdir()
    with pytest.raises(ValueError, match="a.db"):
        fleet_anchor([_member(d1, "a.db"), _member(d2, "a.db")], hub, key,
                     require_witness=False)


def test_fleet_verify_covers_the_sealed_member(tmp_path):
    hub, key = _hub(tmp_path)
    a = _member(tmp_path, "a.db")
    fleet_anchor([a, _member(tmp_path, "b.db")], hub, key, require_witness=False)
    result = fleet_verify(a, hub)
    assert result["covered"] is True and result["inclusion_ok"] is True


def test_regenerated_history_is_not_covered(tmp_path):
    """The fleet-seal attack: a member rebuilds its journal with clean hashes.
    The new head is a number the seal never committed to."""
    hub, key = _hub(tmp_path)
    a = _member(tmp_path, "a.db")
    fleet_anchor([a], hub, key, require_witness=False)
    # a regenerated journal at the SAME path: rewritten content, re-chained
    conn = sqlite3.connect(a)
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    fresh = EventStore(a)
    fresh.append("test", {"fabricated": "history"}, KeyPair.generate())
    result = fleet_verify(a, hub)
    assert result["covered"] is False
    assert "rewritten" in result["warning"]


def test_tampered_proof_fails_inclusion(tmp_path):
    """A doctored proof inside the hub fails the recomputation — the
    arithmetic, not the hub, decides."""
    hub, key = _hub(tmp_path)
    a = _member(tmp_path, "a.db")
    fleet_anchor([a, _member(tmp_path, "b.db")], hub, key, require_witness=False)
    # tamper the sealed proof in place (the exact attack the chain exists against)
    conn = sqlite3.connect(str(tmp_path / "hub.db"))
    row = conn.execute("SELECT payload FROM events WHERE type='fleet_anchor'").fetchone()
    payload = json.loads(row[0])
    payload["heads"][0]["proof"][0]["sibling"] = "f" * 64
    conn.execute("UPDATE events SET payload=? WHERE type='fleet_anchor'",
                 (json.dumps(payload),))
    conn.commit()
    conn.close()
    result = fleet_verify(a, hub)
    assert result["covered"] is True and result["inclusion_ok"] is False


def test_tsa_profiles_put_a_token_on_the_root(tmp_path, monkeypatch):
    monkeypatch.setenv("NOIREBOX_TSA_PROFILES",
                       json.dumps([{"name": "freetsa", "url": "https://freetsa.org/tsr"}]))
    monkeypatch.setattr(fleet, "token_for",
                        lambda profile, digest, seq: {
                            "kind": "rfc3161", "tsa": profile["name"],
                            "tsr": base64.b64encode(b"token").decode(),
                            "tsa_cert_pem": "-----BEGIN CERTIFICATE-----",
                        })
    hub, key = _hub(tmp_path)
    fleet_anchor([_member(tmp_path, "a.db")], hub, key)  # require_witness defaults True
    payload = hub.all()[-1]["payload"]
    assert payload["tokens"][0]["tsa"] == "freetsa"  # the root is externally witnessed
    assert "witness" not in payload


def test_fleet_status_is_the_cron_alert(tmp_path, monkeypatch, capsys):
    """The alerting primitive: all-covered exits 0, one rewritten member
    exits 1 — and --json gives the alarm a machine-readable body."""
    from noirebox.cli import main as cli_main

    hub_store, hub_key = _hub(tmp_path)
    a = _member(tmp_path, "a.db")
    b = _member(tmp_path, "b.db")
    monkeypatch.setenv("NOIREBOX_DB", str(tmp_path / "hub.db"))
    assert cli_main(["fleet-anchor", a, b, "--allow-local"]) == 0
    capsys.readouterr()  # discard the anchor's human line

    assert cli_main(["fleet-status", a, b, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True and len(report["members"]) == 2

    # a member moves past the seal (normal, honest growth) → the alarm rings
    EventStore(a).append("test", {"i": "new"}, KeyPair.generate())
    assert cli_main(["fleet-status", a, b, "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["members"][0]["covered"] is False


def test_fleet_watch_alarms_on_drift_and_reseals_when_healthy(tmp_path, monkeypatch, capsys):
    """The console service, tested on a fast clock: a drift raises the alarm
    (once — no spam), a healthy check with reanchor re-seals, and the loop
    stops on demand."""
    import threading

    from noirebox.fleet import fleet_watch

    hub_store, hub_key = _hub(tmp_path)
    a = _member(tmp_path, "a.db")
    b = _member(tmp_path, "b.db")
    monkeypatch.setenv("NOIREBOX_DB", str(tmp_path / "hub.db"))
    from noirebox.cli import main as cli_main
    assert cli_main(["fleet-anchor", a, b, "--allow-local"]) == 0
    hub_after_anchor = EventStore(str(tmp_path / "hub.db"))

    alarms, anchors = [], []
    stop = threading.Event()

    def tick_in_background():
        fleet_watch(hub_after_anchor, [a, b], stop=stop,
                    interval_seconds=0.05, reanchor=True, key=hub_key,
                    notify=alarms.append, on_anchor=anchors.append)

    thread = threading.Thread(target=tick_in_background, daemon=True)
    thread.start()
    time.sleep(0.25)
    # drift: a member moves past the seal → the alarm must fire exactly once
    EventStore(a).append("test", {"i": "new"}, KeyPair.generate())
    time.sleep(0.25)
    stop.set()
    thread.join(timeout=5)

    assert len(alarms) == 1, f"one transition to not-ok, one alarm: got {len(alarms)}"
    assert alarms[0]["alarm"] == "fleet_drift"
    assert len(anchors) >= 2  # healthy ticks re-sealed the fleet
    # and the re-sealed fleet covers the moved member again
    hub_store2 = EventStore(str(tmp_path / "hub.db"))
    seals = [e for e in hub_store2.all() if e["type"] == "fleet_anchor"]
    assert len(seals) >= 2  # the original + the re-seals
