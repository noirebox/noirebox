"""Prometheus exposition (text 0.0.4, zero dependency) — derived from the
journal, honest about what the integrity gauge actually checks."""
import sqlite3

from fastapi.testclient import TestClient

from noirebox.chain import KeyPair
from noirebox.main import create_app
from noirebox.metrics import render_metrics
from noirebox.store import EventStore


def test_exposition_format_and_counts(tmp_path):
    db = str(tmp_path / "m.db")
    store = EventStore(db)
    key = KeyPair.generate()
    store.append("llm_call", {"i": 1}, key)
    store.append("llm_call", {"i": 2}, key)
    store.append("incident", {"i": 3}, key)

    text = render_metrics(store, key.public_hex())
    assert "noirebox_events_total 3" in text
    assert 'noirebox_events_by_type{type="llm_call"} 2' in text
    assert 'noirebox_events_by_type{type="incident"} 1' in text
    assert "noirebox_anchors_total 0" in text
    assert "noirebox_incidents_total 1" in text
    assert "noirebox_head_intact 1" in text
    assert 'noirebox_build_info{version="' in text
    # exposition hygiene: TYPE lines precede their samples (sample = a line
    # that starts with the metric name, not a HELP comment mentioning it)
    import re

    for metric in ("noirebox_events_total", "noirebox_head_intact"):
        type_pos = text.index(f"# TYPE {metric}")
        sample_pos = re.search(rf"^{re.escape(metric)} ", text, re.M).start()
        assert type_pos < sample_pos


def test_head_intact_flips_when_the_tail_is_tampered(tmp_path):
    """The light custody check does its one job: rewrite the last event and
    the gauge drops — without pretending to have verified the whole chain."""
    db = str(tmp_path / "t.db")
    store = EventStore(db)
    key = KeyPair.generate()
    store.append("test", {"i": 0}, key)
    assert "noirebox_head_intact 1" in render_metrics(store, key.public_hex())

    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET payload='{\"i\": 999}' WHERE seq = 1")
    conn.commit()
    conn.close()
    assert "noirebox_head_intact 0" in render_metrics(store, key.public_hex())


def test_metrics_route_served_and_metadata_class(tmp_path, monkeypatch):
    monkeypatch.setenv("NOIREBOX_CLIENTS", "acme:s3cret")
    monkeypatch.setenv("NOIREBOX_METADATA_AUTH", "1")
    app = create_app(str(tmp_path / "r.db"))
    api = TestClient(app)
    r = api.get("/metrics")
    assert r.status_code == 401  # metadata class: lockable, locked here
    token = api.post("/api/v1/token",
                     json={"client_id": "acme", "client_secret": "s3cret"}).json()["access_token"]
    r = api.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
