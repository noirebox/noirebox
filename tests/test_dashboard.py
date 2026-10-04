"""The supervision dashboard is read-only and always available (no auth):
it renders the same recomputation the verifier performs."""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from noirebox.main import create_app


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(str(tmp_path / "dash.db")))


def test_dashboard_serves_html(tmp_path):
    r = _client(tmp_path).get("/dashboard")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "FLIGHT DECK" in r.text


def test_dashboard_hidden_from_openapi(tmp_path):
    """The dashboard is a convenience view, not part of the API contract."""
    r = _client(tmp_path).get("/openapi.json")
    assert "/dashboard" not in r.text


def test_dashboard_reflects_sealed_events(tmp_path):
    """After one event, verify reports 1 event and the events endpoint backs
    the client-side rendering of the dashboard."""
    client = _client(tmp_path)
    client.post("/api/v1/events", json={"type": "llm_call", "payload": {"model": "demo"}})
    assert client.get("/api/v1/verify").json()["nb_events"] == 1
    r = client.get("/api/v1/events")
    assert r.json()[0]["type"] == "llm_call"


def test_departures_board_has_one_row_per_intent(tmp_path):
    """Regression (review item 1): an unpaired policy_decision was pushed
    twice into the departures board — once PENDING, once UNCONFIRMED — so
    N unanswered intents rendered 2N contradictory rows. The UNCONFIRMED
    chip must exist only in the arrivals push (the departures board already
    shows the decision as PENDING)."""
    html = _client(tmp_path).get("/dashboard").text
    assert html.count("UNCONFIRMED") == 1


def test_esc_escapes_quotes_for_attribute_context(tmp_path):
    """Regression (review item 7): esc() left quotes alive while e.type — a
    free 64-char string from any sealer — is interpolated into a
    class="…" attribute, letting a sealed event break out of it. esc() must
    neutralize quotes as well as angle brackets and ampersands."""
    html = _client(tmp_path).get("/dashboard").text
    esc_line = next(line for line in html.splitlines() if "const esc" in line)
    for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert entity in esc_line


def test_dashboard_heatmap_wired_with_its_modes(tmp_path):
    """The activity heatmap ships with its three modes and the aggregate
    endpoint wired in — the browser never receives payloads for it."""
    html = _client(tmp_path).get("/dashboard").text
    assert "/api/v1/activity" in html
    assert "renderHeatmap" in html
    for mode in ("daily", "weekly", "cumulative"):
        assert f"setHmMode('{mode}')" in html


def test_dashboard_traffic_view_wired_to_the_seq_tail(tmp_path):
    """TRAFFIC is a fourth view: the radar canvas, its button among the
    views, and a poller that rides the since_seq cursor (never the whole
    journal)."""
    html = _client(tmp_path).get("/dashboard").text
    assert 'data-v="traffic"' in html
    assert '<canvas id="radar">' in html
    assert "since_seq=" in html
    assert "trafficStart" in html and "trafficStop" in html


def test_dashboard_degrades_gracefully_behind_auth(tmp_path, monkeypatch):
    """ADR 004 + review P1-8: on an auth-enabled instance the dashboard page
    itself stays served, /api/v1/verify stays open, and the JS handles the
    401 on /api/v1/events with a locked state and a token prompt — never a
    thrown 401 JSON crashing the render loop."""
    monkeypatch.setenv("NOIREBOX_CLIENTS", "acme:s3cret")
    api = _client(tmp_path)
    html = api.get("/dashboard").text
    assert api.get("/dashboard").status_code == 200
    assert "nbAuthPrompt" in html and "nb_token" in html  # token UI
    assert "NbAuthRequired" in html and "Bearer" in html  # 401 handling
    assert api.get("/api/v1/verify").status_code == 200   # verification stays open
    assert api.get("/api/v1/events").status_code == 401   # events are protected
