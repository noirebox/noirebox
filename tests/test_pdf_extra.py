"""The PDF attestation is an optional extra (`noirebox[pdf]`): without
reportlab the route answers a clean 501 with the install hint — never a
traceback. The dev environment ships with reportlab, so the 200 path is
covered by test_auth_pdf.py; this file covers the degraded path honestly.
"""
from __future__ import annotations

import sys

import pytest
from pathlib import Path

from fastapi.testclient import TestClient

from noirebox.main import create_app


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(str(tmp_path / "pdf.db")))


def test_pdf_route_without_reportlab_answers_501_with_hint(tmp_path, monkeypatch):
    """Simulates a core-only install: every reportlab module is hidden."""
    for name in [m for m in sys.modules if m.startswith("reportlab")]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "reportlab", None)
    monkeypatch.setitem(sys.modules, "reportlab.lib", None)
    monkeypatch.setitem(sys.modules, "reportlab.lib.pagesizes", None)
    monkeypatch.setitem(sys.modules, "reportlab.lib.units", None)
    monkeypatch.setitem(sys.modules, "reportlab.pdfgen", None)

    client = _client(tmp_path)
    r = client.get("/api/v1/attestation.pdf")
    assert r.status_code == 501
    assert "noirebox[pdf]" in r.json()["error"]
    assert "pip install" in r.json()["error"]


def test_pdf_route_with_reportlab_serves_the_document(tmp_path):
    """The full install (dev/`noirebox[pdf]`) serves the real attestation."""
    client = _client(tmp_path)
    client.post("/api/v1/events", json={"type": "llm_call", "payload": {"model": "demo"}})
    r = client.get("/api/v1/attestation.pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"


def test_attestation_pdf_speaks_french_on_demand(tmp_path):
    """ADR 005 consequence shipped: the DPO wording has its language. The FR
    render differs from the EN one; the identifiers stay language-independent."""
    api = _client(tmp_path)
    api.post("/api/v1/events", json={"type": "llm_call", "payload": {"prompt": "résume"}})
    en = api.get("/api/v1/attestation.pdf")
    fr = api.get("/api/v1/attestation.pdf?lang=fr")
    assert en.status_code == 200 and fr.status_code == 200
    assert en.content != fr.content
    assert fr.content[:5] == b"%PDF-"
    bad = api.get("/api/v1/attestation.pdf?lang=de")
    assert bad.status_code == 422  # the enum is enforced at the boundary


def test_attestation_pdf_french_directly(tmp_path):
    from noirebox.chain import KeyPair
    from noirebox.pdf_export import attestation_pdf
    from noirebox.store import EventStore

    db = str(tmp_path / "fr.db")
    store = EventStore(db)
    key = KeyPair.load_or_create(db + ".key")
    store.append("test", {"i": 0}, key)
    pdf = attestation_pdf(store, key, lang="fr")
    assert pdf[:5] == b"%PDF-"
    assert b"integrite" in pdf  # the FR document title (accent-free marker)
    with pytest.raises(ValueError, match="unsupported attestation language"):
        attestation_pdf(store, key, lang="de")
