from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.responses import HTMLResponse

from .attestation import build_attestation, verify_attestation
from .auth import build_auth_dependency, issue_token
from .chain import KeyPair, verify_chain
from .dashboard import DASHBOARD_HTML
from .guardrail import scan_transcript
from .schemas import EventIn, ScanIn, TokenIn
from .store import EventStore

DESCRIPTION = """
Flight data recorder for AI agents: **tamper-proof journal** (SHA-256 chain + Ed25519),
**guardrail** on transcripts, **exportable attestation** verifiable by a third party.

Auth (optional, enabled with `NOIREBOX_CLIENTS=id:secret,...`):
`POST /api/v1/token` → 1 h JWT → `Authorization: Bearer ...`. Rate limit 60 req/min/client.
"""


def create_app(db_path: str | None = None) -> FastAPI:
    """Builds the application with its database and key (manual injection).

    No DI container here: the dependencies (store, key) live in closure
    variables — every route "sees" them without a global registry.
    app.state exposes the whole set to external tools (tests, interactive docs).
    """
    app = FastAPI(
        title="NoireBox",
        version="0.4.0",
        description=DESCRIPTION,
    )
    path = db_path or os.environ.get("NOIREBOX_DB", "data/noirebox.db")
    store = EventStore(path)
    key = KeyPair.load_or_create(path + ".key")
    app.state.store = store
    app.state.key = key





    auth_enabled = bool(os.environ.get("NOIREBOX_CLIENTS"))
    require_auth = build_auth_dependency(enabled=auth_enabled)
    app.state.require_auth = require_auth

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": "noirebox", "version": "0.1.0"}

    @app.post("/api/v1/token")
    def token(body: TokenIn) -> dict:
        """Exchanges client_id/client_secret for a JWT (1 h). 401 if invalid."""
        jwt_token = issue_token(body.client_id, body.client_secret)
        if jwt_token is None:
            raise HTTPException(status_code=401, detail="invalid credentials")
        return {"access_token": jwt_token, "token_type": "bearer", "expires_in": 3600}

    @app.post("/api/v1/events", status_code=201)
    def append_event(body: EventIn, client_id: str = Depends(require_auth)) -> dict:
        """Records an event (prompt, LLM output, evaluation, ...). Returns 201."""
        event = store.append(body.type, body.payload, key)
        return event.as_dict()

    @app.get("/api/v1/events")
    def list_events(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        client_id: str = Depends(require_auth),
    ) -> list[dict]:
        """Paginated list. `Query(ge=…, le=…)` ≈ Assert\\Range on a parameter."""
        events = store.all()
        return events[offset : offset + limit]

    @app.get("/api/v1/verify")
    def verify() -> dict:
        """On-the-spot chain verification (internal diagnostic)."""
        return verify_chain(key.public_hex(), store.all())

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> HTMLResponse:
        """Read-only supervision view — renders, never mutates the journal.

        The badge shows the same local recomputation the verifier performs;
        the trust anchor remains the exported dossier (see dashboard.py).
        """
        return HTMLResponse(DASHBOARD_HTML)

    @app.post("/api/v1/transcripts/scan", status_code=201)
    def scan(body: ScanIn, client_id: str = Depends(require_auth)) -> dict:
        """Guardrail: detects injections, logs the incident, 201.

        Two engines to choose from: `regex` (built-in heuristics, default) or
        `ml` (trained micro-model — 293 KB, see ml/train.py). The scan AND
        its logging happen in the same request: an incident detected but not
        recorded would be an audit gap.
        """
        if body.engine == "ml":
            from .ml_guardrail import (
                model_available,
                scan_ml,
            )

            if not model_available(body.lang):
                raise HTTPException(status_code=503,
                                    detail=f"ML model {body.lang} missing — run `make train`")
            incidents = scan_ml(body.text, lang=body.lang)
            engine = "ml"
        else:
            incidents = [i.as_dict() for i in scan_transcript(body.text)]
            engine = "regex"
        event = store.append(
            "incident",
            {"meeting_id": body.meeting_id, "engine": engine,
             "nb_incidents": len(incidents), "incidents": incidents},
            key,
        )
        return {
            "incident_event_seq": event.seq,
            "meeting_id": body.meeting_id,
            "engine": engine,
            "nb_incidents": len(incidents),
            "incidents": incidents,
        }

    @app.get("/api/v1/attestation")
    def attestation() -> dict:
        """Signed attestation of the current state (digest only, no detail)."""
        return build_attestation(store, key)

    @app.get("/api/v1/attestation.pdf")
    def attestation_pdf_route() -> Response:
        """Attestation as PDF — the document a DPO files in a case record.

        The source of truth remains the JSON (machine-readable); the PDF is
        the human version, with the verification procedure printed on it.

        The PDF engine is an optional extra: without `noirebox[pdf]` the
        route answers 501 with the install hint — never a traceback.
        """
        try:
            from .pdf_export import attestation_pdf

            content = attestation_pdf(store, key)
        except RuntimeError as exc:
            return Response(
                content=f'{{"error": "{exc}"}}',
                status_code=501,
                media_type="application/json",
            )
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="noirebox-attestation.pdf"'},
        )

    @app.get("/api/v1/export")
    def export(client_id: str = Depends(require_auth)) -> dict:
        """Full auditable export: events + attestation.

        THIS is the file the third party feeds to verifier/verifier.py.
        """
        att = build_attestation(store, key)
        return {
            "format_version": 1,
            "service": "noirebox",
            "public_key": key.public_hex(),
            "events": store.all(),
            "attestation": att,
        }

    @app.post("/api/v1/anchors", status_code=201)
    def create_anchor(client_id: str = Depends(require_auth)) -> dict:
        """RFC 3161 anchor: seals the current chain head to one or more TSAs.

        Each TSA (separate process with its own key — or a configured external
        service) signs "this head_hash existed at date T". The anchor is
        logged as an "anchor" event: the journal seals its own external
        proof, and a chain regeneration by an insider holding the key becomes
        detectable (ADR 006). Multi-witness profiles (NOIREBOX_TSA_PROFILES,
        ADR 008) put several independent TSAs behind one anchor event — at
        least one qualified eIDAS TSA for legal weight, plus rotating public
        witnesses.
        """
        from .anchors import anchor_now, tsa_configured

        if not tsa_configured():
            raise HTTPException(
                status_code=503,
                detail="no TSA configured — set NOIREBOX_TSA_PROFILES (ADR 008) "
                       "or NOIREBOX_TSA_URL (e.g. http://127.0.0.1:3318 after `make tsa`)",
            )
        try:
            return anchor_now(store, key)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=f"TSA unreachable: {exc}") from exc

    @app.post("/api/v1/attestation/verify")
    def verify_attestation_endpoint(att: dict) -> dict:
        """Verifies a submitted attestation (the third party holding only the digest).

        `att: dict` without a DTO is deliberate — this is foreign data we
        inspect defensively, not an internal contract.
        """
        if not att:
            raise HTTPException(status_code=422, detail="empty attestation")
        return {"valid": verify_attestation(att)}

    return app


app = create_app()
