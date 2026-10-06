from __future__ import annotations

import os
import threading

from fastapi.responses import JSONResponse
from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.responses import HTMLResponse

from . import __version__
from .attestation import build_attestation, verify_attestation
from .auth import build_auth_dependency, issue_token
from .chain import load_instance_key, verify_chain
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


def _tsa_available() -> bool:
    """A TSA profile exists (the auto-anchor needs somewhere to anchor to)."""
    return bool(os.environ.get("NOIREBOX_TSA_URL")
                or os.environ.get("NOIREBOX_TSA_PROFILES"))


def _anchor_loop(store, key, interval_seconds: int, stop: threading.Event) -> None:
    """Anchors the chain head every `interval_seconds` until stopped.

    Failures are logged, never raised: an unreachable TSA must not take the
    API down — the next tick retries, and the un-anchored window stays
    visible in every export (the last anchor event says when coverage
    stopped, ADR 022's honest window).
    """
    from .anchors import anchor_now

    while not stop.wait(interval_seconds):
        try:
            result = anchor_now(store, key)
            print(f"[noirebox] auto-anchor: seq {result['anchor_event_seq']} "
                  f"covers head {result['anchored_head_seq']} "
                  f"({', '.join(result['tsas'])})", flush=True)
        except Exception as exc:  # noqa: BLE001 — the timer must survive anything
            print(f"[noirebox] auto-anchor failed (will retry): {exc}", flush=True)


def create_app(db_path: str | None = None) -> FastAPI:
    """Builds the application with its store and key injected in closure
    variables; `app.state` exposes them to tests and external tools."""
    app = FastAPI(
        title="NoireBox",
        version=__version__,
        description=DESCRIPTION,
    )
    path = db_path or os.environ.get("NOIREBOX_DB", "data/noirebox.db")
    store = EventStore(path)
    key = load_instance_key(path)
    app.state.store = store
    app.state.key = key

    auth_enabled = bool(os.environ.get("NOIREBOX_CLIENTS"))
    require_auth = build_auth_dependency(enabled=auth_enabled)
    app.state.require_auth = require_auth
    # Metadata routes (activity, attestation, attestation.pdf) stay OPEN by
    # default: they expose aggregates and digests only — never payload
    # content — and the third-party / DPO hand-over flows fetch them without
    # credentials. A deployment that wants even the aggregates behind the
    # bearer token opts in with NOIREBOX_METADATA_AUTH=1 (protection is an
    # explicit choice, mirroring ADR 004's activation rule; it presupposes
    # auth being enabled). Verification routes (GET /verify, POST
    # /attestation/verify) stay open ALWAYS — ADR 004: one never locks
    # verification.
    metadata_locked = auth_enabled and os.environ.get(
        "NOIREBOX_METADATA_AUTH", "").strip().lower() in ("1", "true", "yes")
    require_metadata_auth = build_auth_dependency(enabled=metadata_locked)
    app.state.require_metadata_auth = require_metadata_auth

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": "noirebox", "version": __version__}

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
        since_seq: int = Query(0, ge=0),
        client_id: str = Depends(require_auth),
    ) -> list[dict]:
        """Paginated list (offset + limit, capped at 1000).

        `since_seq` switches to tail mode: everything strictly newer than
        that seq, oldest first — the cursor for live consumers (the
        dashboard's TRAFFIC view polls it). seq is the primary key, so the
        cursor can neither skip nor re-deliver an event.
        """
        if since_seq:
            return store.since(since_seq, limit)
        return store.page(offset, limit)

    @app.get("/api/v1/verify")
    def verify() -> dict:
        """On-the-spot chain verification (internal diagnostic)."""
        return verify_chain(key.public_hex(), store.all())

    @app.get("/api/v1/activity")
    def activity(client_id: str = Depends(require_metadata_auth)) -> list[dict]:
        """Per-day sealed-event counts (UTC) — the dashboard heatmap's source.

        Open by default: an aggregate (day → count) carries no payload, and
        the dashboard fetches are plain browser calls that never carry an
        Authorization header. `NOIREBOX_METADATA_AUTH=1` moves it behind the
        bearer token (never /verify — ADR 004).
        """
        return store.activity()

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
        elif body.engine == "tiered":
            from .tiering import scan_tiered

            incidents, tiering_meta = scan_tiered(body.text, lang=body.lang)
            engine = "tiered"
        elif body.engine == "llm":
            from .llm_judge import judge_available, judge_model, scan_llm

            if not judge_available():
                raise HTTPException(
                    status_code=503,
                    detail=f"LLM judge unavailable — install Ollama and run "
                           f"`ollama pull {judge_model()}` (or set NOIREBOX_JUDGE_MODEL)")
            try:
                incidents = [i.as_dict() for i in scan_llm(body.text, lang=body.lang)]
            except RuntimeError as exc:
                # An unparsable judge answer is reported, never manufactured
                # into incidents (ADR 015).
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            engine = "llm"
        else:
            incidents = [i.as_dict() for i in scan_transcript(body.text)]
            engine = "regex"
        event = store.append(
            "incident",
            {"meeting_id": body.meeting_id, "engine": engine,
             "nb_incidents": len(incidents), "incidents": incidents,
             **({"tiering": tiering_meta} if engine == "tiered" else {})},
            key,
        )
        response = {
            "incident_event_seq": event.seq,
            "meeting_id": body.meeting_id,
            "engine": engine,
            "nb_incidents": len(incidents),
            "incidents": incidents,
        }
        if engine == "tiered":
            response["tiering"] = tiering_meta
        return response

    @app.get("/api/v1/attestation")
    def attestation(client_id: str = Depends(require_metadata_auth)) -> dict:
        """Signed attestation of the current state (digest only, no detail).

        Open by default — this is what a third party checks without
        credentials; `NOIREBOX_METADATA_AUTH=1` moves it behind the token
        (the exported dossier still carries a copy, so the auditor's flow
        never depends on this route being open).
        """
        return build_attestation(store, key)

    @app.get("/api/v1/attestation.pdf")
    def attestation_pdf_route(
        client_id: str = Depends(require_metadata_auth),
        lang: str = Query("en", pattern="^(en|fr)$"),
    ) -> Response:
        """Attestation as PDF — the document a DPO files in a case record.

        The source of truth remains the JSON (machine-readable); the PDF is
        the human version, with the verification procedure printed on it.
        `?lang=fr` serves the French DPO wording; identifiers stay
        language-independent.

        The PDF engine is an optional extra: without `noirebox[pdf]` the
        route answers 501 with the install hint — never a traceback.
        """
        try:
            from .pdf_export import attestation_pdf

            content = attestation_pdf(store, key, lang=lang)
        except RuntimeError as exc:
            return JSONResponse(
                content={"error": str(exc)},
                status_code=501,
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

    @app.get("/metrics", include_in_schema=False)
    def metrics(client_id: str = Depends(require_metadata_auth)) -> Response:
        """Prometheus exposition (text 0.0.4, zero dependency).

        Metadata class like /activity: aggregates and digests only, behind
        NOIREBOX_METADATA_AUTH when the deployment opts in. The integrity
        gauge is a LIGHT custody check (last event recomputed + signature),
        deliberately not the full chain verification — that stays the
        verifier's offline job.
        """
        from .metrics import render_metrics

        return Response(
            content=render_metrics(store, key.public_hex()),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    # ── auto-anchor timer (ADR 022 §3, ops default) ──
    # "The interesting events live between the last anchor and the incident."
    # When a TSA is configured, the server anchors the chain head on a
    # WALL-CLOCK timer — a killed session's dead time counts in minutes, not
    # in turn boundaries. Off by default without a witness; 60 min when one
    # is configured; NOIREBOX_ANCHOR_INTERVAL_MIN overrides (0 = off).
    interval_min = float(os.environ.get(
        "NOIREBOX_ANCHOR_INTERVAL_MIN",
        "60" if _tsa_available() else "0"))
    if interval_min > 0:
        stop = threading.Event()
        t = threading.Thread(
            target=_anchor_loop,
            args=(store, key, int(interval_min * 60), stop),
            daemon=True, name="noirebox-auto-anchor")
        t.start()
        app.state.anchor_timer_stop = stop

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
