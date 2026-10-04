from __future__ import annotations

import httpx


class NoireBoxError(RuntimeError):
    """Business error raised by the API (status 4xx/5xx)."""


class NoireBoxClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8768",
                 timeout: float = 15.0, transport: httpx.BaseTransport | None = None):
        # 15 s par défaut : le PREMIER scan `engine: ml` charge le modèle à
        # froid (qqes secondes, variable selon la machine et la version de
        # Python — 3.14 trouvé par le test « stranger »). Les appels suivants
        # réutilisent le modèle en mémoire et répondent en ms.


        self._http = httpx.Client(
            base_url=base_url.rstrip("/"), timeout=timeout, transport=transport
        )

    def _request(self, method: str, path: str, json_body: dict | None = None) -> dict:
        response = self._http.request(method, path, json=json_body)
        if response.status_code >= 400:
            raise NoireBoxError(f"{method} {path} → {response.status_code}: {response.text}")
        return response.json()

    def health(self) -> dict:
        return self._request("GET", "/health")

    def log_event(self, type_: str, payload: dict | None = None) -> dict:
        return self._request("POST", "/api/v1/events",
                             {"type": type_, "payload": payload or {}})

    def scan(self, meeting_id: str, text: str, engine: str = "regex", lang: str = "fr") -> dict:
        """Guardrail on a text. `engine`: "regex", "ml" or "llm" (ADR 015 judge —
503 if the local judge is not pulled); `lang`: "fr"/"en"."""
        return self._request("POST", "/api/v1/transcripts/scan",
                             {"meeting_id": meeting_id, "text": text,
                              "engine": engine, "lang": lang})

    def verify(self) -> dict:
        return self._request("GET", "/api/v1/verify")

    def attestation(self) -> dict:
        return self._request("GET", "/api/v1/attestation")

    def export(self) -> dict:
        return self._request("GET", "/api/v1/export")
