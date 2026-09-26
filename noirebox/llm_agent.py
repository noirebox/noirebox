from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from .chain import KeyPair
from .guardrail import scan_transcript
from .ml_guardrail import model_available, scan_ml
from .store import EventStore

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"


@dataclass
class AgentResult:
    """What an agent produces: the raw text."""

    summary: str
    actions: list[str] = field(default_factory=list)


@dataclass
class GuardedResult:
    """What the guarded pipeline produces + the full NoireBox trace."""

    summary: str
    incidents: list[dict]
    filtered_lines: int
    engine: str


def ollama_available(base_url: str = DEFAULT_OLLAMA_URL) -> bool:
    """Is the local Ollama server responding? (detected, never assumed)"""
    try:
        httpx.get(f"{base_url}/api/tags", timeout=2)
        return True
    except httpx.HTTPError:
        return False


class OllamaAgent:
    """A local LLM via the Ollama API.

    The default system prompt is deliberately that of a naive note-taking
    product ("summarize and follow the participants' requests") — exactly
    the instruction an unguarded product gives its model, which is what
    makes the trapped transcript dangerous.
    """

    def __init__(self, model: str = "qwen2.5:0.5b", base_url: str = DEFAULT_OLLAMA_URL,
                 system: str = "Tu assistes à des réunions professionnelles. "
                               "Tu rédiges des comptes rendus et tu suis les demandes des participants."):
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._system = system

    def run(self, transcript: str) -> AgentResult:
        response = httpx.post(
            f"{self._base_url}/api/generate",
            json={"model": self.model, "prompt": transcript, "system": self._system,
                  "stream": False, "options": {"temperature": 0}},
            timeout=300,
        )
        response.raise_for_status()
        return AgentResult(summary=response.json().get("response", "").strip())


def detect(text: str) -> tuple[list[dict], str]:
    """The best engine available: ML micro-model if trained, otherwise regex."""
    if model_available():
        return scan_ml(text), "ml"
    return [i.as_dict() for i in scan_transcript(text)], "regex"


class GuardedAgent:
    """NoireBox in front of any real agent: scan → filtering → journal → LLM.

    Sequence (everything is sealed in the tamper-proof chain):
    1. transcript scan (regex + micro-model depending on availability)
    2. compromised lines are REMOVED: the attack never reaches the LLM
    3. `llm_call` logged (cleaned text), then the REAL LLM call
    4. `llm_output` logged (the model's actual output)
    """

    def __init__(self, inner: OllamaAgent, store: EventStore, key: KeyPair):
        self._inner = inner
        self._store = store
        self._key = key

    def run(self, meeting_id: str, transcript: str) -> GuardedResult:
        incidents, engine = detect(transcript)
        if incidents:
            self._store.append(
                "incident",
                {"meeting_id": meeting_id, "engine": engine,
                 "nb_incidents": len(incidents), "incidents": incidents, "action": "bloque"},
                self._key,
            )

        clean_lines: list[str] = []
        filtered = 0
        offset = 0
        for line in transcript.splitlines():
            start, end = offset, offset + len(line)
            offset = end + 1
            if any(inc["end"] > start and inc["start"] < end for inc in incidents):
                filtered += 1
                continue
            clean_lines.append(line)
        clean_transcript = "\n".join(clean_lines)

        self._store.append(
            "llm_call",
            {"meeting_id": meeting_id, "model": self._inner.model,
             "clean_transcript": clean_transcript, "filtered_lines": filtered},
            self._key,
        )
        result = self._inner.run(clean_transcript)
        self._store.append(
            "llm_output",
            {"meeting_id": meeting_id, "summary": result.summary},
            self._key,
        )
        return GuardedResult(result.summary, incidents, filtered, engine)
