from pathlib import Path

import pytest

from noirebox.chain import KeyPair, verify_chain
from noirebox.llm_agent import GuardedAgent, OllamaAgent, ollama_available
from noirebox.store import EventStore

CORPUS = Path(__file__).resolve().parent.parent / "corpus"

pytestmark = pytest.mark.skipif(
    not ollama_available(), reason="Ollama not running (brew install ollama && ollama serve)"
)

MODEL_PRESENT = False
if ollama_available():
    import httpx

    try:
        tags = httpx.get("http://127.0.0.1:11434/api/tags", timeout=2).json()
        MODEL_PRESENT = any(m.get("name", "").startswith("qwen2.5:0.5b") for m in tags.get("models", []))
    except httpx.HTTPError:
        MODEL_PRESENT = False


def _transcript(name: str) -> str:
    import json

    data = json.loads((CORPUS / name).read_text(encoding="utf-8"))
    return "\n".join(data["lines"])


@pytest.mark.skipif(not MODEL_PRESENT, reason="qwen2.5:0.5b model not downloaded (ollama pull)")
def test_real_llm_returns_a_real_answer(tmp_path):
    agent = OllamaAgent()
    result = agent.run("Réunion : le devis a été validé par le client hier.")
    assert result.summary


@pytest.mark.skipif(not MODEL_PRESENT, reason="qwen2.5:0.5b model not downloaded (ollama pull)")
def test_guarded_pipeline_strips_attack_and_keeps_chain_valid(tmp_path):
    store = EventStore(str(tmp_path / "t.db"))
    key = KeyPair.load_or_create(str(tmp_path / "t.key"))
    guarded = GuardedAgent(OllamaAgent(), store, key)

    result = guarded.run("REU-TEST", _transcript("transcript_poisonne.json"))

    assert result.incidents
    assert result.filtered_lines >= 4
    assert result.summary
    types = [e["type"] for e in store.all()]
    assert {"incident", "llm_call", "llm_output"} <= set(types)
    assert verify_chain(key.public_hex(), store.all())["valid"] is True
