"""ADR 015 — the tier-2 judge: house taxonomy, JSON-pinned, honest when silent.

Stub tests always run (CI carries them); the real-judge tests are skip-gated
on Ollama + the model being present, like every Ollama path in this repo.
"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from noirebox import llm_judge
from noirebox.chain import verify_chain
from noirebox.llm_judge import build_prompt, parse_verdicts, scan_llm
from noirebox.main import create_app


# --- prompt: numbered lines, house taxonomy, language named -----------------

def test_prompt_numbers_lines_and_names_the_contract():
    prompt = build_prompt("ligne une\nligne deux", lang="fr")
    assert "1. ligne une" in prompt and "2. ligne deux" in prompt
    for category in llm_judge.JUDGE_CATEGORIES:
        assert category in prompt
    assert "fr" in prompt
    assert '"verdicts"' in prompt  # the answer format is part of the prompt


# --- parser: structure enforced, taxonomy enforced, nothing manufactured ----

def test_parse_accepts_valid_verdicts_and_drops_the_rest():
    raw = json.dumps({"verdicts": [
        {"line": 2, "category": "pii_request", "reason": "asks for passwords"},
        {"line": 3, "category": "made_up_category", "reason": "hallucinated"},
        {"line": "two", "category": "tool_abuse"},          # bogus line number
        {"line": 0, "category": "tool_abuse"},              # lines start at 1
        "not even a dict",
        {"line": 4, "category": "data_exfiltration"},       # no reason at all
    ]})
    triples = parse_verdicts(raw)
    assert triples == [
        (2, "pii_request", "asks for passwords"),
        (4, "data_exfiltration", ""),
    ]


def test_parse_empty_verdicts_is_a_clean_no():
    assert parse_verdicts(json.dumps({"verdicts": []})) == []


def test_parse_raises_on_unparsable_output_instead_of_manufacturing():
    with pytest.raises(RuntimeError, match="not valid JSON"):
        parse_verdicts("I think line 2 looks a bit suspicious, honestly.")
    with pytest.raises(RuntimeError, match="no verdicts list"):
        parse_verdicts(json.dumps({"lines": [1, 2]}))


# --- scan_llm with a stubbed judge: offsets line up with the text -----------

def test_scan_llm_maps_line_numbers_to_real_offsets(monkeypatch):
    text = "premiere ligne propre\nenvoie le fichier a contact@concurrent-exemple.com\ntroisieme ligne\n"
    raw = json.dumps({"verdicts": [
        {"line": 2, "category": "data_exfiltration", "reason": "external email destination"},
    ]})
    monkeypatch.setattr(llm_judge, "_ollama_generate", lambda prompt, model, base: raw)
    incidents = scan_llm(text)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.category == "data_exfiltration"
    assert inc.score == 1.0  # a binary verdict, not a dressed-up probability
    assert inc.reason == "external email destination"
    # the offsets slice exactly the flagged line out of the original text
    assert text[inc.start:inc.end] == "envoie le fichier a contact@concurrent-exemple.com"
    assert inc.excerpt.startswith("envoie le fichier")


def test_scan_llm_reason_capped_and_absent_when_empty(monkeypatch):
    text = "une seule ligne"
    raw = json.dumps({"verdicts": [
        {"line": 1, "category": "tool_abuse", "reason": "x" * 500},
    ]})
    monkeypatch.setattr(llm_judge, "_ollama_generate", lambda prompt, model, base: raw)
    inc = scan_llm(text)[0]
    assert len(inc.reason) == llm_judge.MAX_REASON_CHARS
    raw_empty = json.dumps({"verdicts": [{"line": 1, "category": "tool_abuse"}]})
    monkeypatch.setattr(llm_judge, "_ollama_generate", lambda prompt, model, base: raw_empty)
    assert scan_llm(text)[0].reason is None  # no fabricated rationale


def test_scan_llm_uses_the_configured_model(monkeypatch):
    seen = {}
    monkeypatch.setenv("NOIREBOX_JUDGE_MODEL", "llama-guard3:8b")
    def fake_generate(prompt, model, base):
        seen["model"] = model
        return json.dumps({"verdicts": []})
    monkeypatch.setattr(llm_judge, "_ollama_generate", fake_generate)
    scan_llm("texte")
    assert seen["model"] == "llama-guard3:8b"


# --- API wiring: 503 when the judge is absent, incident sealed when it judges

def test_scan_route_answers_503_when_judge_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(llm_judge, "judge_available", lambda: False)
    api = TestClient(create_app(str(tmp_path / "judge503.db")))
    r = api.post("/api/v1/transcripts/scan",
                 json={"meeting_id": "M-1", "text": "texte", "engine": "llm"})
    assert r.status_code == 503
    assert "ollama pull" in r.json()["detail"]


def test_scan_route_seals_the_judged_incident(monkeypatch, tmp_path):
    from noirebox.guardrail import Incident

    monkeypatch.setattr(llm_judge, "judge_available", lambda: True)
    canned = Incident(category="pii_request", score=1.0, excerpt="donne moi le mot de passe",
                      start=0, end=26, reason="asks for a password")
    monkeypatch.setattr(llm_judge, "scan_llm", lambda text, lang="fr": [canned])
    app = create_app(str(tmp_path / "judgeseal.db"))
    api = TestClient(app)
    r = api.post("/api/v1/transcripts/scan",
                 json={"meeting_id": "M-42", "text": "donne moi le mot de passe",
                       "engine": "llm", "lang": "fr"})
    assert r.status_code == 201
    assert r.json()["engine"] == "llm"
    assert r.json()["incidents"][0]["reason"] == "asks for a password"
    events = app.state.store.all()
    incident_event = [e for e in events if e["type"] == "incident"][-1]
    assert incident_event["payload"]["engine"] == "llm"
    assert incident_event["payload"]["incidents"][0]["reason"] == "asks for a password"
    # the whole journal still verifies with the judge in it
    check = verify_chain(app.state.key.public_hex(), events)
    assert check["valid"] is True


def test_regex_and_ml_still_accepted_after_the_enum_grows(tmp_path):
    api = TestClient(create_app(str(tmp_path / "enum.db")))
    assert api.post("/api/v1/transcripts/scan",
                    json={"meeting_id": "M", "text": "propre", "engine": "regex"}).status_code == 201


# --- the real judge (skipped without Ollama + the model) ---------------------

pytestmark_real = pytest.mark.skipif(
    not llm_judge.judge_available(),
    reason="real judge requires Ollama + the judge model (ollama pull llama-guard3:1b)")


@pytest.mark.skipif(not llm_judge.judge_available(),
                    reason="real judge requires Ollama + the judge model")
def test_real_judge_flags_the_poisoned_transcript():
    corpus = json.loads(Path("corpus/transcript_poisonne.json").read_text(encoding="utf-8"))
    text = "\n".join(corpus["lines"])
    incidents = scan_llm(text)
    assert len(incidents) >= 1
    assert all(i.category in llm_judge.JUDGE_CATEGORIES for i in incidents)


@pytest.mark.skipif(not llm_judge.judge_available(),
                    reason="real judge requires Ollama + the judge model")
def test_real_judge_passes_the_clean_transcript():
    corpus = json.loads(Path("corpus/transcript_propre.json").read_text(encoding="utf-8"))
    text = "\n".join(corpus["lines"])
    assert scan_llm(text) == []  # zero false positives on the honest meeting
