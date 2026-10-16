"""SIEM export: CEF escaping by the book (a pipe in a vendor name must not
split one event into two lies) and OTLP/JSON a collector ingests — with the
chain coordinates on every record so alerts trace back to sealed events."""
import json

from noirebox.chain import KeyPair
from noirebox.siem import to_cef, to_otlp
from noirebox.store import EventStore


def _journal(tmp_path):
    store = EventStore(str(tmp_path / "s.db"))
    key = KeyPair.generate()
    store.append("llm_call", {"model": "gpt|evil=ctor", "note": "line1\nline2"}, key)
    store.append("incident", {"nb_incidents": 2, "engine": "ml"}, key)
    return store.all()


def test_cef_escapes_the_adversarial_payload(tmp_path):
    events = _journal(tmp_path)
    lines = to_cef(events).splitlines()
    assert len(lines) == 2  # a pipe in the payload must NOT split the event
    assert r"gpt\|evil\=ctor" in lines[0]
    assert r"line1\nline2" in lines[0]
    assert lines[0].startswith("CEF:0|NoireBox|journal|")
    assert "|9|" in lines[1]  # incidents ride a high CEF severity


def test_otlp_shape_and_chain_coordinates(tmp_path):
    events = _journal(tmp_path)
    doc = to_otlp(events)
    record = doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    keys = {a["key"]: a["value"] for a in record["attributes"]}
    assert keys["noirebox.seq"]["intValue"] == "1"
    assert keys["noirebox.event_hash"]["stringValue"] == events[0]["event_hash"]
    assert keys["payload.model"]["stringValue"] == "gpt|evil=ctor"  # OTLP needs no CEF escaping
    assert record["severityText"] == "INFO"
    json.dumps(doc)  # must be collector-ingestible JSON
