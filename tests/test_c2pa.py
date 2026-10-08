"""The C2PA bridge (ADR 011/024 → Content Credentials 2.4): our seals speak
the provenance standard. A claim with no sealed events binds nothing; the
actions carry the chain coordinates so the audit replays; the verification
assertion names the offline path."""
import hashlib

import pytest

from noirebox.c2pa import c2pa_action, canonical_claim, claim
from noirebox.chain import KeyPair
from noirebox.store import EventStore


def _journal(tmp_path, nb=3):
    store = EventStore(str(tmp_path / "c2pa.db"))
    key = KeyPair.generate()
    for i in range(nb):
        store.append("llm_output", {"summary": f"s{i}"}, key)
    return store, key


def test_event_types_map_to_c2pa_actions_and_custom_namespace():
    assert c2pa_action("llm_call") == "c2pa.created"
    assert c2pa_action("content_transformation") == "c2pa.edited"
    assert c2pa_action("incident") == "noirebox.blocked"          # what C2PA has no word for
    assert c2pa_action("model_trajectory") == "noirebox.trajectory_sealed"


def test_claim_carries_actions_with_chain_coordinates(tmp_path):
    store, key = _journal(tmp_path)
    doc = claim(artifact_sha256=hashlib.sha256(b"art").hexdigest(),
                title="agent report", events=store.all(),
                public_key=key.public_hex(), witnesses=["freetsa"])
    assert doc["spec_version"] == "c2pa/2.4"
    actions = doc["assertions"][0]["data"]["actions"]
    assert [a["action"] for a in actions] == ["c2pa.published"] * 3
    assert actions[0]["noirebox"]["seq"] == 1  # the chain coordinates ride along
    verification = doc["assertions"][1]["data"]
    assert "verifier.py" in verification["instructions"]  # the offline path is named
    assert verification["witnesses"] == ["freetsa"]


def test_empty_claim_refused(tmp_path):
    with pytest.raises(ValueError, match="binds nothing"):
        claim(artifact_sha256="a" * 64, title="t", events=[], public_key="b" * 64)


def test_claim_canonical_bytes_are_deterministic(tmp_path):
    store, key = _journal(tmp_path)
    kwargs = dict(artifact_sha256=hashlib.sha256(b"art").hexdigest(),
                  title="t", events=store.all(), public_key=key.public_hex())
    assert canonical_claim(claim(**kwargs)) == canonical_claim(claim(**kwargs))
