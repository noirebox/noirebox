"""The C2PA bridge (ADR 011/024 → Content Credentials 2.4): our seals speak
the provenance standard's language.

C2PA 2.4 maps Content Credentials to AI Act art. 50 transparency — but
*agentic* provenance is an acknowledged gap on their side, and it is exactly
what this journal seals. This module produces C2PA-shaped CLAIM documents
(the assertion layer of a Content Credential) from journal facts:

  - the artifact binding becomes a `c2pa.hashData`-bound assertion set;
  - our event vocabulary maps to C2PA actions (`c2pa.created`,
    `c2pa.edited`, and the custom `noirebox.sealed` namespace for what C2PA
    has no word for — agent decisions, consumption edges);
  - the signature, timestamps and witnesses travel as our own assertion —
    the journal IS the trust anchor; a full JUMBF/COSE packaging (needed for
    embedding INTO media files) belongs to the `c2pa` optional SDK and
    stays deployment-side.

Honest scope: this builds the claim JSON to C2PA 2.4 field names for
interoperability and audit consumption — it does not produce embedded,
media-container manifests. What it proves: an agent-produced artifact's
provenance can be expressed in the standard the art. 50 conversation is
converging on, without leaving the journal.
"""
from __future__ import annotations

from .chain import canonical

C2PA_SPEC = "c2pa/2.4"
NS = "noirebox"

# our event vocabulary → C2PA action verbs (c2pa.actions assertion)
_ACTION_MAP = {
    "llm_call": "c2pa.created",
    "llm_output": "c2pa.published",
    "incident": f"{NS}.blocked",
    "content_transformation": "c2pa.edited",
    "content_provenance": f"{NS}.origin_asserted",
    "ingestion_decision": f"{NS}.ingested",
    "model_trajectory": f"{NS}.trajectory_sealed",
    "consumption_edge": f"{NS}.consumed",
}


def c2pa_action(event_type: str) -> str:
    """Maps a NoireBox event type to its C2PA action verb."""
    return _ACTION_MAP.get(event_type, f"{NS}.{event_type}")


def actions_assertion(events: list[dict]) -> dict:
    """The `c2pa.actions` assertion built from journal events: one action per
    event, in sealed order, each carrying the event's seq + hash as the
    digital source the audit replays."""
    return {
        "claim_generator": f"noirebox/{_version()}",
        "actions": [
            {
                "action": c2pa_action(e["type"]),
                "when": e["ts"],
                "digitalSourceType": f"{NS}:event/{e['type']}",
                "noirebox": {"seq": e["seq"], "event_hash": e["event_hash"]},
            }
            for e in events
        ],
    }


def claim(*, artifact_sha256: str, title: str, events: list[dict],
          public_key: str, witnesses: list[str] | None = None) -> dict:
    """Builds a C2PA 2.4-shaped claim document from journal facts.

    Structure follows the C2PA claim field names (claim_generator_info,
    assertions, signature placeholder) — the signature slot carries the
    JOURNAL's attestation reference instead of a COSE signer: the trust
    anchor is the anchored journal, and the `noirebox.verification`
    assertion tells the auditor exactly how to recompute it offline.
    """
    if not events:
        raise ValueError("c2pa claim: a claim with no sealed events binds nothing")
    assertions = [
        {"label": "c2pa.actions", "data": actions_assertion(events)},
        {"label": f"{NS}.verification", "data": {
            "method": "noirebox-verifier",
            "public_key": public_key,
            "instructions": "python verifier/verifier.py export.json — offline, exit 0",
            "witnesses": witnesses or [],
            "spec": "noirebox journal, hash-chained + Ed25519, externally anchored (RFC 3161/OTS)",
        }},
    ]
    return {
        "spec_version": C2PA_SPEC,
        "claim_generator_info": [{
            "name": "NoireBox",
            "version": _version(),
            "operator": "https://github.com/noirebox/noirebox",
        }],
        "format": "application/noirebox+journal",
        "title": title,
        "assertions": assertions,
        "signature": f"noirebox:attestation:{artifact_sha256[:32]}",
        "_noirebox_artifact_sha256": artifact_sha256,
    }


def canonical_claim(claim_doc: dict) -> bytes:
    """The canonical bytes of a claim — same serializer as the journal
    (sorted keys, compact, UTF-8), so a claim's integrity is checkable with
    the journal's own arithmetic."""
    return canonical(claim_doc)


def _version() -> str:
    from . import __version__

    return __version__
