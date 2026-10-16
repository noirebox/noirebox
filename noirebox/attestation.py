from __future__ import annotations

from collections import Counter

from .chain import GENESIS, KeyPair, canonical, ed25519_verify, verify_chain
from .store import now_iso


def build_attestation(store, key: KeyPair) -> dict:
    """Builds the attestation of the current state: canonical digest + signature.

    `store` is loosely typed (to avoid a circular import with store.py):
    we only depend on its `.all()`.
    """
    events = store.all()
    report = verify_chain(key.public_hex(), events)
    by_type = dict(Counter(e["type"] for e in events))
    core = {
        "generated_at": now_iso(),
        "algo": "sha256-chain+ed25519",
        "public_key": key.public_hex(),
        "head_seq": len(events),
        "head_hash": events[-1]["event_hash"] if events else GENESIS,
        "total_events": len(events),
        "chain_valid": report["valid"],
        "event_types": by_type,
    }

    return {**core, "signature": key.sign(canonical(core))}


def verify_attestation(attestation: dict) -> bool:
    """Verifies the signature of a submitted attestation.

    The `signature` key is removed from the dict before recomputing the
    digest: that is the "signed payload" scheme — everything is signed
    EXCEPT the signature itself.
    """
    core = {k: v for k, v in attestation.items() if k != "signature"}
    public_key = attestation.get("public_key", "")
    signature = attestation.get("signature", "")
    if not public_key or not signature:
        return False
    return ed25519_verify(public_key, signature, canonical(core))
