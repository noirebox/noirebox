"""The fleet hub, v0 (ADR 017): one seal covers N journals.

The Certificate-Transparency shape merkle.py already implements, wired into
the product: collect the 32-byte chain heads of N journals, build the
canonical Merkle tree, get ONE witness token over the root, and seal the
whole thing as a `fleet_anchor` event in the hub's own journal — the hub is
itself a NoireBox, so even it cannot rewrite which heads took part.

Each member keeps its inclusion proof (~log2(N) hashes): `fleet-verify`
recomputes the branch locally and confronts it with the sealed root — no
hub contacted, no TSA called back, the arithmetic decides. A journal that
regenerated its history produces a head the seal does not cover.

Witness semantics are the honest ones: the root token is what carries the
external date (RFC 3161 profiles from `NOIREBOX_TSA_PROFILES` /
`NOIREBOX_TSA_URL`, as in ADR 006/008). Without a configured witness, the
seal is local-only (`witness: "local"`) — the proofs still verify, but
nobody outside attests WHEN the root existed; the payload says so.
"""
from __future__ import annotations

from pathlib import Path

from .anchors import load_profiles, token_for
from .chain import KeyPair
from .merkle import ProofStep, build_tree, verify_inclusion
from .store import EventStore


def _head_of(path: str) -> tuple[str | None, str]:
    """(head_hash, warning) for one journal — empty journals contribute
    nothing (a GENESIS head is a public constant and proves nothing)."""
    store = EventStore(path)
    events = store.all()
    if not events:
        return None, f"{path}: empty journal — skipped (nothing to include)"
    return events[-1]["event_hash"], ""


def fleet_anchor(journals: list[str], hub_store: EventStore, key: KeyPair,
                 require_witness: bool = True) -> dict:
    """Seals one Merkle root over the journals' heads into the hub journal.

    Returns the payload actually sealed plus per-head proofs. The TSA
    token rides in the same flat/`tokens` payload shape the single-journal
    anchors use (ADR 006/008), digest = the fleet root.
    """
    if not journals:
        raise ValueError("no journals given — nothing to seal")

    heads: dict[str, str] = {}
    warnings: list[str] = []
    for path in journals:
        head, warning = _head_of(path)
        if warning:
            warnings.append(warning)
            continue
        name = Path(path).name
        if name in heads:
            raise ValueError(f"two journals are named {name!r} — rename or pass full unique paths")
        heads[name] = head

    if not heads:
        raise ValueError("every journal was empty — a fleet of nothing seals nothing")

    tree = build_tree(list(heads.values()))

    profiles = load_profiles()
    if profiles:
        tokens = [token_for(profile, tree.root, 0) for profile in profiles]
        witness = {"tokens": tokens}
    elif require_witness:
        raise RuntimeError(
            "no TSA configured — set NOIREBOX_TSA_PROFILES or NOIREBOX_TSA_URL "
            "(a fleet seal without an external witness attests nothing to a third party); "
            "pass --allow-local to seal local-only and say so in the payload")
    else:
        witness = {"witness": "local"}

    payload = {
        "root": tree.root,
        "size": tree.size,
        "heads": [
            {"name": name, "head_hash": head,
             "proof": [{"sibling": s.sibling, "side": s.side} for s in tree.proof(head)]}
            for name, head in sorted(heads.items())
        ],
        **witness,
    }
    event = hub_store.append("fleet_anchor", payload, key)
    return {"event_seq": event.seq, "root": tree.root, "members": sorted(heads),
            "warnings": warnings}


def fleet_verify(journal_path: str, hub_store: EventStore) -> dict:
    """Is THIS journal covered by the hub's latest fleet seal?

    Returns {covered, inclusion_ok, head, root, warning?}: covered=False
    means the journal's current head is not the one the seal committed to —
    either the journal moved on past the seal (normal: seals cover the past)
    or its history was rewritten (the attack). The caller decides which,
    with the previous seals if it kept them.
    """
    head, _ = _head_of(journal_path)
    if head is None:
        return {"covered": False, "inclusion_ok": False, "head": None, "root": None,
                "warning": "journal is empty"}

    anchors = [e for e in hub_store.all() if e["type"] == "fleet_anchor"]
    if not anchors:
        return {"covered": False, "inclusion_ok": False, "head": head, "root": None,
                "warning": "hub holds no fleet_anchor event"}

    seal = anchors[-1]["payload"]
    root = seal.get("root")
    for member in seal.get("heads", []):
        if member.get("head_hash") == head:
            proof = [ProofStep(sibling=s["sibling"], side=s["side"])
                     for s in member["proof"]]
            return {"covered": True, "inclusion_ok": verify_inclusion(head, proof, root),
                    "head": head, "root": root}

    return {"covered": False, "inclusion_ok": False, "head": head, "root": root,
            "warning": "current head is not covered by the latest fleet seal "
                       "(journal moved past it, or history was rewritten)"}


def fleet_status(hub_store: EventStore, member_paths: list[str]) -> dict:
    """The alerting primitive (ADR 017): every member checked against the
    hub's latest fleet seal. `ok` is False the moment one member is not
    covered or fails inclusion — cron-friendly: exit 0 keeps watch, exit 1
    raises the alarm."""
    members = []
    for path in member_paths:
        result = fleet_verify(path, hub_store)
        members.append({"journal": Path(path).name, "path": str(path), **result})
    return {"ok": all(m["covered"] and m["inclusion_ok"] for m in members),
            "members": members}
