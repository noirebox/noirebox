from __future__ import annotations

import pytest

from noirebox.chain import KeyPair
from noirebox.merkle import ProofStep, build_tree, verify_inclusion
from noirebox.store import EventStore


def _heads(n: int, tmp_path) -> list[str]:
    """n real mini-ledgers → their chain heads."""
    heads = []
    for i in range(n):
        store = EventStore(str(tmp_path / f"box{i}.db"))
        key = KeyPair.load_or_create(str(tmp_path / f"box{i}.key"))
        store.append("llm_call", {"agent": f"agent-{i}", "prompt": "…"}, key)
        store.append("llm_output", {"resume": f"CR #{i}"}, key)
        heads.append(store.all()[-1]["event_hash"])
    return heads





def test_root_changes_when_any_leaf_changes(tmp_path):
    """The heart of the idea: touching ONE head changes the root."""
    heads = _heads(4, tmp_path)
    tree = build_tree(heads)
    tampered = list(heads)
    tampered[2] = "f" * 64
    assert build_tree(tampered).root != tree.root


def test_tree_is_order_independent(tmp_path):
    """Canonical sort: collecting in a different order yields the same tree."""
    heads = _heads(5, tmp_path)
    assert build_tree(list(reversed(heads))).root == build_tree(heads).root


def test_duplicate_heads_collapse(tmp_path):
    """A box that declares itself twice = a single leaf."""
    heads = _heads(3, tmp_path)
    tree = build_tree(heads + heads[:1])
    assert tree.size == 3
    assert tree.root == build_tree(heads).root


def test_odd_and_single_leaf_rules():
    """Odd level (last leaf duplicated) and single leaf: fixed rules."""
    a, b = "a" * 64, "0" * 64
    single = build_tree([a])
    assert single.root == build_tree([a, a]).root
    odd = build_tree([a, b])
    assert odd.leaves == sorted([a, b])

    assert build_tree([a, b, ("c" * 64)]).size == 3


def test_empty_fleet_is_an_error():
    with pytest.raises(ValueError):
        build_tree([])


def test_non_hash_leaf_is_rejected():
    with pytest.raises(ValueError):
        build_tree(["pas-un-hash"])





def test_every_head_proves_inclusion(tmp_path):
    """Each box proves its place with ~log2(N) hashes, not the whole tree."""
    heads = _heads(13, tmp_path)
    tree = build_tree(heads)
    for head in heads:
        proof = tree.proof(head)
        assert len(proof) <= 4
        assert verify_inclusion(head, proof, tree.root)


def test_foreign_head_fails_cleanly(tmp_path):
    """A box left out of the batch: an explicit error, not a false negative."""
    heads = _heads(4, tmp_path)
    tree = build_tree(heads)
    stranger = EventStore(str(tmp_path / "stranger.db"))
    key = KeyPair.load_or_create(str(tmp_path / "stranger.key"))
    stranger.append("llm_call", {}, key)
    foreign_head = stranger.all()[-1]["event_hash"]
    with pytest.raises(ValueError, match="does not participate"):
        tree.proof(foreign_head)


def test_tampered_proof_step_detected(tmp_path):
    """A rewritten proof step → the recomputed hash misses the seal."""
    heads = _heads(4, tmp_path)
    tree = build_tree(heads)
    proof = tree.proof(heads[1])
    corrupted = [
        ProofStep(sibling="0" * 64 if i == 0 else s.sibling, side=s.side)
        for i, s in enumerate(proof)
    ]
    assert not verify_inclusion(heads[1], corrupted, tree.root)





def test_fleet_scenario_three_boxes_one_seal(tmp_path):
    """THE demo: the fleet is sealed, one member REGENERATES its ledger
    (rewritten content, cleanly re-chained, same key) — a ledger that is
    internally valid but with a head the fleet seal no longer covers.
    Detected without ever calling the TSA again."""
    heads = _heads(3, tmp_path)
    tree = build_tree(heads)
    proofs = {h: tree.proof(h) for h in heads}
    root = tree.root
    for h in heads:
        assert verify_inclusion(h, proofs[h], root)

    rebuilt = EventStore(str(tmp_path / "box1-rebuilt.db"))
    rkey = KeyPair.load_or_create(str(tmp_path / "box1.key"))
    rebuilt.append("llm_call", {"agent": "agent-1", "prompt": "…"}, rkey)
    rebuilt.append("llm_output", {"resume": "version falsifiée"}, rkey)
    new_head = rebuilt.all()[-1]["event_hash"]

    assert new_head != heads[1]
    with pytest.raises(ValueError, match="does not participate"):
        tree.proof(new_head)
    assert not verify_inclusion(new_head, proofs[heads[1]], root)
    assert verify_inclusion(heads[0], proofs[heads[0]], root)


# --- NB-05 — the compatible half: every proof input is shape-checked ----------

def test_verify_inclusion_refuses_malformed_inputs():
    """NB-05 (grafted from the parallel audit patch): the tournament
    concatenates strings, so arbitrary-length look-alikes must never reach
    _pair_hash — a non-hex sibling, a bad side, or a malformed leaf/root
    reads as NOT included (fail-closed), never as arithmetic on junk."""
    h = "a" * 64
    assert not verify_inclusion(h, [ProofStep(sibling="not-a-hash", side="left")], h)
    assert not verify_inclusion(h, [ProofStep(sibling=h, side="up")], h)
    assert not verify_inclusion("short", [], h)
    assert not verify_inclusion(h, [], "zz" * 32)


def test_verify_inclusion_still_accepts_real_proofs(tmp_path):
    """The shape check changes nothing for honest proofs — a real 3-leaf
    tree still verifies (the compatibility guarantee of the graft)."""
    heads = _heads(3, tmp_path)
    tree = build_tree(heads)
    for h in heads:
        assert verify_inclusion(h, tree.proof(h), tree.root)
