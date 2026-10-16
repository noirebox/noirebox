#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from noirebox import anchors
from noirebox.chain import KeyPair
from noirebox.merkle import build_tree, verify_inclusion
from noirebox.store import EventStore

NAMES = ["cr-reunion", "support-juridique", "scoring-credit"]


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:

        heads = []
        for name in NAMES:
            store = EventStore(f"{tmp}/{name}.db")
            key = KeyPair.load_or_create(f"{tmp}/{name}.key")
            store.append("llm_call", {"agent": name, "prompt": "Traite la demande"}, key)
            store.append("llm_output", {"summary": f"CR {name} — validé"}, key)
            heads.append(store.all()[-1]["event_hash"])
        print(f"[1] {len(NAMES)} active boxes, each with its signed chain.")


        tree = build_tree(heads)
        print(f"[2] Merkle tree: {tree.size} leaves, root {tree.root[:16]}…")
        print("    (the root commits to ALL the heads: touching a single")
        print("     box would change it completely — the way the winner")
        print("     of a tournament depends on every match)")


        proofs = {h: tree.proof(h) for h in heads}
        for head, (name, proof) in zip(heads, zip(NAMES, proofs.values(), strict=True), strict=True):
            ok = verify_inclusion(head, proof, tree.root)
            print(f"    {name:<18} proof: {len(proof)} hashes → {'✓ covered' if ok else '✗'}")
        print(f"[3] Each box proves its place with {len(next(iter(proofs.values())))} hashes — not the whole tree.")


        if anchors.tsa_configured():
            try:
                token = anchors.request_token(tree.root)
                print(f"[4] Root sealed at the TSA ({len(token)} bytes) — ONE anchor for {tree.size} boxes.")
            except OSError as exc:
                print(f"[4] TSA unreachable ({exc.__class__.__name__}) — anchor skipped, the proof stays local.")
        else:
            print("[4] TSA not configured — to seal the root: `make tsa` in a")
            print("    terminal, then NOIREBOX_TSA_URL=http://127.0.0.1:3318 make demo-fleet.")
            print("    Without it, the inclusion proof remains verifiable locally.")


        culprit = NAMES[1]
        rebuilt = EventStore(f"{tmp}/{culprit}-rebuilt.db")
        rkey = KeyPair.load_or_create(f"{tmp}/{culprit}.key")
        rebuilt.append("llm_call", {"agent": culprit, "prompt": "Traite la demande"}, rkey)
        rebuilt.append("llm_output", {"summary": "CR RÉÉCRIT — le client refuse tout"}, rkey)
        new_head = rebuilt.all()[-1]["event_hash"]
        print(f"[5] {culprit} regenerates its journal: content rewritten, re-chained cleanly.")
        print(f"    new head: {new_head[:16]}…  (old: {heads[1][:16]}…)")


        try:
            tree.proof(new_head)
            raise SystemExit("BUG: the regenerated head should have been rejected")
        except ValueError:
            pass
        ok_old = verify_inclusion(heads[1], proofs[heads[1]], tree.root)
        ok_new = verify_inclusion(new_head, proofs[heads[1]], tree.root)
        print("[✗] DETECTED — the new head is not covered by the fleet seal.")
        print(f"    old head covered: {'yes' if ok_old else 'no'}; new one: {'yes' if ok_new else 'NO'}")
        print("    Entirely local detection: no TSA called back, no hub contacted —")
        print("    the arithmetic decides. Same role as the individual RFC 3161")
        print("    anchor, but ONE anchor covers the whole fleet.")


        hub = EventStore(f"{tmp}/hub.db")
        hub_key = KeyPair.load_or_create(f"{tmp}/hub.key")
        hub.append("fleet_anchor", {
            "members": NAMES, "size": tree.size, "root": tree.root,
            "leaves": tree.leaves,
        }, hub_key)
        print(f"[7] The hub seals the whole tree as a `fleet_anchor` event (journal #{hub.all()[-1]['seq']}).")
        print("    Even the hub cannot rewrite which heads took part —")
        print("    it is itself a NoireBox.")


if __name__ == "__main__":
    main()
