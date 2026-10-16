#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from noirebox.attestation import build_attestation
from noirebox.chain import KeyPair
from noirebox.guardrail import scan_transcript
from noirebox.store import EventStore


def run(transcript_path: Path, store: EventStore, key: KeyPair) -> None:
    data = json.loads(transcript_path.read_text(encoding="utf-8"))
    text = "\n".join(data["lines"])
    incidents = scan_transcript(text)
    store.append(
        "incident",
        {"meeting_id": data["meeting_id"], "nb_incidents": len(incidents),
         "incidents": [i.as_dict() for i in incidents]},
        key,
    )
    print(f"\n── {transcript_path.name} ({data['meeting_id']})")
    if not incidents:
        print("    [✓] Aucune attaque détectée — transcript sain.")
    else:
        print(f"    [✗] {len(incidents)} incident(s) détecté(s) :")
        for inc in incidents:
            print(f"      • [{inc.category}] score {inc.score} — « {inc.excerpt} »")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(f"{tmp}/demo.db")
        key = KeyPair.load_or_create(f"{tmp}/demo.key")
        run(ROOT / "corpus" / "transcript_propre.json", store, key)
        run(ROOT / "corpus" / "transcript_poisonne.json", store, key)

        att = build_attestation(store, key)
        print(f"\n── Journal : {att['total_events']} événement(s), "
              f"chaîne intègre : {att['chain_valid']}")
        print(f"    Tête de chaîne : {att['head_hash'][:24]}…")
        print("    → Deux scans journalisés, signés, inaltérables. "
              "Lancez demo/demo_tamper.py pour voir une falsification être détectée.")


if __name__ == "__main__":
    main()
