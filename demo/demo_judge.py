#!/usr/bin/env python3
"""ADR 015 — the tier-2 judge in action: the same poisoned meeting that the
ML engine catches, judged by a local llama-guard3:1b with the house taxonomy.

Binary verdicts with a reason, offsets that line up with the pipeline, and
incidents sealed in the journal. Honest when absent: no Ollama or no model,
the scene explains the one-time install and stops — nothing is simulated.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json

from noirebox.chain import KeyPair, verify_chain
from noirebox.llm_judge import judge_available, judge_model, scan_llm
from noirebox.store import EventStore


def load(name: str) -> str:
    return "\n".join(json.loads(Path(f"corpus/{name}").read_text(encoding="utf-8"))["lines"])


def main() -> int:
    if not judge_available():
        print(f"[!] the judge is not here: Ollama must run and list {judge_model()}")
        print("    ollama pull " + judge_model())
        return 1

    db = Path("/tmp/noirebox-demo-judge.db")
    for leftover in (db, Path(str(db) + ".key"), Path(str(db) + "-wal"), Path(str(db) + "-shm")):
        leftover.unlink(missing_ok=True)
    store = EventStore(str(db))
    key = KeyPair.generate()

    for corpus in ("transcript_poisonne.json", "transcript_propre.json"):
        text = load(corpus)
        print(f"\n=== judging {corpus} with {judge_model()} (temperature 0, local) ===")
        incidents = scan_llm(text)
        if incidents:
            for inc in incidents:
                line_no = text[: inc.start].count("\n") + 1
                print(f"  [{inc.category}] line {line_no} — {inc.reason}")
                print(f"      excerpt: {inc.excerpt[:90]!r}")
            store.append("incident",
                         {"meeting_id": corpus, "engine": "llm",
                          "nb_incidents": len(incidents),
                          "incidents": [i.as_dict() for i in incidents]}, key)
            print(f"  -> incident sealed (engine: llm), {len(incidents)} verdict(s)")
        else:
            print("  -> no attack, no incident, nothing sealed")

    check = verify_chain(key.public_hex(), store.all())
    print(f"\n[{'✓' if check['valid'] else '✗'}] chain valid over {check['nb_events']} events")
    return 0 if check["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
