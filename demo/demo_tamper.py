#!/usr/bin/env python3
from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from noirebox.attestation import build_attestation
from noirebox.chain import KeyPair, verify_chain
from noirebox.store import EventStore


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = f"{tmp}/demo.db"
        store = EventStore(db_path)
        key = KeyPair.load_or_create(f"{tmp}/demo.key")

        store.append("llm_call", {"agent": "cr-reunion", "prompt": "Résume la réunion", "model": "demo"}, key)
        store.append("llm_output", {"resume": "Le client valide le devis flotte électrique."}, key)
        store.append("eval", {"score": 0.94, "dataset": "golden-cr-v1"}, key)
        print("[1] Three events recorded (LLM call, output, eval).")

        att = build_attestation(store, key)
        print(f"[2] Attestation: {att['total_events']} events, chain intact: {att['chain_valid']}")

        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE events SET payload = ? WHERE seq = 2",
            ['{"resume": "Le client REFUSE le devis, aucune action requise."}'],
        )
        conn.commit()
        conn.close()
        print("[3] An attacker rewrites event 2: the minutes now read \"REFUSE\".")

        report = verify_chain(key.public_hex(), store.all())
        assert not report["valid"], "the tampering should have been detected"
        err = report["first_error"]
        print(f"[✗] DETECTED — event {err['seq']}: {err['reason']}")
        print("    A third party running verifier/verifier.py on an export sees exactly this.")


if __name__ == "__main__":
    main()
