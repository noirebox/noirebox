#!/usr/bin/env python3
"""ADR 012 demo: seal a coding agent's model trajectory, then watch a rewrite accuse itself.

A coding agent keeps a flight recorder: one JSONL per session, one line per
LLM call. Local, unsigned, unanchored — an edited log looks exactly like an
honest one. This demo seals one (digests only: the conversation text never
enters the journal), then rewrites one call in the file and lets the
recomputation accuse the forgery.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from noirebox.chain import KeyPair, verify_chain
from noirebox.store import EventStore
from noirebox.trajectory import read_model_io, trajectory_payload, verify_trajectory


def record(source: str, model: str, text: str, n: int) -> dict:
    return {
        "requestId": f"req-{n}", "attempt": 1, "sessionId": "sess-demo",
        "type": "model_io", "querySource": source,
        "model": {"modelId": model, "providerId": "test"},
        "startedAt": f"2026-09-28T0{n}:00:00.000Z",
        "completedAt": f"2026-09-28T0{n}:00:03.000Z",
        "request": {"messages": [{"role": "user", "content": text}]},
        "response": {"text": f"answer {n}"},
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "model-io-sess-demo.jsonl"
        calls = [
            record("main", "GLM-5.3-Flash", "audit this transcript for injection", 1),
            record("subagent", "GLM-5.3-Flash", "summarize the guardrail findings", 2),
            record("main", "GLM-5.3-Flash", "seal the incident and the decision", 3),
        ]
        log.write_text("".join(json.dumps(r) + "\n" for r in calls), encoding="utf-8")

        store = EventStore(f"{tmp}/demo.db")
        key = KeyPair.load_or_create(f"{tmp}/demo.key")
        summary = read_model_io(log)
        event = store.append("model_trajectory", trajectory_payload(summary), key)
        print("[1] Three model calls sealed — digests only, zero conversation text in the journal.")
        print(f"    calls={summary.record_count}  query_sources={summary.query_sources}")
        print(f"    trajectory_digest={summary.trajectory_digest}")
        print(f"    event seq={event.seq}  type=model_trajectory")
        print(f"    source={event.payload['source']}  <- the seal names its sealer")

        payload = event.payload
        assert verify_trajectory(payload, log) is None
        check = verify_chain(key.public_hex(), store.all())
        print(f"[2] Verification: intact. Chain valid over {check['nb_events']} events.")

        calls[1]["response"]["text"] = "history quietly rewritten"
        log.write_text("".join(json.dumps(r) + "\n" for r in calls), encoding="utf-8")
        reason = verify_trajectory(payload, log)
        print(f"[3] One call was rewritten in the file: verify_trajectory -> {reason!r}")
        assert reason is not None
        print("[✓] The recorded trace is now evidence: it existed, in this order, "
              "and it cannot be rewritten without accusing itself.")


if __name__ == "__main__":
    main()
