"""Replay (ADR 019 receipts + ADR 023 belief → the auditor's question):
rebuild the decision timeline from sealed evidence, in the order the chain
forces.

"Replayable" is what auditors ask for — and what a log of actions alone
cannot do. NoireBox can, because the sealed SEQUENCE is the evidence:
for one meeting (or run), the journal answers, in chain order:

    BELIEF    what the agent believed when it acted (self-report, graded)
    ATTEMPT   that it tried (the denominator)
    INCIDENT  what the guardrail caught and blocked
    CALL      what reached the model (the cleaned transcript)
    OUTPUT    what the model answered
    WITNESS   what actually happened (byte counts — the normalized witness)

Replay is deterministic: same journal, same timeline. It does NOT re-run
the model — it re-derives what happened from the seals, which is the only
replay an evidence layer can honestly offer.
"""
from __future__ import annotations

from .chain import KeyPair, verify_chain

_STEP_TYPES = (
    ("incident", "INCIDENT", "guardrail blocked"),
    ("decision_belief", "BELIEF", "what the agent believed (self-report)"),
    ("llm_attempt", "ATTEMPT", "the try, sealed before the outcome"),
    ("llm_call", "CALL", "what reached the model"),
    ("llm_output", "OUTPUT", "what the model answered"),
    ("run_witness", "WITNESS", "what happened, byte-counted"),
)


def replay(events: list[dict], key: KeyPair, subject: str) -> dict:
    """Rebuilds the decision timeline for one meeting_id (or run_id) from
    the journal, verifying the chain first — a replay over a tampered chain
    would be theater.

    Returns {valid, meeting, steps: [{seq, ts, kind, detail}], witness}.
    `steps` is empty when the chain is invalid or the subject sealed nothing.
    """
    check = verify_chain(key.public_hex(), events)
    if not check["valid"]:
        return {"valid": False, "meeting": subject, "steps": [], "witness": None}

    steps = []
    for e in events:
        payload = e.get("payload", {})
        sid = payload.get("meeting_id") or payload.get("run_id")
        if sid != subject:
            continue
        for etype, kind, desc in _STEP_TYPES:
            if e["type"] != etype:
                continue
            if etype == "incident":
                detail = (f"{payload.get('nb_incidents', 0)} attack(s) caught "
                          f"by {payload.get('engine', '?')} — action: {payload.get('action', '?')}")
            elif etype == "decision_belief":
                detail = (f"target={payload.get('resolved_target')} "
                          f"grade={payload.get('belief_grade')}")
            elif etype == "llm_attempt":
                detail = f"inputs digest {payload.get('clean_transcript_sha256', '')[:16]}…"
            elif etype == "llm_call":
                detail = (f"{payload.get('filtered_lines', 0)} line(s) filtered "
                          f"before the model saw it")
            elif etype == "llm_output":
                summary = str(payload.get("summary", ""))
                detail = f"{len(summary)} chars — {summary[:80]}{'…' if len(summary) > 80 else ''}"
            else:  # run_witness
                w = payload.get("witness") or payload
                detail = f"exit {w.get('exit_code')} — {w.get('stdout_bytes')} bytes witnessed"
            steps.append({"seq": e["seq"], "ts": e["ts"], "kind": kind,
                          "type": etype, "detail": detail})
    witness = steps[-1]["detail"] if any(s["type"] == "run_witness" for s in steps) else None
    return {"valid": True, "meeting": subject, "steps": steps, "witness": witness}


def render(replay_report: dict) -> str:
    """Human-readable timeline (the CLI's output)."""
    if not replay_report["valid"]:
        return "[✗] the chain is TAMPERED — replay refuses theater (see /api/v1/verify)"
    lines = [f"[✓] REPLAY {replay_report['meeting']} — {len(replay_report['steps'])} sealed step(s), "
             f"chain verified:"]
    for s in replay_report["steps"]:
        lines.append(f"    seq {s['seq']:<5} {s['kind']:<9} {s['detail']}")
    if replay_report["witness"]:
        lines.append(f"    witness: {replay_report['witness']}")
    return "\n".join(lines)
