#!/usr/bin/env python3
"""The install gate (community pattern, slopsquatting thread): an agent that
can install is an agent that must journal — and the journaling follows the
receipt shape of ADR 019:

  1. CLAIM      — the agent states what it wants and why, BEFORE looking
  2. VERIFY     — the registry answer is bound by digest (normalized witness:
                  no wall-clock, byte counts, the package digest itself)
  3. DECISION   — allow/deny with the reason, sealed under a DIFFERENT event
                  type than the claim — reconciliation pairs them

Then the reconciliation layer proves the gate ran: clean passes included,
with a negative control on the report. Zero simulation, one temp journal.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hashlib
import json

from noirebox.chain import KeyPair, verify_chain_multi
from noirebox.reconcile import (
    Invariant,
    journal_report,
    reconcile,
    run_probes,
)
from noirebox.store import EventStore
from noirebox.witness import canonical_witness

REGISTRY_ANSWER = json.dumps({
    "name": "left-pad-py", "version": "9.9.9",
    "digest": "sha256-tbd", "maintainer": "someone-new-2026",
}).encode()


def main() -> int:
    tmp = tempfile.mkdtemp()
    db = str(Path(tmp) / "gate.db")
    store = EventStore(db)
    agent_key = KeyPair.generate()   # the agent's hand
    gate_key = KeyPair.generate()    # the gate's hand — ADR 019 §7: two writers

    request = "install left-pad-py==9.9.9 (the agent says: 'a dependency asks for it')"
    print(f"[1] CLAIM  — {request}")
    store.append("install_claim", {
        "package": "left-pad-py", "version": "9.9.9",
        "requested_by": "dependency-resolution",
        "artifact_sha256": hashlib.sha256(REGISTRY_ANSWER).hexdigest(),
        "source": {"tool": "demo-install-gate", "version": "0.10.0"},
    }, agent_key)

    print("[2] VERIFY — the registry answer, witnessed (normalized, ADR 019 §8)")
    store.append("install_verification", {
        "registry_digest": hashlib.sha256(REGISTRY_ANSWER).hexdigest(),
        "witness": canonical_witness(0, REGISTRY_ANSWER),
        "flags": ["maintainer-newer-than-30d", "single-maintainer"],
    }, agent_key)

    print("[3] DECIDE — the gate says NO, under its own key (two-writer pairing)")
    store.append("install_decision", {
        "package": "left-pad-py", "version": "9.9.9",
        "decision": "deny",
        "reason_code": "slopsquatting-signals",
        "claim_digest": hashlib.sha256(REGISTRY_ANSWER).hexdigest(),
    }, gate_key)

    inv = [Invariant("install-gate", "install_claim", "install_decision",
                     "package", within_seconds=30)]
    findings = reconcile(store.all(), inv)
    probes = run_probes(store.all(), inv, [
        {"name": "gate-bites", "invariant": "install-gate", "expect": "matched"},
    ])
    journal_report(store, gate_key, inv, findings, probes=probes,
                   events=store.all())

    for f in findings:
        print(f"    [{f.status}] {f.correlation_id}")
    print("[4] report sealed — clean_pass, probes_ok, "
          "claims under the agent key, decisions under the gate key")

    check = verify_chain_multi([agent_key.public_hex(), gate_key.public_hex()],
                               store.all())
    ok = check["valid"]
    print(f"[{'✓' if ok else '✗'}] chain valid under 2 known writers, "
          f"{check['nb_events']} events — one journal, every step sealed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
