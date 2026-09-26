#!/usr/bin/env python3
"""AGENT-GENERATED PAYMENTS demo — the two-event pattern + reconciliation.

The scenario: an agent decides on payments (deterministic rule engine),
a local provider responds (simulated — zero network, zero real money), and
every step is sealed into the journal. The two-event pattern requested by
the community (issue #3):

    policy_decision (allow/hold/deny + reason_code + policy_version)
    provider_response (provider status)
    ... linked by a correlation key: payment_intent_id

Then the two failure cases that exist in every real flow:
- the agent dies AFTER sealing the decision: decision without a response
- a retry skips the journaling step: an orphan response

And the caller-side reconciliation (the schema of the future plugin,
issue #3): pair by correlation key, journal the report as an event —
the journal's auditor is itself audited.

The whole payment flow is synthetic (payloads marked synthetic:true,
provider simulated) — the journal is real: chained, signed, verifiable.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from noirebox.chain import KeyPair, verify_chain
from noirebox.store import EventStore

POLICY_VERSION = "2.4.1"
BLOCKED_VENDORS = {"grey-market-ltd"}
HOLD_THRESHOLD_CENTS = 500_00
MARK = {"synthetic": True, "provider": "stripe (simulated)"}


def policy_agent(vendor: str, amount_cents: int) -> tuple[str, str]:
    """The agent's rule engine — deterministic, testable, journaled."""
    if vendor in BLOCKED_VENDORS:
        return "deny", "4102"
    if amount_cents > HOLD_THRESHOLD_CENTS:
        return "hold", "5007"
    return "allow", "3001"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(f"{tmp}/payout.db")
        key = KeyPair.load_or_create(f"{tmp}/payout.key")

        # ── 1. The agent decides: policy_decision sealed before any call ──
        requests = [
            ("acme-supplies", 120_00),          # allow
            ("grey-market-ltd", 90_00),         # deny (blocked list)
            ("cloudhost-pro", 680_00),          # hold (threshold)
            ("stationery-plus", 35_00),         # allow — and the agent "crashes"
        ]
        # Intents are generated ONCE: decisions and responses share the same
        # correlation key, otherwise the reconciliation would match nothing.
        intents = [f"pi_syn_{vendor.split('-')[0][:6]}{cents}"
                   for vendor, cents in requests]
        for (vendor, cents), intent in zip(requests, intents, strict=True):
            decision, reason = policy_agent(vendor, cents)
            store.append("policy_decision", {
                **MARK, "payment_intent_id": intent, "vendor": vendor,
                "amount_cents": cents, "decision": decision,
                "reason_code": reason, "policy_version": POLICY_VERSION,
            }, key)
            print(f"[1] decision {decision:<5} {intent:<22} ({vendor}, "
                  f"${cents/100:.2f}) — reason {reason}, policy {POLICY_VERSION}")
        crashed_intent = intents[3]
        print(f"    ↳ decision sealed for {crashed_intent} — the agent dies "
              f"BEFORE the provider call. No response will ever follow.")

        # ── 2. The provider responds: provider_response sealed after ─────
        responses = [(intents[0], "succeeded"), (intents[1], "declined_by_policy"),
                     (intents[2], "pending_review")]
        for intent, status in responses:
            store.append("provider_response", {
                **MARK, "payment_intent_id": intent, "status": status}, key)
        print(f"[2] {len(responses)} provider_response events sealed, "
              f"linked by payment_intent_id.")

        # ── 3. The retry that skipped the journaling step ────────────────
        store.append("provider_response", {
            **MARK, "payment_intent_id": "pi_syn_orphan99", "status": "succeeded"}, key)
        print("[3] Real-world case n°2: a retry responded with no sealed "
              "decision in front of it (pi_syn_orphan99).")

        # ── 4. Caller-side reconciliation: pair by correlation key ───────
        events = store.all()
        decisions = {e["payload"]["payment_intent_id"]: e for e in events
                     if e["type"] == "policy_decision"}
        outcomes = {e["payload"]["payment_intent_id"]: e for e in events
                    if e["type"] == "provider_response"}
        open_gaps = sorted(set(decisions) - set(outcomes))
        orphans = sorted(set(outcomes) - set(decisions))
        matched = sorted(set(decisions) & set(outcomes))
        print("[4] Reconciliation (caller-side today, plugin tomorrow — issue #3):")
        print(f"    ✓ matched         : {len(matched)} ({', '.join(matched)})")
        for g in open_gaps:
            print(f"    ✗ open_gap        : {g} — decision sealed, response never came")
        for o in orphans:
            print(f"    ✗ orphan_outcome  : {o} — money moved with no decision in front")

        # ── 5. The reconciliation report is ITSELF sealed ────────────────
        store.append("reconciliation", {
            "checked": len(decisions) + len(orphans), "matched": len(matched),
            "open_gaps": open_gaps, "orphan_outcomes": orphans,
            "policy_version": POLICY_VERSION, **MARK,
        }, key)
        print(f"[5] Report sealed as a `reconciliation` event (seq "
              f"{store.all()[-1]['seq']}) — the journal's auditor is audited by it.")

        # ── 6. The proof ─────────────────────────────────────────────────
        report = verify_chain(key.public_hex(), store.all())
        assert report["valid"], "the chain should have been intact"
        print(f"[✓] INTACT — {len(events) + 1} events, signed chain, provable order.")
        print("    Same box as the meeting-minutes demo: an event is a type")
        print("    and a payload. Proof is universal — payments were just one")
        print("    more domain.")


if __name__ == "__main__":
    main()
