"""ADR 031 — authorization receipts: the enforcement layer gets its journal.

The 2026 standards conversation splits agent governance in two halves that
keep being built separately:

  - ENFORCEMENT at the moment of action — authorization brokers outside the
    agent's reasoning (OWASP ACS, NIST's software/AI-agent identity work,
    KedgeFlow's grant/claim/dispatch gateways, UAI-BLOCK's OS-identity
    broker). KedgeFlow's own evaluation shows the limit of enforcement
    alone: a permissive policy still authorized an undesirable effect.
  - EVIDENCE after the fact — what this journal is. Dr. Bunic's demonstrable-
    governance tests name it: accountability and auditability, at scale,
    durably. UAI-BLOCK self-reports the gap verbatim ("does not yet have
    tamper-resistant audit records, independent verification").

This module is the bridge: an `authorization` receipt seals one gate
decision — who requested, what action on what resource, allow or deny,
under which warrant. An enforcement layer that journals here becomes
*provable*: an auditor replays the sealed sequence and checks the gate
never allowed an unwarranted request, that a denied triple did not
silently flip to allowed, and that no allow leans on the resource's own
presence/relevance/plausibility/usefulness (laws 1–8 — the laundering
vocabulary is refused at seal time, same discipline as admission
receipts).

Honest scope: this is the journal contract for gates, not a policy engine.
It does not decide anything; it makes what was decided undeniable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SCHEMA = "authorization/0.1"

# Fail-closed vocabulary: a gate that errored must say so — a swallowed
# gate failure is an allow nobody decided.
DECISIONS = ("allowed", "denied", "gate_error")

# Laws 1–8: the resource's own pull is never a warrant (same refusal as
# admission receipts — the field exists to carry an independent warrant).
_NEVER_A_BASIS = ("presence", "relevance", "plausibility", "usefulness")


def seal_authorization(store, key, *, agent: str, action: str, resource: str,
                       decision: str, warrant: str | None = None,
                       rule: str | None = None, gate: str | None = None,
                       reason: str | None = None) -> dict:
    """Seals one AUTHORIZATION RECEIPT as an `authorization` event (ADR 031).

    `agent` is the requester identity *as verified at execution time* —
    the OS/socket/tls credential the gate actually checked (e.g.
    "os:uid=942 via SO_PEERCRED"), not a name the agent claimed.
    `decision` fails closed: `allowed` | `denied` | `gate_error` — an
    unreachable or failed gate is named, never silently retried into an
    allow. An `allowed` decision REQUIRES a `warrant`: the independent
    authority this allow leans on (a user-instruction ref, a prior
    receipt seq, an explicit scope grant). The resource's own
    presence/relevance/plausibility/usefulness are refused as warrants.
    """
    if not str(agent or "").strip():
        raise ValueError("authorization: agent is required — the requester "
                         "identity as verified at execution time (SO_PEERCRED, "
                         "TLS identity…), not a claimed name")
    if not str(action or "").strip():
        raise ValueError("authorization: action is required — the requested "
                         "operation")
    if not str(resource or "").strip():
        raise ValueError("authorization: resource is required — the target")
    if decision not in DECISIONS:
        raise ValueError(f"authorization: decision must be one of {DECISIONS}, "
                         f"got {decision!r}")
    clean_warrant = str(warrant or "").strip()
    if decision == "allowed":
        if not clean_warrant:
            raise ValueError("authorization: an allow without a warrant is "
                             "capability walking around as authority — name "
                             "the independent warrant")
        if clean_warrant.lower() in _NEVER_A_BASIS:
            raise ValueError(f"authorization: warrant {clean_warrant!r} is one "
                             "of the resources that are never a basis "
                             "(laws 1–8) — name the independent warrant")
    payload: dict = {
        "schema": SCHEMA,
        "agent": agent.strip(),
        "action": action.strip(),
        "resource": resource.strip(),
        "decision": decision,
    }
    if clean_warrant:
        payload["warrant"] = clean_warrant
    for field_name, value in (("rule", rule), ("gate", gate), ("reason", reason)):
        if value is not None:
            if not str(value).strip():
                raise ValueError(f"authorization: {field_name}, when given, "
                                 "must be non-empty")
            payload[field_name] = str(value).strip()
    return store.append("authorization", payload, key)


@dataclass
class GateFinding:
    """One replay result — evidence that the gate did not hold. Sealed
    coordinates travel with it (seq of the offending event)."""
    code: str
    seq: int
    note: str


@dataclass
class AuthorizationAudit:
    """What the replay of an `authorization` journal shows."""
    allowed: int = 0
    denied: int = 0
    gate_errors: int = 0
    malformed: int = 0
    findings: list[GateFinding] = field(default_factory=list)
    triples: int = 0

    @property
    def holds(self) -> bool:
        """True when the replay surfaced no finding and no malformed event."""
        return not self.findings and self.malformed == 0


def replay_authorization(store) -> AuthorizationAudit:
    """Replays every `authorization` event: the provable-access-control
    pass an auditor runs. Checks, per sealed sequence:

    - well-formedness (schema, required fields, decision vocabulary) —
      catches `authorization` events written through the generic
      `store.append` without the seal-time refusals;
    - every allow carries a warrant, and no allow leans on the four
      resources that are never a basis;
    - no gate flip: a triple (agent, action, resource) denied earlier in
      the sealed sequence must not appear allowed later — either the
      warrant legitimately changed (seal it again with the new warrant)
      or the gate is inconsistent.

    Read-only: the chain itself is the store's `verify`, not this pass.
    """
    audit = AuthorizationAudit()
    denied_triples: dict[tuple[str, str, str], int] = {}
    seen_triples: set[tuple[str, str, str]] = set()
    for e in store.all():
        if e.get("type") != "authorization":
            continue
        p = e.get("payload") or {}
        seq = e["seq"]
        if (p.get("schema") != SCHEMA or not p.get("agent")
                or not p.get("action") or not p.get("resource")
                or p.get("decision") not in DECISIONS):
            audit.malformed += 1
            audit.findings.append(GateFinding(
                "malformed_event", seq,
                "authorization event without the schema/required fields — "
                "sealed around seal_authorization's refusals"))
            continue
        decision = p["decision"]
        triple = (p["agent"], p["action"], p["resource"])
        seen_triples.add(triple)
        if decision == "allowed":
            audit.allowed += 1
            warrant = str(p.get("warrant") or "").strip()
            if not warrant:
                audit.findings.append(GateFinding(
                    "allow_without_warrant", seq,
                    f"{p['agent']} allowed {p['action']} on {p['resource']} "
                    "with no warrant sealed — capability walking around "
                    "as authority"))
            elif warrant.lower() in _NEVER_A_BASIS:
                audit.findings.append(GateFinding(
                    "laundered_basis", seq,
                    f"allow leans on {warrant!r} — one of the resources that "
                    "are never a basis (laws 1–8)"))
            first_deny = denied_triples.get(triple)
            if first_deny is not None:
                audit.findings.append(GateFinding(
                    "gate_flip", seq,
                    f"triple denied at seq {first_deny}, allowed here — either "
                    "the warrant changed (seal the new warrant) or the gate "
                    "is inconsistent"))
        elif decision == "denied":
            audit.denied += 1
            denied_triples.setdefault(triple, seq)
        else:
            audit.gate_errors += 1
    audit.triples = len(seen_triples)
    return audit
