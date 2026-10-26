"""ADR 032 — canary-sweep receipts: the sensor gets its journal.

Row T6-011 of agentic-ai-test-checklist-110 (Padmanabhuni, CC-BY): a
secret the agent has seen must not resurface in its later outputs. The
check is a CANARY SWEEP — plant token secrets in the agent's context,
then scan every output for them — and it runs OUTSIDE the agent, with
the rest of the enforcement stack (the deployer's gateway, where ADR
031's gates live). What the sweep never had is what this journal is:
the run as evidence. "We scanned" is a claim; a sealed receipt saying
THIS canary (by digest), over THESE many outputs, found THIS (where,
by digest) is replayable by an auditor who was not there — and a
resurfaced canary is not the journal failing, it is the sensor doing
its job on the record.

The canary travels as its sha256 DIGEST, never as content. The spec
canary of SCAR-PROC-114 rides verbatim because its presence in the
journal IS the proof of read; a sweep canary STANDS IN for a secret,
and the one bytes-level rule of a secrets sweep is that the secret
stops existing everywhere except where it is authorised — a sweep
receipt that archives the token is the leak it was meant to catch. The
deployer holds the token, the journal holds the digest, and the pair
reconciles out of band.

Honest scope: noirebox does not sweep. The sensor is external; this
module seals what the sensor reports and refuses the shapes that would
let a non-sweep ride as one — the outcome fails closed (`clean |
canary_resurfaced | sweep_error`), findings travel only with
`canary_resurfaced` and never under an error, and a sweep that
certified nothing (`outputs_swept` = 0) is sealable as fact but
surfaces in the replay as `vacuous_sweep`: named, never silence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SCHEMA = "canary-sweep/0.1"

# Fail-closed vocabulary: a sweep that errored must say so — an
# unreachable sensor is never a clean pass.
OUTCOMES = ("clean", "canary_resurfaced", "sweep_error")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _as_digest(value, *, what: str) -> str:
    digest = str(value or "").strip().lower()
    if not _HEX64.match(digest):
        raise ValueError(
            f"canary-sweep: {what} must be a sha256 hex digest (64 hex "
            "chars) — the journal never holds the token itself; digest "
            "it first (a sweep receipt that archives the secret is the "
            "leak it was meant to catch)")
    return digest


def _as_count(value, *, what: str, required: bool) -> int | None:
    if value is None:
        if required:
            raise ValueError(f"canary-sweep: {what} is required — how "
                             "much the sensor actually scanned (the "
                             "denominator, ADR 020's discipline)")
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"canary-sweep: {what} must be an integer count")
    if value < 0:
        raise ValueError(f"canary-sweep: {what} cannot be negative — a "
                         "denominator that subtracts certifies nothing")
    return value


def seal_canary_sweep(store, key, *, canary_digest: str,
                      outputs_swept: int, outcome: str,
                      turns_swept: int | None = None,
                      findings: list[dict] | None = None,
                      sensor: str | None = None,
                      note: str | None = None) -> dict:
    """Seals one CANARY-SWEEP RECEIPT as a `canary_sweep` event (ADR 032):
    the receipt for the sweep itself, not the sweep. `canary_digest` is
    the sha256 of the canary token — the DIGEST, never the token
    (refused at seal time with the reason). `outputs_swept` /
    `turns_swept` are the denominator, the count of outputs (and turns)
    the sensor actually scanned. `outcome` fails closed:
    `clean | canary_resurfaced | sweep_error` — a sensor that did not
    run is named, never silently counted as a pass.

    `findings` travel ONLY with `canary_resurfaced` and are REQUIRED
    with it: a resurfacing with no location is a scare, not a finding.
    Each finding is `{"at": <where — a turn/output coordinate>,
    "output_digest": <sha256 of the offending output>}` — content never
    lands, the coordinate and the digest do. Findings under `clean` or
    `sweep_error` are refused: a clean sweep with findings is a lie, a
    failed sweep with findings is ambiguous evidence — rerun, or seal
    what resurfaced.
    """
    digest = _as_digest(canary_digest, what="canary_digest")
    clean_outputs = _as_count(outputs_swept, what="outputs_swept",
                              required=True)
    clean_turns = _as_count(turns_swept, what="turns_swept", required=False)
    if outcome not in OUTCOMES:
        raise ValueError(f"canary-sweep: outcome must be one of {OUTCOMES}, "
                         f"got {outcome!r} (a sweep that errored is named, "
                         "never clean)")
    clean_findings: list[dict] = []
    if outcome == "canary_resurfaced":
        if not findings:
            raise ValueError("canary-sweep: a `canary_resurfaced` sweep "
                             "names at least one finding — where the "
                             "canary came back (at + output_digest); a "
                             "resurfacing with no location is a scare")
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != {"at",
                                                                "output_digest"}:
                raise ValueError("canary-sweep: each finding is exactly "
                                 '{"at": <coordinate>, "output_digest": '
                                 "<sha256 hex>} — no more, no less")
            at = str(finding.get("at") or "").strip()
            if not at:
                raise ValueError("canary-sweep: a finding's `at` is "
                                 "required — the turn/output coordinate "
                                 "where the canary resurfaced")
            clean_findings.append({
                "at": at,
                "output_digest": _as_digest(finding.get("output_digest"),
                                            what="a finding's "
                                                 "output_digest"),
            })
    elif findings:
        raise ValueError(f"canary-sweep: findings travel only with "
                         f"`canary_resurfaced`, got outcome {outcome!r} — "
                         "a clean sweep with findings is a lie, a failed "
                         "sweep with findings is ambiguous evidence")
    payload: dict = {
        "schema": SCHEMA,
        "canary_digest": digest,
        "outputs_swept": clean_outputs,
        "outcome": outcome,
    }
    if clean_turns is not None:
        payload["turns_swept"] = clean_turns
    if clean_findings:
        payload["findings"] = clean_findings
    for field_name, value in (("sensor", sensor), ("note", note)):
        if value is not None:
            if not str(value).strip():
                raise ValueError(f"canary-sweep: {field_name}, when given, "
                                 "must be non-empty")
            payload[field_name] = str(value).strip()
    return store.append("canary_sweep", payload, key)


@dataclass
class SweepFinding:
    """One replay result — evidence that a sweep receipt does not hold
    as evidence. Sealed coordinates travel with it (seq of the event)."""
    code: str
    seq: int
    note: str


@dataclass
class CanarySweepAudit:
    """What the replay of a `canary_sweep` journal shows. A
    `canary_resurfaced` outcome is NOT a finding against the journal —
    it is the sensor's result, exactly what the receipt exists to
    prove; the findings here are discipline breaks (malformed,
    inconsistent, vacuous)."""
    sweeps: int = 0
    clean: int = 0
    resurfaced: int = 0
    errors: int = 0
    malformed: int = 0
    outputs_swept: int = 0
    findings: list[SweepFinding] = field(default_factory=list)

    @property
    def holds(self) -> bool:
        """True when every sealed sweep is well-formed, consistent, and
        certified something."""
        return not self.findings and self.malformed == 0


def replay_canary_sweep(store) -> CanarySweepAudit:
    """Replays every `canary_sweep` event: the containment pass an
    auditor runs. Checks, per sealed sequence:

    - well-formedness (schema, digest shapes, counts, outcome
      vocabulary) — catches `canary_sweep` events written through the
      generic `store.append` without the seal-time refusals;
    - consistency: no findings under `clean` (`clean_with_findings`),
      no bare `canary_resurfaced` (`resurfaced_without_findings`);
    - vacuity: a `clean` sweep over zero outputs is the finding
      `vacuous_sweep` — a sweep that certified nothing certifies
      nothing, and the auditor sees it named.

    Read-only: the chain itself is the store's `verify`, not this pass.
    """
    audit = CanarySweepAudit()
    for e in store.all():
        if e.get("type") != "canary_sweep":
            continue
        audit.sweeps += 1
        p = e.get("payload") or {}
        seq = e["seq"]
        if (p.get("schema") != SCHEMA
                or not _HEX64.match(str(p.get("canary_digest") or ""))
                or isinstance(p.get("outputs_swept"), bool)
                or not isinstance(p.get("outputs_swept"), int)
                or p.get("outputs_swept", -1) < 0
                or p.get("outcome") not in OUTCOMES):
            audit.malformed += 1
            audit.findings.append(SweepFinding(
                "malformed_event", seq,
                "canary_sweep event without the schema/digest shapes/"
                "counts/outcome vocabulary — sealed around "
                "seal_canary_sweep's refusals"))
            continue
        outcome = p["outcome"]
        findings = p.get("findings") or []
        findings_ok = isinstance(findings, list) and all(
            isinstance(f, dict)
            and set(f) == {"at", "output_digest"}
            and str(f.get("at") or "").strip()
            and _HEX64.match(str(f.get("output_digest") or "").strip().lower())
            for f in findings)
        audit.outputs_swept += p["outputs_swept"]
        if outcome == "clean":
            audit.clean += 1
            if findings:
                audit.findings.append(SweepFinding(
                    "clean_with_findings", seq,
                    "a clean sweep carrying findings — the outcome and "
                    "the evidence cannot both be true"))
            elif p["outputs_swept"] == 0:
                audit.findings.append(SweepFinding(
                    "vacuous_sweep", seq,
                    "a clean sweep over ZERO outputs — it certified "
                    "nothing; run it over the denominator or do not "
                    "count it as a pass"))
        elif outcome == "canary_resurfaced":
            audit.resurfaced += 1
            if not findings:
                audit.findings.append(SweepFinding(
                    "resurfaced_without_findings", seq,
                    "canary_resurfaced with no finding — a resurfacing "
                    "with no location is a scare, not a finding"))
            elif not findings_ok:
                audit.findings.append(SweepFinding(
                    "malformed_finding", seq,
                    "a finding that is not {at, output_digest} with a "
                    "64-hex digest — sealed around the refusals"))
        else:
            audit.errors += 1
            if findings:
                audit.findings.append(SweepFinding(
                    "clean_with_findings", seq,
                    "findings under a sweep_error — a failed sweep with "
                    "findings is ambiguous evidence; rerun or seal what "
                    "resurfaced"))
    return audit
