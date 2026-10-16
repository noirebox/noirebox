"""AI-Act-shaped event vocabulary (ADR 010).

Maps Regulation (EU) 2024/1689 art. 12(3) onto first-class journal payloads
so a high-risk system's log IS the NoireBox journal:

  art. 12(3)(a)  period of each use              → `ai_use`  use_start / use_end
  art. 12(3)(b)  reference database checked      → `ai_use`  reference_db
  art. 12(3)(c)  input data with a match         → `ai_use`  input_digest (sha256)
  art. 12(3)(d)  natural persons who verified
  the results (art. 14(5))                       → `ai_verification`  human_verifier
  art. 55(1)(c) / art. 73  serious incidents:
  keep track of, document, report                → `ai_incident`

Minimization by construction: raw inputs never enter the journal — the
builders accept the sha256 DIGEST of an input, not the input itself. The
builders validate; a non-conforming payload cannot be sealed.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# The mapping table, machine-readable: the audit-pack renders it as the
# "logging characteristics" section of the Annexe IV §2(f) description.
ART12_MAPPING = [
    {"article": "12(3)(a)", "requirement": "period of each use (start/end)",
     "event": "ai_use", "fields": ["use_start", "use_end"]},
    {"article": "12(3)(b)", "requirement": "reference database checked against",
     "event": "ai_use", "fields": ["reference_db"]},
    {"article": "12(3)(c)", "requirement": "input data where the search matched",
     "event": "ai_use", "fields": ["input_digest"],
     "note": "sha256 digest only — the raw input never enters the journal"},
    {"article": "12(3)(d)", "requirement": "identification of the natural persons "
     "involved in the verification of the results (art. 14(5))",
     "event": "ai_verification", "fields": ["human_verifier", "decision"]},
    {"article": "55(1)(c) / 73", "requirement": "serious incidents: keep track "
     "of, document, report", "event": "ai_incident",
     "fields": ["severity", "description", "detected_at"]},
]


def _iso(field: str, value) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}: must be an ISO 8601 string")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field}: not a valid ISO 8601 datetime: {value!r}") from None
    return value


# --- The three evidence grades (issue #51 — mickyarun; ADR 022) --------------
# Every event class labels itself with the grade of the proof it carries and
# states WHOSE OBLIGATION backs it — "no one can impose a cost here" means
# the evidence is voluntary. The authority-facing disclosure cannot hide a
# grade-2 custodian behind a grade-1 counterparty sentence.

_EVIDENCE_GRADES = {
    1: {"label": "adverse counterparty",
        "proof": "custody: the other side's own record, reconciled against yours",
        "obligation": "the counterparty's record-keeping duty — two obliged "
                      "journals reconciled (ADR 020/022)"},
    2: {"label": "disinterested custodian",
        "proof": "a third party with no stake attests WHEN the chain head existed",
        "obligation": "the TSA's signing duty (RFC 3161, eIDAS-qualified where "
                      "pinned) or the OpenTimestamps calendar's impersonal one"},
    3: {"label": "anchored self",
        "proof": "operator-held facts, hash-chained and externally anchored",
        "obligation": "the operator's own record-keeping obligation — VOLUNTARY "
                      "unless a regime imposes it: 'no one can impose a cost "
                      "here' means the evidence is voluntary"},
}

# The default class → grade mapping. Counterparty-shaped events are grade 1;
# third-party witnesses are grade 2; everything journal-local defaults to
# grade 3 — the honest default, because a fact the operator holds can never
# honestly claim a stronger grade than its own custody.
_ADVERSE_COUNTERPARTY_EVENTS = ("provider_response", "expectation_ack")
_DISINTERESTED_CUSTODIAN_EVENTS = ("anchor", "fleet_anchor")


def evidence_grade(event_type: str) -> dict:
    """The evidence-grade label for one event class: {grade, label, proof,
    obligation} — ADR 022's scale made explicit (issue #51)."""
    if event_type in _ADVERSE_COUNTERPARTY_EVENTS:
        grade = 1
    elif event_type in _DISINTERESTED_CUSTODIAN_EVENTS:
        grade = 2
    else:
        grade = 3
    return {"grade": grade, **_EVIDENCE_GRADES[grade]}


def use_event(*, use_start: str, use_end: str, system_ref: str,
              reference_db: str | None = None,
              input_digest: str | None = None,
              **context) -> dict:
    """art. 12(3)(a)-(c): one use of the system.

    `input_digest` is the sha256 HEX of the input data (or of the matched
    record) — never the input itself. Extra keyword arguments travel in
    `context` unchanged (caller's minimization duty, as ever).
    """
    _iso("use_start", use_start)
    _iso("use_end", use_end)
    if datetime.fromisoformat(use_start.replace("Z", "+00:00")) > \
       datetime.fromisoformat(use_end.replace("Z", "+00:00")):
        raise ValueError("use_start must not be after use_end")
    if not system_ref:
        raise ValueError("system_ref: required (which high-risk system is this?)")
    payload: dict = {"use_start": use_start, "use_end": use_end,
                     "system_ref": system_ref}
    if reference_db:
        payload["reference_db"] = str(reference_db)
    if input_digest:
        if not _SHA256.match(input_digest):
            raise ValueError("input_digest: must be a sha256 hex digest (64 "
                             "hex chars) — seal the DIGEST, not the data")
        payload["input_digest"] = input_digest
    if context:
        payload["context"] = context
    return payload


def verification_event(*, human_verifier: str, decision: str,
                       use_seq: int | None = None, **context) -> dict:
    """art. 12(3)(d) / art. 14(5): a natural person verified the output."""
    if not human_verifier or not human_verifier.strip():
        raise ValueError("human_verifier: required (art. 14(5) identification)")
    if not decision or not decision.strip():
        raise ValueError("decision: required (what did the verification conclude?)")
    payload: dict = {"human_verifier": human_verifier.strip(),
                     "decision": decision.strip()}
    if use_seq is not None:
        if not isinstance(use_seq, int) or use_seq < 1:
            raise ValueError("use_seq: must reference the seq of the ai_use event")
        payload["use_seq"] = use_seq
    if context:
        payload["context"] = context
    return payload


def incident_event(*, severity: str, description: str,
                   detected_at: str, **context) -> dict:
    """art. 55(1)(c) / art. 73: keep track of, document — the sealed incident."""
    if severity not in ("minor", "serious"):
        raise ValueError("severity: 'minor' or 'serious' (art. 73 threshold)")
    if not description or not description.strip():
        raise ValueError("description: required")
    payload: dict = {"severity": severity,
                     "description": description.strip(),
                     "detected_at": _iso("detected_at", detected_at)}
    if context:
        payload["context"] = context
    return payload


def annexe_iv_2f(events: list[dict], report: dict, public_key: str) -> str:
    """Generates the "logging characteristics" description required by
    Annexe IV §2(f): what is logged, how it is protected, how to verify —
    filled with THIS journal's actual facts, not boilerplate."""
    types: dict[str, int] = {}
    for ev in events:
        types[ev["type"]] = types.get(ev["type"], 0) + 1
    hist = "\n".join(f"- `{t}` ×{n}" for t, n in sorted(types.items())) or "- (empty journal)"
    # Evidence grades (issue #51 — mickyarun): every class present in THIS
    # journal is labeled with its grade, its proof, and whose obligation
    # backs it — the disclosure cannot hide a grade behind a sentence.
    if types:
        grade_rows = "\n".join(
            f"| `{t}` ×{n} | {g['grade']} — {g['label']} | {g['proof']} | {g['obligation']} |"
            for t, n in sorted(types.items())
            for g in [evidence_grade(t)])
    else:
        grade_rows = "| (empty journal) | — | — | — |"
    anchors = [ev for ev in events if ev["type"] == "anchor"]
    tsas = sorted({t.get("tsa", "?")
                   for ev in anchors
                   for t in (ev["payload"].get("tokens") or [ev["payload"]])})
    witnesses = ", ".join(f"`{t}`" for t in tsas) if tsas else \
        "none yet — anchoring is configured via `NOIREBOX_TSA_PROFILES` (ADR 008)"
    mapping = "\n".join(
        f"| {m['article']} | {m['requirement']} | `{m['event']}` | "
        f"{', '.join('`' + f + '`' for f in m['fields'])} |"
        for m in ART12_MAPPING)
    return f"""# Annexe IV §2(f) — logging characteristics

Automatic record-keeping per Regulation (EU) 2024/1689 art. 12, produced
from the journal itself on {datetime.now(timezone.utc).isoformat(timespec="seconds")}.

## Event types sealed in this journal

{hist}

## Art. 12(3) field mapping

| Article | Requirement | Event | Fields |
|---|---|---|---|
{mapping}

## Evidence grades (ADR 022 — obligation, not immunity)

Every event class states the grade of the proof it carries and WHOSE
OBLIGATION backs it. The evidence exists to prove an obligation was met —
never to shield the operator from it. "No one can impose a cost here" means
the evidence is voluntary.

| Event class | Grade | Proof | Whose obligation backs it |
|---|---|---|---|
{grade_rows}

## Integrity design (why these logs can be trusted)

- Every event is hash-chained (each event seals the previous hash) and
  signed (Ed25519); the chain recomputes offline.
- The chain head is periodically anchored to independent timestamp
  authorities (RFC 3161, ADR 006/008): {witnesses}.
- Only the head HASH ever leaves the infrastructure — no personal data
  transits to the witnesses; input data is sealed as digests (minimization).
- Anchoring is retroactive: one external anchor seals the whole prior chain;
  regular anchoring bounds the falsifiable window to the tail.

## How to verify (auditor)

Public key (Ed25519, hex): `{public_key}`

1. Obtain the verifier from the public repository (pinned version).
2. Run it against `export.json` from this pack.
3. Verifier report in this pack: `verifier_report.json`
   (valid={report.get("valid")}, {report.get("nb_events_checked")} events,
   {report.get("anchors_checked")} witness tokens checked,
   {report.get("anchors_pinned")} against pinned roots).

This description is generated from the journal itself — regenerate it at
any time with `noirebox audit-pack <dir>` and compare.
"""


def audit_pack(store, key, outdir) -> dict:
    """Writes the auditor pack: export.json + verifier_report.json +
    ANNEXE-IV-2f.md. Returns the verifier report. Exit non-zero upstream if
    the report says the chain is broken."""
    from pathlib import Path

    from .attestation import build_attestation

    events = store.all()
    export = {"format_version": 1, "public_key": key.public_hex(),
              "events": events, "attestation": build_attestation(store, key)}

    from verifier.verifier import verify_export  # repo layout: verifier/ at the root

    report = verify_export(export)

    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "export.json").write_text(
        json.dumps(export, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "verifier_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "ANNEXE-IV-2f.md").write_text(
        annexe_iv_2f(events, report, key.public_hex()), encoding="utf-8")
    return report
