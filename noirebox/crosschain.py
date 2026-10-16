"""Cross-chain reconciliation (ADR 024, issue #41) — consumption edges,
partial order, fan-in.

Agents consume each other's outputs. Until now those dependencies lived in
nobody's journal: agent A acts on agent B's report, and when B's output is
later superseded or revealed orphaned, A's decision — and every downstream
decision built on A's — sits in an intact chain with no thread to pull. A
fleet of journals is a graph with no edges. This module adds the edges.

The vocabulary (sealed like everything else):

  consumption_edge (consumer half)  {edge_id, producer, consumed_head
                                     [, consumed_seq]} — "I consumed the
                                     producer's output, whose chain head AS
                                     OBSERVED was this"
  consumption_edge (producer half)  {edge_id, consumer} — "my output was
                                     consumed, by this journal". The
                                     dependency enters BOTH journals (ADR
                                     024 §1); a half missing on either side
                                     is `unrecorded_edge` — silence is the
                                     starting fact (§6).
  supersede                         {superseded_head, reason} — a producer
                                     that supersedes owes the graph a
                                     supersede event (§5); it is the proof
                                     of staleness, as the consumer's intact
                                     chain is the proof of belief.

The invariants are DERIVED from anchors, never asserted by the agent (§3):

  stale_consumed_head — the consumed head is absent from the producer's
      chain (rewritten away, or never was), or a supersede event killed it;
  temporal_inversion  — the consumed event's seal time postdates the anchor
      covering the consumer's edge: per the anchors, the consumption
      preceded the thing consumed (fraud@41 consumed by underwriting@39 —
      the same species as `orphan_outcome`, across chains);
  unrecorded_edge     — one journal sealed its half, the other never did.

Honest derivations, stated:

- a consumed head present in the producer's chain but NOT YET covered by an
  anchor is UNDERIVABLE, not stale: anchoring cadence is ops, not
  admissibility (the per-call latency tax stays rejected, §4) — an anchor
  seals the whole past, the unanchored queue is the only open window;
- the anchor time used for the inversion check is the covering anchor
  event's own seal time — journal-local, so the comparison assumes roughly
  honest local clocks; the RFC 3161 genTime rides inside the token and the
  verifier is where token-level time checks belong. No anchor covering the
  edge → no temporal claim: the anchors are the only clock;
- temporal position is a RELATION between two sealed chains — there is no
  epoch field to write (§4, the rejected alternative).

Fan-in (§5): when a head dies, the finding propagates along the RECORDED
edges — a journal tainted from its stale edge taints every later head of
its own that gets consumed — so the blast radius is a precise path set (it
rides in the finding's note), not "everything downstream, maybe".
"""
from __future__ import annotations

import re
from datetime import datetime

from .reconcile import Finding

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _require_head(value: object, what: str) -> str:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise ValueError(f"crosschain: {what} must be a 64-char sha256 hex "
                         f"digest — a chain head AS OBSERVED, not a claim")
    return value


def seal_consumption_edge(store, key, *, edge_id: str, producer: str,
                          consumed_head: str,
                          consumed_seq: int | None = None) -> dict:
    """Seals the CONSUMER half of a consumption edge (ADR 024 §1): the
    consumption itself is a sealable event carrying the producer's chain
    head as observed. Sealed in the consumer's journal."""
    if not str(edge_id).strip():
        raise ValueError("crosschain: edge_id is required — both halves "
                         "correlate on it")
    if not str(producer).strip():
        raise ValueError("crosschain: producer is required — the name of the "
                         "journal the output came from")
    _require_head(consumed_head, "consumed_head")
    payload: dict = {"edge_id": edge_id, "producer": producer,
                     "consumed_head": consumed_head}
    if consumed_seq is not None:
        if not isinstance(consumed_seq, int) or consumed_seq < 1:
            raise ValueError("crosschain: consumed_seq must be a positive int")
        payload["consumed_seq"] = consumed_seq
    return store.append("consumption_edge", payload, key)


def seal_produced_edge(store, key, *, edge_id: str, consumer: str) -> dict:
    """Seals the PRODUCER half of a consumption edge (ADR 024 §1): what was
    consumed, by whom. Sealed in the producer's journal — the dependency
    enters BOTH journals, and a half missing on either side is the finding
    (`unrecorded_edge`), not a shrug."""
    if not str(edge_id).strip():
        raise ValueError("crosschain: edge_id is required — both halves "
                         "correlate on it")
    if not str(consumer).strip():
        raise ValueError("crosschain: consumer is required — the name of the "
                         "journal that consumed the output")
    return store.append("consumption_edge",
                        {"edge_id": edge_id, "consumer": consumer}, key)


def seal_supersede(store, key, *, superseded_head: str, reason: str) -> dict:
    """A producer that supersedes owes the graph a supersede event (ADR 024
    §5) — the proof of staleness the fan-in correlates against the
    consumer's intact chain (the proof of belief)."""
    _require_head(superseded_head, "superseded_head")
    if not str(reason).strip():
        raise ValueError("crosschain: supersede requires a reason — the graph "
                         "propagates it verbatim")
    return store.append("supersede",
                        {"superseded_head": superseded_head, "reason": reason},
                        key)


def _edge_half(event: dict) -> tuple[str, str]:
    """('consumer', producer-journal) or ('producer', consumer-journal) for
    a consumption_edge event. A malformed edge is the sealer's bug and is
    surfaced loudly at reconciliation time, never skipped silently."""
    payload = event.get("payload", {})
    edge_id = str(payload.get("edge_id", "")).strip()
    if not edge_id:
        raise ValueError(f"crosschain: consumption_edge at seq "
                         f"{event.get('seq')} has no edge_id — both halves "
                         f"correlate on it")
    if payload.get("consumed_head"):
        who = str(payload.get("producer", "")).strip()
        if not who:
            raise ValueError(f"crosschain: edge {edge_id!r} carries "
                             f"consumed_head but no producer name")
        return "consumer", who
    who = str(payload.get("consumer", "")).strip()
    if not who:
        raise ValueError(f"crosschain: edge {edge_id!r} is malformed — "
                         f"neither half (no consumed_head, no consumer)")
    return "producer", who


def _valid_anchors(events: list[dict]) -> list[tuple[int, str]]:
    """(head_seq, anchor ts) for every anchor event whose cited head
    recomputes to the chain's event at that seq — the same verification the
    third-party verifier performs; unprovable anchors are ignored."""
    by_seq = {e["seq"]: e for e in events}
    out = []
    for e in events:
        if e.get("type") != "anchor":
            continue
        head_seq = e.get("payload", {}).get("head_seq")
        head_hash = e.get("payload", {}).get("head_hash")
        if (isinstance(head_seq, int) and head_seq in by_seq
                and by_seq[head_seq]["event_hash"] == head_hash):
            out.append((head_seq, e["ts"]))
    return out


def _anchor_ts_covering(events: list[dict], seq: int) -> str | None:
    """Ts of the EARLIEST valid anchor covering `seq` — the moment `seq` was
    externally sealed. None when no anchor covers it: nothing time-derived
    is asserted then (the anchors are the only clock, ADR 024 §3)."""
    times = [ts for head_seq, ts in _valid_anchors(events) if head_seq >= seq]
    return min(times) if times else None


def _anchored_upto(events: list[dict]) -> int | None:
    """Seq of the highest head provably anchored (latest valid anchor)."""
    seqs = [head_seq for head_seq, _ in _valid_anchors(events)]
    return max(seqs) if seqs else None


def _find_event(events: list[dict], event_hash: str) -> dict | None:
    for e in events:
        if e.get("event_hash") == event_hash:
            return e
    return None


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def reconcile_crosschain(journals: dict[str, list[dict]]) -> list[Finding]:
    """Runs the cross-chain invariants (ADR 024) over a fleet of journals.

    `journals` maps journal NAME → events (what `store.all()` returns); the
    names are what the edges' `producer`/`consumer` fields refer to. An edge
    referencing a name not in the dict is refused loudly — reconciling a
    graph you only half-loaded would produce findings that look like
    absences.

    Findings (correlation id = edge_id):
      unrecorded_edge      — one half sealed, the other never was (§1/§6);
      stale_consumed_head  — the consumed head is gone from the producer's
                             chain or superseded; on propagation the note
                             carries the precise blast path (§5);
      temporal_inversion   — the consumed event's seal time postdates the
                             anchor covering the consumer's edge (§3).
    Underivable is clean, never guessed: no anchor coverage or no producer
    anchor means no temporal/ancestry claim.
    """
    # ── collect the edges: edge_id → (own journal name, event) ───────────
    consumer_edges: dict[str, tuple[str, dict]] = {}
    producer_edges: dict[str, tuple[str, dict]] = {}
    for name, events in journals.items():
        for e in events:
            if e.get("type") != "consumption_edge":
                continue
            half, other = _edge_half(e)
            edge_id = str(e["payload"]["edge_id"]).strip()
            if other not in journals:
                raise ValueError(f"crosschain: edge {edge_id!r} in {name} "
                                 f"references journal {other!r}, which was not "
                                 f"loaded — reconcile the whole graph or none "
                                 f"of it")
            if half == "consumer":
                consumer_edges.setdefault(edge_id, (name, e))
            else:
                producer_edges.setdefault(edge_id, (name, e))

    findings: list[Finding] = []

    # ── unrecorded halves — silence is the starting fact (§6) ────────────
    for edge_id, (_cname, e) in consumer_edges.items():
        if edge_id not in producer_edges:
            findings.append(Finding(
                "crosschain", "unrecorded_edge", edge_id,
                decision_seq=e["seq"],
                note=f"{e['payload']['producer']} never recorded being "
                     f"consumed — the dependency lives in one journal only"))
    for edge_id, (_pname, e) in producer_edges.items():
        if edge_id not in consumer_edges:
            findings.append(Finding(
                "crosschain", "unrecorded_edge", edge_id,
                decision_seq=e["seq"],
                note=f"{e['payload']['consumer']} never recorded consuming — "
                     f"silence, the first thing the propagation asks"))

    # ── supersede map — the proof of staleness (§5) ──────────────────────
    superseded: dict[str, dict[str, str]] = {}
    for name, events in journals.items():
        killed: dict[str, str] = {}
        for e in events:
            if e.get("type") == "supersede":
                killed[e["payload"]["superseded_head"]] = \
                    e["payload"].get("reason", "")
        superseded[name] = killed

    # ── per-edge invariants: ancestry and temporal admissibility (§3) ────
    # A dead head taints its consumer from the edge's own seq onward
    # (journal → (from_seq, blast path)) — the fan-in seed.
    taint: dict[str, tuple[int, str]] = {}

    for edge_id, (cname, e) in consumer_edges.items():
        pname = e["payload"]["producer"]
        head = e["payload"]["consumed_head"]
        consumed = _find_event(journals[pname], head)

        if consumed is None:
            # Absent from the producer's chain entirely: rewritten away, or
            # the edge was fabricated. The anchors decide WHO is lying; the
            # absence itself is already derivable.
            path = f"{pname} → {cname}#{e['seq']}"
            findings.append(Finding(
                "crosschain", "stale_consumed_head", edge_id,
                decision_seq=e["seq"],
                note=f"consumed head is absent from {pname}'s chain — "
                     f"rewritten away or never was (blast path: {path})"))
            if cname not in taint or e["seq"] < taint[cname][0]:
                taint[cname] = (e["seq"], path)
        else:
            anchored_upto = _anchored_upto(journals[pname])
            if (anchored_upto is not None and consumed["seq"] <= anchored_upto
                    and head in superseded[pname]):
                reason_note = superseded[pname][head] or "no reason given"
                path = f"{pname}#{consumed['seq']} → {cname}#{e['seq']}"
                findings.append(Finding(
                    "crosschain", "stale_consumed_head", edge_id,
                    decision_seq=e["seq"],
                    note=f"consumed head superseded: {reason_note} "
                         f"(blast path: {path})"))
                if cname not in taint or e["seq"] < taint[cname][0]:
                    taint[cname] = (e["seq"], path)
            # Temporal admissibility (§3) — an independent fact, checked
            # whenever the consumed event exists. Queue lag is NOT inversion:
            # only the consumed event's own seal time vs the anchor covering
            # the consumer's edge.
            cover_ts = _anchor_ts_covering(journals[cname], e["seq"])
            if cover_ts is not None and _iso(consumed["ts"]) > _iso(cover_ts):
                findings.append(Finding(
                    "crosschain", "temporal_inversion", edge_id,
                    decision_seq=e["seq"],
                    note=f"consumed event sealed {consumed['ts']}, AFTER the "
                         f"consumption was anchored {cover_ts} — per the "
                         f"anchors, the consumption preceded the thing "
                         f"consumed"))

    # ── fan-in: forward propagation along recorded edges (§5) ────────────
    # A journal tainted from seq S taints every consumer whose recorded edge
    # points at one of its heads sealed at seq ≥ S — to fixpoint.
    seen: set[tuple[str, int]] = set()
    changed = True
    while changed:
        changed = False
        for edge_id, (dname, f) in consumer_edges.items():
            pname = f["payload"]["producer"]
            if pname not in taint:
                continue
            from_seq, src_path = taint[pname]
            consumed = _find_event(journals[pname], f["payload"]["consumed_head"])
            if consumed is None or consumed["seq"] <= from_seq:
                continue
            key = (dname, f["seq"])
            if key in seen:
                continue
            seen.add(key)
            path = f"{src_path} → {pname}#{consumed['seq']} → {dname}#{f['seq']}"
            findings.append(Finding(
                "crosschain", "stale_consumed_head", edge_id,
                decision_seq=f["seq"],
                note=f"downstream of a dead head — blast path: {path}"))
            if dname not in taint or f["seq"] < taint[dname][0]:
                taint[dname] = (f["seq"], path)
                changed = True

    return findings


def crosschain_report(store, key, findings: list[Finding],
                      journals: dict[str, list[dict]]) -> dict:
    """Seals the cross-chain reconciliation report — ALWAYS, clean pass
    included (ADR 019's rule holds across chains too: a checker that only
    journals findings has no proof it ever ran)."""
    by_status: dict[str, int] = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
    report = {
        "schema": "crosschain-reconciliation/0.1",
        "journals_examined": {name: len(events)
                              for name, events in sorted(journals.items())},
        "total_findings": len(findings),
        "findings": [f.__dict__ for f in findings],
        "findings_by_status": by_status,
        "clean_pass": len(findings) == 0,
    }
    from .chain import canonical
    from .witness import canonical_witness

    report["witness"] = canonical_witness(0, canonical(report))
    return store.append("crosschain_reconciliation", report, key)
