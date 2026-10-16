"""Prometheus exposition (text format 0.0.4), hand-rolled — zero dependency.

The observability contract is the same honesty contract as everywhere else:
every metric is derivable from the journal itself, and the integrity gauge
says exactly what it checks. `noirebox_head_intact` recomputes the LAST
event's hash and signature only — a cheap liveness-of-custody signal, NOT
the full third-party verification (that is verifier.py's job, and faking
"chain verified" in a scrape would be the exact overclaim this project
exists against; the full check stays offline where it belongs).
"""
from __future__ import annotations

from . import __version__
from .chain import verify_event
from .store import EventStore


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics(store: EventStore, public_key: str) -> str:
    """Renders the journal's metrics in Prometheus text exposition format."""
    lines: list[str] = []
    add = lines.append

    add("# HELP noirebox_build_info Build metadata for this NoireBox instance.")
    add("# TYPE noirebox_build_info gauge")
    add(f'noirebox_build_info{{version="{_escape_label(__version__)}"}} 1')

    events = store.all()
    head_seq = len(events)
    add("# HELP noirebox_events_total Number of sealed events in the journal.")
    add("# TYPE noirebox_events_total gauge")
    add(f"noirebox_events_total {head_seq}")

    add("# HELP noirebox_events_by_type Sealed events, by type.")
    add("# TYPE noirebox_events_by_type gauge")
    by_type: dict[str, int] = {}
    for event in events:
        by_type[event["type"]] = by_type.get(event["type"], 0) + 1
    for type_, count in sorted(by_type.items()):
        add(f'noirebox_events_by_type{{type="{_escape_label(type_)}"}} {count}')

    anchors = by_type.get("anchor", 0)
    add("# HELP noirebox_anchors_total RFC 3161 / OpenTimestamps anchor events sealed.")
    add("# TYPE noirebox_anchors_total gauge")
    add(f"noirebox_anchors_total {anchors}")

    add("# HELP noirebox_incidents_total Guardrail incidents sealed (engine-agnostic).")
    add("# TYPE noirebox_incidents_total gauge")
    add(f"noirebox_incidents_total {by_type.get('incident', 0)}")

    add("# HELP noirebox_fleet_anchors_total Fleet Merkle seals sealed in this journal (ADR 017).")
    add("# TYPE noirebox_fleet_anchors_total gauge")
    add(f"noirebox_fleet_anchors_total {by_type.get('fleet_anchor', 0)}")

    # Light custody check: the LAST event only (hash recomputed + signature
    # verified). Cheap enough to scrape; the full chain check stays the
    # verifier's offline job. An empty journal is trivially intact.
    add("# HELP noirebox_head_intact 1 when the journal's last event recomputes and verifies (light custody check).")
    add("# TYPE noirebox_head_intact gauge")
    head = events[-1] if events else None
    intact = True if head is None else verify_event(public_key, head) is None
    add(f"noirebox_head_intact {1 if intact else 0}")

    return "\n".join(lines) + "\n"
