"""Flow independence as a testable invariant (ADR 021): can one compromise
reach both?

The audit flow and the truth flow are only independent if they share
NOTHING: not the journal file, not the signing key, not any network
endpoint. "Independent" is a claim; this module turns the claim into an
assertion a CI can run:

    from noirebox.independence import Flow, conflicts

    audit = Flow("audit", store_path="audit/.noirebox/journal.db",
                 key_path="audit/.noirebox/journal.db.key",
                 anchor_cadence_min=60)
    truth = Flow("truth", store_path="data/noirebox.db",
                 key_path="data/noirebox.db.key",
                 anchor_cadence_min=60)
    assert conflicts(audit, truth) == []

A non-empty result is the list of shared dependencies — each one a single
compromise that reaches both streams. The clock half of the invariant is
the anchor cadence: a flow that never anchors its own heads inherits the
other flow's clock by default, which is the shared dependency nobody
configures.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Flow:
    """One sealed stream and the resources it touches."""

    name: str
    store_path: str
    key_path: str
    anchor_cadence_min: int | None = None
    hosts: tuple[str, ...] = field(default=())


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def conflicts(a: Flow, b: Flow) -> list[str]:
    """Returns every dependency the two flows SHARE — empty means
    independent. Each entry is one compromise reaching both streams."""
    out: list[str] = []
    if _real(a.store_path) == _real(b.store_path):
        out.append("store: both flows write the same journal file — "
                   "rewriting the truth rewrites the evidence")
    if _real(a.key_path) == _real(b.key_path):
        out.append("key: both flows sign with the same key — 'a name, not "
                   "a role' requires per-writer keys (ADR 021)")
    shared_hosts = sorted(set(a.hosts) & set(b.hosts))
    if shared_hosts:
        out.append(f"network: both flows reach {shared_hosts} — one "
                   f"compromised endpoint serves both")
    for flow in (a, b):
        if flow.anchor_cadence_min is None:
            out.append(f"clock: flow {flow.name!r} never anchors its own "
                       f"heads — its clock is the other flow's by default")
    return out
