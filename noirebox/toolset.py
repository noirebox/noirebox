"""The toolset baseline (issue #50 — bloqarl, Docker thread): the lockfile
nobody writes.

Tool descriptions are instructions the MODEL reads. They ride outside the
image pin — runtime-produced at registration time — and for remote MCP
servers, nothing is pinned at all. A changed description is a changed
instruction surface, and nothing in the deployment noticed. This module
gives that surface the same tamper-evidence as everything else:

  - capture the toolset (the `listTools` response's tools array) at
    registration time, hash it with the journal's own canonical
    serializer, and seal it as the REVIEWED baseline
    (`toolset-baseline/0.1`);
  - two-writer by construction (ADR 021): the baseline is sealed by
    whoever REVIEWED it — `reviewed_by`, a name, not a role — never by
    the process that connects. The connecting process holding the key
    that seals its own instruction surface is the shared-dependency test
    one layer up;
  - on every session start, diff the served definitions against the
    baseline: a changed description or input schema, an added tool, a
    removed tool — each is a finding (`toolset_changed`). "The model
    reads different instructions than the ones that were reviewed" is
    the whole finding; the note names the tool and the direction.
"""
from __future__ import annotations

import hashlib

from .chain import canonical
from .reconcile import Finding


def _tool_digest(tool: dict) -> str:
    return hashlib.sha256(canonical(tool)).hexdigest()


def _validated_tools(tools: list[dict]) -> list[dict]:
    if not isinstance(tools, list) or not tools:
        raise ValueError("toolset: tools must be a non-empty list — "
                         "a baseline over nothing pins nothing")
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError("toolset: every tool must be an object")
        name = tool.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("toolset: every tool needs a non-empty name")
        if name in seen:
            raise ValueError(f"toolset: duplicate tool name {name!r} — "
                             f"the diff would be ambiguous")
        seen.add(name)
    return tools


def seal_toolset_baseline(store, key, *, server: str, tools: list[dict],
                          reviewed_by: str) -> dict:
    """Seals the REVIEWED baseline of a server's toolset as a
    `toolset_baseline` event: the whole-set hash plus a per-tool digest
    table, so the diff names the tool, not just "something changed".

    `reviewed_by` is required and is a NAME, not a role (ADR 021): the
    two-writer caveat is structural — whoever reviewed the instructions is
    not the process that connects to the server at session time."""
    if not str(server).strip():
        raise ValueError("toolset: server name is required")
    if not str(reviewed_by or "").strip():
        raise ValueError("toolset: reviewed_by is required — the baseline is "
                         "sealed by whoever REVIEWED it, never by the process "
                         "that connects (a name, not a role — ADR 021)")
    tools = _validated_tools(tools)
    table = sorted(({"name": t["name"], "sha256": _tool_digest(t)}
                    for t in tools), key=lambda row: row["name"])
    whole = hashlib.sha256(
        canonical([row["sha256"] for row in table])).hexdigest()
    return store.append("toolset_baseline", {
        "schema": "toolset-baseline/0.1",
        "server": server,
        "reviewed_by": reviewed_by,
        "tools_count": len(tools),
        "tools_sha256": whole,
        "tools": table,
    }, key)


def latest_baseline(events: list[dict], server: str) -> dict | None:
    """The most recent `toolset_baseline` payload for this server, or None
    (checking against no baseline is refused upstream — never silently
    'clean')."""
    found = None
    for e in events:
        if e.get("type") == "toolset_baseline" \
                and e.get("payload", {}).get("server") == server:
            found = e["payload"]
    return found


def check_toolset_baseline(baseline: dict, served: list[dict]) -> list[Finding]:
    """Diffs the SERVED toolset against the sealed baseline — the
    session-start gate. Every drift is a `toolset_changed` finding whose
    note names the tool and the direction:

      changed  — same name, different canonical bytes: the model now reads
                 different instructions than the ones that were reviewed;
      added    — a capability the reviewer never saw;
      removed  — a capability silently gone.
    """
    served = _validated_tools(served)
    reviewed = {row["name"]: row["sha256"] for row in baseline.get("tools", [])}
    served_now = {t["name"]: _tool_digest(t) for t in served}

    findings: list[Finding] = []
    for name in sorted(reviewed):
        if name not in served_now:
            findings.append(Finding(
                "toolset", "toolset_changed", f"{baseline.get('server', '?')}:{name}",
                note="tool removed since review — capability silently gone"))
    for name in sorted(served_now):
        if name not in reviewed:
            findings.append(Finding(
                "toolset", "toolset_changed", f"{baseline.get('server', '?')}:{name}",
                note="tool added since review — a capability the reviewer "
                     "never saw"))
        elif served_now[name] != reviewed[name]:
            findings.append(Finding(
                "toolset", "toolset_changed", f"{baseline.get('server', '?')}:{name}",
                note="tool changed since review — the model now reads "
                     "different instructions than the ones that were reviewed"))
    return findings
