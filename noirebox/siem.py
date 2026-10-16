"""SIEM export (CEF + OpenTelemetry): the journal speaks the SOC's dialects.

A tamper-evident journal that doesn't fit the SOC's pipeline is a journal
the SOC ignores. Two formatters over the same events:

  - **CEF** (ArcSight Common Event Format, version 0) — the classic syslog
    sidecar format every legacy SIEM ingests. Escaping follows the CEF
    spec: `\\|`, `\\=`, `\\n`, `\\r` in extension values; full pipes in the
    header fields are replaced, not escaped.
  - **OTLP/JSON** (OpenTelemetry logs resource format) — what modern
    collectors ingest. Each event becomes one log record with the event
    type as the severity-text name, the payload as attributes, and the
    chain coordinates (seq, event_hash, prev_hash) as attributes — so the
    SOC can trace any alert back to the exact sealed event.

Escaping is where SIEM integrations lie: a vendor name containing a pipe
would split a CEF event into two lies. The formatters escape by the book
and are tested against the adversarial cases.
"""
from __future__ import annotations

from . import __version__


def _cef_escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_value(value: str) -> str:
    return (value.replace("\\", "\\\\").replace("=", "\\=")
            .replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r"))


_SEVERITY_BY_TYPE = {
    "incident": 9,            # guardrail catch — the SOC cares first
    "ai_incident": 10,
    "anchor": 3,              # witnessed milestones, low urgency
    "fleet_anchor": 3,
    "reconciliation": 5,
    "reconciliation_policy": 3,
}


def _cef_severity(event_type: str) -> int:
    return _SEVERITY_BY_TYPE.get(event_type, 5)


def to_cef(events: list[dict]) -> str:
    """Renders events as CEF v0 lines (syslog body, no syslog header — the
    collector adds it)."""
    lines = []
    for e in events:
        name = e["type"]
        ext = (f"noireboxSeq={e['seq']} "
               f"noireboxHash={e['event_hash']} "
               f"noireboxPrev={e['prev_hash']} "
               f"fname={_cef_escape_header(name)}")
        for k, v in (e.get("payload") or {}).items():
            if isinstance(v, (str, int, float, bool)):
                ext += f" nk_{_cef_escape_header(str(k))}={_cef_escape_value(str(v))}"
        lines.append(
            f"CEF:0|NoireBox|journal|{__version__}|{name}|"
            f"{_cef_escape_header(name)}|{_cef_severity(name)}|{ext}")
    return "\n".join(lines)


def to_otlp(events: list[dict], service_name: str = "noirebox") -> dict:
    """Renders events as an OTLP/JSON logs resource — POSTable straight to
    an OpenTelemetry collector's /v1/logs."""
    records = []
    for e in events:
        attributes = [
            {"key": "noirebox.seq", "value": {"intValue": str(e["seq"])}},
            {"key": "noirebox.event_hash", "value": {"stringValue": e["event_hash"]}},
            {"key": "noirebox.prev_hash", "value": {"stringValue": e["prev_hash"]}},
            {"key": "event.type", "value": {"stringValue": e["type"]}},
        ]
        for k, v in (e.get("payload") or {}).items():
            if isinstance(v, (str, int, float, bool)):
                key = "intValue" if isinstance(v, int) and not isinstance(v, bool) else \
                    "doubleValue" if isinstance(v, float) else \
                    "boolValue" if isinstance(v, bool) else "stringValue"
                attributes.append({"key": f"payload.{k[:120]}", "value": {key: v}})
        records.append({
            "timeUnixNano": str(e["ts"]),
            "severityText": "WARN" if _cef_severity(e["type"]) >= 9 else "INFO",
            "body": {"stringValue": f"noirebox.{e['type']} seq={e['seq']}"},
            "attributes": attributes,
        })
    return {
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "service.name",
                 "value": {"stringValue": service_name}},
                {"key": "service.version",
                 "value": {"stringValue": __version__}},
            ]},
            "scopeLogs": [{
                "scope": {"name": "noirebox.journal"},
                "logRecords": records,
            }],
        }],
    }
