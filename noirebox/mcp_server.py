from __future__ import annotations

import json
import os
import sys

from . import __version__
from .attestation import build_attestation
from .chain import KeyPair, verify_chain
from .guardrail import scan_transcript
from .store import EventStore

SERVER_INFO = {"name": "noirebox", "version": __version__}
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

_JSON_SCHEMA_STRING = {"type": "string"}

TOOLS = [
    {
        "name": "noirebox_scan",
        "description": "NoireBox guardrail: detects injections in a text "
                       "(transcript, prompt) and logs the incident to the tamper-proof chain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": _JSON_SCHEMA_STRING,
                "meeting_id": _JSON_SCHEMA_STRING,
            },
            "required": ["text"],
        },
    },
    {
        "name": "noirebox_log_event",
        "description": "Adds a signed event to the NoireBox tamper-proof journal.",
        "inputSchema": {
            "type": "object",
            "properties": {"type": _JSON_SCHEMA_STRING, "payload": {"type": "object"}},
            "required": ["type"],
        },
    },
    {
        "name": "noirebox_verify",
        "description": "Verifies the full integrity of the NoireBox chain (order, links, signatures).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "noirebox_attestation",
        "description": "Signed attestation of the current state of the NoireBox journal.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _dispatch_tool(name: str, args: dict, store: EventStore, key: KeyPair) -> str:
    """Runs a tool, returns the serialized result (text shown to the client)."""
    if name == "noirebox_scan":
        incidents = [i.as_dict() for i in scan_transcript(args["text"])]
        event = store.append(
            "incident",
            {"meeting_id": args.get("meeting_id", "mcp"), "nb_incidents": len(incidents),
             "incidents": incidents, "source": "mcp"},
            key,
        )
        return json.dumps({"incident_event_seq": event.seq, "nb_incidents": len(incidents),
                           "incidents": incidents}, ensure_ascii=False)
    if name == "noirebox_log_event":
        event = store.append(args["type"], args.get("payload", {}), key)
        return json.dumps({"seq": event.seq, "event_hash": event.event_hash}, ensure_ascii=False)
    if name == "noirebox_verify":
        return json.dumps(verify_chain(key.public_hex(), store.all()), ensure_ascii=False)
    if name == "noirebox_attestation":
        return json.dumps(build_attestation(store, key), ensure_ascii=False)
    raise KeyError(name)


def handle_message(msg: dict, store: EventStore, key: KeyPair) -> dict | None:
    """Handles a JSON-RPC message. Returns None for notifications
    (no response expected — that is the protocol)."""
    method = msg.get("method", "")
    msg_id = msg.get("id")

    if method == "initialize":
        requested = msg.get("params", {}).get("protocolVersion", DEFAULT_PROTOCOL_VERSION)
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "protocolVersion": requested,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }}
    if method.startswith("notifications/"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params", {})
        try:
            text = _dispatch_tool(params["name"], params.get("arguments", {}), store, key)
        except KeyError:
            return _error(msg_id, -32602, f"unknown tool: {params.get('name')}")
        except (TypeError, ValueError) as exc:
            return _error(msg_id, -32602, f"invalid arguments: {exc}")
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "content": [{"type": "text", "text": text}]
        }}
    return _error(msg_id, -32601, f"unknown method: {method}")


def main() -> None:
    path = os.environ.get("NOIREBOX_DB", "data/noirebox.db")
    store = EventStore(path)
    key = KeyPair.load_or_create(path + ".key")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            response = _error(None, -32700, "invalid JSON")
        else:
            response = handle_message(msg, store, key)
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
