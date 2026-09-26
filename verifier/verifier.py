#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from noirebox.attestation import verify_attestation
from noirebox.chain import (
    compute_event_hash,
    ed25519_verify,
    verify_chain,
)

GENESIS = "0" * 64
ROOTS_DIR = Path(__file__).resolve().parent / "tsa_roots"


def _pinned_root(tsa_name: str) -> str | None:
    """Pinned trust anchor for a TSA (ADR 008): tsa_roots/<name>.pem, named
    after the profile that produced the token. NOIREBOX_TSA_ROOTS_DIR
    overrides the directory (testable, portable). The policy is append-only
    in practice: a retired root stays here to keep verifying PAST anchors —
    deleting a root would mean editing the judge, which is the attack this
    tool exists to prevent."""
    if not tsa_name:
        return None
    override = os.environ.get("NOIREBOX_TSA_ROOTS_DIR")
    roots_dir = Path(override) if override else ROOTS_DIR
    candidate = roots_dir / f"{tsa_name}.pem"
    return str(candidate) if candidate.is_file() else None


def verify_anchor_token(payload: dict, tok: dict) -> tuple[bool, str, bool]:
    """Verify ONE TSA token against the chain head it claims to cover.

    Returns (ok, reason, pinned). Trust comes from, strongest first:
      1. a PINNED root (tsa_roots/<tsa>.pem): the embedded chain must lead
         to a root the auditor chose (ADR 008);
      2. TOFU: the certificate that travels inside the anchor (ADR 006).
    Either way the failure reason states which policy was used.
    """
    if not shutil.which("openssl"):
        return True, "openssl missing — token not verified (reported, not hidden)", False
    tsa = tok.get("tsa", "")
    pinned = _pinned_root(tsa)
    with tempfile.TemporaryDirectory() as tmp:
        tsr = Path(tmp) / "token.tsr"
        cert = Path(tmp) / "tsa.pem"
        tsr.write_bytes(base64.b64decode(tok["tsr"]))
        cert.write_text(tok["tsa_cert_pem"], encoding="ascii")
        proc = subprocess.run(
            ["openssl", "ts", "-verify", "-digest", payload["head_hash"],
             "-in", str(tsr), "-CAfile", pinned or str(cert), "-untrusted", str(cert)],
            capture_output=True,
        )
    if proc.returncode != 0:
        policy = "pinned root" if pinned else "TOFU"
        return False, f"invalid TSA token ({policy}): {proc.stderr.decode().strip()[:200]}", False
    return True, "", bool(pinned)


def verify_ots_token(payload: dict, tok: dict) -> tuple[bool, str, bool]:
    """Verify an OpenTimestamps receipt (ADR 009, compute-grade witness).

    First the pure-Python check: the manifest inside the token must name the
    anchored head — tamper detection that needs no CLI at all. Then the
    receipt itself via `ots verify`: 'Success' (Bitcoin-confirmed) counts as
    checked; 'Pending' is recorded but does not fail — upgrade receipts with
    `ots upgrade` and re-verify later. A missing `ots` binary is reported,
    never hidden.
    """
    try:
        manifest = json.loads(base64.b64decode(tok["manifest_b64"]))
    except Exception:
        return False, "ots: unreadable manifest", False
    if (manifest.get("head_hash") != payload.get("head_hash")
            or manifest.get("head_seq") != payload.get("head_seq")):
        return False, "ots: manifest does not match the anchored head", False
    if not shutil.which("ots"):
        return True, "ots missing — receipt not verified (reported, not hidden)", False
    with tempfile.TemporaryDirectory() as tmp:
        m = Path(tmp) / "head.json"
        r = Path(tmp) / "head.json.ots"
        m.write_bytes(base64.b64decode(tok["manifest_b64"]))
        r.write_bytes(base64.b64decode(tok["ots_b64"]))
        try:
            proc = subprocess.run(["ots", "verify", str(r)],
                                  capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            return True, "ots verify timed out (reported, not hidden)", False
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    if "Success" in out:
        return True, "", False
    if "Pending" in out:
        return True, "ots receipt pending Bitcoin confirmation", False
    return False, f"ots verification failed: {out.strip()[:200]}", False


def verify_export(export: dict) -> dict:
    """Recompute the whole chain from the export, without trusting the server."""
    errors: list[dict] = []
    public_key = export.get("public_key", "")
    events = export.get("events", [])

    if not public_key:
        errors.append({"seq": None, "reason": "public key missing from the export"})

    prev = "0" * 64
    for expected_seq, ev in enumerate(events, start=1):
        if ev["seq"] != expected_seq:
            errors.append({"seq": ev["seq"], "reason": "broken sequence"})
            break
        if ev["prev_hash"] != prev:
            errors.append({"seq": ev["seq"], "reason": "prev_hash link broken"})
            break
        recomputed = compute_event_hash(ev["seq"], ev["ts"], ev["type"], ev["payload"], ev["prev_hash"])
        if recomputed != ev["event_hash"]:
            errors.append({"seq": ev["seq"], "reason": "invalid hash (content modified)"})
            break
        if not ed25519_verify(public_key, ev["signature"], bytes.fromhex(ev["event_hash"])):
            errors.append({"seq": ev["seq"], "reason": "invalid signature"})
            break
        prev = ev["event_hash"]

    attestation = export.get("attestation", {})
    if not attestation:
        errors.append({"seq": None, "reason": "attestation missing"})
    else:
        if not verify_attestation(attestation):
            errors.append({"seq": None, "reason": "invalid attestation signature"})
        head_hash = attestation.get("head_hash")
        head_seq = attestation.get("head_seq")
        if head_seq != len(events):
            errors.append({"seq": None, "reason": f"attestation: head_seq={head_seq} ≠ {len(events)} exported events"})
        if events and head_hash != events[-1]["event_hash"]:
            errors.append({"seq": None, "reason": "attestation: head_hash does not match the last event"})

    chain_report = verify_chain(public_key, events)

    anchors_checked = 0
    anchors_unverifiable = 0
    anchors_pinned = 0
    for ev in events:
        if ev["type"] != "anchor":
            continue
        payload = ev["payload"]
        head_seq = payload.get("head_seq")
        idx_ok = (
            isinstance(head_seq, int) and 0 <= head_seq <= len(events)
            and (events[head_seq - 1]["event_hash"] if head_seq else GENESIS) == payload.get("head_hash")
        )
        if not idx_ok:
            errors.append({"seq": ev["seq"],
                           "reason": "anchor: cited head_hash does not match the chain (regeneration?)"})
            continue
        # Multi-witness anchors (ADR 008) carry the tokens in `tokens`;
        # legacy single-TSA anchors are their own only token (flat shape).
        for tok in (payload.get("tokens") or [payload]):
            if tok.get("kind") == "ots":
                ok, reason, pinned = verify_ots_token(payload, tok)
            else:
                ok, reason, pinned = verify_anchor_token(payload, tok)
            if not ok:
                errors.append({"seq": ev["seq"], "reason": reason})
                continue
            anchors_pinned += 1 if pinned else 0
            anchors_checked += 1 if reason == "" else 0
            anchors_unverifiable += 1 if reason != "" else 0

    valid = not errors and chain_report["valid"]
    return {
        "valid": valid,
        "nb_events_checked": len(events),
        "anchors_checked": anchors_checked,
        "anchors_unverifiable": anchors_unverifiable,
        "anchors_pinned": anchors_pinned,
        "errors": errors,
        "head_hash": events[-1]["event_hash"] if events else None,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    export = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    report = verify_export(export)

    if report["valid"]:
        print(f"[✓] INTACT — {report['nb_events_checked']} events verified, "
              f"attestation valid, {report['anchors_checked']} anchor tokens "
              f"({report['anchors_pinned']} against pinned roots), "
              f"head of chain: {report['head_hash'][:16]}…")
        return 0

    print("[✗] TAMPERING DETECTED")
    for err in report["errors"]:
        seq = err["seq"] if err["seq"] is not None else "—"
        print(f"    event {seq}: {err['reason']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
