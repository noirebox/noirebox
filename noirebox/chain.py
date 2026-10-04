from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


GENESIS = "0" * 64


def canonical(obj: object) -> bytes:
    """Deterministic canonical serialization: identical bytes on every machine.

    The hash is computed over these bytes — key order or whitespace drifting
    across machines would break third-party verification with no tampering
    at all. Sorted keys, no superfluous whitespace, explicit UTF-8.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_event_hash(seq: int, ts: str, type_: str, payload: dict, prev_hash: str) -> str:
    """Hex SHA-256 hash committing the entire content of the event."""
    core = {"seq": seq, "ts": ts, "type": type_, "payload": payload, "prev_hash": prev_hash}
    return hashlib.sha256(canonical(core)).hexdigest()


class KeyPair:
    """The instance's Ed25519 key pair.

    The private key is persisted as PEM with chmod 600: only the server
    process reads it. The public key travels in every export/attestation —
    it is all a third party needs.
    """

    def __init__(self, private_key: Ed25519PrivateKey):
        self._priv = private_key
        self._pub = private_key.public_key()

    @classmethod
    def generate(cls) -> KeyPair:
        """Factory: generates a new key pair."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: str) -> KeyPair:
        """Loads the PEM key if it exists, otherwise generates and writes it.

        Created via os.open(..., 0o600) — permissions set atomically, never
        created-then-chmod'ed: a key file world-readable for even an instant
        would be a vulnerability. Two processes racing at first boot never
        end up with two keys: the loser of the O_EXCL race loads the winner's
        PEM (one journal, one key).
        """
        if os.path.exists(path):
            return cls._load_pem(path)
        kp = cls.generate()
        pem = kp._priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return cls._load_pem(path)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        return kp

    @classmethod
    def _load_pem(cls, path: str) -> KeyPair:
        with open(path, "rb") as f:
            priv = load_pem_private_key(f.read(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError(f"{path} does not contain an Ed25519 key")
        return cls(priv)

    def public_hex(self) -> str:
        """Public key in hexadecimal — the value embedded in the exports."""
        return self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    @classmethod
    def from_private_pem(cls, pem: bytes) -> KeyPair:
        """Builds the KeyPair from an injected PEM (ADR 018) — the secret
        manager's job is to hand over the same key every boot."""
        priv = load_pem_private_key(pem, password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("NOIREBOX_KEY_PEM does not contain an Ed25519 key")
        return cls(priv)

    def private_bytes_raw(self) -> bytes:
        """Raw private key bytes — seed material for instance-scoped secrets.

        Never leaves the process (no log, no export). The PUBLIC key is the
        opposite: it ships in every attestation, so nothing security-critical
        may ever be derived from it (ADR 014).
        """
        return self._priv.private_bytes_raw()

    def sign(self, data: bytes) -> str:
        """Signs bytes, returns the signature in hexadecimal."""
        return self._priv.sign(data).hex()

    def verify(self, signature_hex: str, data: bytes) -> bool:
        """Verifies with THIS instance's public key (self-verification)."""
        try:
            self._pub.verify(bytes.fromhex(signature_hex), data)
            return True
        except (InvalidSignature, ValueError):
            return False


@dataclass
class Event:
    """A journal event."""

    seq: int
    ts: str
    type: str
    payload: dict
    prev_hash: str
    event_hash: str
    signature: str

    def as_dict(self) -> dict:
        """Explicit serialization to a dict (JSON-compatible)."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "type": self.type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "event_hash": self.event_hash,
            "signature": self.signature,
        }


def ed25519_verify(public_hex: str, signature_hex: str, data: bytes) -> bool:
    """Verification with the public key alone.

    Returns False instead of raising: a signature failure is an expected
    BUSINESS outcome (tampering), not a programming error.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_event(public_hex: str, ev: dict) -> str | None:
    """Verifies a single event. Convention: `None` = intact, otherwise the reason.

    No exception is raised for a predictable business case — the auditor wants
    a report, not a crash.
    """
    recomputed = compute_event_hash(ev["seq"], ev["ts"], ev["type"], ev["payload"], ev["prev_hash"])
    if recomputed != ev["event_hash"]:
        return "invalid hash (content was modified)"
    if not ed25519_verify(public_hex, ev["signature"], bytes.fromhex(ev["event_hash"])):
        return "invalid signature"
    return None


def verify_chain(public_hex: str, events: list[dict]) -> dict:
    """Verifies the whole chain: order, links, hashes, signatures.

    Stops at the first anomaly and locates it precisely (`first_error.seq`) —
    the auditor wants to know WHERE it breaks.
    """
    prev = GENESIS
    for expected_seq, ev in enumerate(events, start=1):
        if ev["seq"] != expected_seq:
            return {"valid": False, "nb_events": len(events),
                    "first_error": {"seq": ev["seq"], "reason": "broken sequence (reordering or deletion)"}}
        if ev["prev_hash"] != prev:
            return {"valid": False, "nb_events": len(events),
                    "first_error": {"seq": ev["seq"], "reason": f"broken link: prev_hash ≠ hash of event {ev['seq'] - 1}"}}
        reason = verify_event(public_hex, ev)
        if reason is not None:
            return {"valid": False, "nb_events": len(events),
                    "first_error": {"seq": ev["seq"], "reason": reason}}
        prev = ev["event_hash"]
    return {"valid": True, "nb_events": len(events), "first_error": None}


def load_instance_key(db_path: str) -> KeyPair:
    """Key resolution for an instance (ADR 018): NOIREBOX_KEY_PEM — a PEM
    injected by the deployment's secret manager — wins; else the 0600 PEM
    file beside the journal, created on first boot.

    The guard is the point: if a key file ALREADY exists and the injected
    PEM differs, booting would chain new events onto a journal with a
    different key — the chain would verify broken from the next append.
    That is refused loudly at boot, not discovered by an auditor later.
    """
    env_pem = os.environ.get("NOIREBOX_KEY_PEM")
    if not env_pem:
        return KeyPair.load_or_create(db_path + ".key")
    injected = KeyPair.from_private_pem(env_pem.encode())
    key_file = Path(db_path + ".key")
    if key_file.exists():
        on_disk = KeyPair._load_pem(str(key_file))
        if on_disk.public_hex() != injected.public_hex():
            raise RuntimeError(
                "NOIREBOX_KEY_PEM does not match the journal's existing key — "
                "appending with it would break the chain (the journal's identity "
                "is its key); fix the secret or remove the key file deliberately")
    return injected
