"""The keyholder — the operator's key lives in a process the agent is not.

ADR 020 says keys are per PROCESS; until now the code read a PEM file
(`db_path + ".key"`) or `NOIREBOX_KEY_PEM` — anything that could read the
file could BE the operator ("a premise, not a cipher", howcani's audit of
the floor). The keyholder inverts the custody: the key loads ONCE into
this daemon's memory and never leaves it; signers get a unix socket that
answers one verb — sign these bytes. The key material stops being a fact
about the filesystem; the socket path becomes the fact.

Protocol `noirebox-keyholder/0.1` — newline-delimited JSON, one request
per connection:

    request   {"protocol": "noirebox-keyholder/0.1",
               "op": "sign" | "describe",
               "data": "<hex>"}            # sign: the exact bytes to sign
    response {"signature": "<hex>", "public_hex": "<hex>",
              "peer_uid": <int|null>, "peer_uid_checked": <bool>}
    error    {"error": "<reason>"}

`sign` keeps `KeyPair.sign` semantics EXACTLY — the daemon signs the bytes
received, so `SocketSigner.sign(data)` produces the same deterministic
signature the key would have produced in-process, and every existing
verifier (chain, cross-chain, receipts) reads the journal unchanged.

Honest boundary (the floor, re-priced): the socket is the new, NARROWER
premise — reachability of one path replaces readability of the key bytes.
`--allow-uid` gates the peer by uid on Linux and FAILS CLOSED where the
platform cannot report the peer (the check was asked for; not running it
is a refusal, never an assumption). A deployment that wants "the agent
cannot sign" mounts everything EXCEPT the socket: reachability, not
readability, becomes the assertion — and after start, the PEM file can be
removed from the agent-reachable volume entirely: the daemon holds the
material in memory only.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading

PROTOCOL = "noirebox-keyholder/0.2"
_MAX_LINE = 8192  # a signature request is small by construction: event
                  # hashes are 32 bytes; anything bigger is refused, the
                  # socket is an oracle for THIS journal's signatures


class KeyHolderError(Exception):
    """A keyholder request failed — refused, malformed, or unreachable."""


def _peer_uid(sock: socket.socket) -> tuple[int | None, bool]:
    """The connected peer's uid, and whether the platform could TELL.

    (None, False) means the check did not run — callers must treat that as
    a refusal when a uid gate was requested, never as a pass."""
    if sys.platform == "linux":
        try:
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            return int(uid), True
        except OSError:
            return None, False
    return None, False


class KeyHolder:
    """Serves one loaded key over a unix socket: `sign` and `describe`,
    nothing else. The private bytes never cross the boundary."""

    def __init__(self, key, socket_path: str, *,
                 allow_uid: int | None = None):
        self._key = key
        self.socket_path = str(socket_path)
        self.allow_uid = allow_uid

    # -- request handling ------------------------------------------------

    def handle_line(self, line: bytes,
                    peer: tuple[int | None, bool] = (None, False)) -> dict:
        """One request line → one response dict. Pure: tests call this
        directly; the socket loop is transport."""
        try:
            req = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"error": "request is not valid JSON"}
        if not isinstance(req, dict):
            return {"error": "request must be a JSON object"}
        if req.get("protocol") != PROTOCOL:
            return {"error": f"unknown protocol — this socket speaks {PROTOCOL}"}
        uid, uid_checked = peer
        if self.allow_uid is not None:
            if not uid_checked:
                return {"error": "a uid gate was requested but the peer uid "
                                 "is not checkable on this platform — "
                                 "refusing (fail closed)"}
            if uid != self.allow_uid:
                return {"error": f"peer uid {uid} is not the allowed "
                                 f"operator uid {self.allow_uid}"}
        gate_configured = self.allow_uid is not None
        op = req.get("op")
        if op == "describe":
            return {"protocol": PROTOCOL,
                    "public_hex": self._key.public_hex(),
                    "peer_uid": uid, "peer_uid_checked": uid_checked,
                    "uid_gate_configured": gate_configured}
        if op == "sign":
            data_hex = req.get("data")
            if not isinstance(data_hex, str):
                return {"error": "sign requires data (hex)"}
            try:
                data = bytes.fromhex(data_hex)
            except ValueError:
                return {"error": "data is not valid hex"}
            return {"signature": self._key.sign(data),
                    "public_hex": self._key.public_hex(),
                    "peer_uid": uid, "peer_uid_checked": uid_checked,
                    "uid_gate_configured": gate_configured}
        return {"error": f"unknown op {op!r} — sign or describe"}

    # -- socket loop ------------------------------------------------------

    def serve_forever(self, stop_event: threading.Event | None = None,
                      poll_seconds: float = 0.2,
                      ready_event: threading.Event | None = None) -> None:
        """Binds, listens, serves one request per connection until the stop
        event is set. The socket file is created 0600 — the filesystem, not
        the protocol, is the first gate. `ready_event` is set the instant
        the socket is listening — a client waits on the event, not on a
        file-existence guess."""
        stop = stop_event or threading.Event()
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(self.socket_path)
            os.chmod(self.socket_path, 0o600)
            server.listen(8)
            if ready_event is not None:
                ready_event.set()
            server.settimeout(poll_seconds)
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                with conn:
                    self._serve_connection(conn)
        finally:
            server.close()
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)

    def _serve_connection(self, conn: socket.socket) -> None:
        conn.settimeout(10.0)
        chunks = []
        total = 0
        while total < _MAX_LINE:
            try:
                chunk = conn.recv(_MAX_LINE - total)
            except socket.timeout:
                return
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\n" in chunk:
                break
        joined = b"".join(chunks)
        if b"\n" not in joined:
            return  # no terminator within the cap: oversized, dropped —
            # an oracle for small signatures only, never a general service
        line = joined.split(b"\n", 1)[0]
        peer = _peer_uid(conn)
        try:
            resp = self.handle_line(line, peer)
        except Exception as exc:  # a handler bug must not kill the daemon
            resp = {"error": f"internal error: {exc}"}
        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))


class SocketSigner:
    """The drop-in signer: `.sign(data)` + `.public_hex()`, the two methods
    every writer path already calls. Signing happens by ASKING — the bytes
    to sign travel over the socket, the key material never does."""

    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = str(socket_path)
        self.timeout = timeout
        self._public_hex: str | None = None
        self._describe: dict | None = None

    def _request(self, payload: dict) -> dict:
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(self.timeout)
            client.connect(self.socket_path)
            try:
                client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = client.recv(_MAX_LINE)
                    if not chunk:
                        break
                    buf += chunk
            finally:
                client.close()
        except OSError as exc:
            raise KeyHolderError(
                f"keyholder unreachable at {self.socket_path}: {exc}") from exc
        try:
            resp = json.loads(buf.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KeyHolderError("keyholder response is not valid JSON") from exc
        if "error" in resp:
            raise KeyHolderError(f"keyholder refused: {resp['error']}")
        return resp

    def sign(self, data: bytes) -> str:
        """Signs bytes exactly like KeyPair.sign — the daemon signs what it
        receives, so the deterministic signature matches the key's own."""
        resp = self._request({"protocol": PROTOCOL, "op": "sign",
                              "data": data.hex()})
        return str(resp["signature"])

    def describe(self) -> dict:
        """The daemon's own account of itself — identity, whether the uid
        check RAN (`peer_uid_checked`), and whether a gate is CONFIGURED
        (`uid_gate_configured`, v0.2.9 — 3hl4l: the platform's ability to
        check is one fact; the deployment's gate is the other, and the
        daemon knows both while the caller could only see one).

        Derive the disclosure value with `uid_gate()`, never from
        `peer_uid_checked` alone: an UNGATED daemon on a checkable
        platform reports checked=True — the platform could tell, the
        daemon checks nothing."""
        if self._describe is None:
            self._describe = self._request({"protocol": PROTOCOL,
                                            "op": "describe"})
        return self._describe

    def uid_gate(self) -> str:
        """The disclosure's gate value, derived from the daemon's account
        of BOTH facts (3hl4l's ask — 'checked' stops meaning "the
        platform could" by accident):

        - "off" — no gate configured: nobody's uid was ever consulted
        - "enforced" — a gate is configured and THIS peer passed it
        - "unavailable(<platform>)" — a gate is configured but the
          platform cannot check peers; the daemon refused this peer
          fail-closed (3hkpp, darwin)

        A refused peer never receives a describe at all — the refusal is
        the enforcement — so "enforced" from a refusal means exactly what
        the peer experienced."""
        import sys
        try:
            d = self.describe()
        except KeyHolderError as exc:
            msg = str(exc)
            if "uid gate was requested" in msg:
                return f"unavailable({sys.platform})"
            if "not the allowed operator" in msg:
                return "enforced"  # to THIS peer: the refusal IS enforcement
            raise
        return ("enforced" if d["uid_gate_configured"] else "off")

    def public_hex(self) -> str:
        """The SIGNER's identity, learned from the daemon — the out-of-band
        pin value: read it from the process that holds the key, never from
        the journal it sealed."""
        if self._public_hex is None:
            self._public_hex = str(self._request(
                {"protocol": PROTOCOL, "op": "describe"})["public_hex"])
        return self._public_hex
