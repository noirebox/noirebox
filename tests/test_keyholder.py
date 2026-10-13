"""The keyholder (ADR 020, made runtime): the operator's key lives in a
process the agent is not. The daemon answers one verb — sign these bytes —
and the material never crosses the socket. The client is a drop-in signer:
the two methods every writer path already calls."""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
import threading

import pytest

from noirebox.chain import KeyPair, ed25519_verify, verify_chain_multi
from noirebox.keyholder import PROTOCOL, KeyHolder, KeyHolderError, SocketSigner
from noirebox.store import EventStore


class _Daemon:
    """A keyholder on a background thread, for tests."""

    def __init__(self, allow_uid=None, key=None):
        self.key = key or KeyPair.generate()
        # AF_UNIX paths cap at ~104 bytes: pytest's tmp_path is deeper than
        # that on macOS, so the socket lives in a short /tmp dir instead
        self._base = tempfile.mkdtemp(prefix="nbkh_", dir="/tmp")
        self.socket_path = os.path.join(self._base, "kh.sock")
        self.holder = KeyHolder(self.key, self.socket_path,
                                allow_uid=allow_uid)
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.thread = threading.Thread(
            target=self.holder.serve_forever,
            args=(self.stop,), kwargs={"ready_event": self.ready},
            daemon=True)

    def __enter__(self):
        self.thread.start()
        # readiness is SIGNALED by the daemon after listen() — not guessed
        # from the socket file appearing
        if not self.ready.wait(timeout=10):
            raise RuntimeError("keyholder daemon did not become ready")
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=5)
        shutil.rmtree(self._base, ignore_errors=True)
        return False


def test_sign_roundtrip_matches_the_key_itself(tmp_path):
    """Ed25519 is deterministic: the daemon's signature for these bytes IS
    the key's own signature. Same bytes in, same signature out — the socket
    changes the custody, never the math."""
    with _Daemon() as daemon:
        signer = SocketSigner(daemon.socket_path)
        data = os.urandom(32)
        assert signer.sign(data) == daemon.key.sign(data)
        assert ed25519_verify(daemon.key.public_hex(), signer.sign(data),
                              data)
        # identity learned out-of-band: from the process holding the key
        assert signer.public_hex() == daemon.key.public_hex()


def test_signer_plugs_into_the_store_as_a_drop_in(tmp_path):
    """Every writer path accepts anything with .sign() + .public_hex(): a
    journal sealed THROUGH the socket verifies like any other."""
    with _Daemon() as daemon:
        store = EventStore(str(tmp_path / "j.db"))
        signer = SocketSigner(daemon.socket_path)
        store.append("policy_decision",
                     {"decision_id": "d1", "expected_by": "2026-10-14"},
                     signer)
        store.append("provider_response", {"decision_id": "d1"}, signer)
        check = verify_chain_multi([daemon.key.public_hex()], store.all())
        assert check["valid"], check["first_error"]


def test_describe_reports_the_peer_check_honestly(tmp_path):
    """describe is the deployment's out-of-band read: identity + whether
    the uid check ran. It never claims a check it did not perform."""
    with _Daemon() as daemon:
        described = KeyHolder.handle_line(
            daemon.holder,
            json.dumps({"protocol": PROTOCOL, "op": "describe"}).encode(),
            (1234, True))
        assert described["public_hex"] == daemon.key.public_hex()
        assert described["peer_uid"] == 1234
        assert described["peer_uid_checked"] is True
        # no peer info supplied: reported as NOT checked, never implied
        bare = KeyHolder.handle_line(
            daemon.holder,
            json.dumps({"protocol": PROTOCOL, "op": "describe"}).encode())
        assert bare["peer_uid"] is None
        assert bare["peer_uid_checked"] is False


def test_garbage_is_refused_and_the_daemon_stays_up(tmp_path):
    """A malformed request gets an error line, not a dead socket."""
    with _Daemon() as daemon:
        signer = SocketSigner(daemon.socket_path)
        # raw garbage over the socket
        import socket as _s
        client = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        client.settimeout(5)
        client.connect(daemon.socket_path)
        client.sendall(b"not json at all\n")
        resp = json.loads(client.recv(4096).decode())
        client.close()
        assert "error" in resp
        # and the daemon answers a good request right after
        assert len(signer.sign(b"still alive")) == 128
        with pytest.raises(KeyHolderError, match="unknown protocol"):
            signer._request({"protocol": "other/9", "op": "sign",
                             "data": "ab"})


def test_oversized_request_is_refused(tmp_path):
    """The socket is an oracle for THIS journal's signatures — small bytes.
    An 8 KB+ line is dropped before it reaches the key."""
    with _Daemon() as daemon:
        import socket as _s
        client = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        client.settimeout(5)
        client.connect(daemon.socket_path)
        # the daemon drops an oversized line by DISCONNECTING — the send
        # may hit the closed pipe before the recv does
        with contextlib.suppress(BrokenPipeError):
            client.sendall(b'{"op":"sign","data":"' + b"ab" * 6000
                           + b'"}\n')
        got = b""
        with contextlib.suppress(ConnectionResetError):
            # EOF (macOS) or RST (Linux): both mean the same thing — the
            # oversized line was dropped, never served
            got = client.recv(4096)
        client.close()
        assert got == b""  # no error line either: dropped, not served


def test_the_material_never_crosses_the_socket(tmp_path):
    """No op returns private material; the response vocabulary is fixed."""
    with _Daemon() as daemon:
        raw = KeyHolder.handle_line(
            daemon.holder,
            json.dumps({"protocol": PROTOCOL, "op": "export"}).encode())
        assert "error" in raw  # unknown op — there IS no export op
        signed = KeyHolder.handle_line(
            daemon.holder,
            json.dumps({"protocol": PROTOCOL, "op": "sign",
                        "data": "ab" * 32}).encode())
        assert set(signed) == {"signature", "public_hex",
                               "peer_uid", "peer_uid_checked"}


@pytest.mark.skipif(os.uname().sysname != "Linux",
                    reason="SO_PEERCRED is Linux; the fail-closed branch is "
                           "asserted on every platform")
def test_uid_gate_enforces(tmp_path):
    """The gate is a refusal engine: the right uid signs END-TO-END through
    the live socket, and any other uid is refused — asserted at the request
    boundary, deterministic. (Fail-closed is the next test.)"""
    daemon_key = KeyPair.generate()
    with _Daemon(allow_uid=os.getuid(), key=daemon_key) as daemon:
        signer = SocketSigner(daemon.socket_path)
        assert signer.sign(b"operator uid") == daemon_key.sign(b"operator uid")
        refused = KeyHolder.handle_line(
            daemon.holder,
            json.dumps({"protocol": PROTOCOL, "op": "sign",
                        "data": b"someone else".hex()}).encode(),
            (os.getuid() + 1, True))
        assert "not the allowed operator" in refused["error"]


def test_uid_gate_on_a_deaf_platform_fails_closed(tmp_path):
    """No peer credentials available + a gate requested → refusal. The
    handle_line path is platform-free: (None, False) is never a pass."""
    with _Daemon(allow_uid=os.getuid()) as daemon:
        resp = KeyHolder.handle_line(
            daemon.holder,
            json.dumps({"protocol": PROTOCOL, "op": "sign",
                        "data": "ab"}).encode(),
            (None, False))
        assert "error" in resp
        assert "fail closed" in resp["error"]
