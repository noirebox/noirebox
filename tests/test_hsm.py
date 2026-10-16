"""HSM signing (rung 5 — custody, not evidence): the PKCS#11 contract,
proven on SoftHSM2. The software token proves the INTERFACE — determinism,
key continuity, drop-in composition — never the non-extractability: that
claim belongs to real hardware, and these tests do not make it."""
from __future__ import annotations

import os
import shutil
import tempfile
import textwrap

import pytest
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat)

from noirebox.chain import KeyPair, verify_chain_multi
from noirebox.hsm import ensure_hsm_key, find_softhsm
from noirebox.store import EventStore

# pkcs11 is imported INSIDE the tests: this module must COLLECT cleanly in
# environments without the hsm extra (the skipifs above do the gating)

pytestmark = [
    pytest.mark.skipif(find_softhsm() is None,
                       reason="no SoftHSM2 module on this machine"),
    pytest.mark.skipif(shutil.which("softhsm2-util") is None,
                       reason="softhsm2-util not installed"),
]


@pytest.fixture()
def hsm_env(tmp_path, monkeypatch):
    """A throwaway SoftHSM2: its own config, its own token dir — the
    system's tokens are never touched. SOFTHSM2_CONF must be set BEFORE
    pkcs11.lib() loads: the library reads it once per process."""
    conf = tmp_path / "softhsm2.conf"
    tokens = tmp_path / "tokens"
    tokens.mkdir()
    conf.write_text(textwrap.dedent(f"""
        directories.tokendir = {tokens}
        objectstore.backend = file
        log.level = ERROR
    """))
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    slot_out = os.popen(
        "softhsm2-util --init-token --free --label nbhsm "
        "--so-pin 1234 --pin 1234").read()
    assert "initialized" in slot_out.lower()
    return {"module": find_softhsm(), "token": "nbhsm", "pin": "1234"}


def test_ensure_is_idempotent_and_signs_byte_identical(hsm_env):
    """Import an existing journal key: the public hex does not move, and
    the token's signature IS the key's own (Ed25519 deterministic)."""
    kp = KeyPair.generate()
    pem = kp._priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                 NoEncryption())
    signer = ensure_hsm_key(hsm_env["module"], token_label=hsm_env["token"],
                            pin=hsm_env["pin"], key_label="journal",
                            pem=bytes(pem))
    assert signer.public_hex() == kp.public_hex()  # continuity, not rotation
    sig = signer.sign(b"the same bytes")
    assert sig == kp.sign(b"the same bytes")  # the math did not move either

    # idempotent: a second ensure reuses the token key, no duplicate
    again = ensure_hsm_key(hsm_env["module"], token_label=hsm_env["token"],
                           pin=hsm_env["pin"], key_label="journal",
                           pem=bytes(pem))
    assert again.public_hex() == kp.public_hex()


def test_hsm_sealed_journal_verifies(hsm_env, tmp_path):
    """A journal sealed THROUGH the token verifies like any other — the
    writer path cannot tell which signer it was handed."""
    signer = ensure_hsm_key(hsm_env["module"], token_label=hsm_env["token"],
                            pin=hsm_env["pin"], key_label="fresh")
    store = EventStore(str(tmp_path / "j.db"))
    store.append("policy_decision", {"decision_id": "d1"}, signer)
    store.append("provider_response", {"decision_id": "d1"}, signer)
    check = verify_chain_multi([signer.public_hex()], store.all())
    assert check["valid"], check["first_error"]


def test_the_value_attribute_is_shielded(hsm_env):
    """SENSITIVE does its one job: CKA_VALUE cannot be read back — the
    token answers the export attempt with an error, not with the seed.
    (On SoftHSM2 the FILE still holds the material: the interface is
    proven here, the custody claim belongs to hardware. Stated, not
    hidden.)"""
    import pkcs11
    from pkcs11 import Attribute

    signer = ensure_hsm_key(hsm_env["module"], token_label=hsm_env["token"],
                            pin=hsm_env["pin"], key_label="shielded")
    privs = list(signer._session.get_objects({
        Attribute.CLASS: pkcs11.constants.ObjectClass.PRIVATE_KEY,
        Attribute.LABEL: "shielded",
    }))
    with pytest.raises(pkcs11.exceptions.AttributeSensitive):
        privs[0][Attribute.VALUE]


def test_the_token_does_not_lie_about_never_extractable(hsm_env):
    """An IMPORTED key reports NEVER_EXTRACTABLE False — it did exist
    outside once, and the label says so. The token is honest; only keys
    BORN on real silicon make that label true."""
    import pkcs11
    from pkcs11 import Attribute

    signer = ensure_hsm_key(hsm_env["module"], token_label=hsm_env["token"],
                            pin=hsm_env["pin"], key_label="imported")
    privs = list(signer._session.get_objects({
        Attribute.CLASS: pkcs11.constants.ObjectClass.PRIVATE_KEY,
        Attribute.LABEL: "imported",
    }))
    assert privs[0][Attribute.NEVER_EXTRACTABLE] is False


def test_keyholder_bridges_the_token(hsm_env, tmp_path):
    """THE composition: the agent speaks SocketSigner, the daemon speaks
    PKCS#11 — rung 4 and rung 5 interlock, no caller changes."""
    import threading

    from noirebox.keyholder import KeyHolder, SocketSigner

    signer = ensure_hsm_key(hsm_env["module"], token_label=hsm_env["token"],
                            pin=hsm_env["pin"], key_label="bridged")
    # AF_UNIX caps ~104 bytes: pytest tmp_path is deeper on macOS — the
    # socket lives in a short /tmp dir (same lesson as the keyholder tests)
    base = tempfile.mkdtemp(prefix="nbhsm_", dir="/tmp")
    holder = KeyHolder(signer, os.path.join(base, "kh.sock"))
    stop, ready = threading.Event(), threading.Event()
    t = threading.Thread(target=holder.serve_forever, args=(stop,),
                         kwargs={"ready_event": ready}, daemon=True)
    t.start()
    try:
        assert ready.wait(10)

        store = EventStore(str(tmp_path / "j.db"))
        store.append("receipt", {"schema": "receipt/0.2.2", "run_id": "r1",
                                 "judged_by": "deterministic"},
                     SocketSigner(os.path.join(base, "kh.sock")))
        check = verify_chain_multi([signer.public_hex()], store.all())
        assert check["valid"], check["first_error"]
    finally:
        stop.set()
        t.join(5)
        shutil.rmtree(base, ignore_errors=True)
