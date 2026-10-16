from noirebox.attestation import build_attestation, verify_attestation
from noirebox.chain import KeyPair
from noirebox.store import EventStore


def _setup(tmp_path, nb=3):
    store = EventStore(str(tmp_path / "t.db"))
    key = KeyPair.load_or_create(str(tmp_path / "t.key"))
    for i in range(nb):
        store.append("test", {"i": i}, key)
    return store, key


def test_attestation_fields_and_validity(tmp_path):
    store, key = _setup(tmp_path)
    att = build_attestation(store, key)

    assert att["total_events"] == 3
    assert att["head_seq"] == 3
    assert att["chain_valid"] is True
    assert att["event_types"] == {"test": 3}
    assert att["algo"] == "sha256-chain+ed25519"
    assert verify_attestation(att) is True


def test_empty_chain_attestation_is_valid(tmp_path):
    store, key = _setup(tmp_path, nb=0)
    att = build_attestation(store, key)

    assert att["head_hash"] == "0" * 64
    assert verify_attestation(att) is True


def test_attestation_tamper_detected(tmp_path):
    store, key = _setup(tmp_path)
    att = build_attestation(store, key)
    forged = dict(att, head_hash="a" * 64)

    assert verify_attestation(forged) is False


def test_attestation_signed_by_other_key_rejected(tmp_path):
    store, key = _setup(tmp_path)
    att = build_attestation(store, key)
    impostor = KeyPair.generate()
    forged = dict(att, public_key=impostor.public_hex())

    assert verify_attestation(forged) is False
