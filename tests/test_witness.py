"""ADR 019 §8 — the normalized witness: bind what happened, not the noise.

Two honest runs of the same work must produce the SAME witness; a rewrite
of any touched file must flip it. And a witness carrying wall-clock or raw
streams is refused — laundering noise into a seal is the thing this module
exists against."""
import hashlib

from noirebox.chain import KeyPair, verify_chain
from noirebox.store import EventStore
from noirebox.witness import (
    canonical_witness,
    file_tree_sha256,
    verify_file_tree,
    witness_payload_is_normalized,
)


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_two_honest_runs_produce_the_same_witness():
    """Same exit code, same byte counts, same file states → same payload.
    No wall-clock, no locale text: determinism is the contract."""
    a = canonical_witness(0, b"running...\nok\n", b"", {"f.py": _h(b"v1")}, {"f.py": _h(b"v2")})
    b = canonical_witness(0, b"running...\nok\n", b"", {"f.py": _h(b"v1")}, {"f.py": _h(b"v2")})
    assert a == b


def test_witness_binds_counts_not_content():
    """The raw stream is NOT carried: byte counts only. A progress bar
    changing between two honest runs must not flip the witness."""
    a = canonical_witness(0, b"[####    ] 50%\n[########] 100%\n")
    b = canonical_witness(0, b"[##      ] 25%\n[######  ] 75%\n[########] 100%\n")
    assert a["stdout_bytes"] != b["stdout_bytes"]  # volumes differ — the witness says so
    assert "stdout" not in a and "stdout_text" not in a  # the noise never enters


def test_file_tree_flips_on_any_change():
    files_v1 = {"a.py": _h(b"a1"), "b.py": _h(b"b1")}
    files_v2 = {"a.py": _h(b"a2"), "b.py": _h(b"b1")}
    files_v3 = {"a.py": _h(b"a1"), "b.py": _h(b"b1"), "c.py": _h(b"c")}
    assert file_tree_sha256(files_v1) != file_tree_sha256(files_v2)
    assert file_tree_sha256(files_v1) != file_tree_sha256(files_v3)
    # order of the map never matters — canonical over sorted paths
    assert file_tree_sha256(files_v1) == file_tree_sha256(dict(reversed(list(files_v1.items()))))


def test_diff_tells_which_files_moved(tmp_path):
    w = canonical_witness(0,
                          files_before={"a.py": _h(b"1"), "b.py": _h(b"1"), "d.py": _h(b"1")},
                          files_after={"a.py": _h(b"2"), "b.py": _h(b"1"), "c.py": _h(b"1")})
    assert w["files"]["changed"] == ["a.py"]
    assert w["files"]["added"] == ["c.py"]
    assert w["files"]["removed"] == ["d.py"]
    assert verify_file_tree(w, "after", {"a.py": _h(b"2"), "b.py": _h(b"1"), "c.py": _h(b"1")}) is None
    assert verify_file_tree(w, "after", {"a.py": _h(b"XX"), "b.py": _h(b"1"), "c.py": _h(b"1")}) is not None


def test_non_normalized_witness_is_refused_not_laundered():
    """A witness carrying raw streams or wall-clock keys must not be sealed
    by a sealer claiming the normalized convention."""
    assert witness_payload_is_normalized(canonical_witness(0, b"x")) is True
    for dirty in ({"stdout": "raw text"}, {"timestamp": "2026-10-04"},
                  {"stderr_text": "..."}, {"wall_clock": 1696}):
        assert witness_payload_is_normalized(dirty) is False


def test_witness_seals_into_the_journal_cleanly(tmp_path):
    store = EventStore(str(tmp_path / "w.db"))
    key = KeyPair.generate()
    w = canonical_witness(0, b"ok", b"", {"x.py": _h(b"1")}, {"x.py": _h(b"2")},
                          image_digest="sha256:abc123")
    store.append("run_witness", w, key)
    check = verify_chain(key.public_hex(), store.all())
    assert check["valid"] is True
