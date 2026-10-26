"""ADR 032 — canary-sweep receipts: the sweep becomes evidence. The
refusal discipline is the point: a raw canary token, a clean sweep with
findings, a resurfacing with no location, or findings under a failed
sweep must never reach the journal; the replay pass catches the ones
that got there anyway (generic append), and a sweep that certified
nothing is named `vacuous_sweep`, never silence."""
import hashlib

import pytest

from noirebox.canary_sweep import (
    CanarySweepAudit,
    replay_canary_sweep,
    seal_canary_sweep,
)
from noirebox.chain import KeyPair
from noirebox.store import EventStore

# a real sha256 — the canary token itself never appears in this file
CANARY_DIGEST = hashlib.sha256(b"tok-noirebox-canary-7f3a9c").hexdigest()
OUT_A = hashlib.sha256(b"output at turn 17").hexdigest()
OUT_B = hashlib.sha256(b"output at turn 31").hexdigest()


def _store(tmp_path):
    return EventStore(str(tmp_path / "sweep.db")), KeyPair.generate()


def test_clean_sweep_seals_and_replay_holds(tmp_path):
    store, key = _store(tmp_path)
    seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                      outputs_swept=12, outcome="clean", turns_swept=40,
                      sensor="house-canary-probe 1.4")
    audit = replay_canary_sweep(store)
    assert isinstance(audit, CanarySweepAudit)
    assert (audit.sweeps, audit.clean, audit.resurfaced, audit.errors) == (1, 1, 0, 0)
    assert audit.outputs_swept == 12
    assert audit.holds


def test_resurfaced_sweep_carries_findings_by_coordinate_and_digest(
        tmp_path):
    store, key = _store(tmp_path)
    event = seal_canary_sweep(
        store, key, canary_digest=CANARY_DIGEST, outputs_swept=12,
        outcome="canary_resurfaced",
        findings=[{"at": "turn=17", "output_digest": OUT_A},
                  {"at": "turn=31", "output_digest": OUT_B}],
        sensor="house-canary-probe 1.4")
    payload = event.payload
    assert payload["canary_digest"] == CANARY_DIGEST
    assert payload["findings"][0] == {"at": "turn=17",
                                      "output_digest": OUT_A}
    audit = replay_canary_sweep(store)
    assert audit.resurfaced == 1
    # a resurfaced canary is the sensor's result, not a journal defect
    assert audit.holds


def test_raw_canary_token_refused_with_digest_guidance(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="never holds the token"):
        seal_canary_sweep(store, key,
                          canary_digest="tok-live-CANARY-7f3a9c",
                          outputs_swept=12, outcome="clean")


def test_bad_digest_shape_refused(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="64 hex"):
        seal_canary_sweep(store, key, canary_digest="abc",
                          outputs_swept=12, outcome="clean")


def test_bad_outcome_vocabulary_refused(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="outcome must be one of"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=12, outcome="ok")


def test_clean_with_findings_refused(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="a clean sweep with findings"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=12, outcome="clean",
                          findings=[{"at": "turn=17",
                                     "output_digest": OUT_A}])


def test_resurfaced_without_findings_refused(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="no location is a scare"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=12, outcome="canary_resurfaced")


def test_findings_under_sweep_error_refused(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="ambiguous evidence"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=12, outcome="sweep_error",
                          findings=[{"at": "turn=17",
                                     "output_digest": OUT_A}])


def test_sweep_error_is_a_named_outcome_not_an_exception(tmp_path):
    store, key = _store(tmp_path)
    seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                      outputs_swept=12, outcome="sweep_error",
                      note="sensor socket unavailable")
    audit = replay_canary_sweep(store)
    assert audit.errors == 1
    assert audit.holds


def test_negative_counts_refused(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="cannot be negative"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=-3, outcome="clean")
    with pytest.raises(ValueError, match="cannot be negative"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=3, outcome="clean", turns_swept=-1)


def test_finding_extra_keys_refused(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="no more, no less"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=12, outcome="canary_resurfaced",
                          findings=[{"at": "turn=17",
                                     "output_digest": OUT_A,
                                     "excerpt": "leaked"}])


def test_finding_requires_hex_digest(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="output_digest"):
        seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                          outputs_swept=12, outcome="canary_resurfaced",
                          findings=[{"at": "turn=17",
                                     "output_digest": "not-hex"}])


def test_replay_catches_malformed_events_via_generic_append(tmp_path):
    store, key = _store(tmp_path)
    store.append("canary_sweep",
                 {"canary_digest": CANARY_DIGEST, "outputs_swept": 4,
                  "outcome": "clean"}, key)  # no schema, no refusals
    audit = replay_canary_sweep(store)
    assert audit.malformed == 1
    assert audit.findings[0].code == "malformed_event"
    assert not audit.holds


def test_replay_flags_vacuous_sweep_by_name(tmp_path):
    """A clean sweep over zero outputs seals as fact — and surfaces as
    `vacuous_sweep`, never silence: it certified nothing."""
    store, key = _store(tmp_path)
    seal_canary_sweep(store, key, canary_digest=CANARY_DIGEST,
                      outputs_swept=0, outcome="clean")
    audit = replay_canary_sweep(store)
    codes = [f.code for f in audit.findings]
    assert codes == ["vacuous_sweep"]
    assert "certified nothing" in audit.findings[0].note
    assert not audit.holds


def test_replay_catches_clean_with_findings_via_generic_append(tmp_path):
    store, key = _store(tmp_path)
    store.append("canary_sweep",
                 {"schema": "canary-sweep/0.1",
                  "canary_digest": CANARY_DIGEST, "outputs_swept": 12,
                  "outcome": "clean",
                  "findings": [{"at": "turn=17",
                                "output_digest": OUT_A}]}, key)
    audit = replay_canary_sweep(store)
    assert [f.code for f in audit.findings] == ["clean_with_findings"]
    assert not audit.holds


def test_replay_catches_resurfaced_without_findings_via_generic_append(
        tmp_path):
    store, key = _store(tmp_path)
    store.append("canary_sweep",
                 {"schema": "canary-sweep/0.1",
                  "canary_digest": CANARY_DIGEST, "outputs_swept": 12,
                  "outcome": "canary_resurfaced"}, key)
    audit = replay_canary_sweep(store)
    assert [f.code for f in audit.findings] == [
        "resurfaced_without_findings"]
    assert not audit.holds


def test_replay_catches_malformed_finding_digest_via_generic_append(
        tmp_path):
    store, key = _store(tmp_path)
    store.append("canary_sweep",
                 {"schema": "canary-sweep/0.1",
                  "canary_digest": CANARY_DIGEST, "outputs_swept": 12,
                  "outcome": "canary_resurfaced",
                  "findings": [{"at": "turn=17",
                                "output_digest": "not-hex"}]}, key)
    audit = replay_canary_sweep(store)
    assert [f.code for f in audit.findings] == ["malformed_finding"]
    assert not audit.holds


def test_replay_ignores_other_event_types(tmp_path):
    store, key = _store(tmp_path)
    store.append("llm_output", {"text": "unrelated"}, key)
    assert replay_canary_sweep(store).holds


# --- the shell surface: `noirebox seal-canary-sweep` -------------------------

_CLI_OK = {
    "--canary-digest": CANARY_DIGEST,
    "--outputs-swept": "12",
    "--turns-swept": "40",
    "--outcome": "clean",
    "--sensor": "house-canary-probe 1.4",
}


def _cli(tmp_path, monkeypatch, over: dict | None = None,
         drop: tuple = ()) -> tuple[int, EventStore]:
    """`noirebox seal-canary-sweep --db <fresh journal>` with the happy
    flags, `over` replacing flags by name, `drop` removing them;
    returns (rc, the journal)."""
    from noirebox.cli import main as cli_main
    monkeypatch.delenv("NOIREBOX_KEY_PEM", raising=False)
    db = str(tmp_path / "cli.db")
    KeyPair.load_or_create(db + ".key")
    flags = dict(_CLI_OK)
    flags.update(over or {})
    argv = ["seal-canary-sweep", "--db", db]
    for flag, value in flags.items():
        if flag in drop:
            continue
        if isinstance(value, list):
            for item in value:
                argv += [flag, item]
        else:
            argv += [flag, value]
    return cli_main(argv), EventStore(db)


def test_cli_seals_what_the_api_seals(tmp_path, monkeypatch, capsys):
    """The shell surface is the same gate: one event, the API's payload
    shape."""
    rc, store = _cli(tmp_path, monkeypatch)
    assert rc == 0
    events = store.all()
    assert len(events) == 1 and events[0]["type"] == "canary_sweep"
    payload = events[0]["payload"]
    assert payload["schema"] == "canary-sweep/0.1"
    assert payload["outcome"] == "clean"
    assert payload["outputs_swept"] == 12
    assert payload["turns_swept"] == 40
    assert "[canary-sweep] sealed seq=1" in capsys.readouterr().out


def test_cli_refuses_raw_canary_and_writes_nothing(tmp_path, monkeypatch,
                                                   capsys):
    """The generic `noirebox seal` would take this JSON; this command
    must not — the refusal is the function's, verbatim, and no event
    lands."""
    rc, store = _cli(tmp_path, monkeypatch,
                     over={"--canary-digest": "tok-live-CANARY-7f3a9c"})
    assert rc == 2
    assert "never holds the token" in capsys.readouterr().err
    assert store.all() == []


def test_cli_finding_parses_at_hash_digest(tmp_path, monkeypatch):
    rc, store = _cli(
        tmp_path, monkeypatch,
        over={"--outcome": "canary_resurfaced",
              "--finding": [f"turn=17#{OUT_A}", f"turn=31#{OUT_B}"]})
    assert rc == 0
    findings = store.all()[0]["payload"]["findings"]
    assert findings == [{"at": "turn=17", "output_digest": OUT_A},
                        {"at": "turn=31", "output_digest": OUT_B}]


def test_cli_finding_without_hash_refused_writes_nothing(tmp_path,
                                                         monkeypatch):
    """'turn17' carries no '#<digest>' half — the module's refusal
    catches the shape the shell could not parse."""
    rc, store = _cli(tmp_path, monkeypatch,
                     over={"--outcome": "canary_resurfaced",
                           "--finding": ["turn17"]})
    assert rc == 2
    assert store.all() == []
