"""ADR 031 — authorization receipts: a gate whose decisions are sealed is a
gate an auditor can replay. The refusal discipline is the point: an allow
without a warrant, a laundered warrant, or a swallowed gate error must
never reach the journal; the replay pass catches the ones that got there
anyway (generic append)."""
import pytest

from noirebox.authorization import (
    AuthorizationAudit,
    replay_authorization,
    seal_authorization,
)
from noirebox.chain import KeyPair
from noirebox.store import EventStore


def _store(tmp_path):
    return EventStore(str(tmp_path / "authz.db")), KeyPair.generate()


def test_seal_then_replay_clean_holds(tmp_path):
    store, key = _store(tmp_path)
    seal_authorization(store, key, agent="os:uid=942 via SO_PEERCRED",
                       action="read", resource="/srv/approved/dataset.csv",
                       decision="allowed", warrant="user-instruction #41",
                       rule="allowlist:read_approved", gate="uai-broker T04-v06")
    seal_authorization(store, key, agent="os:uid=942 via SO_PEERCRED",
                       action="delete_file", resource="/srv/approved/dataset.csv",
                       decision="denied", reason="delete not in allowlist",
                       gate="uai-broker T04-v06")
    audit = replay_authorization(store)
    assert isinstance(audit, AuthorizationAudit)
    assert (audit.allowed, audit.denied, audit.gate_errors) == (1, 1, 0)
    assert audit.triples == 2
    assert audit.holds


def test_allow_without_warrant_refused_at_seal_time():
    store, key = _store_tmp()
    with pytest.raises(ValueError, match="allow without a warrant"):
        seal_authorization(store, key, agent="agent-7", action="send_email",
                           resource="client@corp.example", decision="allowed")


def test_laundered_warrant_refused_at_seal_time(tmp_path):
    store, key = _store(tmp_path)
    with pytest.raises(ValueError, match="never a basis"):
        seal_authorization(store, key, agent="agent-7", action="read",
                           resource="/data/triage.csv", decision="allowed",
                           warrant="relevance")


def test_gate_error_is_a_named_decision_not_an_exception(tmp_path):
    store, key = _store(tmp_path)
    seal_authorization(store, key, agent="agent-7", action="read",
                       resource="/data/x.csv", decision="gate_error",
                       reason="broker socket unavailable")
    audit = replay_authorization(store)
    assert audit.gate_errors == 1
    assert audit.holds


def test_bad_decision_vocabulary_refused():
    store, key = _store_tmp()
    with pytest.raises(ValueError, match="decision must be one of"):
        seal_authorization(store, key, agent="a", action="read", resource="r",
                           decision="ok")


def test_empty_agent_refused_with_identity_guidance():
    store, key = _store_tmp()
    with pytest.raises(ValueError, match="as verified at execution time"):
        seal_authorization(store, key, agent="  ", action="read", resource="r",
                           decision="denied")


def test_replay_catches_allow_without_warrant_via_generic_append(tmp_path):
    store, key = _store(tmp_path)
    seal_authorization(store, key, agent="a1", action="read", resource="r1",
                       decision="denied")
    # someone bypasses the seal-time refusals via the generic append
    store.append("authorization", {"schema": "authorization/0.1",
                                   "agent": "a2", "action": "read",
                                   "resource": "r2", "decision": "allowed"},
                 key)
    audit = replay_authorization(store)
    assert not audit.holds
    codes = [f.code for f in audit.findings]
    assert codes == ["allow_without_warrant"]
    assert "no warrant sealed" in audit.findings[0].note


def test_replay_catches_malformed_authorization_events(tmp_path):
    store, key = _store(tmp_path)
    store.append("authorization", {"agent": "a", "decision": "allowed"}, key)
    audit = replay_authorization(store)
    assert audit.malformed == 1
    assert audit.findings[0].code == "malformed_event"
    assert not audit.holds


def test_replay_catches_gate_flip_on_same_triple(tmp_path):
    store, key = _store(tmp_path)
    seal_authorization(store, key, agent="agent-9", action="send_email",
                       resource="press@corp.example", decision="denied",
                       reason="no instruction")
    seal_authorization(store, key, agent="agent-9", action="send_email",
                       resource="press@corp.example", decision="allowed",
                       warrant="plausible")
    audit = replay_authorization(store)
    codes = [f.code for f in audit.findings]
    assert "gate_flip" in codes
    flip = next(f for f in audit.findings if f.code == "gate_flip")
    assert "denied at seq" in flip.note
    assert not audit.holds


def test_flip_finding_not_raised_for_distinct_triples(tmp_path):
    store, key = _store(tmp_path)
    seal_authorization(store, key, agent="a", action="read", resource="r1",
                       decision="denied")
    seal_authorization(store, key, agent="a", action="read", resource="r2",
                       decision="allowed", warrant="user-instruction #7")
    assert replay_authorization(store).holds


def _store_tmp():
    import tempfile
    return EventStore(str(tempfile.mkdtemp() + "/a.db")), KeyPair.generate()


# --- the shell surface: `noirebox seal-authorization` ----------------------------

_CLI_OK = {
    "--agent": "os:uid=942 via SO_PEERCRED",
    "--action": "read",
    "--resource": "/srv/approved/dataset.csv",
    "--decision": "allowed",
    "--warrant": "user instruction #41 ('load the approved dataset')",
    "--rule": "allowlist:read_approved",
    "--gate": "uai-broker T04-v06",
}


def _cli(tmp_path, monkeypatch, over: dict | None = None,
         drop: tuple = ()) -> tuple[int, EventStore]:
    """`noirebox seal-authorization --db <fresh journal>` with the happy
    flags, `over` replacing flags by name, `drop` removing them;
    returns (rc, the journal)."""
    from noirebox.cli import main as cli_main
    monkeypatch.delenv("NOIREBOX_KEY_PEM", raising=False)
    db = str(tmp_path / "cli.db")
    KeyPair.load_or_create(db + ".key")
    flags = dict(_CLI_OK)
    flags.update(over or {})
    argv = ["seal-authorization", "--db", db]
    for flag, value in flags.items():
        if flag in drop:
            continue
        argv += [flag, value]
    return cli_main(argv), EventStore(db)


def test_cli_seals_what_the_api_seals(tmp_path, monkeypatch, capsys):
    """The shell surface is the same gate: one event, the API's payload shape."""
    rc, store = _cli(tmp_path, monkeypatch)
    assert rc == 0
    events = store.all()
    assert len(events) == 1 and events[0]["type"] == "authorization"
    payload = events[0]["payload"]
    assert payload["schema"] == "authorization/0.1"
    assert payload["agent"] == "os:uid=942 via SO_PEERCRED"
    assert payload["decision"] == "allowed"
    assert payload["warrant"].startswith("user instruction #41")
    assert "[authorization] sealed seq=1" in capsys.readouterr().out


def test_cli_refuses_allow_without_warrant_and_writes_nothing(
        tmp_path, monkeypatch, capsys):
    """The generic `noirebox seal` would take this JSON; this command must
    not — the refusal is the function's, verbatim, and no event lands."""
    rc, store = _cli(tmp_path, monkeypatch, drop=("--warrant",))
    assert rc == 2
    assert "allow without a warrant" in capsys.readouterr().err
    assert store.all() == []


@pytest.mark.parametrize("basis", ["presence", "relevance", "plausibility",
                                   "usefulness"])
def test_cli_refuses_the_laundered_warrants(tmp_path, monkeypatch, basis):
    rc, store = _cli(tmp_path, monkeypatch, over={"--warrant": basis})
    assert rc == 2
    assert store.all() == []


def test_cli_denial_needs_no_warrant(tmp_path, monkeypatch, capsys):
    rc, store = _cli(tmp_path, monkeypatch,
                     over={"--decision": "denied",
                           "--reason": "not in allowlist"},
                     drop=("--warrant", "--rule"))
    assert rc == 0
    payload = store.all()[0]["payload"]
    assert payload["decision"] == "denied"
    assert "warrant" not in payload
