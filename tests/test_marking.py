"""The marking receipt (ADR 030 — AI Act art. 50(2)): build-time gate tests
+ the `check_marking_coverage` join. A label can be stripped and a log can
be edited; the receipt lives in the anchored journal, bound to the output's
digest — stripping the mark changes the bytes, not the record."""
from __future__ import annotations

import hashlib

import pytest

from noirebox.c2pa import c2pa_action
from noirebox.chain import KeyPair
from noirebox.reconcile import check_marking_coverage, seal_marking
from noirebox.store import EventStore

OUT = hashlib.sha256(b"a generated paragraph").hexdigest()
OUT2 = hashlib.sha256(b"a generated image").hexdigest()
MANIFEST = hashlib.sha256(b"c2pa manifest bytes").hexdigest()


def _ok(**over) -> dict:
    base = {
        "output_digest": OUT,
        "modality": "text",
        "status": "marked",
        "system_ref": "writer-model@2026-10",
        "methods": ["watermark", "metadata"],
    }
    base.update(over)
    return base


def _journal(tmp_path, name: str) -> tuple[EventStore, KeyPair]:
    return (EventStore(str(tmp_path / f"{name}.db")),
            KeyPair.load_or_create(str(tmp_path / f"{name}.key")))


# --- the happy path --------------------------------------------------------------

def test_happy_payload_shape(tmp_path):
    store, key = _journal(tmp_path, "mk")
    seal_marking(store, key, **_ok())
    event = store.all()[-1]
    assert event["type"] == "marking"
    p = event["payload"]
    assert p["schema"] == "marking/0.1"
    assert p["article"] == "50(2)"
    assert p["output_digest"] == OUT
    assert p["modality"] == "text"
    assert p["status"] == "marked"
    assert p["methods"] == ["watermark", "metadata"]
    assert p["system_ref"] == "writer-model@2026-10"
    for absent in ("manifest_digest", "exemption", "detector"):
        assert absent not in p


def test_optional_fields_travel_when_given(tmp_path):
    store, key = _journal(tmp_path, "mk-opt")
    seal_marking(store, key, **_ok(methods=["c2pa_manifest"],
                                   manifest_digest=MANIFEST,
                                   detector="  c2patool 0.9 verify  "))
    p = store.all()[-1]["payload"]
    assert p["manifest_digest"] == MANIFEST
    assert p["detector"] == "c2patool 0.9 verify"


def test_digest_is_normalised_then_validated(tmp_path):
    """Upper-case hex is the same digest; a short one is not a digest —
    the content never enters the journal, only its sha256."""
    store, key = _journal(tmp_path, "mk-d")
    seal_marking(store, key, **_ok(output_digest=OUT.upper()))
    assert store.all()[-1]["payload"]["output_digest"] == OUT
    with pytest.raises(ValueError, match="seal the DIGEST, not the content"):
        seal_marking(store, key, **_ok(output_digest="deadbeef"))
    with pytest.raises(ValueError, match="seal the DIGEST"):
        seal_marking(store, key, **_ok(output_digest="a generated paragraph"))


# --- the closed vocabularies ------------------------------------------------------

def test_modality_is_art_50_2s_four(tmp_path):
    for i, modality in enumerate(("text", "image", "audio", "video")):
        store, key = _journal(tmp_path, f"mk-m{i}")
        seal_marking(store, key, **_ok(modality=modality))
        assert store.all()[-1]["payload"]["modality"] == modality
    store, key = _journal(tmp_path, "mk-mx")
    with pytest.raises(ValueError, match="modality must be one of"):
        seal_marking(store, key, **_ok(modality="3d_model"))


def test_status_fails_closed_with_the_unmarked_named(tmp_path):
    store, key = _journal(tmp_path, "mk-s")
    seal_marking(store, key, **_ok(status="not_marked", methods=None))
    assert store.all()[-1]["payload"]["status"] == "not_marked"
    assert "methods" not in store.all()[-1]["payload"]
    with pytest.raises(ValueError, match="unmarked is never clean"):
        seal_marking(store, key, **_ok(status="probably_fine"))


def test_marked_names_at_least_one_method(tmp_path):
    store, key = _journal(tmp_path, "mk-m0")
    with pytest.raises(ValueError, match="a mark with no method is a label"):
        seal_marking(store, key, **_ok(methods=[]))
    with pytest.raises(ValueError, match="a mark with no method is a label"):
        seal_marking(store, key, **_ok(methods=None))


def test_method_vocabulary_is_closed(tmp_path):
    store, key = _journal(tmp_path, "mk-mv")
    with pytest.raises(ValueError, match="method must be one of"):
        seal_marking(store, key, **_ok(methods=["watermark", "vibes"]))
    with pytest.raises(ValueError, match="methods must be a list"):
        seal_marking(store, key, **_ok(methods="watermark"))


def test_unmarked_and_exempt_carry_no_methods(tmp_path):
    """Only `marked` names what was applied — a `not_marked` receipt
    listing methods is the contradiction the gate refuses."""
    store, key = _journal(tmp_path, "mk-nm")
    with pytest.raises(ValueError, match="carries no methods"):
        seal_marking(store, key, **_ok(status="not_marked"))
    with pytest.raises(ValueError, match="carries no methods"):
        seal_marking(store, key, **_ok(status="exempt",
                                       exemption="assistive_editing"))


def test_c2pa_manifest_binds_its_digest_both_ways(tmp_path):
    store, key = _journal(tmp_path, "mk-c2pa")
    with pytest.raises(ValueError, match="c2pa_manifest requires manifest_digest"):
        seal_marking(store, key, **_ok(methods=["c2pa_manifest"]))
    with pytest.raises(ValueError, match="c2pa_manifest requires manifest_digest"):
        seal_marking(store, key, **_ok(methods=["c2pa_manifest"],
                                       manifest_digest="not-a-digest"))
    with pytest.raises(ValueError, match="a manifest nobody applied"):
        seal_marking(store, key, **_ok(manifest_digest=MANIFEST))
    seal_marking(store, key, **_ok(methods=["watermark", "c2pa_manifest"],
                                   manifest_digest=MANIFEST.upper()))
    assert store.all()[-1]["payload"]["manifest_digest"] == MANIFEST


def test_exempt_names_its_carve_out(tmp_path):
    """Art. 50(2) carries three carve-outs; a receipt that claims one
    says which — a bare `exempt` is the laundering word, refused."""
    for i, exemption in enumerate(("assistive_editing",
                                   "no_substantial_alteration",
                                   "authorised_by_law")):
        store, key = _journal(tmp_path, f"mk-e{i}")
        seal_marking(store, key, **_ok(status="exempt", methods=None,
                                       exemption=exemption))
        assert store.all()[-1]["payload"]["exemption"] == exemption
    store, key = _journal(tmp_path, "mk-ex")
    with pytest.raises(ValueError, match="exempt requires exemption in"):
        seal_marking(store, key, **_ok(status="exempt", methods=None))
    with pytest.raises(ValueError, match="exempt requires exemption in"):
        seal_marking(store, key, **_ok(status="exempt", methods=None,
                                       exemption="because"))
    with pytest.raises(ValueError, match="travels only with status `exempt`"):
        seal_marking(store, key, **_ok(exemption="assistive_editing"))


def test_system_ref_required(tmp_path):
    store, key = _journal(tmp_path, "mk-sys")
    with pytest.raises(ValueError, match="system_ref is required"):
        seal_marking(store, key, **_ok(system_ref="   "))


def test_detector_optional_but_never_blank(tmp_path):
    store, key = _journal(tmp_path, "mk-det")
    with pytest.raises(ValueError, match="detector, when given"):
        seal_marking(store, key, **_ok(detector="  "))


def test_c2pa_bridge_has_no_word_for_it():
    """C2PA marks the file; the receipt seals that the marking HAPPENED —
    the act of complying, not a media edit. The bridge keeps it in the
    custom namespace rather than borrowing a verb the standard defines
    for something else."""
    assert c2pa_action("marking") == "noirebox.marking"


# --- the reconciliation join --------------------------------------------------------

def test_generated_output_without_receipt_is_a_gap(tmp_path):
    store, key = _journal(tmp_path, "mk-j1")
    store.append("llm_output", {"output_digest": OUT, "summary": "s"}, key)
    findings = check_marking_coverage(store.all())
    assert [f.status for f in findings] == ["marking_gap"]
    assert findings[0].invariant == "marking"
    assert findings[0].correlation_id == OUT
    assert findings[0].decision_seq == 1


def test_marked_receipt_covers_the_output(tmp_path):
    store, key = _journal(tmp_path, "mk-j2")
    seal_marking(store, key, **_ok())
    store.append("llm_output", {"output_digest": OUT}, key)
    assert check_marking_coverage(store.all()) == []


def test_exempt_receipt_covers_too(tmp_path):
    store, key = _journal(tmp_path, "mk-j3")
    seal_marking(store, key, **_ok(status="exempt", methods=None,
                                   exemption="no_substantial_alteration"))
    store.append("llm_output", {"output_digest": OUT}, key)
    assert check_marking_coverage(store.all()) == []


def test_receipt_sealed_after_the_output_still_covers_in_0_1(tmp_path):
    """0.1 does not check order: delivery is not an event the journal
    sees yet, so a mark sealed after the generation event covers it. The
    limit is named in ADR 030, not hidden in the test."""
    store, key = _journal(tmp_path, "mk-j4")
    store.append("llm_output", {"output_digest": OUT}, key)
    seal_marking(store, key, **_ok())
    assert check_marking_coverage(store.all()) == []


def test_not_marked_receipt_is_the_gap_on_the_record(tmp_path):
    """The operator wrote the gap down; the reconciler surfaces it at the
    receipt's own seq — and does not report the same digest twice when
    the generation event is there too."""
    store, key = _journal(tmp_path, "mk-j5")
    store.append("llm_output", {"output_digest": OUT}, key)
    seal_marking(store, key, **_ok(status="not_marked", methods=None))
    findings = check_marking_coverage(store.all())
    assert [(f.status, f.decision_seq) for f in findings] == [("marking_gap", 2)]
    assert "not_marked" in findings[0].note


def test_a_later_mark_does_not_erase_the_unmarked_release(tmp_path):
    """The unmarked release happened; a later `marked` receipt for the
    same digest does not un-happen it — same fail-closed direction as
    an admission sealed after the use."""
    store, key = _journal(tmp_path, "mk-j6")
    seal_marking(store, key, **_ok(status="not_marked", methods=None))
    seal_marking(store, key, **_ok())
    store.append("llm_output", {"output_digest": OUT}, key)
    assert [(f.status, f.decision_seq) for f in check_marking_coverage(store.all())] == \
        [("marking_gap", 1)]


def test_one_finding_per_digest_across_many_outputs(tmp_path):
    store, key = _journal(tmp_path, "mk-j7")
    seal_marking(store, key, **_ok())
    store.append("llm_output", {"output_digest": OUT}, key)
    store.append("llm_output", {"output_digest": OUT2}, key)
    store.append("llm_output", {"output_digest": OUT2}, key)
    findings = check_marking_coverage(store.all())
    assert [(f.correlation_id, f.decision_seq) for f in findings] == [(OUT2, 3)]


def test_output_without_digest_is_out_of_scope(tmp_path):
    store, key = _journal(tmp_path, "mk-j8")
    store.append("llm_output", {"summary": "nothing to join"}, key)
    assert check_marking_coverage(store.all()) == []


def test_generation_type_is_configurable(tmp_path):
    store, key = _journal(tmp_path, "mk-j9")
    store.append("image_render", {"output_digest": OUT2}, key)
    assert check_marking_coverage(store.all()) == []
    findings = check_marking_coverage(store.all(), generation_type="image_render")
    assert [f.correlation_id for f in findings] == [OUT2]


# --- the shell surface: `noirebox seal-marking` ---------------------------------

_CLI_OK = {
    "--output-digest": OUT,
    "--modality": "text",
    "--status": "marked",
    "--system-ref": "writer-model@2026-10",
}


def _cli(tmp_path, monkeypatch, over: dict | None = None,
         methods: tuple[str, ...] = ("watermark",),
         extra: list[str] | None = None) -> tuple[int, EventStore]:
    """`noirebox seal-marking --db <fresh journal>` with the happy flags,
    `over` replacing flags by name, `methods` as repeated `--method`;
    returns (rc, the journal)."""
    from noirebox.cli import main as cli_main
    monkeypatch.delenv("NOIREBOX_KEY_PEM", raising=False)
    db = str(tmp_path / "cli.db")
    KeyPair.load_or_create(db + ".key")
    flags = dict(_CLI_OK)
    flags.update(over or {})
    argv = ["seal-marking", "--db", db]
    for flag, value in flags.items():
        argv += [flag, value]
    for method in methods:
        argv += ["--method", method]
    argv += list(extra or [])
    return cli_main(argv), EventStore(db)


def test_cli_seals_what_the_api_seals(tmp_path, monkeypatch, capsys):
    """The shell surface is the same gate: one event, the API's payload shape."""
    rc, store = _cli(tmp_path, monkeypatch)
    assert rc == 0
    events = store.all()
    assert len(events) == 1 and events[0]["type"] == "marking"
    payload = events[0]["payload"]
    assert payload["schema"] == "marking/0.1"
    assert payload["article"] == "50(2)"
    assert payload["output_digest"] == OUT
    assert payload["methods"] == ["watermark"]
    assert payload["status"] == "marked"
    assert "manifest_digest" not in payload and "exemption" not in payload
    out = capsys.readouterr().out
    assert "[marking] sealed seq=1" in out and OUT[:16] in out


def test_cli_method_is_repeatable_and_manifest_binds(tmp_path, monkeypatch):
    rc, store = _cli(tmp_path, monkeypatch,
                     methods=("watermark", "c2pa_manifest"),
                     extra=["--manifest-digest", MANIFEST,
                            "--detector", "c2patool 0.9 verify"])
    assert rc == 0
    payload = store.all()[0]["payload"]
    assert payload["methods"] == ["watermark", "c2pa_manifest"]
    assert payload["manifest_digest"] == MANIFEST
    assert payload["detector"] == "c2patool 0.9 verify"


def test_cli_exempt_path_names_the_carve_out(tmp_path, monkeypatch):
    rc, store = _cli(tmp_path, monkeypatch, over={"--status": "exempt"},
                     methods=(), extra=["--exemption", "assistive_editing"])
    assert rc == 0
    payload = store.all()[0]["payload"]
    assert payload["status"] == "exempt"
    assert payload["exemption"] == "assistive_editing"
    assert "methods" not in payload


@pytest.mark.parametrize("over, methods, extra, reason", [
    ({"--modality": "hologram"}, ("watermark",), [], "modality must be one of"),
    ({"--status": "fine"}, ("watermark",), [], "unmarked is never clean"),
    ({}, ("vibes",), [], "method must be one of"),
    ({}, (), [], "a mark with no method is a label"),
    ({}, ("c2pa_manifest",), [], "c2pa_manifest requires manifest_digest"),
    ({}, ("watermark",), ["--manifest-digest", MANIFEST], "a manifest nobody applied"),
    ({"--status": "exempt"}, (), [], "exempt requires exemption in"),
    ({"--output-digest": "deadbeef"}, ("watermark",), [], "seal the DIGEST"),
])
def test_cli_refuses_out_of_vocabulary_and_writes_nothing(
        tmp_path, monkeypatch, capsys, over, methods, extra, reason):
    """The generic `noirebox seal` would take this JSON; this command must
    not — the refusal is the function's, verbatim, and no event lands."""
    rc, store = _cli(tmp_path, monkeypatch, over=over, methods=methods, extra=extra)
    assert rc == 2
    assert store.all() == []
    err = capsys.readouterr().err
    assert err.startswith("[marking] refused: marking:") and reason in err


def test_cli_requires_every_field(tmp_path, monkeypatch):
    """argparse owns the missing-flag refusal — exit 2 before any key or
    journal is touched."""
    from noirebox.cli import main as cli_main
    monkeypatch.delenv("NOIREBOX_KEY_PEM", raising=False)
    db = tmp_path / "cli-missing.db"
    argv = ["seal-marking", "--db", str(db), "--method", "watermark"]
    for flag, value in _CLI_OK.items():
        if flag != "--status":
            argv += [flag, value]
    with pytest.raises(SystemExit) as exc:
        cli_main(argv)
    assert exc.value.code == 2
    assert not db.exists() and not db.with_suffix(".db.key").exists()
