"""ADR 013 — journal discovery: NOIREBOX_DB, then the nearest .noirebox/ up."""

import stat
from pathlib import Path

from noirebox.locate import ensure_journal_dir, resolve_existing_journal, resolve_journal


def test_explicit_env_wins_over_everything(tmp_path, monkeypatch):
    monkeypatch.setenv("NOIREBOX_DB", "/tmp/explicit.db")
    assert resolve_journal(tmp_path) == "/tmp/explicit.db"


def test_walks_up_to_the_nearest_custody_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    project = tmp_path / "project"
    (project / ".noirebox").mkdir(parents=True)
    deep = project / "src" / "pkg"
    deep.mkdir(parents=True)
    assert resolve_journal(deep) == str(project / ".noirebox" / "journal.db")


def test_defaults_to_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    assert resolve_journal(tmp_path) == str(tmp_path / ".noirebox" / "journal.db")


def test_ensure_creates_the_directory_private(tmp_path, monkeypatch):
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    db = ensure_journal_dir(tmp_path)
    assert Path(db).parent.is_dir()
    mode = stat.S_IMODE(Path(db).parent.stat().st_mode)
    assert mode & 0o077 == 0  # group/other have nothing — the journal is private


def test_existing_journal_walks_up_to_the_nearest_custody_directory(tmp_path, monkeypatch):
    """Analysis commands (reconcile, audit-pack, seal-trajectory) discover a
    per-project journal the same way `seal`/`verify` do (ADR 013 refinement)."""
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    project = tmp_path / "project"
    (project / ".noirebox").mkdir(parents=True)
    deep = project / "src" / "pkg"
    deep.mkdir(parents=True)
    assert resolve_existing_journal(deep) == str(project / ".noirebox" / "journal.db")


def test_existing_journal_falls_back_to_the_repo_layout(tmp_path, monkeypatch):
    """Without a `.noirebox/` ancestor, analysis commands keep the classic
    repository layout — never a silently-created per-project journal."""
    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    assert resolve_existing_journal(tmp_path) == str(tmp_path / "data" / "noirebox.db")


def test_analysis_commands_and_seal_target_the_same_journal(tmp_path, monkeypatch):
    """The split-brain regression: `seal` creates ./.noirebox/journal.db, then
    `audit-pack` from the same directory must read THAT journal, not invent
    a second one under data/."""
    import json as _json

    from noirebox.cli import main as cli_main

    monkeypatch.delenv("NOIREBOX_DB", raising=False)
    monkeypatch.setenv("NOIREBOX_TSA_ROOTS_DIR", str(tmp_path / "no-roots"))
    monkeypatch.chdir(tmp_path)
    assert cli_main(["seal", "decision", '{"k": "v"}']) == 0
    assert cli_main(["audit-pack", str(tmp_path / "pack")]) == 0
    export = _json.loads((tmp_path / "pack" / "export.json").read_text())
    assert export["attestation"]["total_events"] == 1
    assert not (tmp_path / "data").exists()  # no phantom second journal
