"""ADR 013 — journal discovery: NOIREBOX_DB, then the nearest .noirebox/ up."""

import stat
from pathlib import Path

from noirebox.locate import ensure_journal_dir, resolve_journal


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
