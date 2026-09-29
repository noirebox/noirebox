"""Journal discovery for hooks and integrations (the per-project convention).

A recorder that seals agent decisions must answer "which journal?" without
configuration friction and without scattering evidence across random paths.
The convention, in priority order:

1. `NOIREBOX_DB` — explicit, wins over everything (deployment choice, never
   an accident, as in ADR 004).
2. Walk up from the working directory: the first ancestor holding a
   `.noirebox/` directory owns the journal. This makes a repository the
   natural custody unit: one journal per project, discovered from anywhere
   inside it, portable with the working tree.
3. Otherwise `<working directory>/.noirebox/journal.db`, created on demand
   by the caller — an opt-in recorder has the right to create its directory,
   and users add `.noirebox/` to their .gitignore (or commit it, which is
   evidence publication and their call).
"""
from __future__ import annotations

import os
from pathlib import Path

JOURNAL_DIR = ".noirebox"
JOURNAL_FILENAME = "journal.db"


def resolve_journal(start_dir: str | Path | None = None) -> str:
    """Resolves the journal path for a working directory (env wins)."""
    env = os.environ.get("NOIREBOX_DB")
    if env:
        return env
    start = Path(start_dir or os.getcwd()).expanduser().resolve()
    for candidate in (start, *start.parents):
        if (candidate / JOURNAL_DIR).is_dir():
            return str(candidate / JOURNAL_DIR / JOURNAL_FILENAME)
    return str(start / JOURNAL_DIR / JOURNAL_FILENAME)


def ensure_journal_dir(start_dir: str | Path | None = None) -> str:
    """Same resolution, but creates the `.noirebox/` directory on demand.

    Permissions matter as everywhere in NoireBox: the journal may hold
    personal data, so the directory is created 0700 and the database file
    handles its own 0600 (EventStore does it at open time).
    """
    db = resolve_journal(start_dir)
    directory = Path(db).parent
    if not directory.exists():
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return db
